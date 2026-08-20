//! RFC 8628 device login + hostname picker.
//!
//! `p5 login` prints a URL that already contains the user code
//! (`verification_uri_complete`) and tries to open a browser. Remote
//! servers often cannot open one — the human approves on any device.
//! The CLI polls until the site returns a Connect token, then lists
//! this account's postal.bot hostnames and binds one to this computer.

use std::fmt;
use std::io::{self, BufRead, Write};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use p5_plane::{
    DeviceAuth, HostList, HostView, PlaneClient, PlaneConfig, PlaneError, DEFAULT_PLANE_URL,
};
use p5_tunnel::{hostname_for_label, label_from_host};

use crate::billing;
use crate::pair::{run_login, PairError};
use crate::sm::{EXIT_ERROR, EXIT_USAGE};

#[derive(Debug)]
pub enum LoginError {
    Io(io::Error),
    Pair(PairError),
    Plane(PlaneError),
    Timeout,
    Denied,
    Expired,
    NoHosts,
    BadLabel(String),
    NoUrl,
}

impl LoginError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::BadLabel(_) | Self::NoHosts => EXIT_USAGE,
            Self::Pair(e) => e.exit_code(),
            _ => EXIT_ERROR,
        }
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Pair(e) => write!(f, "{e}"),
            Self::Plane(e) => write!(f, "{e}"),
            Self::Timeout => {
                f.write_str("timed out waiting for approval; open the URL on any device and run p5 login again")
            }
            Self::Denied => f.write_str("device login denied on the website"),
            Self::Expired => f.write_str("device code expired; run p5 login again"),
            Self::NoHosts => write!(
                f,
                "this account has no postal.bot hostname yet; claim one at {}",
                billing::pay_url()
            ),
            Self::BadLabel(msg) => write!(f, "{msg}"),
            Self::NoUrl => f.write_str("plane device start returned no approval URL"),
        }
    }
}

impl From<io::Error> for LoginError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<PairError> for LoginError {
    fn from(e: PairError) -> Self {
        Self::Pair(e)
    }
}

impl From<PlaneError> for LoginError {
    fn from(e: PlaneError) -> Self {
        Self::Plane(e)
    }
}

/// Save a Connect token, pick a hostname, persist both.
pub fn run(
    token_flag: Option<String>,
    label_flag: Option<String>,
    no_browser: bool,
) -> Result<(), LoginError> {
    let token = resolve_token(token_flag, no_browser)?;
    let label = resolve_label(&token, label_flag)?;
    run_login(token, Some(label))?;
    Ok(())
}

fn resolve_token(token_flag: Option<String>, no_browser: bool) -> Result<String, LoginError> {
    if let Some(t) = nonempty(token_flag) {
        return Ok(t);
    }
    if let Some(t) = saved_token() {
        eprintln!("using saved Connect token");
        return Ok(t);
    }
    device_token(no_browser)
}

fn saved_token() -> Option<String> {
    let cfg = PlaneConfig::load(&p5_core::default_root()).ok()?;
    nonempty(cfg.token)
}

fn plane_base() -> String {
    PlaneConfig::load(&p5_core::default_root())
        .map(|c| c.base_url)
        .unwrap_or_else(|_| DEFAULT_PLANE_URL.to_string())
}

fn device_token(no_browser: bool) -> Result<String, LoginError> {
    let client = PlaneClient::new(plane_base(), "");
    let auth = client.start_device()?;
    let url = auth.approve_url();
    if url.is_empty() {
        return Err(LoginError::NoUrl);
    }
    eprintln!("To approve this computer, open this URL on any device");
    eprintln!("(the code is already in the URL):");
    eprintln!("{url}");
    if !auth.user_code.trim().is_empty() {
        eprintln!("User code: {}", auth.user_code.trim());
    }
    if no_browser {
        eprintln!("Not opening a browser (--no-browser).");
    } else if open_browser(&url).is_err() {
        eprintln!("Could not open a browser on this machine (normal on a remote server).");
    }
    eprintln!("Waiting for approval…");
    let _ = io::stderr().flush();
    poll_until_token(&client, &auth)
}

fn poll_until_token(client: &PlaneClient, auth: &DeviceAuth) -> Result<String, LoginError> {
    let env_cap = std::env::var("P5_LOGIN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let cap = Duration::from_secs(env_cap.unwrap_or(auth.lifetime_secs()).max(1));
    let mut interval = Duration::from_secs(auth.poll_interval().max(1));
    if env_cap == Some(0) || auth.interval == 0 {
        // tests: interval 0 means poll immediately
        interval = Duration::from_millis(20);
    }
    let deadline = Instant::now() + cap;
    loop {
        match client.poll_device(&auth.device_code) {
            Ok(tok) => {
                return tok
                    .connect_token()
                    .map(str::to_string)
                    .ok_or_else(|| LoginError::Plane(PlaneError::Http {
                        status: 200,
                        message: "device approved but no token".into(),
                    }));
            }
            Err(PlaneError::AuthorizationPending) => {}
            Err(PlaneError::SlowDown) => {
                interval += Duration::from_secs(5);
            }
            Err(PlaneError::AccessDenied) => return Err(LoginError::Denied),
            Err(PlaneError::ExpiredToken) => return Err(LoginError::Expired),
            Err(e) => return Err(e.into()),
        }
        if Instant::now() >= deadline {
            return Err(LoginError::Timeout);
        }
        let sleep = interval.min(deadline.saturating_duration_since(Instant::now()));
        if !sleep.is_zero() {
            thread::sleep(sleep);
        }
    }
}

fn resolve_label(token: &str, label_flag: Option<String>) -> Result<String, LoginError> {
    let flag = nonempty(label_flag);
    match load_hosts(token) {
        Ok(hosts) => match flag {
            Some(raw) => match_choice(&hosts, &raw),
            None => pick_host(&hosts),
        },
        Err(LoginError::Plane(PlaneError::NotFound))
        | Err(LoginError::Plane(PlaneError::Http { status: 404, .. }))
        | Err(LoginError::Plane(PlaneError::Transport(_))) => match flag {
            Some(raw) => normalize_label(&raw),
            None => Err(LoginError::BadLabel(format!(
                "plane has no hostname list yet; pass --label (the subdomain, e.g. acme). Claim labels at {}",
                billing::pay_url()
            ))),
        },
        Err(e) => Err(e),
    }
}

fn load_hosts(token: &str) -> Result<Vec<HostView>, LoginError> {
    let cfg = PlaneConfig::load(&p5_core::default_root())?;
    let client = PlaneClient::new(&cfg.base_url, token);
    let list = client.list_hosts()?;
    let hosts = normalize_list(list);
    if hosts.is_empty() {
        Err(LoginError::NoHosts)
    } else {
        Ok(hosts)
    }
}

fn normalize_list(list: HostList) -> Vec<HostView> {
    let mut out = Vec::new();
    for raw in list.hosts {
        if let Ok(v) = normalize_host(raw) {
            if !out.iter().any(|h: &HostView| h.label == v.label) {
                out.push(v);
            }
        }
    }
    out
}

fn normalize_host(mut v: HostView) -> Result<HostView, LoginError> {
    v.label = v.label.trim().to_string();
    v.host = v.host.trim().to_string();
    if v.label.is_empty() && !v.host.is_empty() {
        v.label = label_from_host(&v.host).map_err(|e| LoginError::BadLabel(e.to_string()))?;
    }
    if v.host.is_empty() && !v.label.is_empty() {
        v.host = hostname_for_label(&v.label).map_err(|e| LoginError::BadLabel(e.to_string()))?;
    }
    if v.label.is_empty() {
        return Err(LoginError::BadLabel("hostname list entry is empty".into()));
    }
    v.label = normalize_label(&v.label)?;
    v.host = hostname_for_label(&v.label).map_err(|e| LoginError::BadLabel(e.to_string()))?;
    Ok(v)
}

fn normalize_label(raw: &str) -> Result<String, LoginError> {
    let host = hostname_for_label(raw.trim()).map_err(|e| LoginError::BadLabel(e.to_string()))?;
    label_from_host(&host).map_err(|e| LoginError::BadLabel(e.to_string()))
}

fn pick_host(hosts: &[HostView]) -> Result<String, LoginError> {
    if hosts.len() == 1 {
        return Ok(hosts[0].label.clone());
    }
    eprintln!("Which hostname should this computer use?");
    for (i, h) in hosts.iter().enumerate() {
        eprintln!("  {}. {}  {}", i + 1, h.host, plan_label(h));
    }
    if !stdin_is_tty() {
        return Err(LoginError::BadLabel(format!(
            "this account has {} hostnames; pass --label (one of: {})",
            hosts.len(),
            hosts
                .iter()
                .map(|h| h.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    eprint!("Enter number or label: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    match_choice(hosts, line.trim())
}

fn plan_label(h: &HostView) -> &str {
    let p = h.plan.trim();
    if p.is_empty() {
        "postal.bot"
    } else {
        p
    }
}

fn match_choice(hosts: &[HostView], raw: &str) -> Result<String, LoginError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(LoginError::BadLabel(
            "no hostname chosen; run p5 login again".into(),
        ));
    }
    if let Ok(n) = raw.parse::<usize>() {
        if let Some(h) = hosts.get(n.wrapping_sub(1)) {
            return Ok(h.label.clone());
        }
    }
    if let Some(h) = hosts.iter().find(|h| {
        h.label.eq_ignore_ascii_case(raw) || h.host.eq_ignore_ascii_case(raw)
    }) {
        return Ok(h.label.clone());
    }
    if let Ok(want) = normalize_label(raw).or_else(|_| {
        label_from_host(raw).map_err(|e| LoginError::BadLabel(e.to_string()))
    }) {
        if hosts.iter().any(|h| h.label == want) {
            return Ok(want);
        }
        return Err(LoginError::BadLabel(format!(
            "{want} is not one of this account's hostnames"
        )));
    }
    Err(LoginError::BadLabel(format!(
        "unknown choice {raw:?}; enter a number or a label"
    )))
}

fn stdin_is_tty() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn open_browser(url: &str) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        return Ok(());
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = url;
        Err(io::Error::other("no browser opener on this OS"))
    }
}

fn nonempty(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_choice_number_and_label() {
        let hosts = vec![
            HostView {
                label: "acme".into(),
                host: "acme.postal.bot".into(),
                plan: "free".into(),
            },
            HostView {
                label: "studio".into(),
                host: "studio.postal.bot".into(),
                plan: "paid".into(),
            },
        ];
        assert_eq!(match_choice(&hosts, "1").unwrap(), "acme");
        assert_eq!(match_choice(&hosts, "2").unwrap(), "studio");
        assert_eq!(match_choice(&hosts, "studio").unwrap(), "studio");
        assert_eq!(match_choice(&hosts, "studio.postal.bot").unwrap(), "studio");
        assert!(match_choice(&hosts, "3").is_err());
        assert!(match_choice(&hosts, "other").is_err());
    }
}
