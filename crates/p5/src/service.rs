//! login / logout: one launchd plist or one systemd user unit.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LAUNCHD_LABEL: &str = "bot.postal.agent";
pub const LAUNCHD_PLIST_NAME: &str = "bot.postal.agent.plist";
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub const SYSTEMD_UNIT_NAME: &str = "p5-agent.service";

#[derive(Debug)]
pub enum ServiceError {
    Io(io::Error),
    Start(String),
    #[allow(dead_code)]
    Stop(String),
    NoHome,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Start(msg) | Self::Stop(msg) => write!(f, "{msg}"),
            Self::NoHome => f.write_str("HOME is not set"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<io::Error> for ServiceError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

pub fn user_home() -> Result<PathBuf, ServiceError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(ServiceError::NoHome)
}

pub fn launchd_plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents").join(LAUNCHD_PLIST_NAME)
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn systemd_unit_path(home: &Path) -> PathBuf {
    home.join(".config/systemd/user").join(SYSTEMD_UNIT_NAME)
}

pub fn program_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("p5"))
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn systemd_quote(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    if s.bytes().all(|b| {
        matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'_' | b'-'
        )
    }) {
        return s.to_string();
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// launchd plist. `Program` is the `p5` binary; args are `agent run`.
pub fn launchd_plist_text(program: &Path, p5_home: Option<&Path>) -> String {
    let program = xml_escape(&program.to_string_lossy());
    let env = match p5_home {
        Some(home) => format!(
            "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>P5_HOME</key>\n    <string>{}</string>\n  </dict>\n",
            xml_escape(&home.to_string_lossy())
        ),
        None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>Program</key>
  <string>{program}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{program}</string>
    <string>agent</string>
    <string>run</string>
  </array>
{env}  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
</dict>
</plist>
"#
    )
}

/// systemd user unit `p5-agent.service`. ExecStart is `p5 agent run`.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn systemd_unit_text(program: &Path, p5_home: Option<&Path>) -> String {
    let program = systemd_quote(&program.to_string_lossy());
    let env = match p5_home {
        Some(home) => {
            let pair = format!("P5_HOME={}", home.display());
            format!("Environment={}\n", systemd_quote(&pair))
        }
        None => String::new(),
    };
    format!(
        "\
[Unit]
Description=Postal agent (postal.bot)

[Service]
ExecStart={program} agent run
{env}Restart=on-failure

[Install]
WantedBy=default.target
"
    )
}

pub fn write_unit_files(
    home: &Path,
    program: &Path,
    p5_home: Option<&Path>,
) -> Result<PathBuf, ServiceError> {
    #[cfg(target_os = "macos")]
    {
        let path = launchd_plist_path(home);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, launchd_plist_text(program, p5_home))?;
        Ok(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let path = systemd_unit_path(home);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, systemd_unit_text(program, p5_home))?;
        Ok(path)
    }
}

fn skip_start() -> bool {
    matches!(std::env::var("P5_LOGIN_NO_START"), Ok(v) if v == "1" || v.eq_ignore_ascii_case("true"))
}

pub fn login(no_start: bool) -> Result<PathBuf, ServiceError> {
    let home = user_home()?;
    let program = program_path();
    let p5_home = std::env::var_os("P5_HOME").map(PathBuf::from);
    let path = write_unit_files(&home, &program, p5_home.as_deref())?;
    if no_start || skip_start() {
        return Ok(path);
    }
    start_service(&path)?;
    Ok(path)
}

pub fn unit_path(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        launchd_plist_path(home)
    }
    #[cfg(not(target_os = "macos"))]
    {
        systemd_unit_path(home)
    }
}

/// Bootout / disable so KeepAlive cannot respawn, then the caller reaps the pid.
pub fn unload() -> Result<(), ServiceError> {
    stop_service()
}

pub fn remove_unit() -> Result<(), ServiceError> {
    let path = unit_path(&user_home()?);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

fn start_service(unit_path: &Path) -> Result<(), ServiceError> {
    #[cfg(target_os = "macos")]
    {
        let uid = uid();
        let domain = format!("gui/{uid}");
        let label = format!("{domain}/{LAUNCHD_LABEL}");
        let _ = Command::new("launchctl").args(["bootout", &label]).status();
        let st = Command::new("launchctl")
            .args(["bootstrap", &domain])
            .arg(unit_path)
            .status()
            .map_err(|e| ServiceError::Start(e.to_string()))?;
        if st.success() {
            return Ok(());
        }
        let st = Command::new("launchctl")
            .args(["load", "-w"])
            .arg(unit_path)
            .status()
            .map_err(|e| ServiceError::Start(e.to_string()))?;
        if st.success() {
            return Ok(());
        }
        Err(ServiceError::Start(format!(
            "launchctl failed to load {}",
            unit_path.display()
        )))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = unit_path;
        let reload = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .map_err(|e| ServiceError::Start(e.to_string()))?;
        if !reload.success() {
            return Err(ServiceError::Start(
                "systemctl --user daemon-reload failed".into(),
            ));
        }
        let st = Command::new("systemctl")
            .args(["--user", "enable", "--now", SYSTEMD_UNIT_NAME])
            .status()
            .map_err(|e| ServiceError::Start(e.to_string()))?;
        if !st.success() {
            return Err(ServiceError::Start(format!(
                "systemctl failed to start {SYSTEMD_UNIT_NAME}"
            )));
        }
        Ok(())
    }
}

fn stop_service() -> Result<(), ServiceError> {
    #[cfg(target_os = "macos")]
    {
        let uid = uid();
        let domain = format!("gui/{uid}");
        let label = format!("{domain}/{LAUNCHD_LABEL}");
        let _ = Command::new("launchctl").args(["bootout", &label]).status();
        let home = user_home()?;
        let plist = launchd_plist_path(&home);
        if plist.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", "-w"])
                .arg(&plist)
                .status();
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", SYSTEMD_UNIT_NAME])
            .status()
            .map_err(|e| ServiceError::Stop(e.to_string()))?;
        Ok(())
    }
}

#[cfg(unix)]
fn uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_plist_names_postal_p5() {
        let text = launchd_plist_text(Path::new("/usr/local/bin/p5"), None);
        assert!(text.contains(LAUNCHD_LABEL));
        assert!(text.contains("bot.postal.agent"));
        assert!(text.contains("<key>Program</key>"));
        assert!(text.contains("/usr/local/bin/p5"));
        assert!(text.contains("<string>p5</string>") || text.contains("/p5</string>"));
        assert!(text.contains("<string>agent</string>"));
        assert!(text.contains("<string>run</string>"));
        assert!(text.contains("SuccessfulExit"));
        assert!(!text.contains("<key>KeepAlive</key>\n  <true/>"));
        assert!(!text.to_ascii_lowercase().contains("kessel"));
        assert!(!text.contains("k2 "));
    }

    #[test]
    fn launchd_plist_escapes_xml() {
        let text = launchd_plist_text(Path::new("/tmp/a&b<p5"), Some(Path::new("/tmp/x<y")));
        assert!(text.contains("&amp;"));
        assert!(text.contains("&lt;"));
        assert!(!text.contains("/tmp/a&b<p5"));
    }

    #[test]
    fn systemd_unit_is_p5_agent_service() {
        assert_eq!(SYSTEMD_UNIT_NAME, "p5-agent.service");
        let text = systemd_unit_text(Path::new("/usr/local/bin/p5"), None);
        assert!(text.contains("ExecStart=/usr/local/bin/p5 agent run"));
        assert!(text.contains("postal.bot"));
        assert!(text.contains("p5"));
        assert!(!text.to_ascii_lowercase().contains("kessel"));
        let quoted = systemd_unit_text(Path::new("/opt/my p5/p5"), Some(Path::new("/tmp/foo bar")));
        assert!(quoted.contains("\"/opt/my p5/p5\""));
        assert!(quoted.contains("\"P5_HOME=/tmp/foo bar\""));
    }

    #[test]
    fn writes_launch_agents_or_systemd_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_unit_files(tmp.path(), Path::new("/opt/bin/p5"), None).unwrap();
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                path,
                tmp.path()
                    .join("Library/LaunchAgents")
                    .join(LAUNCHD_PLIST_NAME)
            );
            let text = fs::read_to_string(&path).unwrap();
            assert!(text.contains("Program"));
            assert!(text.contains("p5"));
            assert!(text.contains("agent"));
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(
                path,
                tmp.path()
                    .join(".config/systemd/user")
                    .join(SYSTEMD_UNIT_NAME)
            );
            let text = fs::read_to_string(&path).unwrap();
            assert!(text.contains("p5-agent") || path.ends_with(SYSTEMD_UNIT_NAME));
            assert!(text.contains("p5 agent run"));
        }
    }
}
