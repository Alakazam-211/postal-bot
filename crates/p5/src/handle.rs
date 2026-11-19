//! `p5 handle claim|list|show|drop` — plugin + session packed per handle.
//!
//! Agents run this non-interactively (`--json`). See
//! `.k2/prds/prd-handle-last-mile.md`.

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

use p5_core::{
    default_root, Adopted, HomeRow, Homes, KeyReleased, PeerType, PostalAddr, StandDown,
    ToolFlags, EXIT_GATED,
};
use p5_plane::PlaneConfig;
use p5_tunnel::{hostname_for_label, label_from_host};
use serde::Serialize;

use crate::control;
use crate::last_mile;
use crate::pair;
use crate::sm::{EXIT_ERROR, EXIT_USAGE};

pub fn run_claim(
    handle: String,
    plugin: Option<String>,
    cwd: Option<String>,
    session: Option<String>,
    typ: Option<String>,
    json: bool,
    force: bool,
) -> Result<(), HandleError> {
    let plugin = plugin
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or(HandleError::NoPlugin)?;
    let root = default_root();
    let cwd = resolve_cwd(cwd)?;
    let host = enrolled_host(&root)?;
    let handle = normalize_handle(&handle)?;
    let addr: PostalAddr = format!("{handle}::{host}")
        .parse()
        .map_err(|e: p5_core::AddrError| HandleError::BadAddress(e.to_string()))?;

    let claim = last_mile::claim_plugin(
        &root,
        &plugin,
        &handle,
        &cwd,
        session.as_deref(),
    )
    .map_err(HandleError::Claim)?;

    let mut homes = Homes::load(&root)?;
    if let Some(prev) = homes.get(&addr) {
        if let (Some(old), true) = (prev.session_id.as_deref(), !force) {
            if old != claim.session_id {
                return Err(HandleError::Collision {
                    addr: addr.to_string(),
                    old: old.to_string(),
                    new: claim.session_id.clone(),
                });
            }
        }
    }

    let row_typ = typ
        .as_deref()
        .or(claim.typ.as_deref())
        .unwrap_or("session");
    let _parsed_typ: PeerType = row_typ
        .parse()
        .map_err(|e: p5_core::TypeParseError| HandleError::BadTyp(e.to_string()))?;

    if (plugin.eq_ignore_ascii_case("grok") || plugin.eq_ignore_ascii_case("turn"))
        && claim.session_id.trim().is_empty()
    {
        return Err(HandleError::Claim(last_mile::LastMileError::Plugin(
            "grok handle requires a Sand agent UUID; pass --session <uuid>".into(),
        )));
    }

    let row_cwd = if claim.cwd.trim().is_empty() {
        cwd.clone()
    } else {
        PathBuf::from(&claim.cwd)
    };
    let row = HomeRow {
        address: addr.clone(),
        session_id: Some(claim.session_id.clone()),
        cwd: row_cwd.clone(),
        inbox_root: None,
        launch: claim.launch.clone().unwrap_or_default(),
        harness: Some(plugin.clone()),
        terminal: Some(claim.terminal.clone()),
        tools: ToolFlags {
            files: false,
            live_inject: true,
            wake: true,
        },
        enrolled_host: host.clone(),
    };
    homes.insert(row)?;
    homes.save(&root)?;

    let me = publish_me(&addr, row_typ);
    let live = if claim.live {
        control::try_register(&root, &addr.to_string(), &claim.session_id)
    } else {
        false
    };

    let report = ClaimReport {
        claimed: addr.to_string(),
        plugin: plugin.clone(),
        terminal: claim.terminal.clone(),
        session: claim.session_id.clone(),
        cwd: row_cwd.display().to_string(),
        live,
        me: me.clone(),
        next: format!("p5 pair add <peer>"),
        test: format!("p5 msg {addr} \"hi\""),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
    } else {
        println!("claimed  {}", report.claimed);
        println!("plugin   {}", report.plugin);
        println!("terminal {}", report.terminal);
        println!("session  {}", report.session);
        println!("cwd      {}", report.cwd);
        println!("live     {}", if report.live { "yes" } else { "no" });
        println!("me       {}", report.me);
        println!("next     {}", report.next);
        println!("test     {}", report.test);
    }
    Ok(())
}

pub fn run_list(json: bool) -> Result<(), HandleError> {
    let root = default_root();
    let homes = Homes::load(&root)?;
    let adopted = Adopted::load(&root)?;
    let rows: Vec<ListRow> = homes
        .iter()
        .map(|(addr, row)| ListRow {
            stood_down_by: adopted.get(addr).map(|s| s.by.clone()),
            address: addr.to_string(),
            plugin: row.harness.clone().unwrap_or_default(),
            terminal: row.terminal.clone().unwrap_or_default(),
            session: row.session_id.clone().unwrap_or_default(),
            cwd: row.cwd.display().to_string(),
        })
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".into()));
    } else if rows.is_empty() {
        eprintln!("no handles; run: p5 handle claim <handle> --plugin k2|grok|<name>");
    } else {
        let mut cwd_n: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for r in &rows {
            *cwd_n.entry(r.cwd.clone()).or_insert(0) += 1;
        }
        for r in &rows {
            let session = if r.session.trim().is_empty() {
                "empty"
            } else {
                r.session.as_str()
            };
            let cwd = if cwd_n.get(&r.cwd).copied().unwrap_or(0) > 1 {
                format!("{} (shared)", r.cwd)
            } else {
                r.cwd.clone()
            };
            let sd = r
                .stood_down_by
                .as_deref()
                .map(|by| format!(" stood_down_by={by}"))
                .unwrap_or_default();
            println!(
                "{}  plugin={} terminal={} session={} cwd={}{sd}",
                r.address, r.plugin, r.terminal, session, cwd
            );
        }
    }
    Ok(())
}

pub fn run_show(handle: String, json: bool) -> Result<(), HandleError> {
    let root = default_root();
    let host = enrolled_host(&root).ok();
    let addr = resolve_show_addr(&handle, host.as_deref())?;
    let homes = Homes::load(&root)?;
    let Some(row) = homes.get(&addr) else {
        return Err(HandleError::NotFound(addr.to_string()));
    };
    let r = ListRow {
        stood_down_by: Adopted::load(&root)?.get(&addr).map(|s| s.by.clone()),
        address: addr.to_string(),
        plugin: row.harness.clone().unwrap_or_default(),
        terminal: row.terminal.clone().unwrap_or_default(),
        session: row.session_id.clone().unwrap_or_default(),
        cwd: row.cwd.display().to_string(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_else(|_| "{}".into()));
    } else {
        println!("address  {}", r.address);
        println!("plugin   {}", r.plugin);
        println!("terminal {}", r.terminal);
        println!("session  {}", r.session);
        println!("cwd      {}", r.cwd);
    }
    Ok(())
}

pub fn run_drop(handle: String) -> Result<(), HandleError> {
    if !owner_pair() {
        return Err(HandleError::Gated);
    }
    let root = default_root();
    let host = enrolled_host(&root).ok();
    let addr = resolve_show_addr(&handle, host.as_deref())?;
    let mut homes = Homes::load(&root)?;
    if homes.remove(&addr).is_none() {
        return Err(HandleError::NotFound(addr.to_string()));
    }
    homes.save(&root)?;
    println!("dropped {addr}");
    Ok(())
}

fn owner_pair() -> bool {
    match env::var("P5_OWNER_PAIR") {
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

fn resolve_cwd(cwd: Option<String>) -> Result<PathBuf, HandleError> {
    if let Some(raw) = cwd.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(raw));
    }
    env::current_dir().map_err(|e| HandleError::Io(e.to_string()))
}

fn enrolled_host(root: &Path) -> Result<String, HandleError> {
    if let Ok(raw) = env::var("P5_TUNNEL_LABEL") {
        let raw = raw.trim();
        if !raw.is_empty() {
            return hostname_for_label(raw).map_err(|e| HandleError::BadAddress(e.to_string()));
        }
    }
    let cfg = PlaneConfig::load(root).map_err(|e| HandleError::Plane(e.to_string()))?;
    if let Some(label) = cfg
        .file
        .tunnel_label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return hostname_for_label(label).map_err(|e| HandleError::BadAddress(e.to_string()));
    }
    let homes = Homes::load(root)?;
    if let Some((_, row)) = homes.iter().next() {
        return Ok(row.enrolled_host.clone());
    }
    Err(HandleError::HostUnbound)
}

fn normalize_handle(raw: &str) -> Result<String, HandleError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(HandleError::BadAddress("empty handle".into()));
    }
    if raw.contains("::") {
        let addr: PostalAddr = raw
            .parse()
            .map_err(|e: p5_core::AddrError| HandleError::BadAddress(e.to_string()))?;
        let _ = label_from_host(addr.host());
        Ok(addr.handle().to_string())
    } else if raw
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        Ok(raw.to_string())
    } else {
        Err(HandleError::BadAddress(format!(
            "handle must be lowercase [a-z0-9_-]: {raw}"
        )))
    }
}

fn resolve_show_addr(raw: &str, host: Option<&str>) -> Result<PostalAddr, HandleError> {
    PostalAddr::parse(raw, host).map_err(|e| HandleError::BadAddress(e.to_string()))
}

fn publish_me(addr: &PostalAddr, typ: &str) -> String {
    match pair::run_me(Some(typ.to_string()), false) {
        Ok(()) => "ok".into(),
        Err(err) => format!("skipped ({err})"),
    }
}

// ---- S7: stand down for a handle another host (K2) adopted ----------------

/// What `status` / `stand-down` / `resume` print with `--json`.
#[derive(Debug, Serialize)]
pub struct StandDownReport {
    pub addr: String,
    /// `null` while p5 serves the handle.
    pub stood_down_by: Option<String>,
    pub since: Option<i64>,
    /// The box key went out with `export-key`; `resume` refuses after this.
    pub key_exported: bool,
    /// p5 deleted its copy of the box key (`release-key`).
    pub key_released: bool,
}

fn report_for(addr: &PostalAddr, adopted: &Adopted) -> StandDownReport {
    let sd = adopted.get(addr);
    StandDownReport {
        addr: addr.to_string(),
        stood_down_by: sd.map(|s| s.by.clone()),
        since: sd.map(|s| s.since),
        key_exported: sd.is_some_and(|s| s.key_exported_at.is_some()),
        key_released: adopted.key_released.is_some(),
    }
}

fn print_report(r: &StandDownReport, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(r).unwrap_or_else(|_| "{}".into()));
    } else {
        match &r.stood_down_by {
            Some(by) => println!(
                "{}  stood down for {by}{}{}",
                r.addr,
                if r.key_exported { ", key exported" } else { "" },
                if r.key_released { ", key released" } else { "" },
            ),
            None => println!("{}  served by p5", r.addr),
        }
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The handle must be one of p5's homes rows.
fn ours(root: &Path, raw: &str) -> Result<(PostalAddr, Homes), HandleError> {
    let host = enrolled_host(root).ok();
    let addr = resolve_show_addr(raw, host.as_deref())?;
    let homes = Homes::load(root)?;
    if homes.get(&addr).is_none() {
        return Err(HandleError::NotOurs(addr.to_string()));
    }
    Ok((addr, homes))
}

pub fn run_status(handle: String, json: bool) -> Result<(), HandleError> {
    let root = default_root();
    let (addr, _) = ours(&root, &handle)?;
    print_report(&report_for(&addr, &Adopted::load(&root)?), json);
    Ok(())
}

/// Idempotent. Takes effect at once: the agent reloads this state on every
/// request and every hold pull.
pub fn run_stand_down(handle: String, by: String, json: bool) -> Result<(), HandleError> {
    let root = default_root();
    stand_down_at(&root, &handle, &by, now_unix()).map(|r| print_report(&r, json))
}

pub fn stand_down_at(
    root: &Path,
    handle: &str,
    by: &str,
    now: i64,
) -> Result<StandDownReport, HandleError> {
    let by = by.trim();
    if by.is_empty()
        || !by
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(HandleError::BadAddress(format!("--by must be [a-z0-9_-]: {by}")));
    }
    let (addr, _) = ours(root, handle)?;
    let mut adopted = Adopted::load(root)?;
    if let Some(sd) = adopted.get(&addr) {
        if sd.by != by {
            return Err(HandleError::AdoptedBy(addr.to_string(), sd.by.clone()));
        }
        return Ok(report_for(&addr, &adopted));
    }
    adopted.handles.insert(
        addr.to_string(),
        StandDown { by: by.to_string(), since: now, key_exported_at: None },
    );
    adopted.save(root)?;
    Ok(report_for(&addr, &adopted))
}

pub fn run_resume(handle: String, json: bool) -> Result<(), HandleError> {
    let root = default_root();
    resume_at(&root, &handle).map(|r| print_report(&r, json))
}

pub fn resume_at(root: &Path, handle: &str) -> Result<StandDownReport, HandleError> {
    let (addr, _) = ours(root, handle)?;
    let mut adopted = Adopted::load(root)?;
    match adopted.get(&addr) {
        None => {}
        Some(sd) if sd.key_exported_at.is_some() || adopted.key_released.is_some() => {
            return Err(HandleError::AdoptedBy(addr.to_string(), sd.by.clone()));
        }
        Some(_) => {
            adopted.handles.remove(&addr.to_string());
            adopted.save(root)?;
        }
    }
    Ok(report_for(&addr, &adopted))
}

/// Write the box's private key (PKCS#8 PEM) to stdout for the adopter's
/// vault. Never to a file, never to a terminal, and only when every handle
/// on this box has stood down, since they all sign with this one key.
pub fn run_export_key(handle: String) -> Result<(), HandleError> {
    use std::io::{IsTerminal, Write};
    let mut out = std::io::stdout().lock();
    if out.is_terminal() {
        return Err(HandleError::Tty);
    }
    let root = default_root();
    let pem = export_key_at(&root, &handle, now_unix())?;
    out.write_all(pem.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| HandleError::Io(e.to_string()))
}

/// Checks, reads the key, marks every handle `key_exported_at`, and returns
/// the PEM. Marking first means a failed write still blocks `resume`: the
/// key may have gone out. Re-running is allowed until `release-key` (it is
/// the same key), so a failed pipe is never a dead end.
pub fn export_key_at(root: &Path, handle: &str, now: i64) -> Result<String, HandleError> {
    let (addr, homes) = ours(root, handle)?;
    let mut adopted = Adopted::load(root)?;
    if adopted.key_released.is_some() {
        return Err(HandleError::KeyReleased);
    }
    if !adopted.is_stood_down(&addr) {
        return Err(HandleError::NotStoodDown(addr.to_string()));
    }
    let shared: Vec<String> = homes
        .iter()
        .filter(|(a, _)| !adopted.is_stood_down(a))
        .map(|(a, _)| a.to_string())
        .collect();
    if !shared.is_empty() {
        return Err(HandleError::KeyShared(shared));
    }
    let path = root.join(p5_crypto::KEYS_DIR).join(p5_crypto::IDENTITY_FILE);
    // Parse it first, so a broken file never goes out as "the key".
    if p5_crypto::KeyPair::load(root)
        .map_err(|e| HandleError::Io(e.to_string()))?
        .is_none()
    {
        return Err(HandleError::NoKey);
    }
    let pem = std::fs::read_to_string(&path).map_err(|e| HandleError::Io(e.to_string()))?;
    for sd in adopted.handles.values_mut() {
        sd.key_exported_at.get_or_insert(now);
    }
    adopted.save(root)?;
    Ok(pem)
}

/// After the adopter confirms it holds the key (by fingerprint), delete
/// p5's copy so only one holder can sign.
pub fn run_release_key(handle: String, fingerprint: String, json: bool) -> Result<(), HandleError> {
    let root = default_root();
    let r = release_key_at(&root, &handle, &fingerprint, now_unix())?;
    print_report(&r, json);
    Ok(())
}

pub fn release_key_at(
    root: &Path,
    handle: &str,
    fingerprint: &str,
    now: i64,
) -> Result<StandDownReport, HandleError> {
    let (addr, _) = ours(root, handle)?;
    let mut adopted = Adopted::load(root)?;
    if let Some(done) = &adopted.key_released {
        if done.fingerprint == fingerprint.trim() {
            return Ok(report_for(&addr, &adopted));
        }
        return Err(HandleError::KeyReleased);
    }
    if !adopted.get(&addr).is_some_and(|s| s.key_exported_at.is_some()) {
        return Err(HandleError::NotExported(addr.to_string()));
    }
    let key = p5_crypto::KeyPair::load(root)
        .map_err(|e| HandleError::Io(e.to_string()))?
        .ok_or(HandleError::NoKey)?;
    let fp = key.fingerprint();
    if fp != fingerprint.trim().to_ascii_lowercase() {
        return Err(HandleError::FingerprintMismatch);
    }
    adopted.key_released = Some(KeyReleased { fingerprint: fp, at: now });
    adopted.save(root)?;
    let path = root.join(p5_crypto::KEYS_DIR).join(p5_crypto::IDENTITY_FILE);
    std::fs::remove_file(&path).map_err(|e| HandleError::Io(e.to_string()))?;
    Ok(report_for(&addr, &adopted))
}

#[derive(Debug, Serialize)]
struct ClaimReport {
    claimed: String,
    plugin: String,
    terminal: String,
    session: String,
    cwd: String,
    live: bool,
    me: String,
    next: String,
    test: String,
}

#[derive(Debug, Serialize)]
struct ListRow {
    address: String,
    /// S7: set when another host adopted the handle.
    #[serde(skip_serializing_if = "Option::is_none")]
    stood_down_by: Option<String>,
    plugin: String,
    terminal: String,
    session: String,
    cwd: String,
}

#[derive(Debug)]
pub enum HandleError {
    NoPlugin,
    Claim(last_mile::LastMileError),
    Collision {
        addr: String,
        old: String,
        new: String,
    },
    HostUnbound,
    BadAddress(String),
    BadTyp(String),
    NotFound(String),
    Gated,
    Store(p5_core::StoreError),
    Plane(String),
    Io(String),
    // S7
    NotOurs(String),
    AdoptedBy(String, String),
    NotStoodDown(String),
    KeyShared(Vec<String>),
    NotExported(String),
    KeyReleased,
    FingerprintMismatch,
    NoKey,
    Tty,
}

impl HandleError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NoPlugin | Self::BadAddress(_) | Self::BadTyp(_) | Self::HostUnbound => {
                EXIT_USAGE
            }
            // S7 contract with K2: 2 = not p5's handle, or the key is shared.
            Self::NotOurs(_) | Self::KeyShared(_) => EXIT_USAGE,
            Self::Collision { .. }
            | Self::Gated
            | Self::AdoptedBy(..)
            | Self::NotStoodDown(_)
            | Self::NotExported(_)
            | Self::KeyReleased
            | Self::FingerprintMismatch
            | Self::Tty => EXIT_GATED,
            _ => EXIT_ERROR,
        }
    }
}

impl fmt::Display for HandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPlugin => f.write_str(
                "no_plugin — pass --plugin k2|grok|<name> (or install ~/.postal/harness/<name>)",
            ),
            Self::Claim(e) => write!(f, "{e}"),
            Self::Collision { addr, old, new } => write!(
                f,
                "collision — {addr} already session {old}; new {new}. pass --force to replace"
            ),
            Self::HostUnbound => {
                f.write_str("host_unbound — run p5 login --label <subdomain> first")
            }
            Self::BadAddress(m) | Self::BadTyp(m) | Self::Plane(m) | Self::Io(m) => {
                f.write_str(m)
            }
            Self::NotFound(a) => write!(f, "not found: {a}"),
            Self::Gated => f.write_str("gated — drop needs P5_OWNER_PAIR=1"),
            Self::Store(e) => write!(f, "{e}"),
            Self::NotOurs(a) => write!(f, "not_ours — {a} is not a p5 handle on this box"),
            Self::AdoptedBy(a, by) => write!(f, "adopted by {by} — {a}"),
            Self::NotStoodDown(a) => {
                write!(f, "not_stood_down — run p5 handle stand-down {a} --by <host> first")
            }
            Self::KeyShared(rest) => write!(f, "key shared with {}", rest.join(", ")),
            Self::NotExported(a) => write!(f, "not_exported — {a}'s key was never exported"),
            Self::KeyReleased => f.write_str("key_released — p5 no longer holds this key"),
            Self::FingerprintMismatch => {
                f.write_str("fingerprint_mismatch — that is not this box's key")
            }
            Self::NoKey => f.write_str("no_key — this box has no identity key"),
            Self::Tty => f.write_str("refusing to print a private key to a terminal; pipe it"),
        }
    }
}

impl std::error::Error for HandleError {}

impl From<p5_core::StoreError> for HandleError {
    fn from(e: p5_core::StoreError) -> Self {
        Self::Store(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOUT: &str = "scout::acme.postal.bot";
    const ROVER: &str = "rover::acme.postal.bot";

    fn box_with(root: &Path, handles: &[&str]) -> p5_crypto::KeyPair {
        let mut homes = Homes::new();
        for h in handles {
            let address: PostalAddr = h.parse().unwrap();
            homes
                .insert(HomeRow {
                    enrolled_host: address.host().to_string(),
                    address,
                    session_id: Some("s".into()),
                    cwd: PathBuf::from("/srv"),
                    inbox_root: None,
                    launch: Vec::new(),
                    harness: Some("k2".into()),
                    terminal: None,
                    tools: ToolFlags::default(),
                })
                .unwrap();
        }
        homes.save(root).unwrap();
        p5_crypto::KeyPair::load_or_create(root).unwrap()
    }

    #[test]
    fn stand_down_is_idempotent_and_only_for_our_handles() {
        let tmp = tempfile::tempdir().unwrap();
        box_with(tmp.path(), &[SCOUT]);
        let a = stand_down_at(tmp.path(), SCOUT, "k2", 100).unwrap();
        assert_eq!(a.stood_down_by.as_deref(), Some("k2"));
        assert_eq!(a.since, Some(100));
        let b = stand_down_at(tmp.path(), SCOUT, "k2", 200).unwrap();
        assert_eq!(b.since, Some(100), "a second call changes nothing");
        let other = stand_down_at(tmp.path(), SCOUT, "elsewhere", 300).unwrap_err();
        assert!(matches!(other, HandleError::AdoptedBy(..)));
        let not_ours = stand_down_at(tmp.path(), "ghost::acme.postal.bot", "k2", 1).unwrap_err();
        assert!(matches!(not_ours, HandleError::NotOurs(_)));
        assert_eq!(not_ours.exit_code(), 2);
        // resume before the key moves undoes it.
        let r = resume_at(tmp.path(), SCOUT).unwrap();
        assert_eq!(r.stood_down_by, None);
    }

    #[test]
    fn export_key_needs_every_handle_that_shares_the_key_stood_down() {
        let tmp = tempfile::tempdir().unwrap();
        let key = box_with(tmp.path(), &[SCOUT, ROVER]);
        let not_yet = export_key_at(tmp.path(), SCOUT, 1).unwrap_err();
        assert!(matches!(not_yet, HandleError::NotStoodDown(_)));

        stand_down_at(tmp.path(), SCOUT, "k2", 1).unwrap();
        let shared = export_key_at(tmp.path(), SCOUT, 1).unwrap_err();
        assert_eq!(shared.to_string(), format!("key shared with {ROVER}"));
        assert_eq!(shared.exit_code(), 2);
        assert!(resume_at(tmp.path(), SCOUT).is_ok(), "nothing went out yet");

        stand_down_at(tmp.path(), SCOUT, "k2", 2).unwrap();
        stand_down_at(tmp.path(), ROVER, "k2", 2).unwrap();
        let pem = export_key_at(tmp.path(), SCOUT, 3).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        // A failed pipe isn't a dead end: export again, same key, until release.
        assert_eq!(export_key_at(tmp.path(), SCOUT, 9).unwrap(), pem);
        assert_eq!(export_key_at(tmp.path(), ROVER, 9).unwrap(), pem);
        assert_eq!(
            Adopted::load(tmp.path()).unwrap().handles[SCOUT].key_exported_at,
            Some(3),
            "the first export time stays"
        );
        // Once the key is out, neither handle can resume.
        for h in [SCOUT, ROVER] {
            let err = resume_at(tmp.path(), h).unwrap_err();
            assert_eq!(err.to_string(), format!("adopted by k2 — {h}"));
            assert!(run_status_report(tmp.path(), h).key_exported);
        }

        let wrong = release_key_at(tmp.path(), SCOUT, &"0".repeat(64), 4).unwrap_err();
        assert!(matches!(wrong, HandleError::FingerprintMismatch));
        assert!(p5_crypto::KeyPair::load(tmp.path()).unwrap().is_some());

        let fp = key.fingerprint();
        let done = release_key_at(tmp.path(), SCOUT, &fp, 5).unwrap();
        assert!(done.key_released);
        assert!(p5_crypto::KeyPair::load(tmp.path()).unwrap().is_none());
        assert!(release_key_at(tmp.path(), ROVER, &fp, 6).is_ok(), "idempotent");
        assert!(matches!(
            export_key_at(tmp.path(), SCOUT, 7).unwrap_err(),
            HandleError::KeyReleased
        ));
    }

    #[test]
    fn release_key_refuses_before_export() {
        let tmp = tempfile::tempdir().unwrap();
        let key = box_with(tmp.path(), &[SCOUT]);
        stand_down_at(tmp.path(), SCOUT, "k2", 1).unwrap();
        let err = release_key_at(tmp.path(), SCOUT, &key.fingerprint(), 2).unwrap_err();
        assert!(matches!(err, HandleError::NotExported(_)));
        assert!(p5_crypto::KeyPair::load(tmp.path()).unwrap().is_some());
    }

    fn run_status_report(root: &Path, h: &str) -> StandDownReport {
        let addr: PostalAddr = h.parse().unwrap();
        report_for(&addr, &Adopted::load(root).unwrap())
    }

    #[test]
    fn parse_k2_whoami_session_line() {
        let text = "workspace: postal-bot\nrole:      sidecar\naddress:   postal-bot/2\nsession:   7b2ae8f7-547b-42f3-8284-527742a36cc0\n";
        assert_eq!(
            last_mile_parse_session(text).as_deref(),
            Some("7b2ae8f7-547b-42f3-8284-527742a36cc0")
        );
    }

    fn last_mile_parse_session(text: &str) -> Option<String> {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("session:") {
                let v = rest.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        None
    }
}
