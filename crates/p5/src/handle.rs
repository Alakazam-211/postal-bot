//! `p5 handle claim|list|show|drop` — plugin + session packed per handle.
//!
//! Agents run this non-interactively (`--json`). See
//! `.k2/prds/prd-handle-last-mile.md`.

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

use p5_core::{
    default_root, HomeRow, Homes, PeerType, PostalAddr, ToolFlags, EXIT_GATED,
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
        next: format!("p5 pair add <peer> --from {addr}"),
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
    let rows: Vec<ListRow> = homes
        .iter()
        .map(|(addr, row)| ListRow {
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
        for r in &rows {
            println!(
                "{}  plugin={} terminal={} session={} cwd={}",
                r.address, r.plugin, r.terminal, r.session, r.cwd
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
    match pair::run_me(Some(addr.to_string()), Some(typ.to_string()), false) {
        Ok(()) => "ok".into(),
        Err(err) => format!("skipped ({err})"),
    }
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
}

impl HandleError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NoPlugin | Self::BadAddress(_) | Self::BadTyp(_) | Self::HostUnbound => {
                EXIT_USAGE
            }
            Self::Collision { .. } | Self::Gated => EXIT_GATED,
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
