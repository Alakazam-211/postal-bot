//! Last mile after Postal inbox fsync.
//!
//! Mail is harness-agnostic. A live cell is not: `HomeRow.harness` selects a
//! plugin. Built-ins:
//!
//! - `k2` — same `/cli/workspace/msg` route as `k2 msg` (session cells)
//! - `grok` — Grok Bot / Sand: Bearer + `POST /api/listAgents` + `POST /api/sendPrompt`
//!
//! Any other name is an **exec plugin** (`~/.postal/harness/<name>` or
//! `p5-harness-<name>` on PATH). Unknown / missing plugin = tray only.
//! Type `turn` with no matching plugin defaults to `grok`.
//!
//! This is the OSS connection shape. Pairing, hold, and enroll stay on the
//! closed control plane — plugins never see those tokens.
//!
//! Knock JSON v1 (stdin to exec plugins; `argv[1]=knock`):
//!
//! ```json
//! {
//!   "v": 1,
//!   "op": "knock",
//!   "id": "<ulid>",
//!   "to": "handle::sub.postal.bot",
//!   "from": "peer::sub.postal.bot",
//!   "handle": "handle",
//!   "typ": "session",
//!   "title": "first line",
//!   "text": "[p5:<id>] title\\nOpen: p5 inbox read <id>",
//!   "body": "full cover body",
//!   "wake": true,
//!   "cwd": "/path",
//!   "session_id": "optional"
//! }
//! ```
//!
//! Exit 0 and/or `{"ok":true}` on stdout. Non-zero or `{"ok":false}` is a miss;
//! the Postal tray is already durable.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use p5_core::{HomeRow, PeerType, PostalAddr};
use serde::{Deserialize, Serialize};

use crate::k2::{self, K2MsgClient, KnockRequest};
use crate::sm::{Inbound, SmContext};
use crate::turn;

const KNOCK_TIMEOUT: Duration = Duration::from_secs(25);
const RESUME_TIMEOUT: Duration = Duration::from_secs(45);
const PLUGIN_NAME_MAX: usize = 63;

/// Per-process last-mile clients. Dispatch is still `HomeRow.harness`.
#[derive(Debug, Clone, Default)]
pub struct LastMile {
    pub k2: K2MsgClient,
}

/// v1 knock envelope. Built-ins and exec plugins share this object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Knock {
    pub v: u32,
    pub op: String,
    pub id: String,
    pub to: String,
    pub from: String,
    pub handle: String,
    pub typ: String,
    pub title: String,
    pub text: String,
    pub body: String,
    pub wake: bool,
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl Knock {
    pub const V: u32 = 1;

    pub fn from_inbox(home: &HomeRow, inbound: &Inbound) -> Self {
        let title = title_line(&inbound.body);
        Self {
            v: Self::V,
            op: "knock".into(),
            id: inbound.id.clone(),
            to: inbound.to.to_string(),
            from: inbound.from.to_string(),
            handle: inbound.to.handle().to_string(),
            typ: inbound.typ.as_str().to_string(),
            text: pointer_text(&inbound.id, &title),
            body: inbound.body.clone(),
            title,
            wake: !inbound.no_wake,
            cwd: home.cwd.to_string_lossy().into_owned(),
            session_id: home.session_id.clone(),
        }
    }
}

/// Short live-inject pointer. Cover stays in `~/.postal/inbox`.
pub fn pointer_text(id: &str, title: &str) -> String {
    format!("[p5:{id}] {title}\nOpen: p5 inbox read {id}")
}

#[derive(Debug)]
pub enum LastMileError {
    Plugin(String),
    Exec(String),
}

impl fmt::Display for LastMileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plugin(msg) | Self::Exec(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for LastMileError {}

/// Knock the live cell. Inbox bytes are already durable.
///
/// Session callers log a miss. Turn callers map a miss to `host_down`.
pub fn after_inbox_fsync(
    ctx: &SmContext,
    home: &HomeRow,
    inbound: &Inbound,
) -> Result<(), LastMileError> {
    let is_turn = inbound.typ == PeerType::Turn;
    if !is_turn && !home.tools.live_inject {
        return Ok(());
    }
    let Some(name) = resolve_plugin(ctx.mailbox.root(), home, is_turn) else {
        return Ok(());
    };
    let knock = Knock::from_inbox(home, inbound);
    dispatch(ctx, &name, &knock, home.tools.wake)
}

fn resolve_plugin(root: &Path, home: &HomeRow, is_turn: bool) -> Option<String> {
    if let Some(name) = home.harness.as_deref() {
        match name {
            "k2" => return Some("k2".into()),
            "grok" | "turn" => return Some("grok".into()),
            other if is_plugin_name(other) && discover_exec(root, other).is_some() => {
                return Some(other.into());
            }
            _ => {}
        }
    }
    if is_turn {
        return Some("grok".into());
    }
    home.harness
        .as_deref()
        .filter(|n| is_plugin_name(n))
        .map(str::to_string)
}

fn dispatch(
    ctx: &SmContext,
    name: &str,
    knock: &Knock,
    wake: bool,
) -> Result<(), LastMileError> {
    match name {
        "k2" => knock_k2(&ctx.last_mile.k2, knock),
        "grok" => knock_grok(ctx, knock),
        other => match discover_exec(ctx.mailbox.root(), other) {
            Some(path) => exec_knock_or_resume(&path, knock, wake),
            None => Ok(()),
        },
    }
}

fn exec_knock_or_resume(path: &Path, knock: &Knock, wake: bool) -> Result<(), LastMileError> {
    match exec_op(path, "knock", knock, KNOCK_TIMEOUT) {
        Ok(()) => Ok(()),
        Err(err) if wake && looks_dormant(&err) => {
            exec_op(path, "resume", knock, RESUME_TIMEOUT)?;
            exec_op(path, "knock", knock, KNOCK_TIMEOUT)
        }
        Err(err) => Err(err),
    }
}

fn looks_dormant(err: &LastMileError) -> bool {
    let s = err.to_string();
    s.contains("not_live") || s.contains("session not found") || s.contains("tty not found")
}

fn knock_grok(ctx: &SmContext, knock: &Knock) -> Result<(), LastMileError> {
    let from: PostalAddr = knock
        .from
        .parse()
        .map_err(|e| LastMileError::Plugin(format!("bad from: {e}")))?;
    // Same path as k2g: Bearer from gateway.json, agentId from listAgents UUID.
    let agent_id = turn::resolve_sand_agent(
        &ctx.turn,
        knock.session_id.as_deref(),
        Some(knock.handle.as_str()),
    )
    .map_err(|e| LastMileError::Plugin(e.to_string()))?;
    turn::send_prompt(&ctx.turn, &from, &knock.body, &agent_id, &knock.id)
        .map_err(|e| LastMileError::Plugin(e.to_string()))
}

fn k2_workspace(knock: &Knock) -> String {
    let cwd = knock.cwd.trim();
    if cwd.starts_with('/') {
        cwd.to_string()
    } else {
        k2::workspace_target(&knock.handle)
    }
}

fn knock_k2(client: &K2MsgClient, knock: &Knock) -> Result<(), LastMileError> {
    if client.is_off() {
        return Ok(());
    }
    let req = KnockRequest {
        // Absolute cwd is what `k2 msg` accepts (name/handle often ≠ Postal handle).
        workspace: k2_workspace(knock),
        // Live inject is the mail body. k2 already stamps [from …].
        // Do not send "Open: p5 inbox read" — Postal is its own tray.
        text: if knock.body.trim().is_empty() {
            knock.title.clone()
        } else {
            knock.body.clone()
        },
        from: knock.from.clone(),
        wake: knock.wake,
        project: knock.cwd.clone(),
        session_id: knock.session_id.clone(),
    };
    client
        .knock(&req)
        .map(|_| ())
        .map_err(|e| LastMileError::Plugin(e.to_string()))
}

/// Harness names are a single token so they cannot be used as paths.
pub fn is_plugin_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    let rest = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    rest && name.len() <= PLUGIN_NAME_MAX
}

fn discover_exec(root: &Path, name: &str) -> Option<PathBuf> {
    if !is_plugin_name(name) {
        return None;
    }
    if let Ok(dir) = std::env::var("P5_HARNESS_DIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            let p = Path::new(dir).join(name);
            if is_exec(&p) {
                return Some(p);
            }
        }
    }
    let bundled = root.join("harness").join(name);
    if is_exec(&bundled) {
        return Some(bundled);
    }
    find_on_path(&format!("p5-harness-{name}"))
}

fn is_exec(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(bin);
        if is_exec(&p) {
            return Some(p);
        }
    }
    None
}

fn exec_op(path: &Path, op: &str, knock: &Knock, timeout: Duration) -> Result<(), LastMileError> {
    let body = serde_json::to_vec(knock)
        .map_err(|e| LastMileError::Exec(format!("encode {op}: {e}")))?;
    let mut child = Command::new(path)
        .arg(op)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| LastMileError::Exec(format!("{}: {e}", path.display())))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&body)
            .map_err(|e| LastMileError::Exec(e.to_string()))?;
    }
    let output = wait_with_timeout(&mut child, timeout)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(reply) = serde_json::from_str::<PluginReply>(stdout.trim()) {
        if reply.ok == Some(false) {
            let reason = reply.reason.unwrap_or_else(|| "plugin returned ok=false".into());
            return Err(LastMileError::Plugin(reason));
        }
    }
    if output.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err(LastMileError::Exec(format!(
            "{} exit {}: {}",
            path.display(),
            output.status.code().unwrap_or(-1),
            err.trim()
        )))
    }
}

#[derive(Deserialize)]
struct PluginReply {
    ok: Option<bool>,
    reason: Option<String>,
}

struct Finished {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<Finished, LastMileError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return drain_child(child, status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LastMileError::Exec("plugin timed out".into()));
            }
            Err(e) => return Err(LastMileError::Exec(e.to_string())),
        }
    }
}

fn drain_child(
    child: &mut std::process::Child,
    status: std::process::ExitStatus,
) -> Result<Finished, LastMileError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_end(&mut stdout);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_end(&mut stderr);
    }
    Ok(Finished {
        status,
        stdout,
        stderr,
    })
}

/// Result of `<plugin> claim` (built-in or exec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub terminal: String,
    pub session_id: String,
    pub cwd: String,
    pub live: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ClaimWire {
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    terminal: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    live: Option<bool>,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    launch: Option<Vec<String>>,
}

/// Reveal terminal + session id for `p5 handle claim`. Fail closed.
pub fn claim_plugin(
    root: &Path,
    plugin: &str,
    handle: &str,
    cwd: &Path,
    want_session: Option<&str>,
) -> Result<Claim, LastMileError> {
    if !is_plugin_name(plugin) {
        return Err(LastMileError::Plugin(format!("no_plugin: {plugin}")));
    }
    match plugin {
        "k2" => claim_k2(cwd, handle, want_session),
        "grok" | "turn" => claim_grok(handle, want_session),
        other => match discover_exec(root, other) {
            Some(path) => exec_claim(&path, handle, cwd, want_session),
            None => Err(LastMileError::Plugin(format!(
                "no_plugin: {other} not found (built-ins: k2, grok; or ~/.postal/harness/{other})"
            ))),
        },
    }
}

fn claim_k2(
    cwd: &Path,
    _handle: &str,
    want_session: Option<&str>,
) -> Result<Claim, LastMileError> {
    let out = Command::new("k2")
        .arg("whoami")
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| LastMileError::Plugin(format!("claim_failed: k2 whoami: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(LastMileError::Plugin(format!(
            "claim_failed: k2 whoami exit {}: {}",
            out.status.code().unwrap_or(-1),
            err.trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let session_id = parse_whoami_field(&text, "session").ok_or_else(|| {
        LastMileError::Plugin("claim_failed: k2 whoami has no session: line".into())
    })?;
    if let Some(want) = want_session.map(str::trim).filter(|s| !s.is_empty()) {
        if want != session_id {
            return Err(LastMileError::Plugin(format!(
                "session_mismatch: wanted {want}, k2 whoami is {session_id}"
            )));
        }
    }
    Ok(Claim {
        terminal: "k2".into(),
        session_id,
        cwd: cwd.to_string_lossy().into_owned(),
        live: true,
        typ: Some("session".into()),
        launch: None,
    })
}

fn parse_whoami_field(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(&prefix) {
            let v = rest.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn claim_grok(handle: &str, want_session: Option<&str>) -> Result<Claim, LastMileError> {
    let cfg = turn::TurnConfig::from_env();
    let id = turn::resolve_sand_agent(&cfg, want_session, Some(handle))
        .map_err(|e| LastMileError::Plugin(format!("claim_failed: {e}")))?;
    if let Some(want) = want_session.map(str::trim).filter(|s| !s.is_empty()) {
        if want != id {
            return Err(LastMileError::Plugin(format!(
                "session_mismatch: wanted {want}, grok agent is {id}"
            )));
        }
    }
    Ok(Claim {
        terminal: "grok".into(),
        session_id: id,
        cwd: String::new(),
        live: turn::health_up(&cfg).is_ok(),
        typ: Some("turn".into()),
        launch: None,
    })
}

fn exec_claim(
    path: &Path,
    handle: &str,
    cwd: &Path,
    want_session: Option<&str>,
) -> Result<Claim, LastMileError> {
    let body = serde_json::json!({
        "v": 1,
        "op": "claim",
        "handle": handle,
        "cwd": cwd.to_string_lossy(),
        "session_id": want_session,
    });
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| LastMileError::Exec(format!("encode claim: {e}")))?;
    let mut child = Command::new(path)
        .arg("claim")
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| LastMileError::Exec(format!("{}: {e}", path.display())))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&bytes)
            .map_err(|e| LastMileError::Exec(e.to_string()))?;
    }
    let output = wait_with_timeout(&mut child, KNOCK_TIMEOUT)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let wire: ClaimWire = serde_json::from_str(stdout.trim()).unwrap_or(ClaimWire {
        ok: Some(output.status.success()),
        reason: None,
        terminal: None,
        session_id: None,
        cwd: None,
        live: None,
        typ: None,
        launch: None,
    });
    if wire.ok == Some(false) || !output.status.success() {
        let reason = wire
            .reason
            .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).trim().to_string());
        return Err(LastMileError::Plugin(format!(
            "claim_failed: {}",
            if reason.is_empty() {
                format!("{} exit {}", path.display(), output.status.code().unwrap_or(-1))
            } else {
                reason
            }
        )));
    }
    let session_id = wire
        .session_id
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| LastMileError::Plugin("claim_failed: plugin omitted session_id".into()))?;
    if let Some(want) = want_session.map(str::trim).filter(|s| !s.is_empty()) {
        // iTerm tab ids (w0t0p0:UUID) are not the resume id; allow that.
        let iterm_shaped = want.contains(':') || want.chars().any(|c| c.is_ascii_uppercase());
        if want != session_id && !iterm_shaped {
            return Err(LastMileError::Plugin(format!(
                "session_mismatch: wanted {want}, plugin revealed {session_id}"
            )));
        }
    }
    Ok(Claim {
        terminal: wire.terminal.filter(|s| !s.is_empty()).unwrap_or_else(|| {
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("exec")
                .to_string()
        }),
        session_id,
        cwd: wire
            .cwd
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| cwd.to_string_lossy().into_owned()),
        live: wire.live.unwrap_or(true),
        typ: wire.typ,
        launch: wire.launch.filter(|v| !v.is_empty()),
    })
}

fn title_line(body: &str) -> String {
    let line = body
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .trim_start_matches('#')
        .trim();
    if line.is_empty() {
        return "Postal".into();
    }
    let mut chars = line.chars();
    let out: String = chars.by_ref().take(80).collect();
    if chars.next().is_some() {
        format!("{out}…")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use p5_core::{DeliveryMode, HomeRow, PeerType, PostalAddr, ToolFlags};

    use crate::sm::{receive_session, Inbound, SmContext};

    fn addr(s: &str) -> PostalAddr {
        s.parse().unwrap()
    }

    #[test]
    fn title_falls_back_and_clips() {
        assert_eq!(title_line(""), "Postal");
        assert_eq!(title_line("\n\n# Hello\nbody"), "Hello");
        let clipped = title_line(&"x".repeat(90));
        assert!(clipped.ends_with('…'), "{clipped}");
        assert_eq!(clipped.chars().count(), 81);
    }

    #[test]
    fn plugin_names_are_single_tokens() {
        assert!(is_plugin_name("k2"));
        assert!(is_plugin_name("webhook"));
        assert!(is_plugin_name("claude-code"));
        assert!(!is_plugin_name("K2"));
        assert!(!is_plugin_name("../evil"));
        assert!(!is_plugin_name("foo/bar"));
        assert!(!is_plugin_name(""));
        assert!(!is_plugin_name("1webhook"));
    }

    #[test]
    fn pointer_is_p5_not_k2_inbox() {
        let t = pointer_text("01ARZ3NDEKTSV4RRFFQ69G5FAV", "Brief");
        assert_eq!(
            t,
            "[p5:01ARZ3NDEKTSV4RRFFQ69G5FAV] Brief\nOpen: p5 inbox read 01ARZ3NDEKTSV4RRFFQ69G5FAV"
        );
        assert!(!t.contains("k2 inbox"));
    }

    fn home_with_harness(root: &Path, harness: &str) -> (SmContext, Inbound) {
        let mut ctx = SmContext::new(root);
        let address = addr("scout::acme.postal.bot");
        ctx.homes
            .insert(HomeRow {
                address: address.clone(),
                session_id: Some("sess-1".into()),
                cwd: PathBuf::from("/srv/scout"),
                inbox_root: None,
                launch: vec!["x".into()],
                harness: Some(harness.into()),
                terminal: None,
                tools: ToolFlags {
                    files: false,
                    live_inject: true,
                    wake: true,
                },
                enrolled_host: "acme.postal.bot".into(),
            })
            .unwrap();
        let inbound = Inbound {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            to: address,
            from: addr("alice::acme.postal.bot"),
            body: "hello scout".into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Session,
            files: Vec::new(),
            no_wake: false,
        };
        (ctx, inbound)
    }

    #[test]
    fn missing_exec_plugin_is_tray_only() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, inbound) = home_with_harness(tmp.path(), "webhook");
        receive_session(&ctx, &inbound).unwrap();
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
    }

    #[test]
    fn exec_plugin_gets_v1_knock_json() {
        let tmp = tempfile::tempdir().unwrap();
        let harness_dir = tmp.path().join("harness");
        fs::create_dir(&harness_dir).unwrap();
        let plugin = harness_dir.join("sample");
        let capture = tmp.path().join("knock.json");
        let script = format!(
            "#!/bin/sh\ncat > \"{}\"\necho '{{\"ok\":true}}'\n",
            capture.display()
        );
        fs::write(&plugin, script).unwrap();
        fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755)).unwrap();
        let (ctx, inbound) = home_with_harness(tmp.path(), "sample");
        receive_session(&ctx, &inbound).unwrap();
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
        let raw = fs::read_to_string(&capture).unwrap();
        let knock: Knock = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(knock.v, 1);
        assert_eq!(knock.op, "knock");
        assert_eq!(knock.handle, "scout");
        assert_eq!(knock.typ, "session");
        assert_eq!(knock.body, "hello scout");
        assert_eq!(knock.from, "alice::acme.postal.bot");
        assert!(knock.wake);
        assert_eq!(knock.cwd, "/srv/scout");
        assert!(knock.text.contains("p5 inbox read 01ARZ3NDEKTSV4RRFFQ69G5FAV"));
    }

    #[test]
    fn k2_workspace_uses_this_row_cwd_not_handle() {
        assert_eq!(
            k2_workspace(&Knock {
                v: 1,
                op: "knock".into(),
                id: "1".into(),
                to: "claude::acme.postal.bot".into(),
                from: "a::acme.postal.bot".into(),
                handle: "claude".into(),
                typ: "session".into(),
                title: "hi".into(),
                text: "hi".into(),
                body: "hi".into(),
                wake: true,
                cwd: "/Users/z/claude".into(),
                session_id: Some("sess-claude".into()),
            }),
            "/Users/z/claude"
        );
        assert_eq!(
            k2_workspace(&Knock {
                v: 1,
                op: "knock".into(),
                id: "1".into(),
                to: "postal-bot::acme.postal.bot".into(),
                from: "a::acme.postal.bot".into(),
                handle: "postal-bot".into(),
                typ: "session".into(),
                title: "hi".into(),
                text: "hi".into(),
                body: "hi".into(),
                wake: true,
                cwd: "/Users/z/kessel".into(),
                session_id: Some("sess-p5".into()),
            }),
            "/Users/z/kessel"
        );
    }

    #[test]
    fn grok_plugin_resolves_handle_via_list_agents() {
        let tmp = tempfile::tempdir().unwrap();
        let uuid = "0e5f5de8-7619-4ba4-9753-32c5470b2346";
        let sand = crate::turn::MockSand::spawn_authed(
            200,
            200,
            "secret",
            serde_json::json!([{"id": uuid, "name": "Grok", "isActive": true}]),
        );
        let mut ctx = SmContext::new(tmp.path());
        ctx.our_typ = Some(PeerType::Turn);
        ctx.turn = sand.config();
        ctx.turn.agent_id.clear();
        ctx.homes
            .insert(HomeRow {
                address: addr("grok::acme.postal.bot"),
                session_id: None,
                cwd: PathBuf::from("/home/box/ai/Grokbot"),
                inbox_root: None,
                launch: Vec::new(),
                harness: Some("grok".into()),
                terminal: None,
                tools: ToolFlags {
                    files: false,
                    live_inject: true,
                    wake: true,
                },
                enrolled_host: "acme.postal.bot".into(),
            })
            .unwrap();
        let inbound = Inbound {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            to: addr("grok::acme.postal.bot"),
            from: addr("postal-bot::acme.postal.bot"),
            body: "hello grok".into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Turn,
            files: Vec::new(),
            no_wake: false,
        };
        crate::sm::receive_msg(&ctx, &inbound).unwrap();
        let prompts = sand.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["agentId"], uuid);
        assert_eq!(
            prompts[0]["prompt"],
            "[from postal-bot::acme.postal.bot] hello grok"
        );
        assert!(!prompts[0]["prompt"].as_str().unwrap().contains("[k2g]"));
        assert!(!prompts[0]["prompt"].as_str().unwrap().contains("[p5]"));
        let auths = sand.auths.lock().unwrap();
        assert!(auths.iter().any(|a| a.as_deref() == Some("secret")));
    }

    #[test]
    fn exec_plugin_ok_false_is_logged_not_unreceived() {
        let tmp = tempfile::tempdir().unwrap();
        let harness_dir = tmp.path().join("harness");
        fs::create_dir(&harness_dir).unwrap();
        let plugin = harness_dir.join("sample");
        fs::write(
            &plugin,
            "#!/bin/sh\necho '{\"ok\":false,\"reason\":\"busy\"}'\n",
        )
        .unwrap();
        fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755)).unwrap();
        let (ctx, inbound) = home_with_harness(tmp.path(), "sample");
        receive_session(&ctx, &inbound).unwrap();
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
    }

    #[test]
    fn exec_plugin_not_live_runs_resume_then_knock() {
        let tmp = tempfile::tempdir().unwrap();
        let harness_dir = tmp.path().join("harness");
        fs::create_dir(&harness_dir).unwrap();
        let plugin = harness_dir.join("iterm2");
        let flag = tmp.path().join("resumed");
        let script = format!(
            "#!/bin/sh\nFLAG=\"{}\"\nif [ \"$1\" = resume ]; then touch \"$FLAG\"; echo '{{\"ok\":true}}'; exit 0; fi\nif [ -f \"$FLAG\" ]; then echo '{{\"ok\":true}}'; exit 0; fi\necho '{{\"ok\":false,\"reason\":\"not_live\"}}'\nexit 1\n",
            flag.display()
        );
        fs::write(&plugin, script).unwrap();
        fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755)).unwrap();
        let (ctx, inbound) = home_with_harness(tmp.path(), "iterm2");
        receive_session(&ctx, &inbound).unwrap();
        assert!(flag.is_file(), "resume should have run");
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
    }
}
