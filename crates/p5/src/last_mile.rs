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
    dispatch(ctx, &name, &knock)
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

fn dispatch(ctx: &SmContext, name: &str, knock: &Knock) -> Result<(), LastMileError> {
    match name {
        "k2" => knock_k2(&ctx.last_mile.k2, knock),
        "grok" => knock_grok(ctx, knock),
        other => match discover_exec(ctx.mailbox.root(), other) {
            Some(path) => exec_knock(&path, knock),
            None => Ok(()),
        },
    }
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

fn exec_knock(path: &Path, knock: &Knock) -> Result<(), LastMileError> {
    let body = serde_json::to_vec(knock)
        .map_err(|e| LastMileError::Exec(format!("encode knock: {e}")))?;
    let mut child = Command::new(path)
        .arg("knock")
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
    let output = wait_with_timeout(&mut child, KNOCK_TIMEOUT)?;
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
    line.chars().take(80).collect()
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
        assert_eq!(title_line(&"x".repeat(90)).len(), 80);
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
}
