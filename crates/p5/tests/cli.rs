use std::path::Path;
use std::process::Command;

use p5_core::{
    DeliveryMode, HomeRow, Homes, Mailbox, PeerType, PostalAddr, ReceiveRequest, SendRequest,
    ToolFlags,
};

fn p5() -> Command {
    Command::new(env!("CARGO_BIN_EXE_p5"))
}

fn stdout(args: &[&str]) -> String {
    let out = p5()
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("run p5 {args:?}: {err}"));
    assert!(
        out.status.success(),
        "p5 {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

fn stdout_home(home: &Path, args: &[&str]) -> String {
    let out = run_home(home, args, &[]);
    assert!(
        out.status.success(),
        "p5 {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

fn run_home(home: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = p5();
    cmd.env("P5_HOME", home).args(args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|err| panic!("run p5 {args:?}: {err}"))
}

fn add_home(root: &Path, address: &str, wake: bool) {
    let address: PostalAddr = address.parse().unwrap();
    let host = address.host().to_string();
    let mut homes = Homes::load(root).unwrap();
    homes
        .insert(HomeRow {
            address,
            session_id: Some("sess-1".into()),
            cwd: root.to_path_buf(),
            inbox_root: None,
            launch: vec!["claude".into()],
            harness: Some("claude".into()),
            tools: ToolFlags {
                files: false,
                live_inject: true,
                wake,
            },
            enrolled_host: host,
        })
        .unwrap();
    homes.save(root).unwrap();
}

fn tmp_home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn alice() -> PostalAddr {
    "alice::acme.postal.bot".parse().unwrap()
}

fn scout() -> PostalAddr {
    "scout::acme.postal.bot".parse().unwrap()
}

#[test]
fn whoami_prints_stub_identity() {
    let text = stdout(&["whoami"]);
    assert!(text.contains("Postal"));
    assert!(text.contains("postal.bot"));
    assert!(text.contains("command: p5"));
    assert!(text.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_types_prints_session_and_turn() {
    let text = stdout(&["help", "types"]);
    assert!(text.contains("session"));
    assert!(text.contains("turn"));
    assert!(text.contains("terminal harness"));
    assert!(text.contains("Grok Bot") && text.contains("Sand"));
    assert!(text.contains("live"));
    assert!(text.contains("tray"));
    assert!(text.contains("not types"));
}

#[test]
fn help_prints_product_and_commands() {
    let text = stdout(&["help"]);
    assert!(text.contains("Postal"));
    assert!(text.contains("postal.bot"));
    assert!(text.contains("p5"));
    assert!(text.contains("whoami"));
    assert!(text.contains("inbox"));
    assert!(text.contains("sent"));
    assert!(text.contains("outbox"));
    assert!(text.contains("msg"));
    assert!(!text.contains("k2 "));
}

#[test]
fn long_help_flag_works() {
    let text = stdout(&["--help"]);
    assert!(text.contains("Postal"));
    assert!(text.contains("whoami"));
    assert!(text.contains("inbox"));
}

#[test]
fn sent_and_outbox_list_empty() {
    let home = tmp_home();
    assert!(stdout_home(home.path(), &["sent", "list"]).is_empty());
    assert!(stdout_home(home.path(), &["outbox"]).is_empty());
    assert!(stdout_home(home.path(), &["inbox", "list"]).is_empty());
}

#[test]
fn sent_outbox_inbox_list_and_read() {
    let home = tmp_home();
    let mb = Mailbox::new(home.path());
    let sent = mb
        .enqueue(SendRequest {
            to: scout(),
            from: alice(),
            body: "hello scout".into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Session,
            files: Vec::new(),
            files_allowed: false,
            title: None,
        })
        .unwrap();
    let inbox = mb
        .receive(ReceiveRequest {
            id: sent.id.clone(),
            to: scout(),
            from: alice(),
            body: "incoming cover".into(),
            mode: DeliveryMode::Tray,
            typ: PeerType::Session,
            files: Vec::new(),
            files_allowed: false,
            title: Some("Cover".into()),
            hold_id: None,
        })
        .unwrap();

    let sent_list = stdout_home(home.path(), &["sent", "list"]);
    assert!(sent_list.contains(&sent.id));
    assert!(sent_list.contains("queued"));
    assert!(sent_list.contains("scout::acme.postal.bot"));

    let outbox = stdout_home(home.path(), &["outbox", "list"]);
    assert!(outbox.contains(&sent.id));
    assert!(outbox.contains("queued"));

    let inbox_list = stdout_home(home.path(), &["inbox"]);
    assert!(inbox_list.contains(&inbox.id));
    assert!(inbox_list.contains("alice::acme.postal.bot"));

    let cover = stdout_home(home.path(), &["inbox", "read", &inbox.id]);
    assert!(cover.contains("incoming cover"));
    assert!(cover.contains("status: acked"));
}

#[test]
fn inbox_read_missing_exits_nonzero() {
    let home = tmp_home();
    let out = p5()
        .env("P5_HOME", home.path())
        .args(["inbox", "read", "01ARZ3NDEKTSV4RRFFQ69G5FAV"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not found"));
}

#[test]
fn msg_local_home_delivers() {
    let home = tmp_home();
    add_home(home.path(), "scout::acme.postal.bot", true);
    let out = stdout_home(
        home.path(),
        &[
            "msg",
            "scout::acme.postal.bot",
            "hello scout",
            "--from",
            "alice::acme.postal.bot",
        ],
    );
    assert!(out.contains("delivered"));
    assert!(out.contains("scout::acme.postal.bot"));
    let id = out.split_whitespace().next().unwrap();
    let sent = stdout_home(home.path(), &["sent", "list"]);
    assert!(sent.contains(id));
    assert!(sent.contains("delivered"));
    assert!(stdout_home(home.path(), &["outbox"]).is_empty());
    let inbox = stdout_home(home.path(), &["inbox"]);
    assert!(inbox.contains(id));
    assert!(inbox.contains("alice::acme.postal.bot"));
    let cover = stdout_home(home.path(), &["inbox", "read", id]);
    assert!(cover.contains("hello scout"));
}

#[test]
fn msg_json_local_deliver() {
    let home = tmp_home();
    add_home(home.path(), "scout::acme.postal.bot", true);
    let out = stdout_home(
        home.path(),
        &[
            "msg",
            "--json",
            "scout::acme.postal.bot",
            "json body",
            "--from",
            "alice::acme.postal.bot",
        ],
    );
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["success"], true);
    assert_eq!(v["status"], "delivered");
    assert_eq!(v["to"], "scout::acme.postal.bot");
    assert_eq!(v["reason"], serde_json::Value::Null);
    assert!(v["id"].as_str().unwrap().len() == 26);
}

#[test]
fn msg_remote_stays_queued() {
    let home = tmp_home();
    let out = stdout_home(
        home.path(),
        &[
            "msg",
            "scout::acme.postal.bot",
            "later",
            "--from",
            "alice::acme.postal.bot",
        ],
    );
    assert!(out.contains("queued"));
    let sent = stdout_home(home.path(), &["sent"]);
    assert!(sent.contains("queued"));
    let outbox = stdout_home(home.path(), &["outbox"]);
    assert!(outbox.contains("queued"));
    assert!(stdout_home(home.path(), &["inbox"]).is_empty());
}

#[test]
fn msg_no_wake_is_dormant() {
    let home = tmp_home();
    add_home(home.path(), "scout::acme.postal.bot", true);
    let out = run_home(
        home.path(),
        &[
            "msg",
            "--no-wake",
            "scout::acme.postal.bot",
            "shh",
            "--from",
            "alice::acme.postal.bot",
        ],
        &[],
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("dormant_no_wake"));
    assert!(stdout_home(home.path(), &["inbox"]).is_empty());
    let sent = stdout_home(home.path(), &["sent"]);
    assert!(sent.contains("failed"));
}

#[test]
fn msg_local_recv_without_declared_typ_stays_queued() {
    let home = tmp_home();
    // P5_LOCAL_RECV without a roster row or HomeRow is unknown typ (K22):
    // do not guess session / enter the receiver.
    let out = run_home(
        home.path(),
        &[
            "msg",
            "scout::acme.postal.bot",
            "anyone",
            "--from",
            "alice::acme.postal.bot",
        ],
        &[("P5_LOCAL_RECV", "1")],
    );
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("queued"));
    let sent = stdout_home(home.path(), &["sent"]);
    assert!(sent.contains("queued"));
    assert!(stdout_home(home.path(), &["inbox"]).is_empty());
}

#[test]
fn msg_wake_off_is_gated() {
    let home = tmp_home();
    add_home(home.path(), "scout::acme.postal.bot", false);
    let out = run_home(
        home.path(),
        &[
            "msg",
            "scout::acme.postal.bot",
            "wake me",
            "--from",
            "alice::acme.postal.bot",
        ],
        &[],
    );
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("gated"));
}

#[test]
fn msg_bad_address_exits_2() {
    let home = tmp_home();
    let out = run_home(
        home.path(),
        &["msg", "scout@acme.postal.bot", "nope"],
        &[("P5_FROM", "alice::acme.postal.bot")],
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("bad_address") || err.contains('@'));
}

#[test]
fn status_when_agent_not_running() {
    let home = tmp_home();
    let text = stdout_home(home.path(), &["status"]);
    assert!(text.contains("agent: down"));
    assert!(text.contains("tunnel: down"));
}

#[test]
fn login_writes_unit_file() {
    let home = tmp_home();
    let out = run_home(
        home.path(),
        &["login", "--no-start"],
        &[("HOME", home.path().to_str().unwrap())],
    );
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("wrote"), "{stdout}");
    #[cfg(target_os = "macos")]
    {
        let plist = home
            .path()
            .join("Library/LaunchAgents/bot.postal.agent.plist");
        assert!(plist.is_file(), "missing {}", plist.display());
        let text = std::fs::read_to_string(&plist).unwrap();
        assert!(text.contains("bot.postal.agent"));
        assert!(text.contains("<key>Program</key>"));
        assert!(text.contains("p5"));
        assert!(text.contains("agent"));
        assert!(text.contains("run"));
        assert!(text.contains("SuccessfulExit"));
    }
    #[cfg(not(target_os = "macos"))]
    {
        let unit = home.path().join(".config/systemd/user/p5-agent.service");
        assert!(unit.is_file(), "missing {}", unit.display());
        let text = std::fs::read_to_string(&unit).unwrap();
        assert!(text.contains("p5"));
        assert!(text.contains("agent run"));
        assert!(unit.ends_with("p5-agent.service"));
    }
}

#[test]
fn agent_run_refuses_unspecified_bind() {
    let home = tmp_home();
    let out = run_home(
        home.path(),
        &["agent", "run"],
        &[("P5_HTTP_BIND", "0.0.0.0:8443")],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("0.0.0.0") || err.contains("loopback") || err.contains("non-loopback"),
        "{err}"
    );
}

#[test]
fn inbox_respond_is_msg_to_from() {
    let home = tmp_home();
    add_home(home.path(), "alice::acme.postal.bot", true);
    add_home(home.path(), "scout::acme.postal.bot", true);
    let sent = stdout_home(
        home.path(),
        &[
            "msg",
            "scout::acme.postal.bot",
            "ping",
            "--from",
            "alice::acme.postal.bot",
        ],
    );
    let id = sent.split_whitespace().next().unwrap();
    let reply = stdout_home(
        home.path(),
        &[
            "inbox",
            "respond",
            id,
            "pong",
            "--from",
            "scout::acme.postal.bot",
        ],
    );
    assert!(reply.contains("delivered"));
    assert!(reply.contains("alice::acme.postal.bot"));
    let reply_id = reply.split_whitespace().next().unwrap();
    let cover = stdout_home(home.path(), &["inbox", "read", reply_id]);
    assert!(cover.contains("pong"));
    assert!(cover.contains("alice::acme.postal.bot"));
    assert!(cover.contains("scout::acme.postal.bot"));
}
