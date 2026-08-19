use std::fs;
use std::path::PathBuf;
use std::process::Command;

use p5_core::{DeliveryMode, Mailbox, PeerType, PostalAddr, ReceiveRequest, SendRequest};

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

fn stdout_home(home: &PathBuf, args: &[&str]) -> String {
    let out = p5()
        .env("P5_HOME", home)
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

struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tmp_home() -> Tmp {
    let path = std::env::temp_dir().join(format!(
        "p5-cli-mb-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    Tmp(path)
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
    assert!(stdout_home(&home.0, &["sent", "list"]).is_empty());
    assert!(stdout_home(&home.0, &["outbox"]).is_empty());
    assert!(stdout_home(&home.0, &["inbox", "list"]).is_empty());
}

#[test]
fn sent_outbox_inbox_list_and_read() {
    let home = tmp_home();
    let mb = Mailbox::new(&home.0);
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

    let sent_list = stdout_home(&home.0, &["sent", "list"]);
    assert!(sent_list.contains(&sent.id));
    assert!(sent_list.contains("queued"));
    assert!(sent_list.contains("scout::acme.postal.bot"));

    let outbox = stdout_home(&home.0, &["outbox", "list"]);
    assert!(outbox.contains(&sent.id));
    assert!(outbox.contains("queued"));

    let inbox_list = stdout_home(&home.0, &["inbox"]);
    assert!(inbox_list.contains(&inbox.id));
    assert!(inbox_list.contains("alice::acme.postal.bot"));

    let cover = stdout_home(&home.0, &["inbox", "read", &inbox.id]);
    assert!(cover.contains("incoming cover"));
    assert!(cover.contains("status: acked"));
}

#[test]
fn inbox_read_missing_exits_nonzero() {
    let home = tmp_home();
    let out = p5()
        .env("P5_HOME", &home.0)
        .args(["inbox", "read", "01ARZ3NDEKTSV4RRFFQ69G5FAV"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not found"));
}
