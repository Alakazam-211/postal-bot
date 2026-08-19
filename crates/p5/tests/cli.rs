use std::process::Command;

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
    assert!(!text.contains("k2 "));
}

#[test]
fn long_help_flag_works() {
    let text = stdout(&["--help"]);
    assert!(text.contains("Postal"));
    assert!(text.contains("whoami"));
}
