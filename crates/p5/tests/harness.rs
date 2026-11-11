//! Smoke checks for the bundled Python harness plugins (`harness/*`).
//!
//! They aren't run end to end here (they drive iTerm2, Ghostty, …). This
//! catches the cheap breakages: a syntax error, or a local variable that
//! shadows a module-level function the same function then calls.

use std::path::PathBuf;
use std::process::Command;

const CHECK: &str = r#"
import ast, sys
bad = []
for path in sys.argv[1:]:
    src = open(path).read()
    tree = ast.parse(src, path)
    funcs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        local = {t.id for n in ast.walk(fn) if isinstance(n, ast.Assign)
                 for t in n.targets if isinstance(t, ast.Name)}
        called = {n.func.id for n in ast.walk(fn)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        for name in sorted(local & funcs & called):
            bad.append(f"{path}: {fn.name}() assigns {name!r}, shadowing the function it calls")
print("\n".join(bad))
sys.exit(1 if bad else 0)
"#;

fn python_plugins() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../harness");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|s| s.lines().next().unwrap_or("").contains("python"))
                .unwrap_or(false)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn python_plugins_parse_and_do_not_shadow_their_own_functions() {
    if Command::new("python3").arg("-V").output().is_err() {
        eprintln!("skip: no python3");
        return;
    }
    let plugins = python_plugins();
    assert!(plugins.len() >= 6, "expected the bundled plugins, got {plugins:?}");
    let out = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(CHECK)
        .args(&plugins)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
