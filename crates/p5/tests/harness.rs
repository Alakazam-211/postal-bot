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
    defs = (ast.FunctionDef, ast.AsyncFunctionDef)
    funcs = {n.name for n in tree.body if isinstance(n, defs)}
    for fn in [n for n in ast.walk(tree) if isinstance(n, defs)]:
        # Every way a function can bind a local name: parameters, plain /
        # annotated / augmented / walrus assignment (tuple targets too),
        # for and with targets, except-as, imports.
        local = {a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs}
        local |= {a.arg for a in (fn.args.vararg, fn.args.kwarg) if a}
        for n in ast.walk(fn):
            targets = []
            if isinstance(n, ast.Assign):
                targets = n.targets
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                targets = [n.target]
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                targets = [n.target]
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                targets = [i.optional_vars for i in n.items if i.optional_vars]
            elif isinstance(n, ast.ExceptHandler) and n.name:
                local.add(n.name)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                local |= {(a.asname or a.name).split(".")[0] for a in n.names}
            for t in targets:
                local |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
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
    // The plugins are Python; a box that runs these tests must have it.
    assert!(
        Command::new("python3").arg("-V").output().is_ok(),
        "python3 is required to check the harness plugins"
    );
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
