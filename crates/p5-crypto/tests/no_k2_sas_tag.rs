//! Steward (K2 `m_5WRw5944oy`): no **new** Postal code may call
//! `sas_code` with K2's `::k2-federation-sas::` tag.
//!
//! Allowlist is the leftover live path until p5 moves onto `postal-sdk`.
//! When that move lands, shrink this list to empty and delete `sas_code`.

use std::fs;
use std::path::{Path, PathBuf};

const K2_TAG: &str = "::k2-federation-sas::";
const CALL: &str = "sas_code(";

/// Only the leftover definition and the live `p5 pair` path (plus its tests).
const TAG_FILES: &[&str] = &[
    "crates/p5-crypto/src/keys.rs",
    "crates/p5-crypto/tests/no_k2_sas_tag.rs",
];

const CALL_FILES: &[&str] = &[
    "crates/p5-crypto/src/keys.rs",
    "crates/p5-crypto/src/lib.rs",
    "crates/p5-crypto/tests/no_k2_sas_tag.rs",
    "crates/p5/src/pair.rs",
    "crates/p5/tests/pair.rs",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        if name == "target" || name == ".git" || name == "node_modules" {
            continue;
        }
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn k2_sas_tag_only_in_leftover_files() {
    let root = repo_root();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    let mut unexpected = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        if !text.contains(K2_TAG) {
            continue;
        }
        let r = rel(&root, f);
        if !TAG_FILES.contains(&r.as_str()) {
            unexpected.push(r);
        }
    }
    assert!(
        unexpected.is_empty(),
        "new files contain {K2_TAG}; move pairing to postal-sdk instead: {unexpected:?}"
    );
}

#[test]
fn sas_code_call_sites_are_the_leftover_allowlist() {
    let root = repo_root();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    let mut unexpected = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        if !text.contains(CALL) {
            continue;
        }
        let r = rel(&root, f);
        if !CALL_FILES.contains(&r.as_str()) {
            unexpected.push(r);
        }
    }
    assert!(
        unexpected.is_empty(),
        "new sas_code( call sites; use postal-sdk pairing, not the K2-tagged leftover: {unexpected:?}"
    );
}
