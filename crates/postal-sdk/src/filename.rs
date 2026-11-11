//! Storage names for attachments.
//!
//! The name a sender put on the wire is what the envelope digest covers and
//! what the signature signs ([`crate::host::Attachment::wire_name`]). This
//! module only makes the separate name a host writes to disk. It is the
//! same on every platform and idempotent: `sanitize(sanitize(x)) ==
//! sanitize(x)`.
//!
//! Rules, in order:
//! 1. Keep the last component, splitting on both `/` and `\`.
//! 2. Map anything outside `[A-Za-z0-9._-]` to `_`.
//! 3. Strip leading and trailing `.`, `_` and `-` until none is left, so no
//!    hidden files (`.bashrc`), no `..`, and no names that start like a flag.
//! 4. Prefix Windows reserved device names (`CON`, `nul.txt`, `COM1.log`, …)
//!    with `file-`.
//! 5. Cap at [`MAX_LEN`] bytes, keeping a short extension.
//! 6. Anything empty becomes `attachment`.

/// Longest storage name, in bytes (the output is ASCII).
pub const MAX_LEN: usize = 200;
/// Longest extension kept when a name is cut, including the dot.
const MAX_EXT: usize = 16;
const FALLBACK: &str = "attachment";
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// A storage name for `name`.
#[must_use]
pub fn sanitize(name: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mapped: String = last
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    let mut out = trim_edges(&mapped).to_string();
    let stem = out.split('.').next().unwrap_or("");
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        out = format!("file-{out}");
    }
    if out.len() > MAX_LEN {
        out = trim_edges(&cap(&out)).to_string();
    }
    if out.is_empty() {
        FALLBACK.to_string()
    } else {
        out
    }
}

fn trim_edges(s: &str) -> &str {
    s.trim_matches(|c| matches!(c, '.' | '_' | '-'))
}

/// Cut to [`MAX_LEN`], keeping the extension when it's short.
fn cap(s: &str) -> String {
    let (stem, ext) = match s.rfind('.') {
        Some(i) if s.len() - i <= MAX_EXT => (&s[..i], &s[i..]),
        _ => (s, ""),
    };
    let room = MAX_LEN - ext.len();
    let stem = trim_edges(&stem[..room.min(stem.len())]);
    let ext = if trim_edges(ext).is_empty() { "" } else { ext };
    format!("{stem}{ext}")
}

#[cfg(test)]
mod tests {
    use super::{sanitize, MAX_LEN};

    const PROBES: &[&str] = &[
        "../../etc/passwd",
        "..\\..\\evil.exe",
        "a\\b.txt",
        "..",
        ".",
        "",
        "_.bashrc",
        ".bashrc",
        " .git",
        "_.ssh",
        "-rf",
        "my report.pdf",
        "re port\u{202e}.txt",
        "CON",
        "nul.txt",
        "COM1.log",
        "lpt9",
        "CONSOLE.txt",
        "ok-file_1.md",
        "trailing.",
        "___",
        "a.b.c",
    ];

    #[test]
    fn known_names() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize("..\\..\\evil.exe"), "evil.exe");
        assert_eq!(sanitize("a\\b.txt"), "b.txt", "same on every platform");
        assert_eq!(sanitize(".."), "attachment");
        assert_eq!(sanitize(""), "attachment");
        assert_eq!(sanitize("_.bashrc"), "bashrc");
        assert_eq!(sanitize(" .git"), "git");
        assert_eq!(sanitize("-rf"), "rf");
        assert_eq!(sanitize("my report.pdf"), "my_report.pdf");
        assert_eq!(sanitize("CON"), "file-CON");
        assert_eq!(sanitize("nul.txt"), "file-nul.txt");
        assert_eq!(sanitize("COM1.log"), "file-COM1.log");
        assert_eq!(sanitize("CONSOLE.txt"), "CONSOLE.txt");
        assert_eq!(sanitize("ok-file_1.md"), "ok-file_1.md");
    }

    #[test]
    fn idempotent_and_never_hidden() {
        let long = format!("{}.pdf", "x".repeat(300));
        let long_ext = format!("a.{}", "y".repeat(300));
        let mut all: Vec<String> = PROBES.iter().map(|s| (*s).to_string()).collect();
        all.extend([long, long_ext]);
        for raw in &all {
            let once = sanitize(raw);
            assert_eq!(sanitize(&once), once, "not idempotent for {raw:?}");
            assert!(!once.is_empty());
            assert!(!once.starts_with(['.', '_', '-']), "{raw:?} -> {once:?}");
            assert!(once.len() <= MAX_LEN, "{raw:?}");
            assert!(once.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
        }
    }

    #[test]
    fn long_names_keep_their_extension() {
        let out = sanitize(&format!("{}.pdf", "x".repeat(300)));
        assert_eq!(out.len(), MAX_LEN);
        assert_eq!(out.rsplit('.').next(), Some("pdf"));
    }

    /// Golden vectors (`vectors/postal-v1.json`).
    #[test]
    fn golden_vectors() {
        let all: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/postal-v1.json")).unwrap();
        for v in all["filename"].as_array().unwrap() {
            assert_eq!(sanitize(v["wire"].as_str().unwrap()), v["storage"].as_str().unwrap(), "{v}");
        }
    }
}
