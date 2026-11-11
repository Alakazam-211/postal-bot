//! Attachment names a host can write to disk without surprises.
//!
//! Same rule as p5's tray sidecars: keep the last path component, map
//! anything outside `[A-Za-z0-9._-]` to `_`, trim leading and trailing
//! dots and underscores, and fall back to `attachment`.

use std::path::Path;

/// A safe file name for `name`.
#[must_use]
pub fn sanitize(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment");
    if base == ".." || base == "." || base.is_empty() {
        return "attachment".to_string();
    }
    let out: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    let trimmed = out.trim_matches('.').trim_matches('_');
    if trimmed.is_empty() || trimmed == ".." {
        "attachment".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn strips_paths_and_odd_characters() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize(".."), "attachment");
        assert_eq!(sanitize(""), "attachment");
        assert_eq!(sanitize("re port\u{202e}.txt"), "re_port_.txt");
        assert_eq!(sanitize(".hidden"), "hidden");
        assert_eq!(sanitize("ok-file_1.md"), "ok-file_1.md");
    }
}
