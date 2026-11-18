//! Envelope digest and the provenance badge shown next to a message.
//!
//! The digest covers the whole envelope: version, id, from, to, `sent_at`,
//! mode, content type, every attachment (name and SHA-256) and the body
//! hash, each length-framed. Wire v2 signs this digest, so once a message
//! is verified, the badge is bound to the sender's key.
//!
//! **The badge is display-only, never a credential.** It is a public hash:
//! anyone who has seen a message can copy its badge. Hosts must show it out
//! of band, in chrome the body can't write to (a UI label, a separate
//! column), never typed into the same terminal or text stream as the body.
//! Shown that way, a sender can't make its message look like someone
//! else's. It is 80 bits, so finding a different envelope with the same
//! badge is out of reach; still, decisions use the verified sender, not a
//! person comparing badges by eye.

use sha2::{Digest, Sha256};

use crate::hex::to_hex;

/// Domain prefix of the envelope digest.
pub const ENVELOPE_PREFIX: &[u8] = b"postal-envelope-v1";
/// Hex digits of the digest in a badge (80 bits).
pub const BADGE_HEX_LEN: usize = 20;

/// A field didn't fit the 4-byte length frame (over 4 GiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong;

impl std::fmt::Display for TooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("envelope field longer than 4 GiB")
    }
}

impl std::error::Error for TooLong {}

/// One attachment as the envelope digest sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    /// The raw name as sent on the wire, never the sanitized storage name.
    pub name: String,
    pub sha256: [u8; 32],
}

/// Everything the digest covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<'a> {
    pub version: u32,
    pub id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    /// Unix seconds, sender's clock.
    pub sent_at: i64,
    pub mode: crate::host::Mode,
    pub content_type: &'a str,
    pub files: &'a [FileDigest],
    pub body_sha256: [u8; 32],
}

fn frame(h: &mut Sha256, bytes: &[u8]) -> Result<(), TooLong> {
    let len = u32::try_from(bytes.len()).map_err(|_| TooLong)?;
    h.update(len.to_be_bytes());
    h.update(bytes);
    Ok(())
}

/// The digest wire v2 signs.
///
/// # Errors
/// [`TooLong`] if a field doesn't fit the 4-byte frame.
pub fn envelope_digest(e: &Envelope<'_>) -> Result<[u8; 32], TooLong> {
    let mut h = Sha256::new();
    h.update(ENVELOPE_PREFIX);
    h.update(e.version.to_be_bytes());
    for field in [e.id, e.from, e.to] {
        frame(&mut h, field.as_bytes())?;
    }
    h.update(e.sent_at.to_be_bytes());
    for field in [e.mode.as_str(), e.content_type] {
        frame(&mut h, field.as_bytes())?;
    }
    let count = u32::try_from(e.files.len()).map_err(|_| TooLong)?;
    h.update(count.to_be_bytes());
    for f in e.files {
        frame(&mut h, f.name.as_bytes())?;
        h.update(f.sha256);
    }
    h.update(e.body_sha256);
    Ok(h.finalize().into())
}

/// `p_` + the first [`BADGE_HEX_LEN`] hex digits of the envelope digest.
#[must_use]
pub fn badge(envelope_digest: &[u8; 32]) -> String {
    format!("p_{}", &to_hex(envelope_digest)[..BADGE_HEX_LEN])
}

/// `SHA-256(bytes)`, for a body or an attachment.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(files: &[FileDigest]) -> Envelope<'_> {
        Envelope {
            version: 2,
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            from: "alice::acme.postal.bot",
            to: "scout::acme.postal.bot",
            sent_at: 1_800_000_000,
            mode: crate::host::Mode::Live,
            content_type: "text/plain; charset=utf-8",
            files,
            body_sha256: sha256(b"hello scout"),
        }
    }

    #[test]
    fn every_envelope_field_changes_the_badge() {
        let none: [FileDigest; 0] = [];
        let one = [FileDigest { name: "a.txt".into(), sha256: sha256(b"x") }];
        let other = [FileDigest { name: "a.txt".into(), sha256: sha256(b"y") }];
        let base = badge(&envelope_digest(&env(&none)).unwrap());
        let mut variants = Vec::new();
        let mut e = env(&none);
        e.version = 3;
        variants.push(e);
        let mut e = env(&none);
        e.id = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
        variants.push(e);
        let mut e = env(&none);
        e.from = "mallory::acme.postal.bot";
        variants.push(e);
        let mut e = env(&none);
        e.to = "other::acme.postal.bot";
        variants.push(e);
        let mut e = env(&none);
        e.sent_at += 1;
        variants.push(e);
        let mut e = env(&none);
        e.mode = crate::host::Mode::Tray;
        variants.push(e);
        let mut e = env(&none);
        e.content_type = "text/markdown";
        variants.push(e);
        let mut e = env(&none);
        e.body_sha256 = sha256(b"hello scouT");
        variants.push(e);
        variants.push(env(&one));
        for v in &variants {
            assert_ne!(badge(&envelope_digest(v).unwrap()), base, "{v:?}");
        }
        assert_ne!(
            badge(&envelope_digest(&env(&one)).unwrap()),
            badge(&envelope_digest(&env(&other)).unwrap()),
            "messages differing only in a file differ"
        );
    }

    #[test]
    fn framing_keeps_fields_apart() {
        let none: [FileDigest; 0] = [];
        let mut a = env(&none);
        a.id = "ab";
        a.from = "c";
        let mut b = env(&none);
        b.id = "a";
        b.from = "bc";
        assert_ne!(envelope_digest(&a).unwrap(), envelope_digest(&b).unwrap());
    }

    #[test]
    fn shape() {
        let b = badge(&[0xab; 32]);
        assert!(b.starts_with("p_"));
        assert_eq!(b.len(), 2 + BADGE_HEX_LEN);
    }

    /// Golden vectors, computed with Python's hashlib (`vectors/postal-v1.json`).
    #[test]
    fn golden_vectors() {
        let all: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/postal-v1.json")).unwrap();
        for v in all["envelope"].as_array().unwrap() {
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            let files: Vec<FileDigest> = v["files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| FileDigest {
                    name: f["name"].as_str().unwrap().into(),
                    sha256: sha256(f["content"].as_str().unwrap().as_bytes()),
                })
                .collect();
            let (id, from, to, ct) = (s("id"), s("from"), s("to"), s("content_type"));
            let mode = match s("mode").as_str() {
                "live" => crate::host::Mode::Live,
                "tray" => crate::host::Mode::Tray,
                other => panic!("mode {other}"),
            };
            let e = Envelope {
                version: u32::try_from(v["version"].as_u64().unwrap()).unwrap(),
                id: &id,
                from: &from,
                to: &to,
                sent_at: v["sent_at"].as_i64().unwrap(),
                mode,
                content_type: &ct,
                files: &files,
                body_sha256: sha256(s("body").as_bytes()),
            };
            let d = envelope_digest(&e).unwrap();
            assert_eq!(to_hex(&d), s("digest_hex"));
            assert_eq!(badge(&d), s("badge"));
        }
    }
}
