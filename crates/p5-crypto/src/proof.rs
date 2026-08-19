//! `/p5/msg` pairing-key proof. Ed25519 over the v1 transcript.

use ed25519_dalek::{Signature, Signer, Verifier};

use crate::keys::{parse_spki_pem, KeyPair};
use crate::{CryptoError, TAG_MSG};

/// Ed25519 signature over the v1 transcript (unframed concat, no domain bump):
/// `"p5-msg-v1" || method || path || content_sha256_hex || timestamp || nonce`.
///
/// `content_sha256_hex` is exactly 64 `[0-9a-f]`. `method` is a token without
/// `/`. `path` starts with `/`. `timestamp` is decimal unix seconds.
pub fn proof_create(
    key: &KeyPair,
    method: &str,
    path: &str,
    content_sha256_hex: &str,
    timestamp: &str,
    nonce: &str,
) -> Result<Vec<u8>, CryptoError> {
    check_proof_fields(method, path, content_sha256_hex, timestamp)?;
    let msg = proof_message(method, path, content_sha256_hex, timestamp, nonce);
    Ok(key.signing_key().sign(&msg).to_bytes().to_vec())
}

/// Verify `proof` against the Ed25519 SPKI already known for that addr.
pub fn proof_verify(
    spki_pem: &str,
    method: &str,
    path: &str,
    content_sha256_hex: &str,
    timestamp: &str,
    nonce: &str,
    proof: &[u8],
) -> Result<(), CryptoError> {
    check_proof_fields(method, path, content_sha256_hex, timestamp)?;
    let vk = parse_spki_pem(spki_pem)?;
    let sig_bytes: [u8; 64] = proof.try_into().map_err(|_| CryptoError::Proof)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = proof_message(method, path, content_sha256_hex, timestamp, nonce);
    vk.verify(&msg, &sig).map_err(|_| CryptoError::Proof)
}

fn check_proof_fields(
    method: &str,
    path: &str,
    content_sha256_hex: &str,
    timestamp: &str,
) -> Result<(), CryptoError> {
    if !is_sha256_hex(content_sha256_hex) {
        return Err(CryptoError::Proof);
    }
    if method.is_empty() || method.contains('/') {
        return Err(CryptoError::Proof);
    }
    if !path.starts_with('/') {
        return Err(CryptoError::Proof);
    }
    if timestamp.is_empty() || !timestamp.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CryptoError::Proof);
    }
    Ok(())
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn proof_message(
    method: &str,
    path: &str,
    content_sha256_hex: &str,
    timestamp: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        TAG_MSG.len()
            + method.len()
            + path.len()
            + content_sha256_hex.len()
            + timestamp.len()
            + nonce.len(),
    );
    m.extend_from_slice(TAG_MSG.as_bytes());
    m.extend_from_slice(method.as_bytes());
    m.extend_from_slice(path.as_bytes());
    m.extend_from_slice(content_sha256_hex.as_bytes());
    m.extend_from_slice(timestamp.as_bytes());
    m.extend_from_slice(nonce.as_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_hex;
    use sha2::{Digest, Sha256};

    fn body_hex() -> String {
        to_hex(&Sha256::digest(b"{\"to\":\"bob::acme.postal.bot\"}"))
    }

    #[test]
    fn proof_roundtrip_and_bad_sig_fails() {
        let kp = KeyPair::generate();
        let hex = body_hex();
        let proof = proof_create(&kp, "PUT", "/p5/msg", &hex, "1710000000", "n1").unwrap();
        assert_eq!(proof.len(), 64);
        proof_verify(
            &kp.public_key_pem(),
            "PUT",
            "/p5/msg",
            &hex,
            "1710000000",
            "n1",
            &proof,
        )
        .unwrap();

        let mut bad = proof.clone();
        bad[0] ^= 0x01;
        assert!(matches!(
            proof_verify(
                &kp.public_key_pem(),
                "PUT",
                "/p5/msg",
                &hex,
                "1710000000",
                "n1",
                &bad
            ),
            Err(CryptoError::Proof)
        ));

        assert!(matches!(
            proof_verify(
                &kp.public_key_pem(),
                "GET",
                "/p5/msg",
                &hex,
                "1710000000",
                "n1",
                &proof
            ),
            Err(CryptoError::Proof)
        ));
    }

    #[test]
    fn proof_rejects_bad_content_hex() {
        let kp = KeyPair::generate();
        let hex = body_hex();
        assert!(proof_create(&kp, "PUT", "/p5/msg", &hex.to_uppercase(), "1", "n").is_err());
        assert!(proof_create(&kp, "PUT", "/p5/msg", &hex[..63], "1", "n").is_err());
        let mut bad = hex.clone();
        bad.replace_range(0..1, "g");
        assert!(proof_create(&kp, "PUT", "/p5/msg", &bad, "1", "n").is_err());
        let proof = proof_create(&kp, "PUT", "/p5/msg", &hex, "1710000000", "n1").unwrap();
        assert!(proof_verify(
            &kp.public_key_pem(),
            "PUT",
            "/p5/msg",
            &hex.to_uppercase(),
            "1710000000",
            "n1",
            &proof
        )
        .is_err());
    }
}
