//! `/p5/msg` pairing-key proof. Ed25519 over the v1 transcript.

use ed25519_dalek::{Signature, Signer, Verifier};

use crate::keys::{parse_spki_pem, KeyPair};
use crate::{CryptoError, TAG_MSG};

/// `Ed25519.Sign(sk, "p5-msg-v1" || method || path || content-sha256-hex || timestamp || nonce)`.
pub fn proof_create(
    key: &KeyPair,
    method: &str,
    path: &str,
    content_sha256_hex: &str,
    timestamp: &str,
    nonce: &str,
) -> Vec<u8> {
    let msg = proof_message(method, path, content_sha256_hex, timestamp, nonce);
    key.signing_key().sign(&msg).to_bytes().to_vec()
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
    let vk = parse_spki_pem(spki_pem)?;
    let sig_bytes: [u8; 64] = proof.try_into().map_err(|_| CryptoError::Proof)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = proof_message(method, path, content_sha256_hex, timestamp, nonce);
    vk.verify(&msg, &sig).map_err(|_| CryptoError::Proof)
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

    #[test]
    fn proof_roundtrip_and_bad_sig_fails() {
        let kp = KeyPair::generate();
        let body = b"{\"to\":\"bob::acme.postal.bot\"}";
        let hex = to_hex(&Sha256::digest(body));
        let proof = proof_create(&kp, "PUT", "/p5/msg", &hex, "1710000000", "n1");
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
}
