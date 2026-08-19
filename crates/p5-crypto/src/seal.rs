//! HoldSeal-v1: X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use ulid::Ulid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};

use crate::keys::{parse_spki_pem, x25519_public_from_ed25519, KeyPair};
use crate::{CryptoError, HOLDSEAL_V1, MAX_PLAINTEXT, TAG_HOLD};

const EPH_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + EPH_LEN + NONCE_LEN;
const MAX_BLOB: usize = HEADER_LEN + MAX_PLAINTEXT + TAG_LEN;

/// Bound into the hold AAD (and ULID bytes into HKDF info).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealAad {
    pub id: String,
    pub from: String,
    pub to: String,
}

/// Seal `plaintext` to `peer_spki_pem`. Blob is `v || eph_pub || nonce || ct||tag`.
pub fn seal(peer_spki_pem: &str, plaintext: &[u8], aad: &SealAad) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(CryptoError::TooLarge);
    }
    let peer_ed = parse_spki_pem(peer_spki_pem)?;
    let peer_x = x25519_public_from_ed25519(&peer_ed);

    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = X25519Public::from(&eph);
    let ss = eph.diffie_hellman(&peer_x);
    if !ss.was_contributory() {
        return Err(CryptoError::Seal("non-contributory ECDH".into()));
    }

    let key = hold_key(ss.as_bytes(), &aad.id)?;
    let aad_bytes = hold_aad(aad);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| CryptoError::Seal("invalid cipher key".into()))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::Seal("encrypt failed".into()))?;

    let mut blob = Vec::with_capacity(HEADER_LEN + ct.len());
    blob.push(HOLDSEAL_V1);
    blob.extend_from_slice(eph_pub.as_bytes());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

impl KeyPair {
    /// Open a HoldSeal-v1 blob with this identity's X25519 twin.
    pub fn open(&self, blob: &[u8], aad: &SealAad) -> Result<Vec<u8>, CryptoError> {
        if blob.len() < HEADER_LEN + TAG_LEN || blob.len() > MAX_BLOB {
            return Err(CryptoError::Open);
        }
        if blob[0] != HOLDSEAL_V1 {
            return Err(CryptoError::Open);
        }
        let eph_bytes: [u8; EPH_LEN] = blob[1..1 + EPH_LEN]
            .try_into()
            .map_err(|_| CryptoError::Open)?;
        let nonce = &blob[1 + EPH_LEN..HEADER_LEN];
        let ct = &blob[HEADER_LEN..];

        let eph_pub = X25519Public::from(eph_bytes);
        let ss = self.static_secret().diffie_hellman(&eph_pub);
        if !ss.was_contributory() {
            return Err(CryptoError::Open);
        }

        let key = hold_key(ss.as_bytes(), &aad.id).map_err(|_| CryptoError::Open)?;
        let aad_bytes = hold_aad(aad);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| CryptoError::Open)?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| CryptoError::Open)
    }
}

fn hold_key(ikm: &[u8], id: &str) -> Result<[u8; 32], CryptoError> {
    let ulid: Ulid = id
        .parse()
        .map_err(|_| CryptoError::Seal("hold id is not a ULID".into()))?;
    let mut info = Vec::with_capacity(TAG_HOLD.len() + 16);
    info.extend_from_slice(TAG_HOLD.as_bytes());
    info.extend_from_slice(&ulid.to_bytes());
    let hk = Hkdf::<Sha256>::new(Some(TAG_HOLD.as_bytes()), ikm);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| CryptoError::Seal("HKDF expand failed".into()))?;
    Ok(key)
}

fn hold_aad(aad: &SealAad) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_HOLD.len() + aad.id.len() + aad.from.len() + aad.to.len());
    out.extend_from_slice(TAG_HOLD.as_bytes());
    out.extend_from_slice(aad.id.as_bytes());
    out.extend_from_slice(aad.from.as_bytes());
    out.extend_from_slice(aad.to.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn sample_aad() -> SealAad {
        SealAad {
            id: Ulid::new().to_string(),
            from: "alice::acme.postal.bot".into(),
            to: "bob::acme.postal.bot".into(),
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let bob = KeyPair::generate();
        let aad = sample_aad();
        let pt = b"hold body";
        let blob = seal(&bob.public_key_pem(), pt, &aad).unwrap();
        assert_eq!(blob[0], HOLDSEAL_V1);
        assert_eq!(blob.len(), HEADER_LEN + pt.len() + TAG_LEN);
        let opened = bob.open(&blob, &aad).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let bob = KeyPair::generate();
        let aad = sample_aad();
        let mut blob = seal(&bob.public_key_pem(), b"secret", &aad).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(bob.open(&blob, &aad), Err(CryptoError::Open)));
    }

    #[test]
    fn wrong_aad_fails() {
        let bob = KeyPair::generate();
        let aad = sample_aad();
        let blob = seal(&bob.public_key_pem(), b"secret", &aad).unwrap();
        let mut other = aad.clone();
        other.to = "eve::acme.postal.bot".into();
        assert!(matches!(bob.open(&blob, &other), Err(CryptoError::Open)));
        other = aad.clone();
        other.id = Ulid::new().to_string();
        assert!(matches!(bob.open(&blob, &other), Err(CryptoError::Open)));
    }

    #[test]
    fn plaintext_over_256kib_refused() {
        let bob = KeyPair::generate();
        let aad = sample_aad();
        let too_big = vec![0u8; MAX_PLAINTEXT + 1];
        assert!(matches!(
            seal(&bob.public_key_pem(), &too_big, &aad),
            Err(CryptoError::TooLarge)
        ));
        let max = vec![7u8; MAX_PLAINTEXT];
        let blob = seal(&bob.public_key_pem(), &max, &aad).unwrap();
        assert_eq!(bob.open(&blob, &aad).unwrap(), max);
    }

    #[test]
    fn bad_version_fails() {
        let bob = KeyPair::generate();
        let aad = sample_aad();
        let mut blob = seal(&bob.public_key_pem(), b"x", &aad).unwrap();
        blob[0] = 0x99;
        assert!(matches!(bob.open(&blob, &aad), Err(CryptoError::Open)));
    }
}
