//! Golden vectors (`vectors/postal-v1.json`), computed with Python's hashlib.
//! A change here is a wire change: both ends must move together.

use postal_sdk::{badge, hex, pairing};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/postal-v1.json")).unwrap()
}

#[test]
fn pairing_vectors() {
    for v in vectors()["pairing"].as_array().unwrap() {
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let na = hex::from_hex32(&s("na_hex")).unwrap();
        let nb = hex::from_hex32(&s("nb_hex")).unwrap();
        assert_eq!(hex::to_hex(&pairing::commitment(&s("fp_a"), &na)), s("commitment_hex"));
        assert!(pairing::verify_commitment(
            &hex::from_hex32(&s("commitment_hex")).unwrap(),
            &s("fp_a"),
            &na
        ));
        assert_eq!(pairing::sas(&s("fp_a"), &s("fp_b"), &na, &nb), s("sas"));
    }
}

#[test]
fn badge_vectors() {
    for v in vectors()["badge"].as_array().unwrap() {
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let digest = badge::body_sha256(s("body").as_bytes());
        assert_eq!(badge::badge(&s("id"), &s("sender_fingerprint"), &digest), s("badge"));
    }
}
