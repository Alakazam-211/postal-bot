//! End-to-end check of postal-sdk against a running Postal plane v1.
//!
//! Two test handles pair with SAS v2 (both owners confirm), then A holds a
//! sealed message for B, B pulls it from an event, opens it, ACKs it, and A
//! sees the `delivered` receipt. Also checks a duplicate post, a refusal,
//! a replayed hold item and a tampered one.
//!
//! ```text
//! POSTAL_E2E_BASE=http://127.0.0.1:3000 \
//! POSTAL_E2E_CREDS=/path/to/creds.json \
//! cargo run -p postal-sdk --example e2e_plane
//! ```
//!
//! `creds.json` (0600; never printed): `{base_url, labels: {<label>:
//! {connect_credential, decide_token}}}` for labels `ptest-a` and `ptest-b`.
//! Box calls use a `pst_` from `POST /session`; confirm and revoke use the
//! label's `k2c_pd_`.
//! Only for a throwaway plane: it creates pairs and hold items.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePublicKey};
use ed25519_dalek::SigningKey;
use postal_sdk::address::Address;
use postal_sdk::hold::{self, Disposition, OpenWith, Outer};
use postal_sdk::host::Mode;
use postal_sdk::pairing::{
    Attempts, Commitment, Confirmed, Decision, Initiator, PairContext, PublicKey, Responder,
    Response, Reveal,
};
use postal_sdk::plane::{self, AfterEvents, Event, Method, PairItem, Receipt, Request, Typ};
use postal_sdk::replay::MemorySeen;
use postal_sdk::wire::{self, Draft};

struct Side {
    addr: Address,
    box_token: String,
    owner_token: String,
    sk: SigningKey,
    pk: PublicKey,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn ulid() -> String {
    ulid::Ulid::new().to_string()
}

fn call(base: &str, token: &str, req: &Request) -> (u16, Vec<u8>) {
    let url = format!("{base}{}", req.path);
    let r = match req.method {
        Method::Get => ureq::get(&url),
        Method::Post => ureq::post(&url),
        Method::Put => ureq::put(&url),
    }
    .set("Authorization", &format!("Bearer {token}"))
    .set("Content-Type", "application/json")
    .timeout(std::time::Duration::from_secs(75));
    let res = match &req.body {
        Some(b) => r.send_string(b),
        None => r.call(),
    };
    let resp = match res {
        Ok(r) | Err(ureq::Error::Status(_, r)) => r,
        Err(e) => panic!("transport to {}: {e}", req.path),
    };
    let status = resp.status();
    let api = resp.header("Postal-Api").map(str::to_owned);
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut body).unwrap();
    assert_eq!(
        api.as_deref(),
        Some("1"),
        "Postal-Api header on {}",
        req.path
    );
    (status, body)
}

fn ok<T: for<'de> serde::Deserialize<'de>>(what: &str, (s, b): (u16, Vec<u8>)) -> T {
    match plane::parse::<T>(s, &b) {
        Ok(t) => {
            println!("ok    {what} ({s})");
            t
        }
        Err(e) => panic!("FAIL  {what}: {e} / {}", String::from_utf8_lossy(&b)),
    }
}

fn load() -> (String, Side, Side) {
    let path = std::env::var("POSTAL_E2E_CREDS").expect("POSTAL_E2E_CREDS");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let base = std::env::var("POSTAL_E2E_BASE")
        .ok()
        .or_else(|| v["base_url"].as_str().map(str::to_owned))
        .expect("POSTAL_E2E_BASE or base_url");
    // Request paths already start with /api/postal/v1.
    let base = base
        .trim_end_matches('/')
        .trim_end_matches(plane::API)
        .to_string();
    let run = {
        let mut r = [0u8; 3];
        getrandom::getrandom(&mut r).unwrap();
        postal_sdk::hex::to_hex(&r)
    };
    let side = |label: &str, handle: &str| {
        let l = &v["labels"][label];
        let s = |f: &str| {
            l[f].as_str()
                .unwrap_or_else(|| panic!("{label}.{f}"))
                .to_string()
        };
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        // The Connect credential is only for minting a pst_ session.
        let session = Request {
            method: Method::Post,
            path: format!("{}/session", plane::API),
            body: Some("{}".into()),
        };
        let tok: serde_json::Value = ok(
            "POST /session",
            call(&base, &s("connect_credential"), &session),
        );
        Side {
            addr: Address::new(&format!("{handle}{run}"), label).unwrap(),
            box_token: tok["token"].as_str().expect("pst_").to_string(),
            owner_token: s("decide_token"),
            pk: PublicKey::from_pem(&pem).unwrap(),
            sk,
        }
    };
    let a = side("ptest-a", "alice");
    let b = side("ptest-b", "bob");
    (base, a, b)
}

fn get_pair(base: &str, who: &Side, id: &str) -> PairItem {
    ok(
        "GET /pairs/{id}",
        call(base, &who.box_token, &plane::pair_get(id).unwrap()),
    )
}

fn main() {
    let (base, a, b) = load();
    println!("plane {base}: {} -> {}", a.addr, b.addr);

    // ---- pairing, SAS v2 ----
    let id = ulid();
    let ctx = PairContext {
        pair_id: id.clone(),
        initiator: a.addr.to_string(),
        responder: b.addr.to_string(),
    };
    let (init, c) = Initiator::start(ctx.clone(), a.pk.clone(), &mut Attempts::default(), now())
        .expect("start");
    let _: serde_json::Value = ok(
        "POST /pairs",
        call(
            &base,
            &a.box_token,
            &plane::pair_create(&id, &a.addr, &b.addr, Typ::Session, &a.pk, &c).unwrap(),
        ),
    );

    // B sees it, and takes A's key from the PEM (never the fingerprint).
    let row = get_pair(&base, &b, &id);
    assert_eq!(row.status, plane::PairStatus::PendingIn, "B: pending_in");
    let a_key = PublicKey::from_pem(row.peer_key_pem.as_deref().expect("A's PEM")).unwrap();
    assert_eq!(a_key.fingerprint(), a.pk.fingerprint());
    let c_seen = Commitment::from_hex(row.commitment.as_deref().unwrap()).unwrap();
    let (resp_state, resp) = Responder::respond(
        ctx.clone(),
        a_key,
        c_seen,
        b.pk.clone(),
        &mut Attempts::default(),
        now(),
    )
    .expect("respond");
    let _: serde_json::Value = ok(
        "POST respond",
        call(
            &base,
            &b.box_token,
            &plane::pair_respond(&id, &resp, Typ::Session).unwrap(),
        ),
    );

    // A reveals.
    let row = get_pair(&base, &a, &id);
    let resp_seen = Response::from_parts(
        row.peer_key_pem.as_deref().unwrap(),
        row.nb.as_deref().unwrap(),
    )
    .unwrap();
    let (reveal, hs_a) = init.finish(resp_seen, now()).expect("A finish");
    let _: serde_json::Value = ok(
        "POST reveal",
        call(
            &base,
            &a.box_token,
            &plane::pair_reveal(&id, &reveal).unwrap(),
        ),
    );
    let row = get_pair(&base, &b, &id);
    let hs_b = resp_state
        .finish(Reveal::from_hex(row.na.as_deref().unwrap()).unwrap(), now())
        .expect("B finish");

    // Each owner types the OTHER box's code.
    let (code_a, code_b) = (
        hs_a.code().as_str().to_string(),
        hs_b.code().as_str().to_string(),
    );
    assert_eq!(
        code_a, code_b,
        "no one in the middle: same code on both boxes"
    );
    assert_eq!(hs_a.transcript_hex(), hs_b.transcript_hex());
    // A box must refuse confirm with a box credential.
    let Confirmed::Accept {
        confirmation: ca,
        awaiting: wait_a,
    } = hs_a.confirm(&code_b, &a.sk).unwrap()
    else {
        panic!("A mismatch")
    };
    let (s, body) = call(&base, &a.box_token, &plane::pair_confirm(&ca).unwrap());
    let err = plane::parse::<serde_json::Value>(s, &body).unwrap_err();
    assert_eq!(err.code(), Some(&plane::Code::OwnerRequired), "{err}");
    println!("ok    confirm with a box bearer is owner_required");
    let _: serde_json::Value = ok(
        "POST confirm (A)",
        call(&base, &a.owner_token, &plane::pair_confirm(&ca).unwrap()),
    );
    let Confirmed::Accept {
        confirmation: cb,
        awaiting: wait_b,
    } = hs_b.confirm(&code_a, &b.sk).unwrap()
    else {
        panic!("B mismatch")
    };
    let _: serde_json::Value = ok(
        "POST confirm (B)",
        call(&base, &b.owner_token, &plane::pair_confirm(&cb).unwrap()),
    );
    // Same confirmation again: 409, and same_as_stored says it landed.
    let (s, body) = call(&base, &b.owner_token, &plane::pair_confirm(&cb).unwrap());
    let err = plane::parse::<serde_json::Value>(s, &body).unwrap_err();
    assert_eq!(err.code(), Some(&plane::Code::AlreadyDecided), "{err}");
    let row_b = get_pair(&base, &b, &id);
    let stored = row_b
        .confirmations
        .iter()
        .find(|x| x.side == "to")
        .and_then(|x| x.sig.clone())
        .unwrap();
    assert!(cb.same_as_stored(&stored));
    println!("ok    repeat confirm: already_decided, same_as_stored");

    // Pin only after the peer's signed accept verifies over our own T.
    let pin = |row: &PairItem, w: Box<postal_sdk::pairing::AwaitingPeer>| {
        assert_eq!(row.status, plane::PairStatus::Accepted);
        let pc = row.peer_confirmation().expect("peer confirmation");
        w.peer_confirmation(
            Decision::parse(&pc.decision).unwrap(),
            pc.sig.as_deref().unwrap(),
        )
        .expect("peer confirmation verifies")
    };
    let pinned_a = pin(&get_pair(&base, &a, &id), wait_a);
    let pinned_b = pin(&row_b, wait_b);
    assert_eq!(pinned_a.key.fingerprint(), b.pk.fingerprint());
    assert_eq!(pinned_b.key.fingerprint(), a.pk.fingerprint());
    println!("ok    both pinned; codes {code_a} (never sent to the plane)");

    // ---- hold v2 ----
    let start = ok::<plane::EventPage>(
        "GET /events (head, B)",
        call(&base, &b.box_token, &plane::events(None, 0)),
    );
    let a_head = ok::<plane::EventPage>(
        "GET /events (head, A)",
        call(&base, &a.box_token, &plane::events(None, 0)),
    );
    let msg_id = ulid();
    let msg = wire::sign(
        &a.sk,
        &a.pk,
        &Draft {
            id: &msg_id,
            from: &a.addr,
            to: &b.addr,
            sent_at: now(),
            mode: Mode::Tray,
            content_type: "text/plain; charset=utf-8",
            body: "held hello from the e2e driver",
            files: &[],
            wake: false,
        },
    )
    .unwrap();
    let outer = Outer::of(&msg);
    let sealed = hold::seal(&pinned_a.key, &msg).unwrap();
    let put: plane::HoldPutOk = ok(
        "POST /hold",
        call(
            &base,
            &a.box_token,
            &plane::hold_put(&outer, &sealed).unwrap(),
        ),
    );
    assert!(!put.duplicate);
    // A retry seals again: new bytes, same client_id → the original answer.
    let again = hold::seal(&pinned_a.key, &msg).unwrap();
    assert_ne!(again, sealed);
    let dup: plane::HoldPutOk = ok(
        "POST /hold (retry, new bytes)",
        call(
            &base,
            &a.box_token,
            &plane::hold_put(&outer, &again).unwrap(),
        ),
    );
    assert!(dup.duplicate && dup.id == put.id, "first write wins");
    // Plaintext never leaves the box.
    assert!(plane::hold_put(&outer, &wire::encode_json(&msg).unwrap()).is_err());

    // B: an event, then a pull.
    let mut cursor = start.cursor;
    let mut saw_hold = false;
    for _ in 0..3 {
        let (st, body) = call(&base, &b.box_token, &plane::events(Some(&cursor), 25));
        match plane::after_events(st, &body) {
            AfterEvents::Next(p) => {
                cursor = p.cursor;
                if p.events.iter().any(|e| matches!(e, Event::Hold { .. })) {
                    saw_hold = true;
                    break;
                }
            }
            other => panic!("events: {other:?}"),
        }
    }
    assert!(saw_hold, "B got a hold event");
    println!("ok    hold event reached B");
    let page: plane::HoldPage = ok(
        "GET /hold (B)",
        call(&base, &b.box_token, &plane::hold_list(None, 100)),
    );
    let item = page
        .items
        .iter()
        .find(|i| i.client_id == msg_id)
        .expect("our item");
    let (o, blob) = item.decode().unwrap();
    let mut seen = MemorySeen::default();
    let with = OpenWith {
        opener: &b.sk,
        me: &b.pk,
        to: &b.addr,
        sender: &pinned_b.key,
        now: now(),
    };
    let v = hold::open(&o, &blob, &with, &mut seen).expect("open");
    assert_eq!(v.body(), b"held hello from the e2e driver");
    assert!(!v.wake());
    println!("ok    opened and verified, badge {}", v.badge());
    // The same item again is a replay: ACK, don't refuse.
    let replay = hold::open(&o, &blob, &with, &mut seen).unwrap_err();
    assert_eq!(replay.disposition(), Disposition::Ack);
    // A tampered copy doesn't open.
    let mut bad = blob.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        hold::open(&o, &bad, &with, &mut MemorySeen::default())
            .unwrap_err()
            .disposition(),
        Disposition::Refuse(plane::RefuseCode::Gated)
    );
    let acked: plane::Acked = ok(
        "POST /hold/ack",
        call(
            &base,
            &b.box_token,
            &plane::hold_ack(std::slice::from_ref(&item.id)).unwrap(),
        ),
    );
    assert_eq!(acked.acked, std::slice::from_ref(&item.id));
    let acked: plane::Acked = ok(
        "POST /hold/ack (again)",
        call(
            &base,
            &b.box_token,
            &plane::hold_ack(std::slice::from_ref(&item.id)).unwrap(),
        ),
    );
    assert!(acked.acked.is_empty(), "a repeated ACK is harmless");

    // A: the receipt.
    let (s, body) = call(
        &base,
        &a.box_token,
        &plane::hold_sent(std::slice::from_ref(&msg_id)).unwrap(),
    );
    let rc = plane::parse_receipts(s, &body).unwrap();
    assert_eq!(rc.get(&msg_id), Some(&Receipt::Delivered), "{rc:?}");
    println!("ok    receipt delivered");
    // And A was told by an event (a hint; the pull above is the answer).
    let (st, body) = call(&base, &a.box_token, &plane::events(Some(&a_head.cursor), 5));
    let AfterEvents::Next(p) = plane::after_events(st, &body) else {
        panic!("A events")
    };
    assert!(
        p.events
            .iter()
            .any(|e| matches!(e, Event::Receipt { client_id, .. } if *client_id == msg_id)),
        "{:?}",
        p.events
    );
    println!("ok    receipt event reached A");

    // A refusal leaves a refused:<code> receipt.
    let id2 = ulid();
    let msg2 = wire::sign(
        &a.sk,
        &a.pk,
        &Draft {
            id: &id2,
            from: &a.addr,
            to: &b.addr,
            sent_at: now(),
            mode: Mode::Live,
            content_type: "text/plain",
            body: "refuse me",
            files: &[],
            wake: true,
        },
    )
    .unwrap();
    let sealed2 = hold::seal(&pinned_a.key, &msg2).unwrap();
    let put2: plane::HoldPutOk = ok(
        "POST /hold (2)",
        call(
            &base,
            &a.box_token,
            &plane::hold_put(&Outer::of(&msg2), &sealed2).unwrap(),
        ),
    );
    let _: serde_json::Value = ok(
        "POST /hold/refuse",
        call(
            &base,
            &b.box_token,
            &plane::hold_refuse(&[put2.id], plane::RefuseCode::Gated).unwrap(),
        ),
    );
    let (s, body) = call(
        &base,
        &a.box_token,
        &plane::hold_sent(std::slice::from_ref(&id2)).unwrap(),
    );
    let rc = plane::parse_receipts(s, &body).unwrap();
    assert_eq!(
        rc.get(&id2),
        Some(&Receipt::Refused(plane::RefuseCode::Gated)),
        "{rc:?}"
    );
    println!("ok    refused:gated receipt");

    // Revoke, and holding stops.
    let _: serde_json::Value = ok(
        "POST revoke",
        call(&base, &a.owner_token, &plane::pair_revoke(&id).unwrap()),
    );
    let id3 = ulid();
    let msg3 = wire::sign(
        &a.sk,
        &a.pk,
        &Draft {
            id: &id3,
            from: &a.addr,
            to: &b.addr,
            sent_at: now(),
            mode: Mode::Live,
            content_type: "text/plain",
            body: "after revoke",
            files: &[],
            wake: true,
        },
    )
    .unwrap();
    let sealed3 = hold::seal(&pinned_a.key, &msg3).unwrap();
    let (s, body) = call(
        &base,
        &a.box_token,
        &plane::hold_put(&Outer::of(&msg3), &sealed3).unwrap(),
    );
    let err = plane::parse::<plane::HoldPutOk>(s, &body).unwrap_err();
    assert_eq!(err.code(), Some(&plane::Code::PairNotAccepted), "{err}");
    println!("ok    after revoke: pair_not_accepted");
    println!("PASS  e2e");
}
