//! Typed, sans-IO client for the Postal plane API v1 (`/api/postal/v1`).
//!
//! Each call is a [`Request`] builder and a parser for the `(status, body)`
//! the host got back. The host brings HTTP, the base URL and the bearer
//! (Connect token, `pst_`, `k2c_cli_` or `k2c_pd_`), and checks the
//! `Postal-Api: 1` header. Nothing here does I/O.
//!
//! Hold v2 (P-4) and events (P-5) follow contract draft 2 with K2 Web:
//! first-write-wins on `(from, client_id)`, a 512 KiB decoded cap, `after=`
//! paging, `{acked}`, refusals with a receipt, events as hints only.
//! Pair routes are in `docs/postal-plane-v1.md`; the confirm body comes from
//! [`crate::pairing::Confirmation`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::hold::{Outer, HOLDSEAL_V2, MAX_SEALED, MIN_SEALED};
use crate::pairing::{Commitment, PairError, PublicKey, Reveal};

/// Path prefix of every v1 route.
pub const API: &str = "/api/postal/v1";
/// Most ids in one ACK, refuse or receipts call.
pub const MAX_IDS: usize = 100;
/// Longest long-poll wait the plane allows, in seconds.
pub const MAX_WAIT_SECS: u32 = 60;
/// Default page size for `GET /hold`.
pub const HOLD_PAGE: u32 = 100;

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
}

/// One plane call. `body` is JSON, `None` for a GET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    /// Path and query, starting with [`API`].
    pub path: String,
    pub body: Option<String>,
}

impl Request {
    fn get(path: String) -> Self {
        Self {
            method: Method::Get,
            path,
            body: None,
        }
    }

    fn post(path: String, body: &impl Serialize) -> Self {
        Self {
            method: Method::Post,
            path,
            body: Some(serde_json::to_string(body).expect("plane bodies serialize")),
        }
    }
}

// ---------------------------------------------------------------- errors

/// A stable error code from `{"error":{"code",…}}`. Unknown codes are kept,
/// so a newer plane never breaks an older SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Code {
    RateLimited,
    HoldQuota,
    Unavailable,
    Internal,
    BadRequest,
    InvalidAddr,
    Unauthorized,
    Forbidden,
    OwnerRequired,
    NotYourHandle,
    BadConfirmation,
    NotFound,
    Conflict,
    AlreadyResponded,
    NotResponded,
    AlreadyRevealed,
    CommitmentMismatch,
    PairExpired,
    NotRevealed,
    AlreadyDecided,
    TranscriptMismatch,
    PairNotAccepted,
    PairIdTaken,
    CursorExpired,
    TooLarge,
    /// `sealed` isn't HoldSeal-v2 framing (byte 0 = 0x02, at least 61 bytes).
    BadSealed,
    Other(String),
}

impl Code {
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "rate_limited" => Self::RateLimited,
            "hold_quota" => Self::HoldQuota,
            "unavailable" => Self::Unavailable,
            "internal" => Self::Internal,
            "bad_request" => Self::BadRequest,
            "invalid_addr" => Self::InvalidAddr,
            "unauthorized" => Self::Unauthorized,
            "forbidden" => Self::Forbidden,
            "owner_required" => Self::OwnerRequired,
            "not_your_handle" => Self::NotYourHandle,
            "bad_confirmation" => Self::BadConfirmation,
            "not_found" => Self::NotFound,
            "conflict" => Self::Conflict,
            "already_responded" => Self::AlreadyResponded,
            "not_responded" => Self::NotResponded,
            "already_revealed" => Self::AlreadyRevealed,
            "commitment_mismatch" => Self::CommitmentMismatch,
            "pair_expired" => Self::PairExpired,
            "not_revealed" => Self::NotRevealed,
            "already_decided" => Self::AlreadyDecided,
            "transcript_mismatch" => Self::TranscriptMismatch,
            "pair_not_accepted" => Self::PairNotAccepted,
            "pair_id_taken" => Self::PairIdTaken,
            "cursor_expired" => Self::CursorExpired,
            "too_large" => Self::TooLarge,
            "bad_sealed" => Self::BadSealed,
            other => Self::Other(other.to_string()),
        }
    }
}

/// What a failed call means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaneError {
    /// A v1 error answer.
    Api {
        status: u16,
        code: Code,
        message: String,
        retry_after_s: Option<u64>,
    },
    /// A success status with a body that isn't the expected shape.
    BadBody(String),
    /// An argument the SDK refuses to send (bad id, too many ids, plaintext).
    BadInput(&'static str),
}

impl PlaneError {
    /// Whether the same request may succeed later (the contract's class;
    /// an unknown code goes by its HTTP status).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Api { code, status, .. } => match code {
                Code::RateLimited | Code::HoldQuota | Code::Unavailable | Code::Internal => true,
                Code::Other(_) => *status == 429 || *status >= 500,
                _ => false,
            },
            Self::BadBody(_) | Self::BadInput(_) => false,
        }
    }

    /// Seconds to wait before retrying, when the plane said.
    #[must_use]
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Api { retry_after_s, .. } => *retry_after_s,
            _ => None,
        }
    }

    #[must_use]
    pub fn code(&self) -> Option<&Code> {
        match self {
            Self::Api { code, .. } => Some(code),
            _ => None,
        }
    }
}

impl std::fmt::Display for PlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api {
                status,
                code,
                message,
                ..
            } => write!(f, "plane {status} {code:?}: {message}"),
            Self::BadBody(e) => write!(f, "plane answer not understood: {e}"),
            Self::BadInput(e) => write!(f, "refused before sending: {e}"),
        }
    }
}

impl std::error::Error for PlaneError {}

#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorInner,
}

#[derive(Deserialize)]
struct ErrorInner {
    code: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    retry_after_s: Option<u64>,
}

/// Parse any answer: a 2xx body as `T`, anything else as [`PlaneError::Api`].
/// A non-2xx without the v1 error shape (a proxy page, say) is classed by
/// its status.
///
/// # Errors
/// [`PlaneError`].
pub fn parse<T: for<'de> Deserialize<'de>>(status: u16, body: &[u8]) -> Result<T, PlaneError> {
    if (200..300).contains(&status) {
        return serde_json::from_slice(body).map_err(|e| PlaneError::BadBody(e.to_string()));
    }
    Err(match serde_json::from_slice::<ErrorBody>(body) {
        Ok(e) => PlaneError::Api {
            status,
            code: Code::parse(&e.error.code),
            message: e.error.message,
            retry_after_s: e.error.retry_after_s,
        },
        Err(_) => PlaneError::Api {
            status,
            code: Code::Other(format!("http_{status}")),
            message: String::new(),
            retry_after_s: None,
        },
    })
}

// ---------------------------------------------------------------- hold v2

#[derive(Serialize)]
struct HoldPutBody<'a> {
    v: u8,
    from: &'a Address,
    to: &'a Address,
    client_id: &'a str,
    sealed: String,
}

/// `POST /hold {v:2, from, to, client_id, sealed}`. Refuses anything that
/// isn't a sized HoldSeal-v2 blob, so plaintext never leaves the box.
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn hold_put(outer: &Outer, sealed: &[u8]) -> Result<Request, PlaneError> {
    if sealed.len() < MIN_SEALED || sealed.len() > MAX_SEALED || sealed[0] != HOLDSEAL_V2 {
        return Err(PlaneError::BadInput("not a HoldSeal-v2 blob"));
    }
    if !crate::wire::is_canonical_ulid(&outer.client_id) {
        return Err(PlaneError::BadInput("client_id is not a ULID"));
    }
    Ok(Request::post(
        format!("{API}/hold"),
        &HoldPutBody {
            v: HOLDSEAL_V2,
            from: &outer.from,
            to: &outer.to,
            client_id: &outer.client_id,
            sealed: crate::b64::encode(sealed),
        },
    ))
}

/// `POST /hold` answer. A repeat `(from, client_id)` answers the original
/// with `duplicate: true`, whatever the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HoldPutOk {
    pub id: String,
    pub expires_at: String,
    #[serde(default)]
    pub duplicate: bool,
}

/// `GET /hold?after=&limit=`, oldest first.
#[must_use]
pub fn hold_list(after: Option<&str>, limit: u32) -> Request {
    let limit = limit.clamp(1, HOLD_PAGE);
    match after {
        Some(a) => Request::get(format!("{API}/hold?after={}&limit={limit}", query(a))),
        None => Request::get(format!("{API}/hold?limit={limit}")),
    }
}

/// One held item, as listed. `sealed` is still base64; see
/// [`HoldItem::decode`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HoldItem {
    pub id: String,
    pub from: String,
    pub to: String,
    pub client_id: String,
    pub sealed: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub expires_at: String,
}

impl HoldItem {
    /// The outer fields and the sealed bytes, ready for
    /// [`crate::hold::open`]. An item that fails here can never open:
    /// refuse it (`too_large` if oversize) rather than leave it.
    ///
    /// # Errors
    /// [`PlaneError::BadBody`].
    pub fn decode(&self) -> Result<(Outer, Vec<u8>), PlaneError> {
        let bad = |e: &str| PlaneError::BadBody(format!("hold item {}: {e}", self.id));
        let outer = Outer {
            from: Address::parse(&self.from).map_err(|_| bad("from"))?,
            to: Address::parse(&self.to).map_err(|_| bad("to"))?,
            client_id: self.client_id.clone(),
        };
        // Length before decoding: never decode a blob that can't be legal.
        if self.sealed.len() > MAX_SEALED.div_ceil(3) * 4 {
            return Err(bad("sealed over 512 KiB"));
        }
        let sealed = crate::b64::decode(&self.sealed).map_err(|_| bad("sealed"))?;
        Ok((outer, sealed))
    }
}

/// `GET /hold` answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HoldPage {
    pub items: Vec<HoldItem>,
    /// Set by the plane when more items remain, including when it cut the
    /// page short by size (about 2.5 MiB sealed).
    #[serde(default)]
    pub next_after: Option<String>,
}

impl HoldPage {
    /// The `after=` cursor for the next page, or `None` when this was the
    /// last. The plane's `next_after` wins; without it, a full page means
    /// pull again (at worst one empty pull).
    #[must_use]
    pub fn next_after(&self, limit: u32) -> Option<&str> {
        if let Some(n) = self.next_after.as_deref() {
            return Some(n);
        }
        if self.items.len() < limit.clamp(1, HOLD_PAGE) as usize {
            return None;
        }
        self.items.last().map(|i| i.id.as_str())
    }
}

#[derive(Serialize)]
struct Ids<'a> {
    ids: &'a [String],
}

fn check_ids(ids: &[String]) -> Result<(), PlaneError> {
    if ids.is_empty() || ids.len() > MAX_IDS {
        return Err(PlaneError::BadInput("1 to 100 ids"));
    }
    if !ids.iter().all(|i| is_safe_id(i)) {
        return Err(PlaneError::BadInput("bad id"));
    }
    Ok(())
}

/// `POST /hold/ack {ids}`. Only after the host stored each message.
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn hold_ack(ids: &[String]) -> Result<Request, PlaneError> {
    check_ids(ids)?;
    Ok(Request::post(format!("{API}/hold/ack"), &Ids { ids }))
}

/// `POST /hold/ack` answer. An id missing from `acked` was foreign or already
/// gone; that is not an error.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Acked {
    pub acked: Vec<String>,
}

/// Why a box refuses held mail for good. The sender's receipt shows
/// `refused:<code>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefuseCode {
    NoAgent,
    Gated,
    TooLarge,
}

impl From<crate::host::RefuseCode> for RefuseCode {
    fn from(c: crate::host::RefuseCode) -> Self {
        match c {
            crate::host::RefuseCode::NoAgent => Self::NoAgent,
            crate::host::RefuseCode::Gated => Self::Gated,
            crate::host::RefuseCode::TooLarge => Self::TooLarge,
        }
    }
}

#[derive(Serialize)]
struct RefuseBody<'a> {
    ids: &'a [String],
    code: RefuseCode,
}

/// `POST /hold/refuse {ids, code}`: deletes like an ACK and leaves a receipt.
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn hold_refuse(ids: &[String], code: RefuseCode) -> Result<Request, PlaneError> {
    check_ids(ids)?;
    Ok(Request::post(
        format!("{API}/hold/refuse"),
        &RefuseBody { ids, code },
    ))
}

/// `GET /hold/sent?client_ids=a,b`: receipts for this caller's own items,
/// across all its handles. Unknown ids are absent from the answer.
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn hold_sent(client_ids: &[String]) -> Result<Request, PlaneError> {
    check_ids(client_ids)?;
    Ok(Request::get(format!(
        "{API}/hold/sent?client_ids={}",
        client_ids.join(",")
    )))
}

/// A sender's receipt for one held item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
    Held,
    /// The recipient ACKed: the bytes are on its disk.
    Delivered,
    Expired,
    Refused(RefuseCode),
    /// A state this SDK doesn't know yet. Keep waiting.
    Other(String),
}

impl Receipt {
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "held" => Self::Held,
            "delivered" => Self::Delivered,
            "expired" => Self::Expired,
            "refused:no_agent" => Self::Refused(RefuseCode::NoAgent),
            "refused:gated" => Self::Refused(RefuseCode::Gated),
            "refused:too_large" => Self::Refused(RefuseCode::TooLarge),
            other => Self::Other(other.to_string()),
        }
    }
}

/// Parse a `/hold/sent` answer: `{"<client_id>": "<receipt>", …}`.
///
/// # Errors
/// [`PlaneError`].
pub fn parse_receipts(status: u16, body: &[u8]) -> Result<BTreeMap<String, Receipt>, PlaneError> {
    let raw: BTreeMap<String, String> = parse(status, body)?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k, Receipt::parse(&v)))
        .collect())
}

// ---------------------------------------------------------------- events

/// `GET /events?cursor=&wait=`. No cursor starts at the head.
#[must_use]
pub fn events(cursor: Option<&str>, wait_secs: u32) -> Request {
    let wait = wait_secs.min(MAX_WAIT_SECS);
    match cursor {
        Some(c) if !c.is_empty() => {
            Request::get(format!("{API}/events?cursor={}&wait={wait}", query(c)))
        }
        _ => Request::get(format!("{API}/events?wait={wait}")),
    }
}

/// A content-blind hint. Events are only hints: on any event, pull the
/// state it points at (`/hold`, `/pairs/{id}`, `/hold/sent`) and act on that
/// answer. Nothing is decided from an event alone, so a lost, repeated or
/// malformed event costs at most a pull.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Held mail is waiting: pull `GET /hold`.
    Hold {
        #[serde(default)]
        handle: String,
        #[serde(default)]
        count: u64,
    },
    /// A pair moved a step: pull `GET /pairs/{id}`.
    Pair {
        id: String,
        #[serde(default)]
        status: String,
        #[serde(default)]
        step: Option<String>,
        #[serde(default)]
        reason: Option<String>,
    },
    /// One of this sender's held items changed state: pull
    /// `GET /hold/sent?client_ids=<client_id>` and feed that receipt to
    /// [`crate::outbox::Item::on_receipt`]. Find the item by `client_id`;
    /// `handle` is plane data, so don't route on it.
    Receipt {
        #[serde(default)]
        handle: String,
        client_id: String,
        #[serde(default)]
        state: String,
    },
    /// A type this SDK doesn't know, or an event missing a field it needs.
    /// Skip it.
    #[serde(other)]
    Unknown,
}

/// `GET /events` answer. A timeout is 200 with no events. Each event is
/// parsed on its own: one this SDK can't read becomes [`Event::Unknown`]
/// instead of failing the page, so the cursor always moves on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPage {
    pub cursor: String,
    pub events: Vec<Event>,
}

impl<'de> Deserialize<'de> for EventPage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            cursor: String,
            #[serde(default)]
            events: Vec<serde_json::Value>,
        }
        let raw = Raw::deserialize(d)?;
        Ok(Self {
            cursor: raw.cursor,
            events: raw
                .events
                .into_iter()
                .map(|e| serde_json::from_value(e).unwrap_or(Event::Unknown))
                .collect(),
        })
    }
}

/// What to do after an events call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfterEvents {
    /// Store `cursor`, act on the events, poll again at once.
    Next(EventPage),
    /// 410 `cursor_expired`: drop the cursor, do one full pull of `/hold`
    /// and `/pairs`, then poll from the head.
    Restart,
    /// Back off (60 s is fine, or `retry_after_s`), keep the cursor.
    BackOff(PlaneError),
    /// A permanent error (auth, say). Stop and tell the owner.
    Stop(PlaneError),
}

#[must_use]
pub fn after_events(status: u16, body: &[u8]) -> AfterEvents {
    match parse::<EventPage>(status, body) {
        Ok(page) => AfterEvents::Next(page),
        Err(e) if e.code() == Some(&Code::CursorExpired) => AfterEvents::Restart,
        Err(e) if e.is_retryable() => AfterEvents::BackOff(e),
        Err(e @ PlaneError::BadBody(_)) => AfterEvents::BackOff(e),
        Err(e) => AfterEvents::Stop(e),
    }
}

// ---------------------------------------------------------------- me

#[derive(Serialize)]
struct MeBody<'a> {
    addr: &'a Address,
    public_key_pem: &'a str,
    typ: Typ,
}

/// `PUT /me {addr, public_key_pem, typ}`: register a handle's key.
#[must_use]
pub fn me_put(addr: &Address, key: &PublicKey, typ: Typ) -> Request {
    Request {
        method: Method::Put,
        path: format!("{API}/me"),
        body: Some(
            serde_json::to_string(&MeBody {
                addr,
                public_key_pem: key.pem(),
                typ,
            })
            .expect("plane bodies serialize"),
        ),
    }
}

// ---------------------------------------------------------------- pairs

/// The client's own pair id: a ULID, because the commitment binds it.
fn pair_path(pair_id: &str, rest: &str) -> Result<String, PlaneError> {
    if !crate::wire::is_canonical_ulid(pair_id) {
        return Err(PlaneError::BadInput("pair id is not a ULID"));
    }
    Ok(format!("{API}/pairs/{pair_id}{rest}"))
}

/// The other end's kind of agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Typ {
    Session,
    Turn,
}

#[derive(Serialize)]
struct PairCreate<'a> {
    id: &'a str,
    from: &'a Address,
    to: &'a Address,
    typ: Typ,
    public_key_pem: &'a str,
    sas_version: u8,
    commitment: String,
}

/// `POST /pairs`, step 1 (A). `id` must be the `pair_id` in the
/// [`crate::pairing::PairContext`] the commitment was made over.
///
/// # Errors
/// [`PlaneError::BadInput`] for a non-ULID id.
pub fn pair_create(
    id: &str,
    from: &Address,
    to: &Address,
    typ: Typ,
    me: &PublicKey,
    c: &Commitment,
) -> Result<Request, PlaneError> {
    pair_path(id, "")?;
    Ok(Request::post(
        format!("{API}/pairs"),
        &PairCreate {
            id,
            from,
            to,
            typ,
            public_key_pem: me.pem(),
            sas_version: 2,
            commitment: c.to_hex(),
        },
    ))
}

#[derive(Serialize)]
struct PairRespond<'a> {
    public_key_pem: &'a str,
    nb: String,
    typ: Typ,
}

/// `POST /pairs/{id}/respond`, step 2 (B).
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn pair_respond(
    id: &str,
    resp: &crate::pairing::Response,
    typ: Typ,
) -> Result<Request, PlaneError> {
    Ok(Request::post(
        pair_path(id, "/respond")?,
        &PairRespond {
            public_key_pem: resp.key().pem(),
            nb: resp.nb_hex(),
            typ,
        },
    ))
}

#[derive(Serialize)]
struct PairReveal {
    na: String,
}

/// `POST /pairs/{id}/reveal`, step 3 (A).
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn pair_reveal(id: &str, reveal: &Reveal) -> Result<Request, PlaneError> {
    Ok(Request::post(
        pair_path(id, "/reveal")?,
        &PairReveal {
            na: reveal.to_hex(),
        },
    ))
}

/// `POST /pairs/{id}/confirm` with this box's signed confirmation. Owner
/// credentials only (`k2c_pd_`, `k2c_cli_`).
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn pair_confirm(c: &crate::pairing::Confirmation) -> Result<Request, PlaneError> {
    Ok(Request {
        method: Method::Post,
        path: c
            .path()
            .map_err(|_: PairError| PlaneError::BadInput("pair id"))?,
        body: Some(c.body_json()),
    })
}

/// `POST /pairs/{id}/revoke {}`. Owner credentials only.
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn pair_revoke(id: &str) -> Result<Request, PlaneError> {
    Ok(Request {
        method: Method::Post,
        path: crate::pairing::revoke_path(id).map_err(|_| PlaneError::BadInput("pair id"))?,
        body: Some(crate::pairing::REVOKE_BODY.to_string()),
    })
}

/// `GET /pairs`.
#[must_use]
pub fn pairs_list() -> Request {
    Request::get(format!("{API}/pairs"))
}

/// `GET /pairs/{id}`.
///
/// # Errors
/// [`PlaneError::BadInput`].
pub fn pair_get(id: &str) -> Result<Request, PlaneError> {
    Ok(Request::get(pair_path(id, "")?))
}

/// A pair's status, from the caller's side.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairStatus {
    PendingIn,
    PendingOut,
    Accepted,
    Rejected,
    Revoked,
    Failed,
    Expired,
    #[serde(other)]
    Unknown,
}

/// One stored confirmation, as the plane relays it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StoredConfirmation {
    pub side: String,
    pub decision: String,
    /// Null only for a dashboard (unsigned) reject.
    pub transcript_sha256: Option<String>,
    pub sig: Option<String>,
    #[serde(default)]
    pub at: Option<String>,
}

/// One `GET /pairs` item. Plane data: the box derives fingerprints from
/// `peer_key_pem` and never trusts `peer_fingerprint` (rule B2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PairItem {
    pub id: String,
    pub side: Option<String>,
    pub handle: String,
    pub peer: String,
    pub peer_typ: Option<Typ>,
    pub peer_key_pem: Option<String>,
    pub direction: String,
    pub status: PairStatus,
    pub step: Option<String>,
    pub sas_version: u8,
    pub commitment: Option<String>,
    pub nb: Option<String>,
    pub na: Option<String>,
    #[serde(default)]
    pub confirmed_by: Vec<String>,
    #[serde(default)]
    pub confirmations: Vec<StoredConfirmation>,
    pub failed_reason: Option<String>,
    pub rekey_of: Option<String>,
    #[serde(default)]
    pub rekey_pending: bool,
    pub created_at: Option<String>,
    pub decided_at: Option<String>,
    pub expires_at: Option<String>,
}

impl PairItem {
    /// The peer's signed confirmation, if it has one.
    #[must_use]
    pub fn peer_confirmation(&self) -> Option<&StoredConfirmation> {
        let mine = self.side.as_deref()?;
        self.confirmations.iter().find(|c| c.side != mine)
    }
}

/// `GET /pairs` answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PairList {
    pub pairs: Vec<PairItem>,
}

// ---------------------------------------------------------------- helpers

/// A plane-issued id that can sit in a path or a comma list.
#[must_use]
pub fn is_safe_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::tests::{key, signed};
    use serde_json::{json, Value};

    fn body(r: &Request) -> Value {
        serde_json::from_str(r.body.as_deref().unwrap()).unwrap()
    }

    #[test]
    fn hold_put_sends_only_sealed_v2() {
        let msg = signed(&[]);
        let (_, scout) = key(0x22);
        let blob = crate::hold::seal(&scout, &msg).unwrap();
        let outer = Outer::of(&msg);
        let r = hold_put(&outer, &blob).unwrap();
        assert_eq!(
            (r.method, r.path.as_str()),
            (Method::Post, "/api/postal/v1/hold")
        );
        let b = body(&r);
        assert_eq!(b["v"], 2);
        assert_eq!(b["from"], "alice::acme.postal.bot");
        assert_eq!(b["to"], "scout::bravo.postal.bot");
        assert_eq!(b["client_id"], msg.id.as_str());
        assert_eq!(
            crate::b64::decode(b["sealed"].as_str().unwrap()).unwrap(),
            blob
        );
        assert_eq!(b.as_object().unwrap().len(), 5, "{b}");

        let json = crate::wire::encode_json(&msg).unwrap();
        assert!(hold_put(&outer, &json).is_err(), "plaintext refused");
        let mut v1 = blob.clone();
        v1[0] = 1;
        assert!(hold_put(&outer, &v1).is_err());
        assert!(hold_put(&outer, &blob[..MIN_SEALED - 1]).is_err());
    }

    #[test]
    fn hold_put_answers_and_duplicates() {
        let ok: HoldPutOk =
            parse(200, br#"{"id":"h1","expires_at":"2026-11-25T00:00:00Z"}"#).unwrap();
        assert!(!ok.duplicate);
        let dup: HoldPutOk =
            parse(200, br#"{"id":"h1","expires_at":"x","duplicate":true}"#).unwrap();
        assert!(dup.duplicate);
        let quota = parse::<HoldPutOk>(
            429,
            br#"{"error":{"code":"hold_quota","message":"full","retry_after_s":60}}"#,
        )
        .unwrap_err();
        assert!(quota.is_retryable());
        assert_eq!(quota.retry_after(), Some(60));
        let big =
            parse::<HoldPutOk>(413, br#"{"error":{"code":"too_large","message":""}}"#).unwrap_err();
        assert!(!big.is_retryable());
        assert_eq!(big.code(), Some(&Code::TooLarge));
        let proxy = parse::<HoldPutOk>(502, b"<html>bad gateway</html>").unwrap_err();
        assert!(proxy.is_retryable());
        let future =
            parse::<HoldPutOk>(409, br#"{"error":{"code":"brand_new","message":""}}"#).unwrap_err();
        assert!(!future.is_retryable());
    }

    #[test]
    fn hold_list_pages_and_items_decode() {
        assert_eq!(hold_list(None, 100).path, "/api/postal/v1/hold?limit=100");
        assert_eq!(
            hold_list(Some("h 1&x"), 500).path,
            "/api/postal/v1/hold?after=h%201%26x&limit=100"
        );
        let msg = signed(&[]);
        let (_, scout) = key(0x22);
        let blob = crate::hold::seal(&scout, &msg).unwrap();
        let page: HoldPage = parse(
            200,
            json!({"items":[{"id":"h1","from":"alice::acme.postal.bot","to":"scout::bravo.postal.bot",
                "client_id": msg.id, "sealed": crate::b64::encode(&blob), "size": blob.len(),
                "created_at":"t","expires_at":"t"}]})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(page.next_after(100), None);
        assert_eq!(page.next_after(1), Some("h1"));
        // A page cut short by size still says there's more.
        let cut: HoldPage = parse(200, br#"{"items":[],"next_after":"h9"}"#).unwrap();
        assert_eq!(cut.next_after(100), Some("h9"));
        let last: HoldPage = parse(200, br#"{"items":[],"next_after":null}"#).unwrap();
        assert_eq!(last.next_after(100), None);
        let (outer, sealed) = page.items[0].decode().unwrap();
        assert_eq!(outer, Outer::of(&msg));
        assert_eq!(sealed, blob);
        let mut bad = page.items[0].clone();
        bad.from = "Alice::acme.postal.bot".into();
        assert!(bad.decode().is_err());
        let mut big = page.items[0].clone();
        big.sealed = "A".repeat(MAX_SEALED.div_ceil(3) * 4 + 4);
        assert!(big.decode().is_err());
    }

    #[test]
    fn ack_refuse_and_receipts() {
        let ids = vec!["h1".to_string(), "h2".to_string()];
        let r = hold_ack(&ids).unwrap();
        assert_eq!(r.path, "/api/postal/v1/hold/ack");
        assert_eq!(body(&r), json!({"ids":["h1","h2"]}));
        let acked: Acked = parse(200, br#"{"acked":["h1"]}"#).unwrap();
        assert_eq!(acked.acked, ["h1"]);
        let r = hold_refuse(&ids, crate::host::RefuseCode::Gated.into()).unwrap();
        assert_eq!(body(&r), json!({"ids":["h1","h2"],"code":"gated"}));
        assert!(hold_ack(&[]).is_err());
        assert!(hold_ack(&vec!["x".to_string(); MAX_IDS + 1]).is_err());
        assert!(hold_ack(&["a/b".to_string()]).is_err());
        assert!(hold_ack(&["a,b".to_string()]).is_err());
        let r = hold_sent(&ids).unwrap();
        assert_eq!(r.path, "/api/postal/v1/hold/sent?client_ids=h1,h2");
        let rc = parse_receipts(
            200,
            br#"{"a":"held","b":"delivered","c":"expired","d":"refused:too_large","e":"lost"}"#,
        )
        .unwrap();
        assert_eq!(rc["b"], Receipt::Delivered);
        assert_eq!(rc["d"], Receipt::Refused(RefuseCode::TooLarge));
        assert_eq!(rc["e"], Receipt::Other("lost".into()));
    }

    #[test]
    fn events_paths_and_outcomes() {
        assert_eq!(events(None, 25).path, "/api/postal/v1/events?wait=25");
        assert_eq!(
            events(Some("c/1="), 99).path,
            "/api/postal/v1/events?cursor=c%2F1%3D&wait=60"
        );
        let page = br#"{"cursor":"c2","events":[
            {"type":"hold","handle":"scout::bravo.postal.bot","count":2},
            {"type":"pair","id":"01J","status":"pending_in","step":"responded"},
            {"type":"receipt","handle":"alice::acme.postal.bot","client_id":"m1","state":"refused:gated"},
            {"type":"from_the_future","x":1}]}"#;
        let AfterEvents::Next(p) = after_events(200, page) else {
            panic!()
        };
        assert_eq!(p.cursor, "c2");
        assert_eq!(p.events.len(), 4);
        assert_eq!(p.events[3], Event::Unknown);
        let Event::Receipt { client_id, .. } = &p.events[2] else {
            panic!("{:?}", p.events[2])
        };
        assert_eq!(client_id, "m1");
        // K2 review MUST 2: a bad event never fails the page.
        let page = br#"{"cursor":"c9","events":[
            {"type":"receipt","handle":"h","state":"delivered"},
            {"type":"receipt","client_ids":["m1"]},
            {"type":"pair","status":"accepted"},
            {"type":"pair","id":7},
            "not an object",
            {"no_type":true},
            {"type":"hold","handle":"scout::bravo.postal.bot","count":1}]}"#;
        let AfterEvents::Next(p) = after_events(200, page) else {
            panic!("a bad event must not fail the page")
        };
        assert_eq!(p.cursor, "c9");
        assert_eq!(p.events[..6], vec![Event::Unknown; 6][..]);
        assert!(matches!(p.events[6], Event::Hold { count: 1, .. }));
        // The page itself still has to be a page.
        assert!(matches!(
            after_events(200, br#"{"events":[]}"#),
            AfterEvents::BackOff(PlaneError::BadBody(_))
        ));

        assert!(matches!(
            after_events(200, br#"{"cursor":"c3","events":[]}"#),
            AfterEvents::Next(_)
        ));
        assert_eq!(
            after_events(410, br#"{"error":{"code":"cursor_expired","message":""}}"#),
            AfterEvents::Restart
        );
        assert!(matches!(after_events(503, b""), AfterEvents::BackOff(_)));
        assert!(matches!(
            after_events(401, br#"{"error":{"code":"unauthorized","message":""}}"#),
            AfterEvents::Stop(_)
        ));
    }

    #[test]
    fn pair_routes_match_the_contract() {
        use crate::pairing::{Attempts, Initiator, PairContext, Responder};
        let id = "01JD8X4Q2W3E4R5T6Y7Z8A9B0C";
        assert!(crate::wire::is_canonical_ulid(id));
        let ctx = PairContext {
            pair_id: id.into(),
            initiator: "alice::acme.postal.bot".into(),
            responder: "scout::bravo.postal.bot".into(),
        };
        let (_, a) = key(0x11);
        let (_, b) = key(0x22);
        let (init, c) = Initiator::start(
            ctx.clone(),
            a.clone(),
            &mut Attempts::default(),
            1_800_000_000,
        )
        .unwrap();
        let from = Address::parse(&ctx.initiator).unwrap();
        let to = Address::parse(&ctx.responder).unwrap();
        let r = pair_create(id, &from, &to, Typ::Session, &a, &c).unwrap();
        assert_eq!(r.path, "/api/postal/v1/pairs");
        let bd = body(&r);
        assert_eq!(bd["id"], id);
        assert_eq!(bd["sas_version"], 2);
        assert_eq!(bd["commitment"], c.to_hex());
        assert_eq!(bd["typ"], "session");
        assert_eq!(bd["public_key_pem"], a.pem());

        let (_resp_state, resp) =
            Responder::respond(ctx, a, c, b, &mut Attempts::default(), 1_800_000_000).unwrap();
        let r = pair_respond(id, &resp, Typ::Turn).unwrap();
        assert_eq!(r.path, format!("/api/postal/v1/pairs/{id}/respond"));
        assert_eq!(body(&r)["nb"], resp.nb_hex());
        let (reveal, _hs) = init.finish(resp, 1_800_000_001).unwrap();
        let r = pair_reveal(id, &reveal).unwrap();
        assert_eq!(r.path, format!("/api/postal/v1/pairs/{id}/reveal"));
        assert_eq!(body(&r), json!({"na": reveal.to_hex()}));
        assert_eq!(pair_revoke(id).unwrap().body.as_deref(), Some("{}"));
        assert_eq!(pairs_list().path, "/api/postal/v1/pairs");
        let me = me_put(&from, &key(0x11).1, Typ::Session);
        assert_eq!((me.method, me.path.as_str()), (Method::Put, "/api/postal/v1/me"));
        assert_eq!(body(&me)["addr"], "alice::acme.postal.bot");
        assert_eq!(
            pair_get(id).unwrap().path,
            format!("/api/postal/v1/pairs/{id}")
        );
        assert!(pair_get("../me").is_err());
    }

    #[test]
    fn pair_items_parse() {
        let list: PairList = parse(
            200,
            json!({"pairs":[{"id":"01J","side":"from","handle":"alice::acme.postal.bot",
              "peer":"scout::bravo.postal.bot","peer_typ":"session","peer_fingerprint":"ab",
              "peer_key_pem":null,"direction":"out","status":"pending_out","step":"revealed",
              "sas_version":2,"commitment":"c","nb":"n","na":"a","confirmed_by":["from","to"],
              "confirmations":[{"side":"from","decision":"accept","transcript_sha256":"t","sig":"s","at":"x"},
                               {"side":"to","decision":"reject","transcript_sha256":null,"sig":null,"at":"y"}],
              "failed_reason":null,"rekey_of":null,"rekey_pending":false,
              "created_at":"x","decided_at":null,"expires_at":"y"},
              {"id":"01K","side":null,"handle":"h","peer":"p","peer_typ":null,"peer_key_pem":null,
               "direction":"in","status":"something_new","step":null,"sas_version":1,"commitment":null,
               "nb":null,"na":null,"failed_reason":null,"rekey_of":null,"created_at":null,
               "decided_at":null,"expires_at":null}]})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(list.pairs[0].status, PairStatus::PendingOut);
        assert_eq!(
            list.pairs[0].peer_confirmation().unwrap().decision,
            "reject"
        );
        assert_eq!(list.pairs[1].status, PairStatus::Unknown);
        assert!(list.pairs[1].peer_confirmation().is_none());
    }
}
