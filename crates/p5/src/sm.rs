//! Sender SM + local session / turn receiver SM.
//!
//! Local dest = a HomeRow for the address or `P5_LOCAL_RECV=1` (UDS / in-process
//! receiver). Remote dest = `POST https://<host>/p5/msg` with pairing-key proof.
//! `P5_HOLD=1` then HOLDs on a definite miss. Loopback inbound reuses
//! [`receive_msg`]. Type `turn` is HTTP sendPrompt on the loopback gateway —
//! never a PTY.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use p5_core::{
    default_root, DeliveryMode, DeliveryStatus, Homes, MailItem, Mailbox, MailboxError, PeerType,
    PostalAddr, ReceiveRequest, Roster, SendRequest, StoreError, Trust, EXIT_GATED, MAX_BODY_BYTES,
};
use p5_crypto::KeyPair;
use p5_live::{LiveClient, LiveRequest, LiveResult};
use serde::{Deserialize, Serialize};

use crate::last_mile::{self, LastMile};
use crate::session_map::SessionMap;
use crate::turn::{self, TurnConfig, TurnLimiter};

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

pub const REASON_BAD_ADDRESS: &str = "bad_address";
pub const REASON_NO_AGENT: &str = "no_agent";
pub const REASON_NOT_CONNECTED: &str = "not_connected";
pub const REASON_DORMANT_NO_WAKE: &str = "dormant_no_wake";
pub const REASON_GATED: &str = "gated";
pub const REASON_TOO_LARGE: &str = "too_large";
pub const REASON_NO_IDENTITY: &str = "no_identity";
pub const REASON_ERROR: &str = "error";
pub const REASON_HOST_DOWN: &str = "host_down";
pub const REASON_RATE_LIMITED: &str = "rate_limited";
pub const REASON_QUOTA: &str = "quota";

/// CLI / test input for [`send_msg`].
#[derive(Debug, Clone)]
pub struct MsgRequest {
    pub to: String,
    pub body: String,
    pub no_wake: bool,
    /// Display From (K14). Not the pairing identity.
    pub from: Option<String>,
}

/// PRD §6 `--json` object. `success` matches exit 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgResponse {
    pub success: bool,
    pub id: Option<String>,
    pub to: Option<String>,
    pub status: Option<String>,
    pub target_session_id: Option<String>,
    pub attempts: u32,
    pub reason: Option<String>,
    pub hint: Option<String>,
    pub woke: bool,
    pub wake_ms: Option<u64>,
    pub already: bool,
}

impl MsgResponse {
    pub fn exit_code(&self) -> i32 {
        if self.success {
            return EXIT_OK;
        }
        match self.reason.as_deref() {
            Some(REASON_BAD_ADDRESS) | Some(REASON_TOO_LARGE) => EXIT_USAGE,
            Some(REASON_GATED) | Some(REASON_NOT_CONNECTED) | Some(REASON_QUOTA) => EXIT_GATED,
            _ => EXIT_ERROR,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("msg response is always valid JSON")
    }

    pub fn pretty_line(&self) -> String {
        let id = self.id.as_deref().unwrap_or("-");
        let status = self.status.as_deref().unwrap_or("failed");
        let to = self.to.as_deref().unwrap_or("-");
        match (self.reason.as_deref(), self.hint.as_deref()) {
            (Some(reason), Some(hint)) => format!("{id}  {status}  {to}  {reason}\n{hint}"),
            (Some(reason), None) => format!("{id}  {status}  {to}  {reason}"),
            (None, Some(hint)) => format!("{id}  {status}  {to}\n{hint}"),
            (None, None) => format!("{id}  {status}  {to}"),
        }
    }

    pub(crate) fn ok_status(
        id: String,
        to: &PostalAddr,
        status: DeliveryStatus,
        attempts: u32,
        target_session_id: Option<String>,
        already: bool,
    ) -> Self {
        Self {
            success: true,
            id: Some(id),
            to: Some(to.to_string()),
            status: Some(status.as_str().to_string()),
            target_session_id,
            attempts,
            reason: None,
            hint: None,
            woke: false,
            wake_ms: None,
            already,
        }
    }

    fn fail(
        id: Option<String>,
        to: Option<&PostalAddr>,
        status: Option<DeliveryStatus>,
        reason: &'static str,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            success: false,
            id,
            to: to.map(ToString::to_string),
            status: status.map(|s| s.as_str().to_string()),
            target_session_id: None,
            attempts: 0,
            reason: Some(reason.to_string()),
            hint: Some(hint.into()),
            woke: false,
            wake_ms: None,
            already: false,
        }
    }

    pub fn from_error(hint: impl Into<String>) -> Self {
        Self::fail(None, None, None, REASON_ERROR, hint)
    }
}

/// Disk + in-memory state for one `p5 msg` / receive.
#[derive(Debug, Clone)]
pub struct SmContext {
    pub mailbox: Mailbox,
    pub homes: Homes,
    pub roster: Roster,
    /// Shared with the resident agent when one is running; never clone-and-forget.
    pub sessions: Arc<Mutex<SessionMap>>,
    /// `P5_LOCAL_RECV=1` — treat dest as this box even without a HomeRow.
    pub local_recv: bool,
    /// Non-empty `P5_DEV_SECRET` — loopback inbound pairing skip.
    pub dev_secret: bool,
    /// Advertised type for **this** agent (`P5_TYP` / config.toml). K22.
    pub our_typ: Option<PeerType>,
    pub turn: TurnConfig,
    pub turn_limiter: Arc<Mutex<TurnLimiter>>,
    /// `P5_HOLD=1` — live send + hold PUT after a definite miss.
    pub hold: bool,
    pub plane_url: String,
    pub plane_token: Option<String>,
    /// Test / override base for live `POST /p5/msg`.
    pub live_url: Option<String>,
    pub live_timeout: Duration,
    /// Outbound live POST. Tests inject a short timeout / test CA.
    pub live: LiveClient,
    /// Override `https://<host>` (mock HTTPS peer). Production is [`PostalAddr::live_base_url`].
    pub live_base: Option<String>,
    /// Harness adapters after inbox fsync. Off in unit tests.
    pub last_mile: LastMile,
}

impl SmContext {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            mailbox: Mailbox::new(&root),
            homes: Homes::new(),
            roster: Roster::new(),
            sessions: Arc::new(Mutex::new(SessionMap::new())),
            local_recv: false,
            dev_secret: false,
            our_typ: None,
            turn: TurnConfig::loopback_default(),
            turn_limiter: Arc::new(Mutex::new(TurnLimiter::new())),
            hold: false,
            plane_url: p5_plane::DEFAULT_PLANE_URL.to_string(),
            plane_token: None,
            live_url: None,
            live_timeout: Duration::from_secs(5),
            live: LiveClient::new(),
            live_base: None,
            last_mile: LastMile::default(),
        }
    }

    pub fn load(root: impl Into<PathBuf>) -> Result<Self, SmError> {
        let mut ctx = Self::new(root);
        let root = ctx.mailbox.root();
        ctx.homes = Homes::load(root)?;
        ctx.roster = Roster::load(root)?;
        ctx.local_recv = env_flag("P5_LOCAL_RECV");
        ctx.dev_secret = env_is_set("P5_DEV_SECRET");
        ctx.our_typ = load_our_typ(root);
        ctx.turn = TurnConfig::from_env();
        ctx.hold = env_flag("P5_HOLD");
        if let Ok(cfg) = p5_plane::PlaneConfig::load(root) {
            ctx.plane_url = cfg.base_url;
            ctx.plane_token = cfg.token;
        }
        ctx.live_url = env_nonempty("P5_LIVE_URL");
        ctx.live_base = ctx.live_url.clone();
        ctx.last_mile.k2 = crate::k2::K2MsgClient::from_k2_home();
        Ok(ctx)
    }

    /// What we advertise on whoami / inbound branch. Never the sender's guess.
    pub fn our_declared_typ(&self) -> Option<PeerType> {
        if let Some(t) = self.our_typ {
            return Some(t);
        }
        self.homes.iter().next().map(|_| PeerType::Session)
    }

    pub fn load_default() -> Result<Self, SmError> {
        Self::load(default_root())
    }

    pub fn dest_is_local(&self, addr: &PostalAddr) -> bool {
        self.local_recv || self.homes.get(addr).is_some()
    }

    pub fn live_session(&self, addr: &PostalAddr) -> Option<crate::session_map::LiveSession> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(addr)
            .cloned()
    }
}

#[derive(Debug)]
pub enum SmError {
    Mailbox(MailboxError),
    Store(StoreError),
    BadAddress(String),
    NoIdentity,
}

impl SmError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Mailbox(err) => err.exit_code(),
            Self::BadAddress(_) => EXIT_USAGE,
            _ => EXIT_ERROR,
        }
    }
}

impl fmt::Display for SmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mailbox(err) => write!(f, "{err}"),
            Self::Store(err) => write!(f, "{err}"),
            Self::BadAddress(msg) => write!(f, "{msg}"),
            Self::NoIdentity => f.write_str(
                "no local identity; set P5_FROM or add a homes row (handle::sub.postal.bot)",
            ),
        }
    }
}

impl std::error::Error for SmError {}

impl From<MailboxError> for SmError {
    fn from(err: MailboxError) -> Self {
        Self::Mailbox(err)
    }
}

impl From<StoreError> for SmError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

/// Stamp used on live inject (P5-7a). Inbox covers keep the original body.
#[allow(dead_code)]
pub fn fabric_stamp(from: &PostalAddr, body: &str) -> String {
    format!("[from {from}] {body}")
}

/// Sender SM: parse → sent queued first → local receiver or live HTTPS.
pub fn send_msg(ctx: &SmContext, req: &MsgRequest) -> Result<MsgResponse, SmError> {
    let default_host = ctx
        .homes
        .iter()
        .next()
        .map(|(_, row)| row.enrolled_host.clone());
    let to = match PostalAddr::parse(&req.to, default_host.as_deref()) {
        Ok(addr) => addr,
        Err(err) => {
            return Ok(MsgResponse::fail(
                None,
                None,
                None,
                REASON_BAD_ADDRESS,
                err.to_string(),
            ));
        }
    };

    let from = match resolve_from(ctx, req.from.as_deref(), &to) {
        Ok(addr) => addr,
        Err(SmError::NoIdentity) => {
            return Ok(MsgResponse::fail(
                None,
                Some(&to),
                None,
                REASON_NO_IDENTITY,
                "set P5_FROM or add a homes row",
            ));
        }
        Err(SmError::BadAddress(msg)) => {
            return Ok(MsgResponse::fail(
                None,
                Some(&to),
                None,
                REASON_BAD_ADDRESS,
                msg,
            ));
        }
        Err(err) => return Err(err),
    };

    if crate::billing::enforce() {
        match crate::billing::collect(ctx.mailbox.root()) {
            Ok(report) if !crate::billing::allow_send(&report) => {
                return Ok(MsgResponse::fail(
                    None,
                    Some(&to),
                    None,
                    REASON_QUOTA,
                    crate::billing::quota_hint(&report),
                ));
            }
            _ => {}
        }
    }

    if req.body.len() as u64 > MAX_BODY_BYTES {
        return Ok(MsgResponse::fail(
            None,
            Some(&to),
            None,
            REASON_TOO_LARGE,
            format!(
                "message is {} bytes; v0 cap is {MAX_BODY_BYTES}",
                req.body.len()
            ),
        ));
    }

    let typ = declared_typ(ctx, &to);
    // Cover-only `p5 msg` is allowed when files are off.
    // Unknown typ is not declared session (K22). Mailbox still needs a
    // field; flush must call `declared_typ` again, never this snapshot.
    let item = match ctx.mailbox.enqueue(SendRequest {
        to: to.clone(),
        from: from.clone(),
        body: req.body.clone(),
        mode: DeliveryMode::Live,
        typ: typ.unwrap_or(PeerType::Session),
        files: Vec::new(),
        files_allowed: false,
        title: None,
    }) {
        Ok(item) => item,
        Err(MailboxError::TooLarge { size }) => {
            return Ok(MsgResponse::fail(
                None,
                Some(&to),
                None,
                REASON_TOO_LARGE,
                format!("message is {size} bytes; v0 cap is {MAX_BODY_BYTES}"),
            ));
        }
        Err(MailboxError::Gated) => {
            return Ok(MsgResponse::fail(
                None,
                Some(&to),
                None,
                REASON_GATED,
                "tools.files=off",
            ));
        }
        Err(MailboxError::Addr(err)) => {
            return Ok(MsgResponse::fail(
                None,
                Some(&to),
                None,
                REASON_BAD_ADDRESS,
                err.to_string(),
            ));
        }
        Err(err) => return Err(err.into()),
    };

    if !ctx.dest_is_local(&to) {
        if ctx.hold {
            return crate::hold::finish_remote(ctx, &item, &to, &from, &req.body);
        }
        return send_live(ctx, &item, &from, req, &to);
    }

    if typ != Some(PeerType::Session) && typ != Some(PeerType::Turn) {
        // Unknown is not session (K22).
        return Ok(MsgResponse::ok_status(
            item.id,
            &to,
            DeliveryStatus::Queued,
            item.attempts,
            None,
            false,
        ));
    }

    let inbound = Inbound {
        id: item.id.clone(),
        to: to.clone(),
        from,
        body: req.body.clone(),
        mode: DeliveryMode::Live,
        typ: typ.expect("session or turn"),
        files: Vec::new(),
        no_wake: req.no_wake,
    };

    match receive_msg(ctx, &inbound) {
        Ok(rx) => {
            let marked = ctx
                .mailbox
                .mark(&item.id, DeliveryStatus::Delivered, None)?;
            Ok(MsgResponse::ok_status(
                marked.id,
                &to,
                DeliveryStatus::Delivered,
                marked.attempts,
                rx.target_session_id,
                rx.already,
            ))
        }
        Err(ReceiveError::Permanent { reason, .. }) if is_retryable_receive(reason) => {
            // 503 host_down → later HOLD; 429 → retry live. Stay queued.
            Ok(MsgResponse::ok_status(
                item.id,
                &to,
                DeliveryStatus::Queued,
                item.attempts,
                None,
                false,
            ))
        }
        Err(ReceiveError::Permanent { reason, hint }) => {
            let marked = ctx.mailbox.mark(&item.id, DeliveryStatus::Failed, None)?;
            let mut resp = MsgResponse::fail(
                Some(marked.id),
                Some(&to),
                Some(DeliveryStatus::Failed),
                reason,
                hint,
            );
            resp.attempts = marked.attempts;
            Ok(resp)
        }
        Err(ReceiveError::Mailbox(MailboxError::Gated)) => {
            let marked = ctx.mailbox.mark(&item.id, DeliveryStatus::Failed, None)?;
            Ok(MsgResponse::fail(
                Some(marked.id),
                Some(&to),
                Some(DeliveryStatus::Failed),
                REASON_GATED,
                "tools.files=off",
            ))
        }
        Err(ReceiveError::Mailbox(err)) => Err(err.into()),
    }
}

/// Remote dest: pairing-key proof then POST. Without a local identity, do not dial.
fn send_live(
    ctx: &SmContext,
    item: &MailItem,
    from: &PostalAddr,
    req: &MsgRequest,
    to: &PostalAddr,
) -> Result<MsgResponse, SmError> {
    let Some(key) = load_identity(ctx.mailbox.root()) else {
        return Ok(MsgResponse::ok_status(
            item.id.clone(),
            to,
            DeliveryStatus::Queued,
            item.attempts,
            None,
            false,
        ));
    };
    let base = ctx.live_base.clone().unwrap_or_else(|| to.live_base_url());
    let result = ctx.live.send(
        &key,
        &LiveRequest {
            base_url: base,
            to: to.to_string(),
            from: from.to_string(),
            id: item.id.clone(),
            wake: !req.no_wake,
            mode: item.mode.as_str().to_string(),
            body: req.body.clone(),
        },
    );
    match result {
        LiveResult::Delivered { already } => {
            let marked = ctx
                .mailbox
                .mark(&item.id, DeliveryStatus::Delivered, None)?;
            Ok(MsgResponse::ok_status(
                marked.id,
                to,
                DeliveryStatus::Delivered,
                marked.attempts,
                None,
                already,
            ))
        }
        LiveResult::Queued { last_error, .. } => {
            let marked = ctx.mailbox.record_last_error(&item.id, &last_error)?;
            let mut resp = MsgResponse::ok_status(
                marked.id,
                to,
                DeliveryStatus::Queued,
                marked.attempts,
                None,
                false,
            );
            resp.hint = Some(friend_keep_hint(ctx, to, &last_error));
            Ok(resp)
        }
        LiveResult::Permanent { reason, hint } => {
            let marked = ctx.mailbox.mark(&item.id, DeliveryStatus::Failed, None)?;
            let mut resp = MsgResponse::fail(
                Some(marked.id),
                Some(to),
                Some(DeliveryStatus::Failed),
                reason,
                hint,
            );
            resp.attempts = marked.attempts;
            Ok(resp)
        }
    }
}

fn friend_keep_hint(ctx: &SmContext, to: &PostalAddr, last_error: &str) -> String {
    if ctx
        .roster
        .get(to)
        .is_some_and(|e| e.trust == Trust::Trusted)
    {
        return format!(
            "{to} is a friend but isn't reachable yet ({last_error}). Message kept. They just need Postal running (install + p5 login); you don't redo the invite."
        );
    }
    last_error.to_string()
}

fn load_identity(root: &std::path::Path) -> Option<KeyPair> {
    KeyPair::load(root).ok().flatten()
}

/// Inbound payload for the session receiver (local path; later `POST /p5/msg`).
#[derive(Debug, Clone)]
pub struct Inbound {
    pub id: String,
    pub to: PostalAddr,
    pub from: PostalAddr,
    pub body: String,
    pub mode: DeliveryMode,
    pub typ: PeerType,
    pub files: Vec<PathBuf>,
    pub no_wake: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveOutcome {
    pub already: bool,
    pub target_session_id: Option<String>,
}

#[derive(Debug)]
pub enum ReceiveError {
    Permanent { reason: &'static str, hint: String },
    Mailbox(MailboxError),
}

impl From<MailboxError> for ReceiveError {
    fn from(err: MailboxError) -> Self {
        Self::Mailbox(err)
    }
}

/// Inbound entry for the resident agent. Branch on **our** type (K22).
pub fn receive_msg(ctx: &SmContext, inbound: &Inbound) -> Result<ReceiveOutcome, ReceiveError> {
    if inbound_is_turn(ctx, inbound) {
        receive_turn(ctx, inbound)
    } else {
        receive_session(ctx, inbound)
    }
}

fn inbound_is_turn(ctx: &SmContext, inbound: &Inbound) -> bool {
    ctx.our_typ == Some(PeerType::Turn) || declared_typ(ctx, &inbound.to) == Some(PeerType::Turn)
}

pub fn is_retryable_receive(reason: &str) -> bool {
    reason == REASON_HOST_DOWN || reason == REASON_RATE_LIMITED
}

/// Session receiver SM. Attach leftover + real wake/spawn are not in this PR.
pub fn receive_session(ctx: &SmContext, inbound: &Inbound) -> Result<ReceiveOutcome, ReceiveError> {
    if !pairing_allowed(ctx, inbound) {
        return Err(permanent(
            REASON_NOT_CONNECTED,
            "send direction is not trusted",
        ));
    }

    // Auth → dedup id (K20) → gates. A retry of an already-fsynced id is
    // `{already: true}` even if --no-wake / files-off would refuse a first write.
    if inbox_has_id(ctx, &inbound.id)? {
        return Ok(ReceiveOutcome {
            already: true,
            target_session_id: session_id_hint(ctx, &inbound.to),
        });
    }

    let Some(home) = ctx.homes.get(&inbound.to) else {
        return Err(permanent(
            REASON_NO_AGENT,
            "no homes row for this address; p5 does not invent a bot",
        ));
    };

    if home.harness.is_none() && home.launch.is_empty() {
        return Err(permanent(
            REASON_NO_AGENT,
            "homes row has no harness; p5 does not invent a bot",
        ));
    }

    let live = ctx.live_session(&inbound.to);
    if live.is_none() {
        if inbound.no_wake {
            return Err(permanent(
                REASON_DORMANT_NO_WAKE,
                "session is dormant; omit --no-wake to write inbox",
            ));
        }
        if !home.tools.wake {
            return Err(permanent(REASON_GATED, "tools.wake=off"));
        }
    }

    if !inbound.files.is_empty() && !home.tools.files {
        return Err(permanent(REASON_GATED, "tools.files=off"));
    }

    ctx.mailbox.receive(ReceiveRequest {
        id: inbound.id.clone(),
        to: inbound.to.clone(),
        from: inbound.from.clone(),
        body: inbound.body.clone(),
        mode: inbound.mode,
        typ: inbound.typ,
        files: inbound.files.clone(),
        files_allowed: home.tools.files,
        title: None,
        hold_id: None,
    })?;

    if let Err(err) = last_mile::after_inbox_fsync(ctx, home, inbound) {
        eprintln!("p5: last-mile: {err}");
    }

    Ok(ReceiveOutcome {
        already: false,
        target_session_id: live
            .map(|s| s.session_id.clone())
            .or_else(|| home.session_id.clone()),
    })
}

/// Turn receiver SM. HOST UP = gateway `/health`. Then inbox, then sendPrompt.
///
/// No session map, no WAIT_READY, no PTY spawn. SendToAgent is not a public
/// HTTP verb — we only POST `/api/sendPrompt` on loopback. Health fail writes
/// nothing; a durable inbox id is required before sendPrompt so a persist
/// miss cannot double-bill.
pub fn receive_turn(ctx: &SmContext, inbound: &Inbound) -> Result<ReceiveOutcome, ReceiveError> {
    if !pairing_allowed(ctx, inbound) {
        return Err(permanent(
            REASON_NOT_CONNECTED,
            "send direction is not trusted",
        ));
    }

    if inbox_has_id(ctx, &inbound.id)? {
        return Ok(ReceiveOutcome {
            already: true,
            target_session_id: None,
        });
    }

    let Some(home) = ctx.homes.get(&inbound.to) else {
        return Err(permanent(
            REASON_NO_AGENT,
            "no homes row for this address; p5 does not invent a bot",
        ));
    };

    if !inbound.files.is_empty() && !home.tools.files {
        return Err(permanent(REASON_GATED, "tools.files=off"));
    }

    let files_allowed = home.tools.files;

    if turn::health_up(&ctx.turn).is_err() {
        return Err(permanent(
            REASON_HOST_DOWN,
            "turn gateway /health is down; sender should HOLD",
        ));
    }

    let reserved_at = Instant::now();
    {
        let mut lim = ctx.turn_limiter.lock().unwrap_or_else(|e| e.into_inner());
        if !lim.try_reserve(&inbound.from, reserved_at) {
            return Err(permanent(
                REASON_RATE_LIMITED,
                "12 turns / hour / sending peer",
            ));
        }
    }

    if let Err(err) = ctx.mailbox.receive(ReceiveRequest {
        id: inbound.id.clone(),
        to: inbound.to.clone(),
        from: inbound.from.clone(),
        body: inbound.body.clone(),
        mode: inbound.mode,
        typ: PeerType::Turn,
        files: inbound.files.clone(),
        files_allowed,
        title: None,
        hold_id: None,
    }) {
        release_turn_slot(ctx, &inbound.from, reserved_at);
        return Err(err.into());
    }

    if let Err(err) = last_mile::after_inbox_fsync(ctx, home, inbound) {
        release_turn_slot(ctx, &inbound.from, reserved_at);
        return Err(permanent(
            REASON_HOST_DOWN,
            format!("grok last-mile failed; sender should HOLD ({err})"),
        ));
    }

    Ok(ReceiveOutcome {
        already: false,
        target_session_id: None,
    })
}

fn release_turn_slot(ctx: &SmContext, from: &PostalAddr, at: Instant) {
    ctx.turn_limiter
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .release(from, at);
}

fn pairing_allowed(ctx: &SmContext, inbound: &Inbound) -> bool {
    // Local dest or loopback secret. Public inbound checks proof in http.rs.
    if ctx.dest_is_local(&inbound.to) || ctx.dev_secret {
        return true;
    }
    ctx.roster
        .get(&inbound.from)
        .is_some_and(|entry| entry.trust == Trust::Trusted)
}

/// Peer-declared type (K22). Roster wins for *peers*. A local HomeRow uses
/// **our** advertised type (`P5_TYP` / config), defaulting to Session.
/// `None` is unknown — do not guess.
pub fn declared_typ(ctx: &SmContext, to: &PostalAddr) -> Option<PeerType> {
    if let Some(entry) = ctx.roster.get(to) {
        return Some(entry.typ);
    }
    if ctx.homes.get(to).is_some() {
        return Some(ctx.our_typ.unwrap_or(PeerType::Session));
    }
    None
}

fn inbox_has_id(ctx: &SmContext, id: &str) -> Result<bool, ReceiveError> {
    match ctx.mailbox.read_inbox(id) {
        Ok(_) => Ok(true),
        Err(MailboxError::NotFound { .. }) => Ok(false),
        // InvalidId is a reject, not a miss — otherwise we sendPrompt then fail persist.
        Err(err) => Err(ReceiveError::Mailbox(err)),
    }
}

fn session_id_hint(ctx: &SmContext, to: &PostalAddr) -> Option<String> {
    ctx.live_session(to)
        .map(|s| s.session_id)
        .or_else(|| ctx.homes.get(to).and_then(|h| h.session_id.clone()))
}

fn resolve_from(
    ctx: &SmContext,
    display: Option<&str>,
    to: &PostalAddr,
) -> Result<PostalAddr, SmError> {
    if let Some(raw) = display.map(str::trim).filter(|s| !s.is_empty()) {
        return parse_from(raw, ctx);
    }
    if let Some(raw) = std::env::var("P5_FROM")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return parse_from(&raw, ctx);
    }
    if let Some((addr, _)) = ctx.homes.iter().next() {
        return Ok(addr.clone());
    }
    if ctx.dest_is_local(to) {
        return Ok(to.clone());
    }
    Err(SmError::NoIdentity)
}

fn parse_from(raw: &str, ctx: &SmContext) -> Result<PostalAddr, SmError> {
    let default_host = ctx
        .homes
        .iter()
        .next()
        .map(|(_, row)| row.enrolled_host.clone());
    PostalAddr::parse(raw, default_host.as_deref())
        .map_err(|err| SmError::BadAddress(err.to_string()))
}

fn permanent(reason: &'static str, hint: impl Into<String>) -> ReceiveError {
    ReceiveError::Permanent {
        reason,
        hint: hint.into(),
    }
}

pub(crate) fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

fn env_is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

fn load_our_typ(root: &Path) -> Option<PeerType> {
    if let Some(t) = parse_typ_env("P5_TYP") {
        return Some(t);
    }
    if let Ok(cfg) = p5_plane::PlaneConfig::load(root) {
        if let Some(raw) = cfg.typ.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(t) = raw.parse() {
                return Some(t);
            }
        }
    }
    parse_typ_config(&root.join("config.toml"))
}

fn parse_typ_env(name: &str) -> Option<PeerType> {
    env_nonempty(name).and_then(|s| s.parse().ok())
}

fn parse_typ_config(path: &Path) -> Option<PeerType> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `type=` first so it is not eaten by `typ`.
        let rest = line
            .strip_prefix("type")
            .or_else(|| line.strip_prefix("typ"))?;
        let rest = rest.trim().strip_prefix('=')?.trim();
        let val = rest.trim_matches('"').trim_matches('\'').trim();
        if let Ok(t) = val.parse::<PeerType>() {
            return Some(t);
        }
    }
    None
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// True when `root` has no live-map file (the map is process-only).
#[cfg(test)]
fn session_map_not_on_disk(root: &std::path::Path) -> bool {
    !root.join("session_map").exists() && !root.join("session_map.json").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    use p5_core::{HomeRow, RosterEntry, ToolFlags};

    use crate::session_map::LiveSession;

    fn addr(s: &str) -> PostalAddr {
        s.parse().unwrap()
    }

    fn home(address: &str, wake: bool, harness: bool) -> HomeRow {
        let address = addr(address);
        let host = address.host().to_string();
        HomeRow {
            address,
            session_id: Some("sess-1".into()),
            cwd: PathBuf::from("/srv/scout"),
            inbox_root: None,
            launch: if harness {
                vec!["claude".into()]
            } else {
                Vec::new()
            },
            harness: if harness { Some("claude".into()) } else { None },
            tools: ToolFlags {
                files: false,
                live_inject: true,
                wake,
            },
            enrolled_host: host,
        }
    }

    fn ctx_with_home(root: &Path, wake: bool) -> SmContext {
        let mut ctx = SmContext::new(root);
        ctx.homes
            .insert(home("scout::acme.postal.bot", wake, true))
            .unwrap();
        ctx
    }

    fn msg(to: &str, body: &str) -> MsgRequest {
        MsgRequest {
            to: to.into(),
            body: body.into(),
            no_wake: false,
            from: Some("alice::acme.postal.bot".into()),
        }
    }

    #[test]
    fn local_home_writes_inbox_and_marks_delivered() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_home(tmp.path(), true);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "hello scout")).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("delivered"));
        assert_eq!(resp.reason, None);
        let id = resp.id.as_deref().unwrap();
        assert_eq!(
            ctx.mailbox.read_sent(id).unwrap().status,
            DeliveryStatus::Delivered
        );
        assert!(ctx.mailbox.list_outbox().unwrap().is_empty());
        let inbox = ctx.mailbox.read_inbox(id).unwrap();
        assert_eq!(inbox.body, "hello scout");
        assert_eq!(inbox.from, addr("alice::acme.postal.bot"));
        assert!(session_map_not_on_disk(tmp.path()));
    }

    #[test]
    fn remote_stays_queued() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = SmContext::new(tmp.path());
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "hold please")).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("queued"));
        assert_eq!(resp.exit_code(), EXIT_OK);
        let id = resp.id.as_deref().unwrap();
        assert_eq!(
            ctx.mailbox.read_sent(id).unwrap().status,
            DeliveryStatus::Queued
        );
        assert_eq!(ctx.mailbox.list_outbox().unwrap().len(), 1);
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
        assert!(ctx.mailbox.read_sent(id).unwrap().last_error.is_none());
    }

    #[test]
    fn remote_without_identity_does_not_dial() {
        let tmp = tempfile::tempdir().unwrap();
        let peer =
            p5_live::mock::HttpsPeer::spawn(200, r#"{"already":false,"status":"delivered"}"#);
        let mut ctx = SmContext::new(tmp.path());
        ctx.live_base = Some(peer.base_url.clone());
        ctx.live =
            LiveClient::with_root_der(std::time::Duration::from_secs(2), &peer.cert_der).unwrap();
        let resp = send_msg(&ctx, &remote_peer_msg()).unwrap();
        assert_eq!(resp.status.as_deref(), Some("queued"));
        assert!(peer.recorded().is_empty());
        assert!(ctx
            .mailbox
            .read_sent(resp.id.as_deref().unwrap())
            .unwrap()
            .last_error
            .is_none());
    }

    fn remote_peer_msg() -> MsgRequest {
        msg("scout::peer.postal.bot", "hello scout")
    }

    fn live_ctx_https(root: &Path, peer: &p5_live::mock::HttpsPeer) -> SmContext {
        KeyPair::load_or_create(root).unwrap();
        let mut ctx = SmContext::new(root);
        ctx.live_base = Some(peer.base_url.clone());
        ctx.live =
            LiveClient::with_root_der(std::time::Duration::from_secs(2), &peer.cert_der).unwrap();
        ctx
    }

    #[test]
    fn live_https_2xx_marks_delivered_and_sends_proof() {
        let tmp = tempfile::tempdir().unwrap();
        let peer = p5_live::mock::HttpsPeer::spawn(
            200,
            r#"{"already":false,"status":"delivered","typ":"session"}"#,
        );
        let ctx = live_ctx_https(tmp.path(), &peer);
        let resp = send_msg(&ctx, &remote_peer_msg()).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("delivered"));
        let id = resp.id.as_deref().unwrap();
        let sent = ctx.mailbox.read_sent(id).unwrap();
        assert_eq!(sent.status, DeliveryStatus::Delivered);
        assert!(sent.last_error.is_none());
        assert!(ctx.mailbox.list_outbox().unwrap().is_empty());
        let rec = peer.recorded();
        assert_eq!(rec.len(), 1);
        let proof = rec[0].header(p5_live::PROOF_HEADER).expect("proof header");
        assert_eq!(proof.len(), 128);
        assert_eq!(rec[0].header(p5_live::IDEMPOTENCY_HEADER), Some(id));
    }

    #[test]
    fn live_timeout_stays_queued() {
        let tmp = tempfile::tempdir().unwrap();
        KeyPair::load_or_create(tmp.path()).unwrap();
        let mut ctx = SmContext::new(tmp.path());
        ctx.live_base = Some(p5_live::spawn_hang());
        ctx.live = LiveClient::with_timeout(std::time::Duration::from_millis(250));
        let resp = send_msg(&ctx, &remote_peer_msg()).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("queued"));
        let id = resp.id.as_deref().unwrap();
        let sent = ctx.mailbox.read_sent(id).unwrap();
        assert_eq!(sent.status, DeliveryStatus::Queued);
        assert!(sent.hold_id.is_none());
        assert!(
            sent.last_error.as_deref() == Some("timeout")
                || sent.last_error.as_deref() == Some("no_status"),
            "{:?}",
            sent.last_error
        );
        assert_eq!(ctx.mailbox.list_outbox().unwrap().len(), 1);
    }

    #[test]
    fn live_401_unauthorized_stays_queued() {
        let tmp = tempfile::tempdir().unwrap();
        let peer = p5_live::mock::HttpsPeer::spawn(401, r#"{"error":"unauthorized"}"#);
        let ctx = live_ctx_https(tmp.path(), &peer);
        let resp = send_msg(&ctx, &remote_peer_msg()).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("queued"));
        let id = resp.id.as_deref().unwrap();
        let sent = ctx.mailbox.read_sent(id).unwrap();
        assert_eq!(sent.status, DeliveryStatus::Queued);
        assert_eq!(sent.last_error.as_deref(), Some("401"));
        assert!(sent.hold_id.is_none());
    }

    #[test]
    fn live_401_not_connected_is_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let peer = p5_live::mock::HttpsPeer::spawn(
            401,
            r#"{"error":"not_connected","reason":"not_connected"}"#,
        );
        let ctx = live_ctx_https(tmp.path(), &peer);
        let resp = send_msg(&ctx, &remote_peer_msg()).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.reason.as_deref(), Some(REASON_NOT_CONNECTED));
        assert_eq!(resp.status.as_deref(), Some("failed"));
        let id = resp.id.as_deref().unwrap();
        assert_eq!(
            ctx.mailbox.read_sent(id).unwrap().status,
            DeliveryStatus::Failed
        );
    }

    #[test]
    fn live_503_queued_not_held() {
        let tmp = tempfile::tempdir().unwrap();
        let peer = p5_live::mock::HttpsPeer::spawn(503, r#"{"error":"host_down"}"#);
        let ctx = live_ctx_https(tmp.path(), &peer);
        let resp = send_msg(&ctx, &remote_peer_msg()).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("queued"));
        let id = resp.id.as_deref().unwrap();
        let sent = ctx.mailbox.read_sent(id).unwrap();
        assert_eq!(sent.status, DeliveryStatus::Queued);
        assert_eq!(sent.last_error.as_deref(), Some("host_down"));
        assert!(sent.hold_id.is_none());
        assert_eq!(ctx.mailbox.list_outbox().unwrap().len(), 1);
    }

    fn roster_entry(typ: PeerType) -> RosterEntry {
        RosterEntry {
            typ,
            fingerprint: "fp".into(),
            public_key_pem: "pem".into(),
            trust: Trust::Trusted,
            pair_id: "p1".into(),
            sand_uuid: None,
            tools: ToolFlags::default(),
        }
    }

    #[test]
    fn local_recv_without_declared_typ_stays_queued() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = SmContext::new(tmp.path());
        ctx.local_recv = true;
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "anyone home")).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("queued"));
        assert_eq!(resp.exit_code(), EXIT_OK);
        let id = resp.id.as_deref().unwrap();
        assert_eq!(
            ctx.mailbox.read_sent(id).unwrap().status,
            DeliveryStatus::Queued
        );
        assert_eq!(ctx.mailbox.list_outbox().unwrap().len(), 1);
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
    }

    #[test]
    fn local_recv_declared_session_without_home_is_no_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = SmContext::new(tmp.path());
        ctx.local_recv = true;
        ctx.roster.insert(
            addr("scout::acme.postal.bot"),
            roster_entry(PeerType::Session),
        );
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "anyone home")).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.reason.as_deref(), Some(REASON_NO_AGENT));
        assert_eq!(resp.status.as_deref(), Some("failed"));
        assert_eq!(resp.exit_code(), EXIT_ERROR);
        let id = resp.id.as_deref().unwrap();
        assert_eq!(
            ctx.mailbox.read_sent(id).unwrap().status,
            DeliveryStatus::Failed
        );
        assert!(ctx.mailbox.list_outbox().unwrap().is_empty());
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
    }

    #[test]
    fn no_harness_is_no_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = SmContext::new(tmp.path());
        ctx.homes
            .insert(home("scout::acme.postal.bot", true, false))
            .unwrap();
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "ghost")).unwrap();
        assert_eq!(resp.reason.as_deref(), Some(REASON_NO_AGENT));
        assert!(!resp.success);
    }

    #[test]
    fn no_wake_without_live_is_dormant() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_home(tmp.path(), true);
        let mut req = msg("scout::acme.postal.bot", "shh");
        req.no_wake = true;
        let resp = send_msg(&ctx, &req).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.reason.as_deref(), Some(REASON_DORMANT_NO_WAKE));
        assert_eq!(resp.exit_code(), EXIT_ERROR);
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
        let id = resp.id.as_deref().unwrap();
        assert_eq!(
            ctx.mailbox.read_sent(id).unwrap().status,
            DeliveryStatus::Failed
        );
    }

    #[test]
    fn live_session_delivers_even_with_no_wake() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_home(tmp.path(), true);
        ctx.sessions.lock().unwrap().insert(
            addr("scout::acme.postal.bot"),
            LiveSession {
                session_id: "live-9".into(),
                ready: true,
            },
        );
        let mut req = msg("scout::acme.postal.bot", "knock");
        req.no_wake = true;
        let resp = send_msg(&ctx, &req).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("delivered"));
        assert_eq!(resp.target_session_id.as_deref(), Some("live-9"));
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
    }

    #[test]
    fn wake_off_without_live_is_gated() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_home(tmp.path(), false);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "wake me")).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.reason.as_deref(), Some(REASON_GATED));
        assert_eq!(resp.exit_code(), EXIT_GATED);
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
    }

    #[test]
    fn receive_files_off_is_gated() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_home(tmp.path(), true);
        let src = tmp.path().join("note.bin");
        fs::write(&src, b"abc").unwrap();
        let inbound = Inbound {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            to: addr("scout::acme.postal.bot"),
            from: addr("alice::acme.postal.bot"),
            body: "with file".into(),
            mode: DeliveryMode::Tray,
            typ: PeerType::Session,
            files: vec![src],
            no_wake: false,
        };
        match receive_session(&ctx, &inbound) {
            Err(ReceiveError::Permanent { reason, .. }) => assert_eq!(reason, REASON_GATED),
            other => panic!("expected gated, got {other:?}"),
        }
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
    }

    #[test]
    fn bad_address_has_no_sent_row() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = SmContext::new(tmp.path());
        let resp = send_msg(&ctx, &msg("scout@acme.postal.bot", "nope")).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.reason.as_deref(), Some(REASON_BAD_ADDRESS));
        assert_eq!(resp.exit_code(), EXIT_USAGE);
        assert!(ctx.mailbox.list_sent().unwrap().is_empty());
    }

    #[test]
    fn too_large_has_no_sent_row() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_home(tmp.path(), true);
        let body = "x".repeat(MAX_BODY_BYTES as usize + 1);
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", &body)).unwrap();
        assert_eq!(resp.reason.as_deref(), Some(REASON_TOO_LARGE));
        assert_eq!(resp.exit_code(), EXIT_USAGE);
        assert!(ctx.mailbox.list_sent().unwrap().is_empty());
    }

    #[test]
    fn turn_peer_host_down_stays_queued() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_home(tmp.path(), true);
        ctx.roster
            .insert(addr("scout::acme.postal.bot"), roster_entry(PeerType::Turn));
        ctx.turn.health_url = "http://127.0.0.1:1/health".into();
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "turn later")).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("queued"));
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
    }

    #[test]
    fn fabric_stamp_is_p5_not_k2g() {
        let text = fabric_stamp(&addr("alice::acme.postal.bot"), "ship it");
        assert_eq!(text, "[from alice::acme.postal.bot] ship it");
        assert!(!text.contains("k2g"));
        assert!(!text.contains("[p5]"));
    }

    #[test]
    fn config_toml_typ_turn_is_our_typ() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("config.toml"), "typ = \"turn\"\naddr = \"grok::acme.postal.bot\"\n")
            .unwrap();
        let ctx = SmContext::load(tmp.path()).unwrap();
        assert_eq!(ctx.our_typ, Some(PeerType::Turn));
    }

    fn k2_inbound(body: &str) -> Inbound {
        Inbound {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            to: addr("scout::acme.postal.bot"),
            from: addr("alice::acme.postal.bot"),
            body: body.into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Session,
            files: Vec::new(),
            no_wake: false,
        }
    }

    #[test]
    fn k2_harness_knocks_after_inbox_fsync() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_home(tmp.path(), true);
        let mut row = ctx
            .homes
            .get(&addr("scout::acme.postal.bot"))
            .unwrap()
            .clone();
        row.harness = Some("k2".into());
        ctx.homes.insert(row).unwrap();
        ctx.last_mile.k2 = crate::k2::K2MsgClient::capture();
        let inbound = k2_inbound("hello scout");
        let rx = receive_session(&ctx, &inbound).unwrap();
        assert!(!rx.already);
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
        let knocks = ctx.last_mile.k2.recorded();
        assert_eq!(knocks.len(), 1);
        assert_eq!(knocks[0].workspace, "/srv/scout");
        assert_eq!(knocks[0].from, "alice::acme.postal.bot");
        assert!(knocks[0].wake);
        assert_eq!(knocks[0].text, "hello scout");
        assert!(!knocks[0].text.contains("p5 inbox"));
        assert!(!knocks[0].text.contains("[p5:"));
        assert_eq!(knocks[0].project, "/srv/scout");
    }

    #[test]
    fn other_harness_does_not_call_k2() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_home(tmp.path(), true);
        ctx.last_mile.k2 = crate::k2::K2MsgClient::capture();
        receive_session(&ctx, &k2_inbound("hello")).unwrap();
        assert!(ctx.last_mile.k2.recorded().is_empty());
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
    }

    #[test]
    fn live_inject_off_skips_k2_knock() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = SmContext::new(tmp.path());
        let mut row = home("scout::acme.postal.bot", true, true);
        row.harness = Some("k2".into());
        row.tools.live_inject = false;
        ctx.homes.insert(row).unwrap();
        ctx.last_mile.k2 = crate::k2::K2MsgClient::capture();
        receive_session(&ctx, &k2_inbound("hello")).unwrap();
        assert!(ctx.last_mile.k2.recorded().is_empty());
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
    }

    #[test]
    fn json_schema_has_prd_fields() {
        let resp = MsgResponse::ok_status(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            &addr("scout::acme.postal.bot"),
            DeliveryStatus::Delivered,
            0,
            None,
            false,
        );
        let v: serde_json::Value = serde_json::from_str(&resp.to_json()).unwrap();
        for key in [
            "success",
            "id",
            "to",
            "status",
            "target_session_id",
            "attempts",
            "reason",
            "hint",
            "woke",
            "wake_ms",
            "already",
        ] {
            assert!(v.get(key).is_some(), "missing {key}");
        }
        assert_eq!(v["success"], true);
        assert_eq!(v["status"], "delivered");
    }

    #[test]
    fn receive_dedupes_id() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_home(tmp.path(), true);
        let inbound = Inbound {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            to: addr("scout::acme.postal.bot"),
            from: addr("alice::acme.postal.bot"),
            body: "first".into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Session,
            files: Vec::new(),
            no_wake: false,
        };
        let first = receive_session(&ctx, &inbound).unwrap();
        assert!(!first.already);
        let mut again = inbound.clone();
        again.body = "second".into();
        let second = receive_session(&ctx, &again).unwrap();
        assert!(second.already);
        assert_eq!(ctx.mailbox.read_inbox(&inbound.id).unwrap().body, "first");

        let mut no_wake = inbound.clone();
        no_wake.no_wake = true;
        let retry_dormant = receive_session(&ctx, &no_wake).unwrap();
        assert!(retry_dormant.already);

        let src = tmp.path().join("note.bin");
        fs::write(&src, b"abc").unwrap();
        let mut with_file = inbound.clone();
        with_file.files = vec![src];
        let retry_files = receive_session(&ctx, &with_file).unwrap();
        assert!(retry_files.already);
        assert_eq!(ctx.mailbox.read_inbox(&inbound.id).unwrap().body, "first");
    }

    #[test]
    fn declared_typ_does_not_guess_session() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = SmContext::new(tmp.path());
        let scout = addr("scout::acme.postal.bot");
        assert_eq!(declared_typ(&ctx, &scout), None);
        ctx.homes
            .insert(home("scout::acme.postal.bot", true, true))
            .unwrap();
        assert_eq!(declared_typ(&ctx, &scout), Some(PeerType::Session));
        ctx.roster
            .insert(scout.clone(), roster_entry(PeerType::Turn));
        assert_eq!(declared_typ(&ctx, &scout), Some(PeerType::Turn));
    }

    fn turn_inbound(id: &str, from: &str, body: &str) -> Inbound {
        Inbound {
            id: id.into(),
            to: addr("scout::acme.postal.bot"),
            from: addr(from),
            body: body.into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Turn,
            files: Vec::new(),
            no_wake: false,
        }
    }

    fn ctx_turn(root: &Path, sand: &crate::turn::MockSand) -> SmContext {
        let mut ctx = ctx_with_home(root, true);
        ctx.our_typ = Some(PeerType::Turn);
        ctx.turn = sand.config();
        ctx
    }

    #[test]
    fn turn_health_up_sendprompt_writes_inbox() {
        let tmp = tempfile::tempdir().unwrap();
        let sand = crate::turn::MockSand::spawn(200, 200);
        let ctx = ctx_turn(tmp.path(), &sand);
        let inbound = turn_inbound("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice::acme.postal.bot", "hi");
        let rx = receive_msg(&ctx, &inbound).unwrap();
        assert!(!rx.already);
        assert_eq!(rx.target_session_id, None);
        let item = ctx.mailbox.read_inbox(&inbound.id).unwrap();
        assert_eq!(item.body, "hi");
        assert_eq!(item.typ, PeerType::Turn);
        let prompts = sand.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(
            prompts[0]["prompt"],
            "[from alice::acme.postal.bot] hi"
        );
        assert!(!prompts[0]["prompt"].as_str().unwrap().contains("k2g"));
        assert_eq!(prompts[0]["agentId"], "sand-1");
        assert_eq!(prompts[0]["clientNonce"], inbound.id);
        assert!(session_map_not_on_disk(tmp.path()));
    }

    #[test]
    fn turn_health_fail_is_host_down_no_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let sand = crate::turn::MockSand::spawn(503, 200);
        let ctx = ctx_turn(tmp.path(), &sand);
        let inbound = turn_inbound("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice::acme.postal.bot", "hi");
        match receive_msg(&ctx, &inbound) {
            Err(ReceiveError::Permanent { reason, .. }) => assert_eq!(reason, REASON_HOST_DOWN),
            other => panic!("expected host_down, got {other:?}"),
        }
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
        assert!(sand.prompts.lock().unwrap().is_empty());
    }

    #[test]
    fn turn_rate_limit_is_12_per_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let sand = crate::turn::MockSand::spawn(200, 200);
        let ctx = ctx_turn(tmp.path(), &sand);
        for i in 0..12u32 {
            let id = format!("01ARZ3NDEKTSV4RRFFQ69G5F{i:02}");
            receive_msg(&ctx, &turn_inbound(&id, "alice::acme.postal.bot", "n")).unwrap();
        }
        let over = turn_inbound(
            "01ARZ3NDEKTSV4RRFFQ69G5F99",
            "alice::acme.postal.bot",
            "too many",
        );
        match receive_msg(&ctx, &over) {
            Err(ReceiveError::Permanent { reason, .. }) => assert_eq!(reason, REASON_RATE_LIMITED),
            other => panic!("expected rate_limited, got {other:?}"),
        }
        assert!(ctx.mailbox.read_inbox(&over.id).is_err());
        let other = turn_inbound(
            "01ARZ3NDEKTSV4RRFFQ69G5F98",
            "bob::other.postal.bot",
            "other peer",
        );
        assert!(!receive_msg(&ctx, &other).unwrap().already);
        assert_eq!(sand.prompts.lock().unwrap().len(), 13);
    }

    #[test]
    fn turn_dedupes_without_second_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let sand = crate::turn::MockSand::spawn(200, 200);
        let ctx = ctx_turn(tmp.path(), &sand);
        let inbound = turn_inbound(
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "alice::acme.postal.bot",
            "first",
        );
        assert!(!receive_msg(&ctx, &inbound).unwrap().already);
        let mut again = inbound.clone();
        again.body = "second".into();
        let second = receive_msg(&ctx, &again).unwrap();
        assert!(second.already);
        assert_eq!(ctx.mailbox.read_inbox(&inbound.id).unwrap().body, "first");
        assert_eq!(sand.prompts.lock().unwrap().len(), 1);
    }

    #[test]
    fn turn_invalid_id_does_not_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let sand = crate::turn::MockSand::spawn(200, 200);
        let ctx = ctx_turn(tmp.path(), &sand);
        let inbound = turn_inbound("not-a-ulid", "alice::acme.postal.bot", "nope");
        match receive_msg(&ctx, &inbound) {
            Err(ReceiveError::Mailbox(MailboxError::InvalidId)) => {}
            other => panic!("expected InvalidId, got {other:?}"),
        }
        assert!(ctx.mailbox.list_inbox(None, None).unwrap().is_empty());
        assert!(sand.prompts.lock().unwrap().is_empty());
    }

    #[test]
    fn turn_prompt_fail_after_inbox_does_not_reprompt() {
        let tmp = tempfile::tempdir().unwrap();
        let sand = crate::turn::MockSand::spawn(200, 500);
        let ctx = ctx_turn(tmp.path(), &sand);
        let inbound = turn_inbound("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice::acme.postal.bot", "hi");
        match receive_msg(&ctx, &inbound) {
            Err(ReceiveError::Permanent { reason, .. }) => assert_eq!(reason, REASON_HOST_DOWN),
            other => panic!("expected host_down, got {other:?}"),
        }
        assert_eq!(ctx.mailbox.read_inbox(&inbound.id).unwrap().body, "hi");
        assert_eq!(sand.prompts.lock().unwrap().len(), 1);
        let retry = receive_msg(&ctx, &inbound).unwrap();
        assert!(retry.already);
        assert_eq!(sand.prompts.lock().unwrap().len(), 1);
    }

    #[test]
    fn turn_does_not_require_harness_or_session_map() {
        let tmp = tempfile::tempdir().unwrap();
        let sand = crate::turn::MockSand::spawn(200, 200);
        let mut ctx = SmContext::new(tmp.path());
        ctx.homes
            .insert(home("scout::acme.postal.bot", true, false))
            .unwrap();
        ctx.our_typ = Some(PeerType::Turn);
        ctx.turn = sand.config();
        let inbound = turn_inbound("01ARZ3NDEKTSV4RRFFQ69G5FAV", "alice::acme.postal.bot", "ok");
        receive_msg(&ctx, &inbound).unwrap();
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
        assert!(ctx.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn our_typ_from_config_toml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("config.toml"), "type = \"turn\"\n").unwrap();
        let ctx = SmContext::load(tmp.path()).unwrap();
        assert_eq!(ctx.our_typ, Some(PeerType::Turn));
        assert_eq!(ctx.our_declared_typ(), Some(PeerType::Turn));
    }

    #[test]
    fn turn_send_msg_delivers_when_gateway_up() {
        let tmp = tempfile::tempdir().unwrap();
        let sand = crate::turn::MockSand::spawn(200, 200);
        let mut ctx = ctx_with_home(tmp.path(), true);
        ctx.our_typ = Some(PeerType::Turn);
        ctx.turn = sand.config();
        let resp = send_msg(&ctx, &msg("scout::acme.postal.bot", "ping")).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status.as_deref(), Some("delivered"));
        assert_eq!(ctx.mailbox.list_inbox(None, None).unwrap().len(), 1);
        assert_eq!(sand.prompts.lock().unwrap().len(), 1);
    }
}
