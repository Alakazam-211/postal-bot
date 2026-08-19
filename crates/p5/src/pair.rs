//! Pairing UX against the CP-3 plane.
//!
//! `add` may request. `accept` / `reject` / `revoke` stay owner-gated
//! unless `P5_OWNER_PAIR=1`. Private keys never leave this process.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use p5_core::{
    default_root, Homes, PeerType, PostalAddr, Roster, StoreError, Trust, TypeParseError,
    EXIT_GATED,
};
use p5_crypto::{fingerprint_spki_pem, sas_code, KeyPair};
use p5_plane::{PairLists, PairView, PlaneClient, PlaneConfig, PlaneError, DASHBOARD_PAIR};

use crate::sm::{EXIT_ERROR, EXIT_USAGE};

pub const REASON_GATED: &str = "gated";

pub struct PairCtx {
    root: PathBuf,
    cfg: PlaneConfig,
    homes: Homes,
}

impl PairCtx {
    pub fn load() -> Result<Self, PairError> {
        let root = default_root();
        let cfg = PlaneConfig::load(&root)?;
        let homes = Homes::load(&root)?;
        Ok(Self { root, cfg, homes })
    }

    fn client(&self) -> Result<PlaneClient, PairError> {
        Ok(PlaneClient::new(
            &self.cfg.base_url,
            self.cfg.require_token()?,
        ))
    }

    fn keys(&self) -> Result<KeyPair, PairError> {
        Ok(KeyPair::load_or_create(&self.root)?)
    }

    fn public_pem(&self) -> Result<String, PairError> {
        let pem = self.keys()?.public_key_pem();
        if pem.contains("PRIVATE") {
            return Err(PairError::PrivateKey);
        }
        Ok(pem)
    }

    fn resolve_from(&self, from_flag: Option<&str>) -> Result<PostalAddr, PairError> {
        if let Some(raw) = from_flag.map(str::trim).filter(|s| !s.is_empty()) {
            return parse_addr(raw, self.default_host());
        }
        if let Some(raw) = self.cfg.addr.as_deref() {
            return parse_addr(raw, self.default_host());
        }
        if let Some((addr, _)) = self.homes.iter().next() {
            return Ok(addr.clone());
        }
        Err(PairError::NoIdentity)
    }

    fn resolve_typ(&self, typ_flag: Option<&str>) -> Result<PeerType, PairError> {
        if let Some(raw) = typ_flag.map(str::trim).filter(|s| !s.is_empty()) {
            return parse_typ(raw);
        }
        if let Some(raw) = self.cfg.typ.as_deref() {
            return parse_typ(raw);
        }
        Ok(PeerType::Session)
    }

    fn default_host(&self) -> Option<&str> {
        self.homes
            .iter()
            .next()
            .map(|(_, row)| row.enrolled_host.as_str())
    }

    fn configured_addrs(&self, from_flag: Option<&str>) -> Vec<PostalAddr> {
        let mut out = BTreeSet::new();
        if let Ok(a) = self.resolve_from(from_flag) {
            out.insert(a);
        }
        for (addr, _) in self.homes.iter() {
            out.insert(addr.clone());
        }
        out.into_iter().collect()
    }
}

pub fn run_login(token: String) -> Result<(), PairError> {
    let mut ctx = PairCtx::load()?;
    ctx.cfg.file.connect_token = Some(token.clone());
    ctx.cfg.file.save(&ctx.root)?;
    ctx.cfg.token = Some(token);
    if ctx.cfg.require_token().is_ok() {
        publish_handles(&ctx, None, None)?;
    }
    println!("ok");
    Ok(())
}

pub fn run_me(from: Option<String>, typ: Option<String>) -> Result<(), PairError> {
    let ctx = PairCtx::load()?;
    let published = publish_handles(&ctx, from.as_deref(), typ.as_deref())?;
    if published.is_empty() {
        return Err(PairError::NoIdentity);
    }
    for (addr, fp) in published {
        println!("{addr}");
        println!("fingerprint  {fp}");
    }
    Ok(())
}

pub fn run_add(addr: String, from: Option<String>, typ: Option<String>) -> Result<(), PairError> {
    let ctx = PairCtx::load()?;
    let to = parse_addr(&addr, ctx.default_host())?;
    let from_addr = ctx.resolve_from(from.as_deref())?;
    let typ = ctx.resolve_typ(typ.as_deref())?;
    let pem = ctx.public_pem()?;
    let client = ctx.client()?;
    let _me = client.put_me(&from_addr.to_string(), &pem, typ)?;
    let add = client.add_pair(&from_addr.to_string(), &to.to_string(), typ, &pem)?;
    if let Ok(lists) = client.list_pairs(false) {
        let _ = sync_roster(&ctx.root, &lists, &ctx.configured_addrs(from.as_deref()));
    }
    print_add(&add.id, &from_addr, &to, add.sas.as_deref(), add.created);
    Ok(())
}

pub fn run_list(inbox_only: bool) -> Result<(), PairError> {
    let ctx = PairCtx::load()?;
    let lists = ctx.client()?.list_pairs(inbox_only)?;
    let _ = sync_roster(&ctx.root, &lists, &ctx.configured_addrs(None));
    if inbox_only {
        print_views(&lists.inbox);
        return Ok(());
    }
    print_section("inbox", &lists.inbox);
    print_section("sent", &lists.sent);
    print_section("friends", &lists.friends);
    Ok(())
}

pub fn run_show(id: String) -> Result<(), PairError> {
    let ctx = PairCtx::load()?;
    let lists = ctx.client()?.list_pairs(false)?;
    let _ = sync_roster(&ctx.root, &lists, &ctx.configured_addrs(None));
    let view = lists.find(&id).ok_or(PairError::NotFound(id.clone()))?;
    print_show(&ctx, view)?;
    Ok(())
}

pub fn run_accept(id: String, sas: Option<String>) -> Result<(), PairError> {
    require_owner_pair()?;
    let ctx = PairCtx::load()?;
    let client = ctx.client()?;
    let lists = client.list_pairs(false)?;
    let view = lists.find(&id);
    let sas = match sas.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => resolve_sas(&ctx, view)?,
    };
    client.accept(&id, &sas)?;
    if let Ok(lists) = client.list_pairs(false) {
        let _ = sync_roster(&ctx.root, &lists, &ctx.configured_addrs(None));
    }
    println!("ok");
    Ok(())
}

pub fn run_reject(id: String) -> Result<(), PairError> {
    require_owner_pair()?;
    let ctx = PairCtx::load()?;
    let client = ctx.client()?;
    client.reject(&id)?;
    if let Ok(lists) = client.list_pairs(false) {
        let _ = sync_roster(&ctx.root, &lists, &ctx.configured_addrs(None));
    }
    println!("ok");
    Ok(())
}

pub fn run_revoke(id: String) -> Result<(), PairError> {
    require_owner_pair()?;
    let ctx = PairCtx::load()?;
    let client = ctx.client()?;
    client.revoke(&id)?;
    if let Ok(lists) = client.list_pairs(false) {
        let _ = sync_roster(&ctx.root, &lists, &ctx.configured_addrs(None));
    }
    println!("ok");
    Ok(())
}

pub fn finish(result: Result<(), PairError>) {
    if let Err(err) = result {
        eprintln!("{err}");
        if matches!(err, PairError::Gated) {
            eprintln!("use {DASHBOARD_PAIR}");
        }
        std::process::exit(err.exit_code());
    }
}

fn require_owner_pair() -> Result<(), PairError> {
    if env_flag("P5_OWNER_PAIR") {
        Ok(())
    } else {
        Err(PairError::Gated)
    }
}

fn publish_handles(
    ctx: &PairCtx,
    from_flag: Option<&str>,
    typ_flag: Option<&str>,
) -> Result<Vec<(PostalAddr, String)>, PairError> {
    let typ = ctx.resolve_typ(typ_flag)?;
    let pem = ctx.public_pem()?;
    let client = ctx.client()?;
    let addrs = ctx.configured_addrs(from_flag);
    if addrs.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for addr in addrs {
        let me = client.put_me(&addr.to_string(), &pem, typ)?;
        out.push((addr, me.fingerprint));
    }
    Ok(out)
}

fn sync_roster(
    root: &Path,
    lists: &PairLists,
    self_addrs: &[PostalAddr],
) -> Result<(), StoreError> {
    let mut roster = Roster::load(root)?;
    let selves: BTreeSet<_> = self_addrs.iter().cloned().collect();
    for p in &lists.sent {
        apply_view(&mut roster, &selves, p, &p.to, None, Trust::Pending);
    }
    for p in &lists.inbox {
        apply_view(&mut roster, &selves, p, &p.from, p.from_typ, Trust::Pending);
    }
    for p in &lists.friends {
        let trust = Trust::from_pair_status(&p.status).unwrap_or(Trust::Trusted);
        apply_view(&mut roster, &selves, p, &p.from, p.from_typ, trust);
    }
    roster.save(root)
}

fn apply_view(
    roster: &mut Roster,
    selves: &BTreeSet<PostalAddr>,
    view: &PairView,
    peer_raw: &str,
    typ: Option<PeerType>,
    trust: Trust,
) {
    let Ok(addr) = PostalAddr::parse(peer_raw, None) else {
        return;
    };
    if selves.contains(&addr) {
        return;
    }
    let fp = view.fingerprint.clone().or_else(|| {
        view.public_key_pem
            .as_deref()
            .and_then(|pem| fingerprint_spki_pem(pem).ok())
    });
    let _ = roster.merge_peer(
        addr,
        typ,
        fp,
        view.public_key_pem.clone(),
        trust,
        view.id.clone(),
    );
}

fn resolve_sas(ctx: &PairCtx, view: Option<&PairView>) -> Result<String, PairError> {
    if let Some(v) = view {
        if let Some(local) = local_sas(ctx, v) {
            return Ok(local.sas);
        }
        if let Some(s) = v.sas.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            return Ok(s.to_string());
        }
    }
    Err(PairError::NoSas)
}

struct LocalSas {
    local_fp: String,
    peer_fp: String,
    sas: String,
}

fn local_sas(ctx: &PairCtx, view: &PairView) -> Option<LocalSas> {
    let kp = ctx.keys().ok()?;
    let local_fp = kp.fingerprint();
    let roster = Roster::load(&ctx.root).ok();
    let peer_raw = peer_of(ctx, view);
    let pem = view.public_key_pem.clone().or_else(|| {
        let addr = PostalAddr::parse(&peer_raw, None).ok()?;
        roster
            .as_ref()
            .and_then(|r| r.get(&addr).map(|e| e.public_key_pem.clone()))
            .filter(|s| !s.is_empty())
    })?;
    let peer_fp = fingerprint_spki_pem(&pem).ok()?;
    Some(LocalSas {
        local_fp,
        peer_fp: peer_fp.clone(),
        sas: sas_code(&kp.fingerprint(), &peer_fp),
    })
}

fn peer_of(ctx: &PairCtx, view: &PairView) -> String {
    let selves: BTreeSet<String> = ctx
        .configured_addrs(None)
        .into_iter()
        .map(|a| a.to_string())
        .collect();
    if selves.contains(&view.from) {
        view.to.clone()
    } else {
        view.from.clone()
    }
}

fn print_add(id: &str, from: &PostalAddr, to: &PostalAddr, sas: Option<&str>, created: bool) {
    let state = if created { "created" } else { "exists" };
    match sas {
        Some(s) => println!("{id}  pending  {from}  {to}  {state}  sas={s}"),
        None => println!("{id}  pending  {from}  {to}  {state}"),
    }
}

fn print_section(name: &str, views: &[PairView]) {
    println!("{name}");
    print_views(views);
}

fn print_views(views: &[PairView]) {
    for v in views {
        match v.sas.as_deref().filter(|s| !s.is_empty()) {
            Some(sas) => println!("{}  {}  {}  {}  sas={sas}", v.id, v.status, v.from, v.to),
            None => println!("{}  {}  {}  {}", v.id, v.status, v.from, v.to),
        }
    }
}

fn print_show(ctx: &PairCtx, view: &PairView) -> Result<(), PairError> {
    println!("id      {}", view.id);
    println!("from    {}", view.from);
    println!("to      {}", view.to);
    println!("status  {}", view.status);
    if let Some(typ) = view.from_typ {
        println!("typ     {typ}");
    }
    match (
        local_sas(ctx, view),
        view.sas.as_deref().filter(|s| !s.is_empty()),
    ) {
        (Some(local), plane) => {
            println!("local   {}", local.local_fp);
            println!("peer    {}", local.peer_fp);
            println!("sas     {}", local.sas);
            if let Some(p) = plane {
                if p != local.sas {
                    println!("sas_plane {p}");
                }
            }
        }
        (None, Some(p)) => println!("sas     {p}"),
        (None, None) => println!("sas     —"),
    }
    Ok(())
}

fn parse_addr(raw: &str, default_host: Option<&str>) -> Result<PostalAddr, PairError> {
    PostalAddr::parse(raw, default_host).map_err(|e| PairError::BadAddress(e.to_string()))
}

fn parse_typ(raw: &str) -> Result<PeerType, PairError> {
    PeerType::from_str(raw).map_err(PairError::BadTyp)
}

fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

#[derive(Debug)]
pub enum PairError {
    Plane(PlaneError),
    Store(StoreError),
    Crypto(p5_crypto::CryptoError),
    BadAddress(String),
    BadTyp(TypeParseError),
    NoIdentity,
    NoSas,
    NotFound(String),
    Gated,
    PrivateKey,
}

impl PairError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Gated => EXIT_GATED,
            Self::BadAddress(_) | Self::BadTyp(_) => EXIT_USAGE,
            Self::Plane(e) => e.exit_code(),
            _ => EXIT_ERROR,
        }
    }
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plane(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::BadAddress(msg) => write!(f, "{msg}"),
            Self::BadTyp(e) => write!(f, "{e}"),
            Self::NoIdentity => f.write_str(
                "no local identity; set P5_FROM or add a homes row (handle::sub.postal.bot)",
            ),
            Self::NoSas => f.write_str("no SAS; pass --sas after p5 pair show"),
            Self::NotFound(id) => write!(f, "pair not found: {id}"),
            Self::Gated => write!(f, "{REASON_GATED}"),
            Self::PrivateKey => f.write_str("refusing to upload a private key"),
        }
    }
}

impl std::error::Error for PairError {}

impl From<PlaneError> for PairError {
    fn from(e: PlaneError) -> Self {
        Self::Plane(e)
    }
}

impl From<StoreError> for PairError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<p5_crypto::CryptoError> for PairError {
    fn from(e: p5_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
