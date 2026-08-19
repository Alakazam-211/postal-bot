//! Local mailbox: sent ledger, outbox retry queue, inbox tray.
//!
//! On-disk shape is cover markdown plus optional `<id>.files/` sidecars
//! (K2 inbox layout, different API: a mailbox root, not a workspace path).

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ulid::Ulid;

use crate::{AddrError, DeliveryMode, PeerType, PostalAddr};

/// Automatic outbox tries before `failed`. Manual retry resets the counter.
pub const MAX_AUTO_ATTEMPTS: u32 = 12;
/// Hard reject for cover body + sidecar bytes. Fail closed; no sent row.
pub const MAX_BODY_BYTES: u64 = 256 * 1024;
/// CLI / caller exit when file transfer is refused (`tools.files=off`).
pub const EXIT_GATED: i32 = 3;

/// Delivery status on a sent row (K5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Queued,
    Held,
    Delivered,
    Acked,
    Failed,
}

impl DeliveryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Held => "held",
            Self::Delivered => "delivered",
            Self::Acked => "acked",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for DeliveryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DeliveryStatus {
    type Err = MailboxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "queued" => Ok(Self::Queued),
            "held" => Ok(Self::Held),
            "delivered" => Ok(Self::Delivered),
            "acked" => Ok(Self::Acked),
            "failed" => Ok(Self::Failed),
            _ => Err(MailboxError::Parse(format!("unknown status {s}"))),
        }
    }
}

/// One cover (sent, outbox, or inbox) plus optional sidecar names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailItem {
    pub id: String,
    pub to: PostalAddr,
    pub from: PostalAddr,
    pub status: DeliveryStatus,
    pub hold_id: Option<String>,
    pub mode: DeliveryMode,
    pub typ: PeerType,
    pub attempts: u32,
    pub next_attempt_at: Option<SystemTime>,
    pub created: SystemTime,
    pub title: String,
    pub body: String,
    pub sidecar_names: Vec<String>,
}

/// Outbound compose. Files are refused before any sent row when `files_allowed` is false.
#[derive(Debug, Clone)]
pub struct SendRequest {
    pub to: PostalAddr,
    pub from: PostalAddr,
    pub body: String,
    pub mode: DeliveryMode,
    pub typ: PeerType,
    pub files: Vec<PathBuf>,
    pub files_allowed: bool,
    pub title: Option<String>,
}

/// Inbound tray write. Same files-off rule as send (no cover if sidecars are refused).
#[derive(Debug, Clone)]
pub struct ReceiveRequest {
    pub id: String,
    pub to: PostalAddr,
    pub from: PostalAddr,
    pub body: String,
    pub mode: DeliveryMode,
    pub typ: PeerType,
    pub files: Vec<PathBuf>,
    pub files_allowed: bool,
    pub title: Option<String>,
    pub hold_id: Option<String>,
}

/// Mailbox rooted at `~/.postal` (or a test temp dir).
#[derive(Debug, Clone)]
pub struct Mailbox {
    root: PathBuf,
}

#[derive(Debug)]
pub enum MailboxError {
    Io(io::Error),
    Gated,
    NotFound {
        id: String,
    },
    InvalidId,
    InvalidHandle,
    Parse(String),
    TooLarge {
        size: u64,
    },
    Addr(AddrError),
    NotAFile {
        path: PathBuf,
    },
    NotRetryable {
        status: DeliveryStatus,
    },
    InvalidTransition {
        from: DeliveryStatus,
        to: DeliveryStatus,
    },
}

impl MailboxError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Gated => EXIT_GATED,
            _ => 1,
        }
    }
}

impl fmt::Display for MailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Gated => f.write_str("gated: tools.files=off"),
            Self::NotFound { id } => write!(f, "item not found: {id}"),
            Self::InvalidId => f.write_str("id is not a ULID"),
            Self::InvalidHandle => f.write_str("invalid handle or folder name"),
            Self::Parse(msg) => write!(f, "{msg}"),
            Self::TooLarge { size } => {
                write!(f, "message is {size} bytes; v0 cap is {MAX_BODY_BYTES}")
            }
            Self::Addr(err) => write!(f, "{err}"),
            Self::NotAFile { path } => write!(f, "not a readable file: {}", path.display()),
            Self::NotRetryable { status } => {
                write!(f, "cannot retry a {status} message")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "illegal status transition: {from} -> {to}")
            }
        }
    }
}

impl std::error::Error for MailboxError {}

impl From<io::Error> for MailboxError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<AddrError> for MailboxError {
    fn from(err: AddrError) -> Self {
        Self::Addr(err)
    }
}

/// Default root: `$P5_HOME`, else `~/.postal`.
pub fn default_root() -> PathBuf {
    resolve_root(
        std::env::var_os("P5_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

fn resolve_root(p5_home: Option<&OsStr>, home: Option<&OsStr>) -> PathBuf {
    if let Some(p) = p5_home {
        return PathBuf::from(p);
    }
    match home {
        Some(h) => PathBuf::from(h).join(".postal"),
        None => PathBuf::from(".postal"),
    }
}

/// Knock text for `--inbox-wake` (cover is already on disk).
pub fn wake_pointer_text(id: &str, title: &str) -> String {
    format!("[inbox:{id}] {title}\nOpen: p5 inbox read {id}")
}

/// Delay after `attempts` completed automatic tries. 0 means run now.
pub fn backoff_secs(attempts: u32) -> u64 {
    const TABLE: &[u64] = &[1, 2, 4, 8, 16, 32, 60, 120, 300];
    if attempts == 0 {
        return 0;
    }
    let idx = (attempts as usize - 1).min(TABLE.len() - 1);
    TABLE[idx]
}

/// Map `unit` in `[0, 1)` onto ±20% of `base_secs`.
pub fn apply_jitter(base_secs: u64, unit: f64) -> Duration {
    let unit = unit.clamp(0.0, 0.999_999);
    let frac = (unit * 0.4) - 0.2;
    Duration::from_secs_f64((base_secs as f64 * (1.0 + frac)).max(0.0))
}

/// Sidecar basename: drop path parts, `..`, keep `[A-Za-z0-9._-]`.
pub fn sanitize_sidecar_filename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment");
    if base == ".." || base == "." || base.is_empty() {
        return "attachment".to_string();
    }
    let mut out = String::with_capacity(base.len());
    for c in base.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('.').trim_matches('_');
    if trimmed.is_empty() || trimmed == ".." {
        "attachment".to_string()
    } else {
        trimmed.to_string()
    }
}

impl Mailbox {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ensure(&self) -> Result<(), MailboxError> {
        for dir in [
            self.root.as_path(),
            &self.sent_dir(),
            &self.outbox_dir(),
            &self.inbox_dir(),
        ] {
            ensure_dir(dir)?;
        }
        Ok(())
    }

    /// Write sent (ledger) + outbox (retry) first. Does not talk to the plane.
    pub fn enqueue(&self, req: SendRequest) -> Result<MailItem, MailboxError> {
        if !req.files.is_empty() && !req.files_allowed {
            return Err(MailboxError::Gated);
        }
        let size = total_size(&req.body, &req.files)?;
        if size > MAX_BODY_BYTES {
            return Err(MailboxError::TooLarge { size });
        }

        self.ensure()?;
        let now = SystemTime::now();
        let item = MailItem {
            id: mint_id(),
            to: req.to,
            from: req.from,
            status: DeliveryStatus::Queued,
            hold_id: None,
            mode: req.mode,
            typ: req.typ,
            attempts: 0,
            next_attempt_at: Some(now),
            created: truncate_secs(now),
            title: title_for(req.title.as_deref(), &req.body),
            body: req.body,
            sidecar_names: Vec::new(),
        };
        let mut item = item;
        item.sidecar_names = copy_sidecars(&self.sent_files_dir(&item.id), &req.files)?;
        self.commit_queued(&item)?;
        Ok(item)
    }

    /// Persist inbound cover (+ sidecars) under `inbox/<handle>/`. Dedupes on `id`.
    pub fn receive(&self, req: ReceiveRequest) -> Result<MailItem, MailboxError> {
        if !req.files.is_empty() && !req.files_allowed {
            return Err(MailboxError::Gated);
        }
        let id = parse_id(&req.id)?.to_string();
        if let Some(existing) = self.find_inbox(&id)? {
            return Ok(existing);
        }
        let size = total_size(&req.body, &req.files)?;
        if size > MAX_BODY_BYTES {
            return Err(MailboxError::TooLarge { size });
        }

        self.ensure()?;
        let handle = req.to.handle();
        let dir = self.inbox_handle_dir(handle);
        ensure_dir(&dir)?;
        let now = SystemTime::now();
        let mut item = MailItem {
            id: id.clone(),
            to: req.to,
            from: req.from,
            status: DeliveryStatus::Acked,
            hold_id: req.hold_id,
            mode: req.mode,
            typ: req.typ,
            attempts: 0,
            next_attempt_at: None,
            created: truncate_secs(now),
            title: title_for(req.title.as_deref(), &req.body),
            body: req.body,
            sidecar_names: Vec::new(),
        };
        item.sidecar_names = copy_sidecars(&dir.join(format!("{id}.files")), &req.files)?;
        atomic_write(&dir.join(format!("{id}.md")), &render_cover(&item))?;
        Ok(item)
    }

    pub fn list_sent(&self) -> Result<Vec<MailItem>, MailboxError> {
        list_covers(&self.sent_dir())
    }

    pub fn list_outbox(&self) -> Result<Vec<MailItem>, MailboxError> {
        // Sent queued rows are authoritative so a crash after write_sent still flushes.
        let mut items: Vec<MailItem> = self
            .list_sent()?
            .into_iter()
            .filter(|item| item.status == DeliveryStatus::Queued)
            .collect();
        let seen: HashSet<String> = items.iter().map(|item| item.id.clone()).collect();
        for id in md_stems(&self.outbox_dir())? {
            if seen.contains(&id) {
                continue;
            }
            match self.read_sent(&id) {
                Ok(_) => {}
                Err(MailboxError::NotFound { .. }) => {
                    if let Ok(item) = read_cover(&self.outbox_dir().join(format!("{id}.md"))) {
                        if item.status == DeliveryStatus::Queued {
                            items.push(item);
                        }
                    }
                }
                Err(err) => return Err(err),
            }
        }
        sort_newest_first(&mut items);
        Ok(items)
    }

    /// `handle = None` lists every handle. `folder = None` is untriaged (inbox root).
    pub fn list_inbox(
        &self,
        handle: Option<&str>,
        folder: Option<&str>,
    ) -> Result<Vec<MailItem>, MailboxError> {
        let folder = match folder {
            Some(f) if !f.is_empty() => {
                safe_segment(f)?;
                f
            }
            _ => "",
        };
        let mut items = Vec::new();
        for handle_name in self.inbox_handles(handle)? {
            let dir = if folder.is_empty() {
                self.inbox_handle_dir(&handle_name)
            } else {
                self.inbox_handle_dir(&handle_name).join(folder)
            };
            items.extend(list_covers(&dir)?);
        }
        sort_newest_first(&mut items);
        Ok(items)
    }

    pub fn read_sent(&self, id: &str) -> Result<MailItem, MailboxError> {
        let id = parse_id(id)?.to_string();
        let path = self.sent_dir().join(format!("{id}.md"));
        if !path.is_file() {
            return Err(MailboxError::NotFound { id });
        }
        read_cover(&path)
    }

    pub fn read_inbox(&self, id: &str) -> Result<MailItem, MailboxError> {
        let id = parse_id(id)?.to_string();
        self.find_inbox(&id)?.ok_or(MailboxError::NotFound { id })
    }

    pub fn read_inbox_cover(&self, id: &str) -> Result<String, MailboxError> {
        let id = parse_id(id)?.to_string();
        let path = self
            .locate_inbox_cover(&id)?
            .ok_or_else(|| MailboxError::NotFound { id: id.clone() })?;
        Ok(fs::read_to_string(path)?)
    }

    pub fn mark(
        &self,
        id: &str,
        status: DeliveryStatus,
        hold_id: Option<String>,
    ) -> Result<MailItem, MailboxError> {
        let mut item = self.read_sent(id)?;
        if !can_transition(item.status, status) {
            return Err(MailboxError::InvalidTransition {
                from: item.status,
                to: status,
            });
        }
        item.status = status;
        if hold_id.is_some() {
            item.hold_id = hold_id;
        }
        if status != DeliveryStatus::Queued {
            item.next_attempt_at = None;
        }
        self.write_sent(&item)?;
        if status == DeliveryStatus::Queued {
            self.write_outbox(&item)?;
        } else {
            self.remove_outbox(&item.id)?;
        }
        Ok(item)
    }

    pub fn mark_held(&self, id: &str, hold_id: &str) -> Result<MailItem, MailboxError> {
        self.mark(id, DeliveryStatus::Held, Some(hold_id.to_string()))
    }

    /// Count one automatic try. At [`MAX_AUTO_ATTEMPTS`] the row becomes `failed` and leaves outbox.
    pub fn record_attempt(&self, id: &str, now: SystemTime) -> Result<MailItem, MailboxError> {
        let mut item = self.read_sent(id)?;
        if item.status != DeliveryStatus::Queued {
            return Ok(item);
        }
        item.attempts = item.attempts.saturating_add(1);
        if item.attempts >= MAX_AUTO_ATTEMPTS {
            item.status = DeliveryStatus::Failed;
            item.next_attempt_at = None;
            self.write_sent(&item)?;
            self.remove_outbox(&item.id)?;
            return Ok(item);
        }
        let delay = apply_jitter(
            backoff_secs(item.attempts),
            jitter_unit(&item.id, item.attempts),
        );
        item.next_attempt_at = Some(now + delay);
        // Sent already exists — never delete it if outbox write flaps.
        self.write_sent(&item)?;
        self.write_outbox(&item)?;
        Ok(item)
    }

    /// Reset the automatic counter and re-queue immediately.
    pub fn manual_retry(&self, id: &str, now: SystemTime) -> Result<MailItem, MailboxError> {
        let mut item = self.read_sent(id)?;
        match item.status {
            DeliveryStatus::Queued | DeliveryStatus::Failed => {}
            status => return Err(MailboxError::NotRetryable { status }),
        }
        item.status = DeliveryStatus::Queued;
        item.attempts = 0;
        item.next_attempt_at = Some(now);
        self.write_sent(&item)?;
        self.write_outbox(&item)?;
        Ok(item)
    }

    pub fn due_outbox(&self, now: SystemTime) -> Result<Vec<MailItem>, MailboxError> {
        Ok(self
            .list_outbox()?
            .into_iter()
            .filter(|item| {
                item.status == DeliveryStatus::Queued
                    && item.next_attempt_at.map(|t| t <= now).unwrap_or(true)
            })
            .collect())
    }

    fn commit_queued(&self, item: &MailItem) -> Result<(), MailboxError> {
        self.write_sent(item)?;
        if let Err(err) = self.write_outbox(item) {
            self.rollback_sent(&item.id);
            return Err(err);
        }
        Ok(())
    }

    fn rollback_sent(&self, id: &str) {
        let _ = fs::remove_file(self.sent_dir().join(format!("{id}.md")));
        let _ = fs::remove_dir_all(self.sent_files_dir(id));
    }

    fn write_sent(&self, item: &MailItem) -> Result<(), MailboxError> {
        ensure_dir(&self.sent_dir())?;
        atomic_write(
            &self.sent_dir().join(format!("{}.md", item.id)),
            &render_cover(item),
        )
    }

    fn write_outbox(&self, item: &MailItem) -> Result<(), MailboxError> {
        ensure_dir(&self.outbox_dir())?;
        atomic_write(
            &self.outbox_dir().join(format!("{}.md", item.id)),
            &render_cover(item),
        )
    }

    fn remove_outbox(&self, id: &str) -> Result<(), MailboxError> {
        let path = self.outbox_dir().join(format!("{id}.md"));
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn sent_dir(&self) -> PathBuf {
        self.root.join("sent")
    }

    fn outbox_dir(&self) -> PathBuf {
        self.root.join("outbox")
    }

    fn inbox_dir(&self) -> PathBuf {
        self.root.join("inbox")
    }

    fn inbox_handle_dir(&self, handle: &str) -> PathBuf {
        self.inbox_dir().join(handle)
    }

    fn sent_files_dir(&self, id: &str) -> PathBuf {
        self.sent_dir().join(format!("{id}.files"))
    }

    fn find_inbox(&self, id: &str) -> Result<Option<MailItem>, MailboxError> {
        match self.locate_inbox_cover(id)? {
            Some(path) => Ok(Some(read_cover(&path)?)),
            None => Ok(None),
        }
    }

    fn locate_inbox_cover(&self, id: &str) -> Result<Option<PathBuf>, MailboxError> {
        let target = format!("{id}.md");
        for handle in self.inbox_handles(None)? {
            let root = self.inbox_handle_dir(&handle);
            let at_root = root.join(&target);
            if at_root.is_file() {
                return Ok(Some(at_root));
            }
            if let Ok(entries) = fs::read_dir(&root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() {
                        continue;
                    }
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with('.') || name.ends_with(".files") {
                        continue;
                    }
                    let nested = path.join(&target);
                    if nested.is_file() {
                        return Ok(Some(nested));
                    }
                }
            }
        }
        Ok(None)
    }

    fn inbox_handles(&self, only: Option<&str>) -> Result<Vec<String>, MailboxError> {
        if let Some(handle) = only {
            safe_segment(handle)?;
            return Ok(vec![handle.to_string()]);
        }
        let dir = self.inbox_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            names.push(name.to_string());
        }
        names.sort();
        Ok(names)
    }
}

fn mint_id() -> String {
    Ulid::new().to_string()
}

fn can_transition(from: DeliveryStatus, to: DeliveryStatus) -> bool {
    use DeliveryStatus::{Acked, Delivered, Failed, Held, Queued};
    from == to
        || matches!(
            (from, to),
            (Queued, Delivered | Held | Failed) | (Held, Acked | Failed) | (Delivered, Acked)
        )
}

fn parse_id(id: &str) -> Result<Ulid, MailboxError> {
    Ulid::from_string(id.trim()).map_err(|_| MailboxError::InvalidId)
}

fn title_for(title: Option<&str>, body: &str) -> String {
    if let Some(t) = title.map(str::trim).filter(|t| !t.is_empty()) {
        return t.to_string();
    }
    let line = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let line = line.trim().trim_start_matches('#').trim();
    if line.is_empty() {
        "message".to_string()
    } else {
        line.chars().take(80).collect()
    }
}

fn total_size(body: &str, files: &[PathBuf]) -> Result<u64, MailboxError> {
    let mut n = body.len() as u64;
    for path in files {
        let meta = fs::metadata(path).map_err(|_| MailboxError::NotAFile { path: path.clone() })?;
        if !meta.is_file() {
            return Err(MailboxError::NotAFile { path: path.clone() });
        }
        n = n.saturating_add(meta.len());
    }
    Ok(n)
}

fn copy_sidecars(dest_dir: &Path, files: &[PathBuf]) -> Result<Vec<String>, MailboxError> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    ensure_dir(dest_dir)?;
    let mut used = Vec::new();
    let mut names = Vec::new();
    for path in files {
        if !path.is_file() {
            return Err(MailboxError::NotAFile { path: path.clone() });
        }
        let original = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("attachment");
        let name = unique_sidecar_name(original, &used);
        used.push(name.clone());
        let dest = dest_dir.join(&name);
        fs::copy(path, &dest)?;
        File::open(&dest)?.sync_all()?;
        names.push(name);
    }
    Ok(names)
}

fn unique_sidecar_name(original: &str, used: &[String]) -> String {
    let base = sanitize_sidecar_filename(original);
    if !used.iter().any(|u| u == &base) {
        return base;
    }
    let (stem, ext) = match base.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), ext.to_string()),
        _ => (base, String::new()),
    };
    let mut n = 2;
    loop {
        let candidate = if ext.is_empty() {
            format!("{stem}-{n}")
        } else {
            format!("{stem}-{n}.{ext}")
        };
        if !used.iter().any(|u| u == &candidate) {
            return candidate;
        }
        n += 1;
    }
}

fn ensure_dir(path: &Path) -> Result<(), MailboxError> {
    fs::create_dir_all(path)?;
    chmod700(path)?;
    Ok(())
}

#[cfg(unix)]
fn chmod700(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn chmod700(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), MailboxError> {
    let dir = path
        .parent()
        .ok_or_else(|| MailboxError::Parse(format!("path has no parent: {}", path.display())))?;
    ensure_dir(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("cover.md")
    ));
    {
        let mut file = File::create(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn list_covers(dir: &Path) -> Result<Vec<MailItem>, MailboxError> {
    let mut items = Vec::new();
    if !dir.exists() {
        return Ok(items);
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "md") {
            if let Ok(item) = read_cover(&path) {
                items.push(item);
            }
        }
    }
    sort_newest_first(&mut items);
    Ok(items)
}

fn md_stems(dir: &Path) -> Result<Vec<String>, MailboxError> {
    let mut ids = Vec::new();
    if !dir.exists() {
        return Ok(ids);
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "md") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                ids.push(stem.to_string());
            }
        }
    }
    Ok(ids)
}

fn sort_newest_first(items: &mut [MailItem]) {
    items.sort_by(|a, b| b.id.cmp(&a.id));
}

fn read_cover(path: &Path) -> Result<MailItem, MailboxError> {
    let contents = fs::read_to_string(path)?;
    let sidecar_names = sibling_sidecars(path);
    parse_cover(&contents, sidecar_names)
}

fn sibling_sidecars(cover: &Path) -> Vec<String> {
    let Some(stem) = cover.file_stem().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    let Some(dir) = cover.parent() else {
        return Vec::new();
    };
    let files = dir.join(format!("{stem}.files"));
    let Ok(entries) = fs::read_dir(files) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        if entry.path().is_file() {
            if let Some(name) = entry.file_name().to_str() {
                if !name.starts_with('.') {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    names
}

fn render_cover(item: &MailItem) -> String {
    let hold = item.hold_id.as_deref().unwrap_or("");
    let next = item.next_attempt_at.map(format_rfc3339).unwrap_or_default();
    format!(
        "---\n\
         id: {}\n\
         to: {}\n\
         from: {}\n\
         status: {}\n\
         hold_id: {}\n\
         mode: {}\n\
         typ: {}\n\
         attempts: {}\n\
         next_attempt_at: {}\n\
         created: {}\n\
         title: {}\n\
         ---\n\n\
         {}\n",
        item.id,
        yaml_string(&item.to.to_string()),
        yaml_string(&item.from.to_string()),
        item.status.as_str(),
        yaml_string(hold),
        item.mode.as_str(),
        item.typ.as_str(),
        item.attempts,
        yaml_string(&next),
        yaml_string(&format_rfc3339(item.created)),
        yaml_string(&item.title),
        item.body.trim_end()
    )
}

fn parse_cover(contents: &str, sidecar_names: Vec<String>) -> Result<MailItem, MailboxError> {
    let (fm, body) = split_frontmatter(contents);
    let id = required(&fm, "id")?;
    let id = parse_id(&id)?.to_string();
    let to = PostalAddr::parse(&required(&fm, "to")?, None)?;
    let from = PostalAddr::parse(&required(&fm, "from")?, None)?;
    let status = fm
        .get("status")
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(DeliveryStatus::Queued);
    let hold_id = fm
        .get("hold_id")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mode = fm
        .get("mode")
        .map(|s| s.parse().map_err(|e| MailboxError::Parse(format!("{e}"))))
        .transpose()?
        .unwrap_or(DeliveryMode::Live);
    let typ = fm
        .get("typ")
        .map(|s| s.parse().map_err(|e| MailboxError::Parse(format!("{e}"))))
        .transpose()?
        .unwrap_or(PeerType::Session);
    let attempts = fm
        .get("attempts")
        .map(|s| s.parse::<u32>())
        .transpose()
        .map_err(|_| MailboxError::Parse("attempts is not a number".into()))?
        .unwrap_or(0);
    let next_attempt_at = fm
        .get("next_attempt_at")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| parse_rfc3339(&s).ok_or_else(|| MailboxError::Parse("bad next_attempt_at".into())))
        .transpose()?;
    let created = fm
        .get("created")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .and_then(|s| parse_rfc3339(&s))
        .unwrap_or(UNIX_EPOCH);
    let title = fm
        .get("title")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| title_for(None, &body));
    Ok(MailItem {
        id,
        to,
        from,
        status,
        hold_id,
        mode,
        typ,
        attempts,
        next_attempt_at,
        created,
        title,
        body,
        sidecar_names,
    })
}

fn required(fm: &BTreeMap<String, String>, key: &str) -> Result<String, MailboxError> {
    fm.get(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MailboxError::Parse(format!("missing {key}")))
}

fn split_frontmatter(contents: &str) -> (BTreeMap<String, String>, String) {
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let mut fm = BTreeMap::new();
    if !contents.starts_with("---") {
        return (fm, contents.trim().to_string());
    }
    let rest = &contents[3..];
    let rest = rest
        .strip_prefix('\n')
        .or_else(|| rest.strip_prefix("\r\n"))
        .unwrap_or(rest);
    let Some(end) = rest.find("\n---") else {
        return (fm, contents.trim().to_string());
    };
    let yaml = &rest[..end];
    let body = rest[end + 4..]
        .trim_start_matches('\r')
        .trim_start_matches('\n')
        .trim_end()
        .to_string();
    for line in yaml.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            fm.insert(key.trim().to_string(), unquote(value));
        }
    }
    (fm, body)
}

fn yaml_string(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        s.to_string()
    }
}

fn safe_segment(s: &str) -> Result<&str, MailboxError> {
    if s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\\') {
        return Err(MailboxError::InvalidHandle);
    }
    Ok(s)
}

fn jitter_unit(id: &str, attempts: u32) -> f64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut hasher);
    attempts.hash(&mut hasher);
    hasher.finish() as f64 / u64::MAX as f64
}

fn truncate_secs(ts: SystemTime) -> SystemTime {
    let secs = ts.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn format_rfc3339(ts: SystemTime) -> String {
    let secs = ts.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    if s.len() != 20 || !s.ends_with('Z') {
        return None;
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let year: i32 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: u32 = s[11..13].parse().ok()?;
    let min: u32 = s[14..16].parse().ok()?;
    let sec: u32 = s[17..19].parse().ok()?;
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let unix = days
        .checked_mul(86400)?
        .checked_add(i64::from(hour) * 3600)?
        .checked_add(i64::from(min) * 60)?
        .checked_add(i64::from(sec))?;
    if unix < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(unix as u64))
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 {
        u64::from(month) - 3
    } else {
        u64::from(month) + 9
    };
    let doy = (153 * mp + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(i64::from(era) * 146097 + doe as i64 - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmp() -> (Mailbox, Tmp) {
        let path = std::env::temp_dir().join(format!("p5-mailbox-{}", mint_id()));
        fs::create_dir_all(&path).unwrap();
        (Mailbox::new(&path), Tmp(path))
    }

    fn alice() -> PostalAddr {
        "alice::acme.postal.bot".parse().unwrap()
    }

    fn scout() -> PostalAddr {
        "scout::acme.postal.bot".parse().unwrap()
    }

    fn send(files: Vec<PathBuf>, files_allowed: bool) -> SendRequest {
        SendRequest {
            to: scout(),
            from: alice(),
            body: "hello scout".into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Session,
            files,
            files_allowed,
            title: None,
        }
    }

    #[test]
    fn enqueue_writes_sent_and_outbox() {
        let (mb, _tmp) = tmp();
        let item = mb.enqueue(send(Vec::new(), false)).unwrap();
        assert!(Ulid::from_string(&item.id).is_ok());
        assert_eq!(item.status, DeliveryStatus::Queued);
        assert_eq!(item.to, scout());
        assert_eq!(item.attempts, 0);
        assert_eq!(mb.list_sent().unwrap().len(), 1);
        assert_eq!(mb.list_outbox().unwrap().len(), 1);
        let cover = mb.root().join("sent").join(format!("{}.md", item.id));
        assert!(cover.is_file());
        let text = fs::read_to_string(cover).unwrap();
        assert!(text.contains("status: queued"));
        assert!(text.contains("hello scout"));
    }

    #[test]
    fn enqueue_mints_distinct_random_ulids() {
        let (mb, _tmp) = tmp();
        let a = mb.enqueue(send(Vec::new(), true)).unwrap();
        let b = mb.enqueue(send(Vec::new(), true)).unwrap();
        assert_ne!(a.id, b.id);
        let ua = Ulid::from_string(&a.id).unwrap();
        let ub = Ulid::from_string(&b.id).unwrap();
        assert_ne!(ua.random(), 0);
        assert_ne!(ua.random(), ub.random());
        // Old mint_id was (pid << 48) ^ (n << 16) ^ nanos, n starting at 1.
        let pid = u128::from(std::process::id());
        let old_shape = (pid << 48) ^ (1u128 << 16);
        assert_ne!(ua.random(), old_shape);
        assert_ne!(ub.random(), old_shape);
    }

    #[test]
    fn files_off_refuses_sidecar_without_sent_row() {
        let (mb, tmp) = tmp();
        let src = tmp.0.join("note.bin");
        fs::write(&src, b"abc").unwrap();
        let err = mb.enqueue(send(vec![src], false)).unwrap_err();
        assert!(matches!(err, MailboxError::Gated));
        assert_eq!(err.exit_code(), EXIT_GATED);
        assert!(!mb.root().join("sent").exists());
        assert!(!mb.root().join("outbox").exists());
        assert!(mb.list_sent().unwrap().is_empty());
    }

    #[test]
    fn files_off_allows_cover_only() {
        let (mb, _tmp) = tmp();
        let item = mb.enqueue(send(Vec::new(), false)).unwrap();
        assert!(item.sidecar_names.is_empty());
        assert_eq!(mb.list_sent().unwrap().len(), 1);
    }

    #[test]
    fn files_on_writes_sidecar() {
        let (mb, tmp) = tmp();
        let src = tmp.0.join("brief.pdf");
        fs::write(&src, b"%PDF").unwrap();
        let item = mb.enqueue(send(vec![src], true)).unwrap();
        assert_eq!(item.sidecar_names, vec!["brief.pdf"]);
        let side = mb
            .root()
            .join("sent")
            .join(format!("{}.files", item.id))
            .join("brief.pdf");
        assert_eq!(fs::read(side).unwrap(), b"%PDF");
    }

    #[test]
    fn receive_writes_inbox_handle_cover_and_sidecar() {
        let (mb, tmp) = tmp();
        let src = tmp.0.join("clip.txt");
        fs::write(&src, b"bytes").unwrap();
        let id = mint_id();
        let item = mb
            .receive(ReceiveRequest {
                id: id.clone(),
                to: scout(),
                from: alice(),
                body: "incoming".into(),
                mode: DeliveryMode::Tray,
                typ: PeerType::Session,
                files: vec![src],
                files_allowed: true,
                title: Some("Brief".into()),
                hold_id: None,
            })
            .unwrap();
        assert_eq!(item.id, id);
        assert_eq!(item.status, DeliveryStatus::Acked);
        let cover = mb
            .root()
            .join("inbox")
            .join("scout")
            .join(format!("{id}.md"));
        assert!(cover.is_file());
        let side = mb
            .root()
            .join("inbox")
            .join("scout")
            .join(format!("{id}.files"))
            .join("clip.txt");
        assert_eq!(fs::read(side).unwrap(), b"bytes");
        assert_eq!(mb.list_inbox(Some("scout"), None).unwrap().len(), 1);
        assert_eq!(mb.read_inbox(&id).unwrap().title, "Brief");
        let again = mb
            .receive(ReceiveRequest {
                id: id.clone(),
                to: scout(),
                from: alice(),
                body: "duplicate".into(),
                mode: DeliveryMode::Tray,
                typ: PeerType::Session,
                files: Vec::new(),
                files_allowed: true,
                title: None,
                hold_id: None,
            })
            .unwrap();
        assert_eq!(again.body, "incoming");
        assert_eq!(mb.list_inbox(Some("scout"), None).unwrap().len(), 1);
    }

    #[test]
    fn receive_files_off_writes_nothing() {
        let (mb, tmp) = tmp();
        let src = tmp.0.join("x.bin");
        fs::write(&src, b"x").unwrap();
        let err = mb
            .receive(ReceiveRequest {
                id: mint_id(),
                to: scout(),
                from: alice(),
                body: "x".into(),
                mode: DeliveryMode::Tray,
                typ: PeerType::Turn,
                files: vec![src],
                files_allowed: false,
                title: None,
                hold_id: None,
            })
            .unwrap_err();
        assert!(matches!(err, MailboxError::Gated));
        assert!(mb.list_inbox(None, None).unwrap().is_empty());
    }

    #[test]
    fn mark_delivered_leaves_outbox_keeps_sent() {
        let (mb, _tmp) = tmp();
        let item = mb.enqueue(send(Vec::new(), true)).unwrap();
        mb.mark(&item.id, DeliveryStatus::Delivered, None).unwrap();
        assert!(mb.list_outbox().unwrap().is_empty());
        let sent = mb.read_sent(&item.id).unwrap();
        assert_eq!(sent.status, DeliveryStatus::Delivered);
        assert!(mb
            .root()
            .join("sent")
            .join(format!("{}.md", item.id))
            .is_file());
    }

    #[test]
    fn mark_held_sets_hold_id() {
        let (mb, _tmp) = tmp();
        let item = mb.enqueue(send(Vec::new(), true)).unwrap();
        let held = mb.mark_held(&item.id, "hold-1").unwrap();
        assert_eq!(held.status, DeliveryStatus::Held);
        assert_eq!(held.hold_id.as_deref(), Some("hold-1"));
        assert!(mb.list_outbox().unwrap().is_empty());
    }

    #[test]
    fn queued_sent_without_outbox_still_lists() {
        let (mb, _tmp) = tmp();
        let item = mb.enqueue(send(Vec::new(), true)).unwrap();
        fs::remove_file(mb.root().join("outbox").join(format!("{}.md", item.id))).unwrap();
        let listed = mb.list_outbox().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, item.id);
        assert_eq!(listed[0].status, DeliveryStatus::Queued);
        let due = mb
            .due_outbox(SystemTime::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn enqueue_rolls_back_sent_if_outbox_write_fails() {
        let (mb, _tmp) = tmp();
        mb.ensure().unwrap();
        let outbox = mb.root().join("outbox");
        fs::remove_dir_all(&outbox).unwrap();
        fs::write(&outbox, b"not-a-dir").unwrap();
        let err = mb.enqueue(send(Vec::new(), true)).unwrap_err();
        assert!(matches!(err, MailboxError::Io(_)));
        assert!(mb.list_sent().unwrap().is_empty());
    }

    #[test]
    fn mark_rejects_illegal_transitions() {
        let (mb, _tmp) = tmp();
        let item = mb.enqueue(send(Vec::new(), true)).unwrap();
        mb.mark(&item.id, DeliveryStatus::Delivered, None).unwrap();
        let err = mb.mark_held(&item.id, "hold-x").unwrap_err();
        assert!(matches!(
            err,
            MailboxError::InvalidTransition {
                from: DeliveryStatus::Delivered,
                to: DeliveryStatus::Held,
            }
        ));
        mb.mark(&item.id, DeliveryStatus::Acked, None).unwrap();
        let err = mb.mark(&item.id, DeliveryStatus::Queued, None).unwrap_err();
        assert!(matches!(
            err,
            MailboxError::InvalidTransition {
                from: DeliveryStatus::Acked,
                to: DeliveryStatus::Queued,
            }
        ));
        assert_eq!(
            mb.read_sent(&item.id).unwrap().status,
            DeliveryStatus::Acked
        );
    }

    #[test]
    fn twelve_attempts_fail_and_leave_outbox() {
        let (mb, _tmp) = tmp();
        let item = mb.enqueue(send(Vec::new(), true)).unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut last = item;
        for i in 1..=MAX_AUTO_ATTEMPTS {
            last = mb.record_attempt(&last.id, now).unwrap();
            if i < MAX_AUTO_ATTEMPTS {
                assert_eq!(last.status, DeliveryStatus::Queued);
                assert_eq!(last.attempts, i);
                let delay = last.next_attempt_at.unwrap().duration_since(now).unwrap();
                let base = backoff_secs(i);
                let min = Duration::from_secs_f64(base as f64 * 0.8);
                let max = Duration::from_secs_f64(base as f64 * 1.2);
                assert!(delay >= min && delay <= max, "{delay:?} vs {base}s");
            }
        }
        assert_eq!(last.status, DeliveryStatus::Failed);
        assert_eq!(last.attempts, MAX_AUTO_ATTEMPTS);
        assert!(mb.list_outbox().unwrap().is_empty());
        assert_eq!(
            mb.read_sent(&last.id).unwrap().status,
            DeliveryStatus::Failed
        );
    }

    #[test]
    fn manual_retry_resets_counter() {
        let (mb, _tmp) = tmp();
        let item = mb.enqueue(send(Vec::new(), true)).unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        for _ in 0..MAX_AUTO_ATTEMPTS {
            mb.record_attempt(&item.id, now).unwrap();
        }
        assert_eq!(
            mb.read_sent(&item.id).unwrap().status,
            DeliveryStatus::Failed
        );
        let retried = mb.manual_retry(&item.id, now).unwrap();
        assert_eq!(retried.status, DeliveryStatus::Queued);
        assert_eq!(retried.attempts, 0);
        assert_eq!(retried.next_attempt_at, Some(now));
        assert_eq!(mb.list_outbox().unwrap().len(), 1);
    }

    #[test]
    fn backoff_table_caps_at_five_minutes() {
        assert_eq!(backoff_secs(0), 0);
        assert_eq!(backoff_secs(1), 1);
        assert_eq!(backoff_secs(2), 2);
        assert_eq!(backoff_secs(3), 4);
        assert_eq!(backoff_secs(4), 8);
        assert_eq!(backoff_secs(5), 16);
        assert_eq!(backoff_secs(6), 32);
        assert_eq!(backoff_secs(7), 60);
        assert_eq!(backoff_secs(8), 120);
        assert_eq!(backoff_secs(9), 300);
        assert_eq!(backoff_secs(12), 300);
        let d = apply_jitter(100, 0.5);
        assert_eq!(d, Duration::from_secs(100));
        let low = apply_jitter(100, 0.0);
        let high = apply_jitter(100, 0.999);
        assert_eq!(low, Duration::from_secs(80));
        assert!(high > Duration::from_secs(119) && high < Duration::from_secs(120));
    }

    #[test]
    fn default_root_prefers_p5_home() {
        assert_eq!(
            resolve_root(Some(OsStr::new("/tmp/m")), Some(OsStr::new("/Users/x"))),
            PathBuf::from("/tmp/m")
        );
        assert_eq!(
            resolve_root(None, Some(OsStr::new("/Users/x"))),
            PathBuf::from("/Users/x/.postal")
        );
        assert_eq!(resolve_root(None, None), PathBuf::from(".postal"));
    }

    #[test]
    fn rfc3339_roundtrip() {
        assert_eq!(format_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_787_097_600);
        assert_eq!(format_rfc3339(t), "2026-08-19T00:00:00Z");
        assert_eq!(parse_rfc3339("2026-08-19T00:00:00Z"), Some(t));
        let leap = UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(format_rfc3339(leap), "2024-02-29T00:00:00Z");
        assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), Some(leap));
    }

    #[test]
    fn wake_pointer_is_p5() {
        let text = wake_pointer_text("01ARZ3NDEKTSV4RRFFQ69G5FAV", "Brief");
        assert!(text.contains("p5 inbox read 01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!text.contains("k2"));
    }

    #[test]
    fn sanitize_sidecar_rejects_traversal() {
        assert_eq!(sanitize_sidecar_filename("../etc/passwd"), "passwd");
        assert_eq!(sanitize_sidecar_filename(".."), "attachment");
        assert_eq!(
            sanitize_sidecar_filename("my file (1).pdf"),
            "my_file__1_.pdf"
        );
    }

    #[test]
    fn too_large_does_not_write_sent() {
        let (mb, _tmp) = tmp();
        let mut req = send(Vec::new(), true);
        req.body = "x".repeat(MAX_BODY_BYTES as usize + 1);
        let err = mb.enqueue(req).unwrap_err();
        assert!(matches!(err, MailboxError::TooLarge { .. }));
        assert!(mb.list_sent().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn root_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let (mb, _tmp) = tmp();
        mb.enqueue(send(Vec::new(), true)).unwrap();
        let mode = fs::metadata(mb.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let mode = fs::metadata(mb.root().join("sent"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn cover_roundtrip_fields() {
        let (mb, _tmp) = tmp();
        let item = mb
            .enqueue(SendRequest {
                to: scout(),
                from: alice(),
                body: "tray body".into(),
                mode: DeliveryMode::Tray,
                typ: PeerType::Turn,
                files: Vec::new(),
                files_allowed: true,
                title: Some("Title".into()),
            })
            .unwrap();
        let loaded = mb.read_sent(&item.id).unwrap();
        assert_eq!(loaded.to, item.to);
        assert_eq!(loaded.from, item.from);
        assert_eq!(loaded.mode, DeliveryMode::Tray);
        assert_eq!(loaded.typ, PeerType::Turn);
        assert_eq!(loaded.title, "Title");
        assert_eq!(loaded.body, "tray body");
    }
}
