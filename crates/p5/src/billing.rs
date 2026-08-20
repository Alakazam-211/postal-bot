//! Account meter: 1 postal.bot subdomain + 100 messages/month free.
//! Extra labels $2.99/mo. No free k2.dev subdomain (websockets cost more).
//!
//! Same K2X account. Paid checkout is the K2 Connect Stripe portal
//! (k2.dev/pricing) from either site. Stripe lives on K2 Web.
//!
//! Message meter key is the enrolled host. Plane `GET /postal/usage`
//! when `P5_USAGE_PLANE=1`; else the local sent ledger. Mail from
//! before billing first ran does not count. `P5_BILLING=0` shows
//! usage but does not block send.

use std::time::{SystemTime, UNIX_EPOCH};

use p5_core::{Homes, Mailbox, PostalAddr};
use p5_plane::{BillingFile, PlaneClient, PlaneConfig, PostalFile, UsageReport};

pub const FREE_LIMIT: u32 = 100;
pub const FREE_SUBDOMAINS: u32 = 1;
pub const PRICE_USD: &str = "2.99";
pub const PAY_URL: &str = "https://k2.dev/p/account";
pub const SIGNUP_URL: &str = "https://k2.dev/p/signup";
/// Same Connect Stripe portal as k2.dev (K2 Web holds the keys).
pub const CHECKOUT_URL: &str = "https://k2.dev/pricing";
pub const SITE_URL: &str = "https://www.postal.bot";
pub const PLAN_FREE: &str = "free";
pub const PLAN_UNLIMITED: &str = "unlimited";

pub fn pay_url() -> String {
    std::env::var("P5_PAY_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| PAY_URL.into())
}

pub fn site_url() -> String {
    std::env::var("P5_SITE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| SITE_URL.into())
}

/// Default on. `P5_BILLING=0` / `false` / `off` skips the send gate.
pub fn enforce() -> bool {
    match std::env::var("P5_BILLING") {
        Ok(v) => {
            let v = v.trim();
            !(v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off"))
        }
        Err(_) => true,
    }
}

pub fn usage_text(report: &UsageReport) -> String {
    let remaining = if report.plan == PLAN_UNLIMITED {
        "unlimited".to_string()
    } else {
        report.remaining.to_string()
    };
    let until = report
        .until_unix
        .map(|u| format!("\nuntil:     {}", rfc3339_utc(u)))
        .unwrap_or_default();
    format!(
        "\
host:       {host}
period:     {period} (UTC)
plan:       {plan}
sent:       {sent}
included:   {limit} messages
remaining:  {remaining}
subdomains: {subs} / {sub_inc} free{until}
account:    {pay}
",
        host = report.host,
        period = report.period,
        plan = report.plan,
        sent = report.sent,
        limit = report.limit,
        subs = report.subdomains,
        sub_inc = if report.subdomain_included == 0 {
            FREE_SUBDOMAINS
        } else {
            report.subdomain_included
        },
        pay = pay_url(),
    )
}

pub fn checkout_url() -> String {
    std::env::var("P5_CHECKOUT_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| CHECKOUT_URL.into())
}

pub fn quota_hint(report: &UsageReport) -> String {
    format!(
        "1 postal.bot subdomain is free ({FREE_LIMIT} messages/month). Remaining {} on {}. Extra labels ${PRICE_USD}/mo on the same Stripe portal as k2.dev: {}",
        report.remaining,
        report.host,
        checkout_url()
    )
}

/// Load (and persist meter epoch if needed), prefer plane, else local sent.
pub fn collect(root: &std::path::Path) -> Result<UsageReport, p5_plane::PlaneError> {
    let mb = Mailbox::new(root);
    let homes = Homes::load(root).unwrap_or_else(|_| Homes::new());
    let cfg = PlaneConfig::load(root)?;
    collect_with(&mb, &homes, cfg)
}

pub fn collect_with(
    mailbox: &Mailbox,
    homes: &Homes,
    mut cfg: PlaneConfig,
) -> Result<UsageReport, p5_plane::PlaneError> {
    let now = now_unix();
    let host = enrolled_host(homes, cfg.addr.as_deref());
    ensure_meter_from(&mut cfg.file, mailbox, now)?;
    cfg.file.save(mailbox.root())?;

    if plane_usage_enabled() {
        if let Some(token) = cfg.token.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            match PlaneClient::new(&cfg.base_url, token).usage() {
                Ok(mut plane) => {
                    if cfg.file.billing.is_unlimited_now(now) {
                        plane.plan = PLAN_UNLIMITED.into();
                        plane.until_unix = cfg.file.billing.until_unix.or(plane.until_unix);
                    }
                    if plane.host.trim().is_empty() {
                        plane.host = host;
                    }
                    if plane.subdomain_included == 0 {
                        plane.subdomain_included = FREE_SUBDOMAINS;
                    }
                    if plane.subdomains == 0 {
                        plane.subdomains = subdomain_count(homes);
                    }
                    return Ok(plane);
                }
                Err(p5_plane::PlaneError::NotFound)
                | Err(p5_plane::PlaneError::Unauthorized)
                | Err(p5_plane::PlaneError::Http { status: 404, .. })
                | Err(_) => {}
            }
        }
    }
    Ok(local_report(
        mailbox,
        homes,
        &cfg.file.billing,
        &host,
        now,
    ))
}

/// Plane `GET /postal/usage` is not cut yet. Opt in with `P5_USAGE_PLANE=1`.
fn plane_usage_enabled() -> bool {
    match std::env::var("P5_USAGE_PLANE") {
        Ok(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on")
        }
        Err(_) => false,
    }
}

pub fn allow_send(report: &UsageReport) -> bool {
    report.plan == PLAN_UNLIMITED || report.remaining > 0
}

pub fn redeem(root: &std::path::Path, session_id: &str) -> Result<UsageReport, p5_plane::PlaneError> {
    let view = PlaneClient::checkout_session(site_url(), session_id.trim())?;
    if !view.paid {
        return Err(p5_plane::PlaneError::Http {
            status: 402,
            message: "checkout is not paid yet".into(),
        });
    }
    let mut file = PostalFile::load(root)?;
    file.billing.plan = Some(PLAN_UNLIMITED.into());
    if !view.host.trim().is_empty() {
        file.billing.host = Some(view.host.trim().to_string());
    }
    file.billing.until_unix = view.until_unix;
    file.billing.session = Some(session_id.trim().to_string());
    file.save(root)?;
    collect(root)
}

fn ensure_meter_from(
    file: &mut PostalFile,
    mailbox: &Mailbox,
    now: u64,
) -> Result<(), p5_plane::PlaneError> {
    if file.billing.meter_from_unix.is_some() {
        return Ok(());
    }
    let sent_len = mailbox.list_sent().map(|v| v.len()).unwrap_or(0);
    let epoch = if sent_len == 0 {
        start_of_utc_month_unix(now)
    } else {
        now
    };
    file.billing.meter_from_unix = Some(epoch);
    Ok(())
}

fn enrolled_host(homes: &Homes, cfg_addr: Option<&str>) -> String {
    if let Some((_, row)) = homes.iter().next() {
        let h = row.enrolled_host.trim();
        if !h.is_empty() {
            return h.to_string();
        }
    }
    if let Some(addr) = cfg_addr {
        if let Ok(a) = addr.parse::<PostalAddr>() {
            return a.host().to_string();
        }
    }
    String::new()
}

fn local_report(
    mailbox: &Mailbox,
    homes: &Homes,
    billing: &BillingFile,
    host: &str,
    now: u64,
) -> UsageReport {
    let (year, month) = utc_ym(now);
    let period = format!("{year:04}-{month:02}");
    let month_start = start_of_utc_month_unix(now);
    let meter_from = billing.meter_from_unix.unwrap_or(month_start);
    let start = meter_from.max(month_start);
    let sent_items = mailbox.list_sent().unwrap_or_default();
    let sent = sent_items
        .iter()
        .filter(|item| {
            let created = system_unix(item.created);
            if created < start {
                return false;
            }
            if host.is_empty() {
                return true;
            }
            item.from.host() == host
        })
        .count() as u32;
    let unlimited = billing.is_unlimited_now(now);
    let plan = if unlimited {
        PLAN_UNLIMITED
    } else {
        PLAN_FREE
    };
    let remaining = if unlimited {
        FREE_LIMIT
    } else {
        FREE_LIMIT.saturating_sub(sent)
    };
    UsageReport {
        host: if host.is_empty() {
            "(no enrolled host)".into()
        } else {
            host.to_string()
        },
        period,
        sent,
        limit: FREE_LIMIT,
        remaining,
        plan: plan.into(),
        until_unix: billing.until_unix,
        subdomains: subdomain_count(homes),
        subdomain_included: FREE_SUBDOMAINS,
    }
}

fn subdomain_count(homes: &Homes) -> u32 {
    let mut seen = std::collections::BTreeSet::new();
    for (_, row) in homes.iter() {
        let h = row.enrolled_host.trim();
        if !h.is_empty() {
            seen.insert(h.to_ascii_lowercase());
        }
    }
    seen.len() as u32
}

fn now_unix() -> u64 {
    system_unix(SystemTime::now())
}

fn system_unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn rfc3339_utc(unix: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_hms(unix);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant civil_from_days. `unix` is seconds since epoch UTC.
pub fn utc_ym(unix: u64) -> (i32, u8) {
    let (y, m, _, _, _, _) = civil_hms(unix);
    (y, m)
}

pub fn start_of_utc_month_unix(unix: u64) -> u64 {
    let (y, m) = utc_ym(unix);
    days_from_civil(y, m, 1) as u64 * 86400
}

fn civil_hms(unix: u64) -> (i32, u8, u8, u8, u8, u8) {
    let secs = unix as i64;
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400) as u64;
    let hh = (sod / 3600) as u8;
    let mm = ((sod % 3600) / 60) as u8;
    let ss = (sod % 60) as u8;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, hh, mm, ss)
}

fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn days_from_civil(y: i32, m: u8, d: u8) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 }.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { (m as u64) - 3 } else { (m as u64) + 9 };
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146_097 + doe as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use p5_core::{DeliveryMode, HomeRow, PeerType, SendRequest, ToolFlags};
    use std::path::PathBuf;

    fn addr(s: &str) -> PostalAddr {
        s.parse().unwrap()
    }

    #[test]
    fn utc_ym_known_instant() {
        // 2026-08-20 18:00:00 UTC
        assert_eq!(utc_ym(1_787_248_800), (2026, 8));
        assert_eq!(start_of_utc_month_unix(1_787_248_800), 1_785_542_400);
    }

    #[test]
    fn empty_mailbox_has_full_free_remaining() {
        let tmp = tempfile::tempdir().unwrap();
        let mb = Mailbox::new(tmp.path());
        let homes = Homes::new();
        let cfg = PlaneConfig::load(tmp.path()).unwrap();
        let report = collect_with(&mb, &homes, cfg).unwrap();
        assert_eq!(report.sent, 0);
        assert_eq!(report.remaining, FREE_LIMIT);
        assert_eq!(report.plan, PLAN_FREE);
        assert_eq!(report.limit, FREE_LIMIT);
        assert!(allow_send(&report));
    }

    #[test]
    fn sent_this_month_decrements_remaining() {
        let tmp = tempfile::tempdir().unwrap();
        let mb = Mailbox::new(tmp.path());
        let mut homes = Homes::new();
        homes
            .insert(HomeRow {
                address: addr("alice::acme.postal.bot"),
                session_id: None,
                cwd: PathBuf::from("/tmp"),
                inbox_root: None,
                launch: Vec::new(),
                harness: None,
                tools: ToolFlags {
                    files: false,
                    live_inject: true,
                    wake: true,
                },
                enrolled_host: "acme.postal.bot".into(),
            })
            .unwrap();
        mb.enqueue(SendRequest {
            to: addr("scout::acme.postal.bot"),
            from: addr("alice::acme.postal.bot"),
            body: "one".into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Session,
            files: Vec::new(),
            files_allowed: false,
            title: None,
        })
        .unwrap();
        let cfg = PlaneConfig::load(tmp.path()).unwrap();
        let report = collect_with(&mb, &homes, cfg).unwrap();
        assert_eq!(report.host, "acme.postal.bot");
        assert_eq!(report.sent, 1);
        assert_eq!(report.remaining, FREE_LIMIT - 1);
        assert_eq!(report.subdomains, 1);
        assert_eq!(report.subdomain_included, FREE_SUBDOMAINS);
        assert!(allow_send(&report));
    }

    #[test]
    fn existing_sent_does_not_eat_cap_on_first_touch() {
        let tmp = tempfile::tempdir().unwrap();
        let mb = Mailbox::new(tmp.path());
        mb.enqueue(SendRequest {
            to: addr("scout::acme.postal.bot"),
            from: addr("alice::acme.postal.bot"),
            body: "old".into(),
            mode: DeliveryMode::Live,
            typ: PeerType::Session,
            files: Vec::new(),
            files_allowed: false,
            title: None,
        })
        .unwrap();
        let mut file = PostalFile::default();
        file.billing.meter_from_unix = Some(now_unix() + 60);
        file.save(tmp.path()).unwrap();
        let homes = Homes::new();
        let cfg = PlaneConfig::load(tmp.path()).unwrap();
        let report = collect_with(&mb, &homes, cfg).unwrap();
        assert_eq!(report.sent, 0);
        assert_eq!(report.remaining, FREE_LIMIT);
    }

    #[test]
    fn zero_remaining_free_is_blocked() {
        let report = UsageReport {
            host: "acme.postal.bot".into(),
            remaining: 0,
            plan: PLAN_FREE.into(),
            sent: FREE_LIMIT,
            limit: FREE_LIMIT,
            ..Default::default()
        };
        assert!(!allow_send(&report));
        let hint = quota_hint(&report);
        assert!(hint.contains("$2.99"));
        assert!(hint.contains("acme.postal.bot"));
        assert!(hint.contains("1 postal.bot subdomain"));
        assert!(hint.contains("k2.dev"));
    }

    #[test]
    fn unlimited_plan_allows_when_remaining_would_be_zero() {
        let mut billing = BillingFile::default();
        billing.plan = Some(PLAN_UNLIMITED.into());
        assert!(billing.is_unlimited_now(now_unix()));
        let tmp = tempfile::tempdir().unwrap();
        let mb = Mailbox::new(tmp.path());
        let file = PostalFile {
            billing,
            ..Default::default()
        };
        file.save(tmp.path()).unwrap();
        let cfg = PlaneConfig::load(tmp.path()).unwrap();
        let report = collect_with(&mb, &Homes::new(), cfg).unwrap();
        assert_eq!(report.plan, PLAN_UNLIMITED);
        assert!(allow_send(&report));
    }

    #[test]
    fn usage_text_names_price_and_pay_url() {
        let report = UsageReport {
            host: "rosson.postal.bot".into(),
            period: "2026-08".into(),
            sent: 12,
            limit: FREE_LIMIT,
            remaining: 88,
            plan: PLAN_FREE.into(),
            subdomains: 1,
            subdomain_included: FREE_SUBDOMAINS,
            ..Default::default()
        };
        let text = usage_text(&report);
        assert!(text.contains("rosson.postal.bot"));
        assert!(text.contains("88"));
        assert!(text.contains("100"));
        assert!(text.contains("1 / 1 free"));
        assert!(text.contains("k2.dev/p/account"));
        assert!(!text.contains("9.99"));
        assert!(!text.to_ascii_lowercase().contains("kessel"));
    }
}
