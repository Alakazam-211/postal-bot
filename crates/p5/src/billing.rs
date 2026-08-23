//! Account meter: 1 postal.bot subdomain + 10000 messages/UTC month free.
//! Extra labels $2.99/mo. No free k2.dev subdomain (websockets cost more).
//!
//! Same K2X account. Paid checkout is the K2 Connect Stripe portal
//! (k2.dev/pricing) from either site. Stripe lives on K2 Web.
//!
//! The meter is the plane, not the device. `p5 usage` and the send
//! gate always `GET /postal/usage`. Display and gate from that
//! `limit` / `remaining` / `plan`. A local sent ledger / `config.toml`
//! is not the quota — anyone can edit the box. Parse miss is an error,
//! not a fallback to a hardcoded free ledger. `P5_BILLING=0` shows
//! usage but does not block send.

use p5_core::{Homes, Mailbox, PostalAddr};
use p5_plane::{PlaneClient, PlaneConfig, PostalFile, UsageReport};

pub const FREE_LIMIT: u32 = 10000;
pub const FREE_SUBDOMAINS: u32 = 1;
pub const PRICE_USD: &str = "2.99";
pub const PAY_URL: &str = "https://www.postal.bot/account";
pub const SIGNUP_URL: &str = "https://www.postal.bot/signup";
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
    let included = if report.limit == 0 {
        FREE_LIMIT
    } else {
        report.limit
    };
    format!(
        "1 postal.bot subdomain is free ({included} messages/month). Remaining {} on {}. Extra labels ${PRICE_USD}/mo on the same Stripe portal as k2.dev: {}",
        report.remaining,
        report.host,
        checkout_url()
    )
}

/// Always `GET /postal/usage`. Never a local sent ledger.
pub fn collect(root: &std::path::Path) -> Result<UsageReport, p5_plane::PlaneError> {
    let mb = Mailbox::new(root);
    let homes = Homes::load(root).unwrap_or_else(|_| Homes::new());
    let cfg = PlaneConfig::load(root)?;
    collect_with(&mb, &homes, cfg)
}

pub fn collect_with(
    mailbox: &Mailbox,
    homes: &Homes,
    cfg: PlaneConfig,
) -> Result<UsageReport, p5_plane::PlaneError> {
    let _ = mailbox;
    let token = cfg.require_token()?;
    let mut plane = PlaneClient::new(&cfg.base_url, token).usage()?;
    if plane.host.trim().is_empty() {
        let host = enrolled_host(homes, cfg.addr.as_deref());
        plane.host = if host.is_empty() {
            "(no enrolled host)".into()
        } else {
            host
        };
    }
    Ok(plane)
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
    use p5_plane::{BillingFile, PlaneError};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn addr(s: &str) -> PostalAddr {
        s.parse().unwrap()
    }

    fn spawn_usage(status: u16, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        let (ready_tx, ready_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = ready_tx.send(());
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        ready_rx.recv().unwrap();
        format!("http://{addr}")
    }

    fn plane_cfg(url: &str) -> PlaneConfig {
        PlaneConfig {
            base_url: url.into(),
            token: Some("k2c_test".into()),
            addr: None,
            typ: None,
            file: PostalFile::default(),
        }
    }

    fn k2x_report(plan: &str, sent: u32, remaining: u32) -> String {
        format!(
            r#"{{
                "host":"rosson.postal.bot",
                "period":"2026-08",
                "sent":{sent},
                "limit":10000,
                "remaining":{remaining},
                "plan":"{plan}",
                "subdomains":1,
                "subdomain_included":1,
                "account":"https://www.postal.bot/account",
                "current":{{"host":"rosson.postal.bot","label":"rosson","plan":"{plan}","free":false,"k2_reserved":true,"k2_active":true,"sent":{sent},"cap":null,"unlimited":true}},
                "hosts":[{{"host":"rosson.postal.bot","label":"rosson","plan":"{plan}","sent":{sent},"cap":null,"unlimited":true}}]
            }}"#
        )
    }

    #[test]
    fn utc_ym_known_instant() {
        // 2026-08-20 18:00:00 UTC
        assert_eq!(utc_ym(1_787_248_800), (2026, 8));
        assert_eq!(start_of_utc_month_unix(1_787_248_800), 1_785_542_400);
    }

    #[test]
    fn no_token_is_error_not_local_free() {
        let tmp = tempfile::tempdir().unwrap();
        let mb = Mailbox::new(tmp.path());
        let cfg = PlaneConfig {
            base_url: "http://127.0.0.1:1".into(),
            token: None,
            addr: None,
            typ: None,
            file: PostalFile::default(),
        };
        let err = collect_with(&mb, &Homes::new(), cfg).unwrap_err();
        assert!(matches!(err, PlaneError::NoToken));
    }

    #[test]
    fn plane_unlimited_is_the_meter_not_local_sent() {
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
                terminal: None,
                tools: ToolFlags {
                    files: false,
                    live_inject: true,
                    wake: true,
                },
                enrolled_host: "acme.postal.bot".into(),
            })
            .unwrap();
        for _ in 0..3 {
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
        }
        let url = spawn_usage(200, &k2x_report("unlimited", 0, FREE_LIMIT));
        let report = collect_with(&mb, &homes, plane_cfg(&url)).unwrap();
        assert_eq!(report.host, "rosson.postal.bot");
        assert_eq!(report.plan, PLAN_UNLIMITED);
        assert_eq!(report.sent, 0);
        assert_eq!(report.limit, FREE_LIMIT);
        assert_eq!(report.remaining, FREE_LIMIT);
        assert!(allow_send(&report));
    }

    #[test]
    fn local_config_unlimited_does_not_override_plane_free() {
        let tmp = tempfile::tempdir().unwrap();
        let mb = Mailbox::new(tmp.path());
        let mut file = PostalFile::default();
        file.billing = BillingFile {
            plan: Some(PLAN_UNLIMITED.into()),
            ..Default::default()
        };
        file.save(tmp.path()).unwrap();
        let url = spawn_usage(200, &k2x_report("free", 100, 0));
        let mut cfg = plane_cfg(&url);
        cfg.file = PostalFile::load(tmp.path()).unwrap();
        let report = collect_with(&mb, &Homes::new(), cfg).unwrap();
        assert_eq!(report.plan, PLAN_FREE);
        assert_eq!(report.remaining, 0);
        assert!(!allow_send(&report));
    }

    #[test]
    fn parse_miss_is_error_not_local_100() {
        let tmp = tempfile::tempdir().unwrap();
        let mb = Mailbox::new(tmp.path());
        let url = spawn_usage(200, r#"{"subdomains":{"n":1},"ok":true}"#);
        let err = collect_with(&mb, &Homes::new(), plane_cfg(&url)).unwrap_err();
        assert!(
            !matches!(err, PlaneError::NoToken | PlaneError::Unauthorized),
            "parse miss must not become a local ledger; got {err}"
        );
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
        let report = UsageReport {
            host: "rosson.postal.bot".into(),
            remaining: 0,
            plan: PLAN_UNLIMITED.into(),
            sent: 0,
            limit: FREE_LIMIT,
            ..Default::default()
        };
        assert!(allow_send(&report));
    }

    #[test]
    fn usage_text_names_price_and_pay_url() {
        let report = UsageReport {
            host: "rosson.postal.bot".into(),
            period: "2026-08".into(),
            sent: 12,
            limit: FREE_LIMIT,
            remaining: 988,
            plan: PLAN_FREE.into(),
            subdomains: 1,
            subdomain_included: FREE_SUBDOMAINS,
            ..Default::default()
        };
        let text = usage_text(&report);
        assert!(text.contains("rosson.postal.bot"));
        assert!(text.contains("988"));
        assert!(text.contains("10000"));
        assert!(text.contains("1 / 1 free"));
        assert!(text.contains("postal.bot/account"));
        assert!(!text.contains("9.99"));
        assert!(!text.to_ascii_lowercase().contains("kessel"));
    }
}
