//! Which frps relay to dial.
//!
//! The plane publishes the current relays at `GET {base}/api/tunnel/relays`
//! (Bearer = the label's tunnel token, the one frpc sends as metadata):
//!
//! ```text
//! {"v":1,"relays":[{"host":"…","port":7000,"role":"primary"},
//!                  {"host":"…","port":7000,"role":"standby"}],
//!  "refresh_s":21600,"ts":…}
//! ```
//!
//! At tunnel start p5 fetches it, keeps the last good copy in
//! `tunnel/relays.json`, and picks the first relay whose port answers a TCP
//! connect (primary, then standby). If the fetch fails it uses that copy; with
//! no list at all it dials `frp.postal.bot`. `P5_FRP_SERVER` skips all this.
//! The list is read again whenever the agent starts the tunnel.
//!
//! The token goes only to an https base (loopback http for tests), never
//! across a redirect, and only to relays under postal.bot, k2.dev or k5.dev
//! (or the relay IPs listed below). If no listed relay answers, p5 tries
//! `frp.postal.bot` before settling on the primary.

use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::csr::TUNNEL_DIR;
use crate::render::{DEFAULT_FRP_PORT, DEFAULT_FRP_SERVER};

/// Base URL for the relay list. k5.dev serves the same route as k2.dev,
/// which is being retired.
pub const DEFAULT_RELAYS_BASE: &str = "https://k5.dev";
/// Override the base (tests, staging).
pub const RELAYS_BASE_ENV: &str = "P5_RELAYS_BASE";
pub const RELAYS_FILE: &str = "relays.json";

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayList {
    pub v: u32,
    pub relays: Vec<Relay>,
    #[serde(default)]
    pub refresh_s: u64,
    #[serde(default)]
    pub ts: i64,
}

impl RelayList {
    /// v1 only, at least one relay, sane hosts and ports. Primary first,
    /// then the rest in the plane's order.
    fn checked(mut self) -> Option<Self> {
        if self.v != 1 {
            return None;
        }
        self.relays.retain(|r| r.port != 0 && valid_host(&r.host));
        if self.relays.is_empty() {
            return None;
        }
        self.relays.sort_by_key(|r| r.role != "primary");
        Some(self)
    }
}

/// Relay names p5 will dial: frpc sends the tunnel token to the relay, so a
/// bad cache or plane answer must not be able to point it anywhere else.
const RELAY_DOMAINS: &[&str] = &["postal.bot", "k2.dev", "k5.dev"];
/// Relays published by IP. A relay at a new IP needs a name under
/// [`RELAY_DOMAINS`] or a release.
const RELAY_IPS: &[&str] = &["147.135.65.8", "51.81.155.236"];

fn valid_host(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    if RELAY_IPS.contains(&h.as_str()) {
        return true;
    }
    let shape = !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    shape
        && RELAY_DOMAINS
            .iter()
            .any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

fn valid_base(base: &str) -> bool {
    crate::broker::safe_url(base)
}

pub fn relays_base() -> String {
    std::env::var(RELAYS_BASE_ENV)
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_RELAYS_BASE.to_string())
}

fn cache_path(root: &Path) -> PathBuf {
    root.join(TUNNEL_DIR).join(RELAYS_FILE)
}

/// GET the list. Any failure (no token, transport, status, bad body) is None.
pub fn fetch(base: &str, token: &str) -> Option<RelayList> {
    if token.trim().is_empty() || !valid_base(base) {
        return None;
    }
    let url = format!("{base}/api/tunnel/relays");
    // No redirects: a 3xx would carry the Bearer to wherever it points.
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(FETCH_TIMEOUT)
        .build();
    let resp = agent
        .get(&url)
        .set("Authorization", &format!("Bearer {}", token.trim()))
        .call()
        .ok()?;
    if resp.status() != 200 {
        return None;
    }
    let text = resp.into_string().ok()?;
    serde_json::from_str::<RelayList>(&text).ok()?.checked()
}

fn load_cache(root: &Path) -> Option<RelayList> {
    let text = std::fs::read_to_string(cache_path(root)).ok()?;
    serde_json::from_str::<RelayList>(&text).ok()?.checked()
}

fn save_cache(root: &Path, list: &RelayList) {
    let path = cache_path(root);
    let tmp = path.with_extension("json.tmp");
    if let Ok(text) = serde_json::to_vec_pretty(list) {
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

fn reachable(host: &str, port: u16) -> bool {
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    addrs
        .into_iter()
        .any(|a| TcpStream::connect_timeout(&a, PROBE_TIMEOUT).is_ok())
}

/// The relay frpc should dial, and where the choice came from (for status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub host: String,
    pub port: u16,
    pub source: &'static str,
}

/// Pick a relay. `probe` is the reachability check (tests stub it).
pub fn choose_with(
    root: &Path,
    base: &str,
    token: Option<&str>,
    probe: impl Fn(&str, u16) -> bool,
) -> Choice {
    let fetched = token.and_then(|t| fetch(base, t));
    let (list, source) = match fetched {
        Some(l) => {
            save_cache(root, &l);
            (Some(l), "list")
        }
        None => (load_cache(root), "cached list"),
    };
    if let Some(list) = list {
        if let Some(r) = list.relays.iter().find(|r| probe(&r.host, r.port)) {
            return Choice {
                host: r.host.clone(),
                port: r.port,
                source,
            };
        }
        // None answered (say a stale cache naming a retired relay): try
        // frp.postal.bot, which follows the active relay, before settling
        // on the primary for frpc to keep retrying.
        if probe(DEFAULT_FRP_SERVER, DEFAULT_FRP_PORT) {
            return Choice {
                host: DEFAULT_FRP_SERVER.to_string(),
                port: DEFAULT_FRP_PORT,
                source: "default (no listed relay answered)",
            };
        }
        let r = &list.relays[0];
        return Choice {
            host: r.host.clone(),
            port: r.port,
            source,
        };
    }
    Choice {
        host: DEFAULT_FRP_SERVER.to_string(),
        port: DEFAULT_FRP_PORT,
        source: "default",
    }
}

pub fn choose(root: &Path, token: Option<&str>) -> Choice {
    choose_with(root, &relays_base(), token, reachable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const BODY: &str = r#"{"v":1,"relays":[{"host":"r2.postal.bot","port":7001,"role":"standby"},{"host":"r1.postal.bot","port":7000,"role":"primary"}],"refresh_s":21600,"ts":1}"#;

    /// One-shot HTTP server; returns its base URL and the request it saw.
    fn serve(
        status: &'static str,
        body: &'static str,
    ) -> (String, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
            req
        });
        (base, h)
    }

    fn root() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(TUNNEL_DIR)).unwrap();
        d
    }

    #[test]
    fn primary_first_and_bearer_sent() {
        let d = root();
        let (base, h) = serve("200 OK", BODY);
        let c = choose_with(d.path(), &base, Some("tok123"), |_, _| true);
        assert_eq!(
            (c.host.as_str(), c.port, c.source),
            ("r1.postal.bot", 7000, "list")
        );
        let req = h.join().unwrap();
        assert!(req.starts_with("GET /api/tunnel/relays "));
        assert!(req
            .to_ascii_lowercase()
            .contains("authorization: bearer tok123"));
    }

    #[test]
    fn standby_when_primary_does_not_answer() {
        let d = root();
        let (base, _h) = serve("200 OK", BODY);
        let c = choose_with(d.path(), &base, Some("t"), |h, _| h == "r2.postal.bot");
        assert_eq!((c.host.as_str(), c.port), ("r2.postal.bot", 7001));
    }

    #[test]
    fn neither_answers_keeps_primary() {
        let d = root();
        let (base, _h) = serve("200 OK", BODY);
        let c = choose_with(d.path(), &base, Some("t"), |_, _| false);
        assert_eq!(c.host, "r1.postal.bot");
    }

    #[test]
    fn stale_cache_falls_back_to_the_default_when_it_answers() {
        let d = root();
        let (base, _h) = serve("200 OK", BODY);
        choose_with(d.path(), &base, Some("t"), |_, _| true);
        // Plane unreachable, cached relays dead, frp.postal.bot alive.
        let c = choose_with(d.path(), "http://127.0.0.1:1", Some("t"), |h, _| {
            h == DEFAULT_FRP_SERVER
        });
        assert_eq!(
            (c.host.as_str(), c.port, c.source),
            (
                DEFAULT_FRP_SERVER,
                DEFAULT_FRP_PORT,
                "default (no listed relay answered)"
            )
        );
    }

    #[test]
    fn a_redirect_is_a_failed_fetch() {
        let d = root();
        let (base, _h) = serve("302 Found\r\nLocation: http://127.0.0.1:1/x", "");
        let c = choose_with(d.path(), &base, Some("t"), |_, _| true);
        assert_eq!(c.source, "default");
    }

    #[test]
    fn non_https_base_is_never_fetched() {
        assert!(fetch("http://k5.dev", "t").is_none());
        assert!(valid_base("https://k5.dev"));
        assert!(valid_base("http://127.0.0.1:8080"));
        assert!(!valid_base("http://127.0.0.1.evil.com"));
        assert!(!valid_base("http://localhost:1@evil.com"));
        assert!(!valid_base("http://localhost:"));
    }

    #[test]
    fn relay_hosts_are_limited_to_ours() {
        for ok in [
            "frp.postal.bot",
            "R1.K5.dev",
            "k2.dev",
            "147.135.65.8",
            "51.81.155.236",
        ] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in [
            "evil.com",
            "postal.bot.evil.com",
            "xpostal.bot",
            "1.2.3.4",
            "178.156.232.105",
            "",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
    }

    #[test]
    fn fetch_failure_uses_the_cached_list_then_the_default() {
        let d = root();
        // No list yet, fetch fails: the default name.
        let (base, _h) = serve("401 Unauthorized", r#"{"error":"unauthorized"}"#);
        let c = choose_with(d.path(), &base, Some("t"), |_, _| true);
        assert_eq!((c.host.as_str(), c.source), (DEFAULT_FRP_SERVER, "default"));
        // A good fetch is cached ...
        let (base, _h) = serve("200 OK", BODY);
        choose_with(d.path(), &base, Some("t"), |_, _| true);
        // ... and used when the next fetch fails.
        let (base, _h) = serve("500 Internal Server Error", "{}");
        let c = choose_with(d.path(), &base, Some("t"), |_, _| true);
        assert_eq!(
            (c.host.as_str(), c.source),
            ("r1.postal.bot", "cached list")
        );
    }

    #[test]
    fn no_token_never_fetches() {
        let d = root();
        let c = choose_with(d.path(), "http://127.0.0.1:1", None, |_, _| true);
        assert_eq!(c.source, "default");
    }

    #[test]
    fn bad_lists_are_refused() {
        let bad = [
            r#"{"v":2,"relays":[{"host":"a","port":1,"role":"primary"}]}"#,
            r#"{"v":1,"relays":[]}"#,
            r#"{"v":1,"relays":[{"host":"a b\n","port":1,"role":"primary"}]}"#,
            r#"{"v":1,"relays":[{"host":"a","port":0,"role":"primary"}]}"#,
        ];
        for b in bad {
            let l: RelayList = serde_json::from_str(b).unwrap();
            assert!(l.checked().is_none(), "{b}");
        }
    }
}
