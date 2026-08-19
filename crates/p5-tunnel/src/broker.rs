//! Cert broker client for `https://cert.postal.bot/cert`.
//!
//! Wire shape matches the deployed `/cert` RPC (`{ csr, subdomain, token }`)
//! so the Postal broker twin can share the control-plane parser. URL and SAN
//! policy are Postal-owned — this is not k2-core `cert_broker.rs`.

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

/// Default Postal broker. K2 Web 2026-08-19: this URL answers (400 on empty POST).
pub const DEFAULT_BROKER_URL: &str = "https://cert.postal.bot/cert";
/// Override (`https://cert.k2.dev/cert` remains a cutover fallback).
pub const BROKER_URL_ENV: &str = "P5_CERT_BROKER";

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

pub fn broker_url() -> String {
    match std::env::var(BROKER_URL_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => DEFAULT_BROKER_URL.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    InvalidToken(String),
    SubdomainNotOwned(String),
    SanMismatch(String),
    IssuanceFailed(String),
    BrokerDisabled(String),
    Other { code: String, detail: String },
    Unreachable(String),
    Protocol(String),
}

impl BrokerError {
    pub fn code(&self) -> &str {
        match self {
            Self::InvalidToken(_) => "invalid_token",
            Self::SubdomainNotOwned(_) => "subdomain_not_owned",
            Self::SanMismatch(_) => "san_mismatch",
            Self::IssuanceFailed(_) => "issuance_failed",
            Self::BrokerDisabled(_) => "broker_disabled",
            Self::Other { code, .. } => code,
            Self::Unreachable(_) => "unreachable",
            Self::Protocol(_) => "protocol_error",
        }
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToken(d) => write!(f, "cert broker invalid_token: {d}"),
            Self::SubdomainNotOwned(d) => write!(f, "cert broker subdomain_not_owned: {d}"),
            Self::SanMismatch(d) => write!(f, "cert broker san_mismatch: {d}"),
            Self::IssuanceFailed(d) => write!(f, "cert broker issuance_failed: {d}"),
            Self::BrokerDisabled(d) => write!(f, "cert broker broker_disabled: {d}"),
            Self::Other { code, detail } => write!(f, "cert broker error ({code}): {detail}"),
            Self::Unreachable(d) => write!(f, "cert broker unreachable: {d}"),
            Self::Protocol(d) => write!(f, "cert broker protocol error: {d}"),
        }
    }
}

impl std::error::Error for BrokerError {}

fn map_error_code(code: &str, detail: String) -> BrokerError {
    match code {
        "invalid_token" => BrokerError::InvalidToken(detail),
        "subdomain_not_owned" => BrokerError::SubdomainNotOwned(detail),
        "san_mismatch" => BrokerError::SanMismatch(detail),
        "issuance_failed" => BrokerError::IssuanceFailed(detail),
        "broker_disabled" => BrokerError::BrokerDisabled(detail),
        other => BrokerError::Other {
            code: other.to_string(),
            detail,
        },
    }
}

#[derive(Debug, Deserialize)]
struct CertResponse {
    cert: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

pub fn request_cert(csr_pem: &str, subdomain: &str, token: &str) -> Result<String, BrokerError> {
    request_cert_at(&broker_url(), csr_pem, subdomain, token)
}

/// POST `{ csr, subdomain, token }` to `url`. No filesystem side effects.
pub fn request_cert_at(
    url: &str,
    csr_pem: &str,
    subdomain: &str,
    token: &str,
) -> Result<String, BrokerError> {
    let body = serde_json::json!({
        "csr": csr_pem,
        "subdomain": subdomain,
        "token": token,
    });
    let resp = ureq::post(url)
        .timeout(HTTP_TIMEOUT)
        .set("Content-Type", "application/json")
        .send_json(body);
    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            return Err(parse_error_body(code, &text));
        }
        Err(ureq::Error::Transport(t)) => {
            return Err(BrokerError::Unreachable(format!("POST {url}: {t}")));
        }
    };
    let status = resp.status();
    let text = resp
        .into_string()
        .map_err(|e| BrokerError::Protocol(format!("read broker response body: {e}")))?;
    if (200..300).contains(&status) {
        let parsed: CertResponse = serde_json::from_str(&text).map_err(|e| {
            BrokerError::Protocol(format!(
                "broker 200 but body wasn't {{cert}} JSON: {e} (body: {})",
                truncate(&text, 200)
            ))
        })?;
        return match parsed.cert {
            Some(c) if !c.trim().is_empty() => Ok(c),
            _ => Err(BrokerError::Protocol(
                "broker 200 but `cert` field was missing/empty".into(),
            )),
        };
    }
    Err(parse_error_body(status, &text))
}

fn parse_error_body(status: u16, text: &str) -> BrokerError {
    match serde_json::from_str::<ErrorResponse>(text) {
        Ok(err) => {
            let code = err.error.unwrap_or_default();
            let detail = err.detail.unwrap_or_default();
            if code.trim().is_empty() {
                BrokerError::Protocol(format!(
                    "broker returned HTTP {status} with no error code (body: {})",
                    truncate(text, 200)
                ))
            } else {
                map_error_code(code.trim(), detail)
            }
        }
        Err(_) => BrokerError::Protocol(format!(
            "broker returned HTTP {status} with unparsable body: {}",
            truncate(text, 200)
        )),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn read_http_request(sock: &mut std::net::TcpStream) -> String {
        use std::io::{BufRead, Read};
        let mut reader = std::io::BufReader::new(sock);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            headers.push_str(&line);
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        let len = headers
            .lines()
            .find_map(|l| {
                l.split_once(':').and_then(|(k, v)| {
                    k.eq_ignore_ascii_case("content-length")
                        .then_some(v.trim().parse::<usize>().unwrap_or(0))
                })
            })
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        if len > 0 {
            let _ = reader.read_exact(&mut body);
        }
        headers.push_str(&String::from_utf8_lossy(&body));
        headers
    }

    fn spawn_mock(status_line: &str, body: &str) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let status_line = status_line.to_string();
        let body = body.to_string();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                let req = read_http_request(&mut sock);
                let _ = tx.send(req);
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        (format!("http://127.0.0.1:{port}/cert"), rx)
    }

    #[test]
    fn broker_url_defaults_and_env_override() {
        let _g = env_lock();
        let prev = std::env::var_os(BROKER_URL_ENV);
        std::env::remove_var(BROKER_URL_ENV);
        assert_eq!(broker_url(), DEFAULT_BROKER_URL);
        std::env::set_var(BROKER_URL_ENV, "https://cert.k2.dev/cert");
        assert_eq!(broker_url(), "https://cert.k2.dev/cert");
        std::env::set_var(BROKER_URL_ENV, "   ");
        assert_eq!(broker_url(), DEFAULT_BROKER_URL);
        match prev {
            Some(p) => std::env::set_var(BROKER_URL_ENV, p),
            None => std::env::remove_var(BROKER_URL_ENV),
        }
    }

    #[test]
    fn successful_broker_returns_cert() {
        let body = serde_json::json!({ "cert": "-----BEGIN CERTIFICATE-----\nUEs=\n-----END CERTIFICATE-----\n" })
            .to_string();
        let (url, rx) = spawn_mock("200 OK", &body);
        let cert = request_cert_at(
            &url,
            "-----BEGIN CERTIFICATE REQUEST-----\nxx\n-----END CERTIFICATE REQUEST-----\n",
            "acme",
            "tok",
        )
        .expect("broker 200");
        assert!(cert.contains("BEGIN CERTIFICATE"));
        let req = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(req.contains("BEGIN CERTIFICATE REQUEST"), "{req}");
        assert!(req.contains("\"subdomain\":\"acme\""), "{req}");
        assert!(req.contains("\"token\":\"tok\""), "{req}");
    }

    #[test]
    fn structured_error_is_typed() {
        let body = serde_json::json!({
            "error": "san_mismatch",
            "detail": "wildcard not allowed",
        })
        .to_string();
        let (url, _rx) = spawn_mock("400 Bad Request", &body);
        let err = request_cert_at(&url, "csr", "acme", "tok").unwrap_err();
        assert!(matches!(err, BrokerError::SanMismatch(_)), "{err:?}");
    }

    #[test]
    fn unreachable_is_hard_error() {
        let dead = {
            let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            format!("http://127.0.0.1:{p}/cert")
        };
        let err = request_cert_at(&dead, "csr", "acme", "tok").unwrap_err();
        assert!(matches!(err, BrokerError::Unreachable(_)), "{err:?}");
    }
}
