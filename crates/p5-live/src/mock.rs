//! Loopback HTTPS peer for live-send tests.

use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair as RcgenKey};
use tiny_http::{Header, Method, Response, Server, SslConfig, StatusCode};

#[derive(Debug, Clone)]
pub struct Captured {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Captured {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct HttpsPeer {
    pub base_url: String,
    pub cert_der: Vec<u8>,
    recorded: Arc<Mutex<Vec<Captured>>>,
    stop: Arc<AtomicBool>,
    server: Arc<Server>,
    join: Option<thread::JoinHandle<()>>,
}

impl HttpsPeer {
    pub fn spawn(status: u16, body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock bind");
        let addr = listener.local_addr().expect("mock addr");
        let (ssl, cert_der) = test_tls();
        let server = Server::from_listener(listener, Some(ssl)).expect("mock https");
        let server = Arc::new(server);
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let body = body.to_string();
        let join = {
            let server = Arc::clone(&server);
            let recorded = Arc::clone(&recorded);
            let stop = Arc::clone(&stop);
            thread::spawn(move || serve(server, recorded, stop, status, body))
        };
        Self {
            base_url: format!("https://{addr}"),
            cert_der,
            recorded,
            stop,
            server,
            join: Some(join),
        }
    }

    pub fn recorded(&self) -> Vec<Captured> {
        self.recorded
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Drop for HttpsPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.unblock();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve(
    server: Arc<Server>,
    recorded: Arc<Mutex<Vec<Captured>>>,
    stop: Arc<AtomicBool>,
    status: u16,
    body: String,
) {
    while !stop.load(Ordering::Relaxed) {
        match server.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(mut request)) => {
                let method = method_str(request.method());
                let url = request.url().to_string();
                let path = url.split('?').next().unwrap_or(&url).to_string();
                let headers: Vec<(String, String)> = request
                    .headers()
                    .iter()
                    .map(|h| {
                        (
                            h.field.as_str().as_str().to_string(),
                            h.value.as_str().to_string(),
                        )
                    })
                    .collect();
                let cap = request.body_length().unwrap_or(64 * 1024);
                let mut buf = Vec::new();
                let mut limited = Read::take(request.as_reader(), cap as u64);
                let _ = Read::read_to_end(&mut limited, &mut buf);
                let captured = Captured {
                    method,
                    path,
                    headers,
                    body: String::from_utf8_lossy(&buf).into_owned(),
                };
                recorded
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(captured);
                let resp = Response::from_string(body.clone())
                    .with_status_code(StatusCode(status))
                    .with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .expect("header"),
                    );
                let _ = request.respond(resp);
            }
            Ok(None) => {}
            Err(_) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }
}

fn test_tls() -> (SslConfig, Vec<u8>) {
    let params = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).expect("san");
    let key = RcgenKey::generate().expect("key");
    let cert = params.self_signed(&key).expect("self-signed");
    let ssl = SslConfig {
        certificate: cert.pem().into_bytes(),
        private_key: key.serialize_pem().into_bytes(),
    };
    (ssl, cert.der().as_ref().to_vec())
}

fn method_str(method: &Method) -> String {
    match method {
        Method::Get => "GET".into(),
        Method::Post => "POST".into(),
        Method::Put => "PUT".into(),
        Method::Delete => "DELETE".into(),
        Method::Head => "HEAD".into(),
        Method::Options => "OPTIONS".into(),
        Method::Patch => "PATCH".into(),
        other => other.to_string(),
    }
}
