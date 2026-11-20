//! Loopback HTTPS peer for live-send tests (rustls 0.23).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair as RcgenKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

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
    addr: std::net::SocketAddr,
    join: Option<thread::JoinHandle<()>>,
}

impl HttpsPeer {
    pub fn spawn(status: u16, body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock bind");
        listener
            .set_nonblocking(true)
            .expect("mock nonblocking");
        let addr = listener.local_addr().expect("mock addr");
        let (config, cert_der) = test_tls();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let body = body.to_string();
        let join = {
            let recorded = Arc::clone(&recorded);
            let stop = Arc::clone(&stop);
            thread::spawn(move || serve(listener, config, recorded, stop, status, body))
        };
        Self {
            base_url: format!("https://{addr}"),
            cert_der,
            recorded,
            stop,
            addr,
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
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(80));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    recorded: Arc<Mutex<Vec<Captured>>>,
    stop: Arc<AtomicBool>,
    status: u16,
    body: String,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((tcp, _)) => {
                let _ = tcp.set_nonblocking(false);
                if let Ok(conn) = ServerConnection::new(Arc::clone(&config)) {
                    let mut stream = StreamOwned::new(conn, tcp);
                    if let Ok(captured) = read_request(&mut stream) {
                        recorded
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(captured);
                        let _ = write_response(&mut stream, status, &body);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn test_tls() -> (Arc<ServerConfig>, Vec<u8>) {
    let params = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).expect("san");
    let key = RcgenKey::generate().expect("key");
    let cert = params.self_signed(&key).expect("self-signed");
    let cert_der = cert.der().as_ref().to_vec();
    let certs = vec![CertificateDer::from(cert_der.clone())];
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).expect("pkcs8");
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .expect("tls");
    (Arc::new(cfg), cert_der)
}

fn read_request<R: Read>(r: &mut R) -> std::io::Result<Captured> {
    let (method, path, headers, body) = read_http(r)?;
    Ok(Captured {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn read_http<R: Read>(
    r: &mut R,
) -> std::io::Result<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = r.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    };
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.split("\r\n");
    let req = lines.next().unwrap_or("");
    let mut parts = req.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let url = parts.next().unwrap_or("/").to_string();
    let path = url.split('?').next().unwrap_or(&url).to_string();
    let mut headers = Vec::new();
    let mut content_len = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.parse().unwrap_or(0);
            }
            headers.push((k.to_string(), v.to_string()));
        }
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_len {
        let n = r.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);
    Ok((method, path, headers, body))
}

fn write_response<W: Write>(w: &mut W, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    w.write_all(head.as_bytes())?;
    w.write_all(body.as_bytes())?;
    w.flush()
}
