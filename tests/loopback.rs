//! Loopback end-to-end tests for the REAL WinHTTP transport.
//!
//! Windows only: they spin a std TcpListener HTTP server on
//! 127.0.0.1 and drive NetKit's public `request_json` against it
//! (the pattern UpdateKit proved on windows-latest). This is the
//! transport's real gate — the host suite tests the policy core
//! against a scripted fake, and check/clippy cannot link.
//!
//! HTTPS and public-internet access are NOT exercised here (or
//! anywhere in CI); TLS behavior rests on WinHTTP's platform
//! defaults plus code review. See the README.
#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Server {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn start_server() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let handle = std::thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => handle_conn(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    Server {
        port,
        stop,
        handle: Some(handle),
    }
}

fn handle_conn(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_nonblocking(false);
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let path = loop {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = find(&buf, b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    let first = head.lines().next().unwrap_or("");
                    break first.split_whitespace().nth(1).unwrap_or("/").to_string();
                }
                if buf.len() > 64 * 1024 {
                    return;
                }
            }
            Err(_) => return,
        }
    };
    let (status, reason, location, body, delay) = match path.as_str() {
        "/ok" => (200, "OK", None, "hello-netkit", 0),
        "/chain" => (302, "Found", Some("/ok"), "", 0),
        "/chain2" => (302, "Found", Some("/chain"), "", 0),
        "/missing" => (404, "Not Found", None, "nope", 0),
        "/slow" => (200, "OK", None, "slow-body", 3000),
        _ => (404, "Not Found", None, "unknown", 0),
    };
    if delay > 0 {
        std::thread::sleep(Duration::from_millis(delay));
    }
    let mut resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(loc) = location {
        resp.push_str(&format!("Location: {loc}\r\n"));
    }
    resp.push_str("\r\n");
    resp.push_str(body);
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn config(port: u16, path: &str, extra: &str) -> String {
    format!("{{\"url\":\"http://127.0.0.1:{port}{path}\",\"allow_http\":true{extra}}}")
}

#[test]
fn loopback_ok_200_with_body() {
    let s = start_server();
    let json = net_kit::request_json(&config(s.port, "/ok", "")).unwrap();
    assert!(json.contains("\"status\":200"), "{json}");
    assert!(json.contains("\"bytes\":12"), "{json}");
    // base64("hello-netkit")
    assert!(
        json.contains("\"body_base64\":\"aGVsbG8tbmV0a2l0\""),
        "{json}"
    );
    assert!(json.contains("\"attempts\":1"), "{json}");
}

#[test]
fn loopback_redirect_chain_followed_by_executor() {
    let s = start_server();
    let json = net_kit::request_json(&config(s.port, "/chain2", "")).unwrap();
    assert!(json.contains("\"status\":200"), "{json}");
    assert!(json.contains("\"redirects\":2"), "{json}");
    assert!(
        json.contains(&format!("\"final_url\":\"http://127.0.0.1:{}/ok\"", s.port)),
        "{json}"
    );
}

#[test]
fn loopback_404_is_a_result_not_an_error() {
    let s = start_server();
    let json = net_kit::request_json(&config(s.port, "/missing", "")).unwrap();
    assert!(json.contains("\"status\":404"), "{json}");
    assert!(json.contains("\"attempts\":1"), "{json}"); // 404 is not retried
}

#[test]
fn loopback_slow_response_times_out() {
    let s = start_server();
    let err = net_kit::request_json(&config(
        s.port,
        "/slow",
        ",\"timeout_ms_total\":400,\"retries\":0",
    ))
    .unwrap_err();
    assert_eq!(err.0, net_kit::ERR_TIMEOUT, "{err:?}");
}

#[test]
fn loopback_download_to_file() {
    let s = start_server();
    let dir = std::env::temp_dir().join(format!("nk-loop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("dl.bin");
    let cfg = format!(
        "{{\"url\":\"http://127.0.0.1:{}/ok\",\"allow_http\":true,\"download_to\":\"{}\"}}",
        s.port,
        target.to_string_lossy().replace('\\', "\\\\")
    );
    let json = net_kit::request_json(&cfg).unwrap();
    assert!(json.contains("\"file_written\""), "{json}");
    assert_eq!(std::fs::read(&target).unwrap(), b"hello-netkit");
    assert!(!dir.join("dl.bin.part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
