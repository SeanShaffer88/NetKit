//! NetKit — a hardened HTTP(S) client behind one clean C ABI.
//!
//! Every consumer in the family used to hand-roll its own WinHTTP
//! transport (UpdateKit's `uk_download` is the one this kit
//! generalizes), and each re-decided the same policy questions —
//! usually unsafely. NetKit makes those decisions ONCE, here:
//!
//! - HTTPS is required unless the caller opts in to plain HTTP
//!   per request (`"allow_http": true`). There is NO option —
//!   config key, flag, or otherwise — to disable TLS certificate
//!   verification. That is permanent, not a missing feature.
//! - Redirects are followed by the executor in this file, never
//!   by the transport: https → http downgrades are refused,
//!   Authorization/Cookie never cross origins, hop-by-hop
//!   headers are stripped, and the hop limit is enforced.
//! - Retries apply only to idempotent methods (POST is never
//!   auto-retried), with deterministic-in-the-core backoff.
//! - The response size cap is enforced WHILE streaming: the
//!   transport is told to stop the moment the cap is exceeded,
//!   never after buffering the whole body.
//! - Downloads land in `<path>.part`, are fsynced, hash-verified
//!   when a digest is configured, and atomically renamed over the
//!   target. A failed download leaves no file behind.
//!
//! The policy core (URL handling, config, redirect/retry engines)
//! is platform-free and fully unit-tested; only the transport in
//! `platform` touches the OS (WinHTTP on Windows). The executor
//! takes its clock-dependent pieces (jitter seed, sleeping) as
//! parameters, so tests are deterministic: no wall clock, no RNG
//! in the core.

pub mod ffi;
pub mod json;
pub mod platform;
pub mod sha256;

use sha256::Sha256;
use std::io::Write as _;
use std::path::PathBuf;

pub const VERSION: &str = "0.1.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;

// Error codes (mirror include/netkit.h). 0–6 are the shared
// family set; 7–14 are NetKit extensions in the ArchiveKit /
// UpdateKit precedent (PARSE matches ProcessKit's 7).
pub const NK_OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = 1;
pub const ERR_NOT_SUPPORTED: i32 = 2;
pub const ERR_NOT_FOUND: i32 = 3;
pub const ERR_ACCESS_DENIED: i32 = 4;
pub const ERR_PLATFORM: i32 = 5;
pub const ERR_INTERNAL: i32 = 6;
/// Config is not valid JSON, has an unknown key, or duplicates a key.
pub const ERR_PARSE: i32 = 7;
/// Body/file bytes do not match the configured SHA-256.
pub const ERR_DIGEST: i32 = 8;
/// A redirect tried to downgrade https → http. Always refused.
pub const ERR_REDIRECT_DOWNGRADE: i32 = 9;
/// The redirect chain exceeded `max_redirects`.
pub const ERR_TOO_MANY_REDIRECTS: i32 = 10;
/// The response exceeded `max_bytes` while streaming.
pub const ERR_TOO_LARGE: i32 = 11;
/// The caller's result buffer is too small (nk_request/nk_download).
pub const ERR_BUFFER_TOO_SMALL: i32 = 12;
/// A connect/send/receive/total timeout fired.
pub const ERR_TIMEOUT: i32 = 13;
/// The URL failed validation (scheme, userinfo, host, port).
pub const ERR_URL: i32 = 14;

/// The crate-wide result: failures carry a stable code + message,
/// rendered at the FFI boundary into the thread-local last error.
pub type NkResult<T> = Result<T, (i32, String)>;

pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_REDIRECTS: u32 = 5;
pub const DEFAULT_RETRIES: u32 = 2;
pub const DEFAULT_TIMEOUT_MS_TOTAL: u64 = 30_000;
pub const DEFAULT_TIMEOUT_MS_CONNECT: u64 = 10_000;
/// Retry-After is honored up to this cap, in milliseconds.
pub const RETRY_AFTER_CAP_MS: u64 = 30_000;
pub const BACKOFF_BASE_MS: u64 = 200;

// ---------------------------------------------------------------- URL

/// A parsed, validated http(s) URL. The host is stored lowercased
/// (DNS is case-insensitive; normalization keeps origin compares
/// honest). IPv6 literal hosts are not supported in v0.1.
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    /// Path + optional "?query". Always starts with '/'.
    pub path: String,
}

impl Url {
    pub fn parse(raw: &str) -> NkResult<Url> {
        if raw.is_empty() {
            return Err((ERR_URL, "URL is empty".into()));
        }
        if raw.chars().any(|c| c.is_control() || c == ' ') {
            return Err((
                ERR_URL,
                format!("URL contains whitespace/control characters: '{raw}'"),
            ));
        }
        // Fragments are never sent to a server; drop before parsing.
        let raw = raw.split('#').next().unwrap_or(raw);
        let scheme_end = raw.find("://").ok_or_else(|| {
            (
                ERR_URL,
                format!("URL must start with http:// or https://: '{raw}'"),
            )
        })?;
        let scheme = &raw[..scheme_end];
        let secure = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return Err((
                ERR_URL,
                format!("only http:// and https:// URLs are supported: '{raw}'"),
            ));
        };
        let rest = &raw[scheme_end + 3..];
        let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        let path = match &rest[auth_end..] {
            "" => "/".to_string(),
            p if p.starts_with('?') => format!("/{p}"),
            p => p.to_string(),
        };
        if authority.is_empty() {
            return Err((ERR_URL, format!("URL has no host: '{raw}'")));
        }
        if authority.contains('@') {
            return Err((
                ERR_URL,
                format!("URLs with userinfo (user@host) are rejected: '{raw}'"),
            ));
        }
        if authority.contains('[') || authority.contains(']') {
            return Err((
                ERR_URL,
                format!("IPv6 literal hosts are not supported in v0.1: '{raw}'"),
            ));
        }
        let (host_raw, port) = match authority.rfind(':') {
            Some(i) => {
                let p = &authority[i + 1..];
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err((ERR_URL, format!("bad port in URL: '{raw}'")));
                }
                let n: u32 = p
                    .parse()
                    .map_err(|_| (ERR_URL, format!("bad port in URL: '{raw}'")))?;
                if n == 0 || n > 65535 {
                    return Err((ERR_URL, format!("port out of range in URL: '{raw}'")));
                }
                (&authority[..i], n as u16)
            }
            None => (authority, if secure { 443 } else { 80 }),
        };
        if host_raw.is_empty() {
            return Err((ERR_URL, format!("URL has no host: '{raw}'")));
        }
        if !host_raw.is_ascii() {
            return Err((
                ERR_URL,
                format!(
                    "non-ASCII host '{host_raw}': NetKit does not resolve IDN — use the punycode (xn--) form"
                ),
            ));
        }
        if !host_raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        {
            return Err((ERR_URL, format!("invalid characters in host: '{raw}'")));
        }
        Ok(Url {
            secure,
            host: host_raw.to_lowercase(),
            port,
            path,
        })
    }

    pub fn default_port(&self) -> u16 {
        if self.secure {
            443
        } else {
            80
        }
    }

    /// Origin identity: scheme + host + effective port.
    pub fn same_origin(&self, other: &Url) -> bool {
        self.secure == other.secure && self.host == other.host && self.port == other.port
    }

    /// Resolve a redirect `Location` value against this URL
    /// (RFC 3986 §5.3, restricted to http/https targets).
    pub fn resolve(&self, location: &str) -> NkResult<Url> {
        let loc = location.trim();
        if loc.is_empty() {
            return Ok(self.clone());
        }
        // Absolute URI (has a scheme): only http/https may result.
        if let Some(i) = loc.find(':') {
            let cand = &loc[..i];
            if !cand.is_empty()
                && cand
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
                && cand
                    .bytes()
                    .next()
                    .map(|b| b.is_ascii_alphabetic())
                    .unwrap_or(false)
            {
                if cand.eq_ignore_ascii_case("http") || cand.eq_ignore_ascii_case("https") {
                    return Url::parse(loc);
                }
                return Err((
                    ERR_URL,
                    format!("redirect to non-HTTP scheme '{cand}:' refused"),
                ));
            }
        }
        if let Some(rest) = loc.strip_prefix("//") {
            let scheme = if self.secure { "https" } else { "http" };
            return Url::parse(&format!("{scheme}://{rest}"));
        }
        let (loc_path, loc_query) = split_query(loc);
        let mut out = self.clone();
        if loc.starts_with('/') {
            out.path = with_query(&remove_dot_segments(loc_path), loc_query);
        } else if loc.starts_with('?') {
            let base_path = self.path.split('?').next().unwrap_or("/");
            out.path = format!("{base_path}{loc}");
        } else if loc_path.is_empty() {
            out.path = with_query(self.path.split('?').next().unwrap_or("/"), loc_query);
        } else {
            let base_path = self.path.split('?').next().unwrap_or("/");
            let dir = match base_path.rfind('/') {
                Some(i) => &base_path[..=i],
                None => "/",
            };
            out.path = with_query(&remove_dot_segments(&format!("{dir}{loc_path}")), loc_query);
        }
        Ok(out)
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = if self.secure { "https" } else { "http" };
        if self.port == self.default_port() {
            write!(f, "{scheme}://{}{}", self.host, self.path)
        } else {
            write!(f, "{scheme}://{}:{}{}", self.host, self.port, self.path)
        }
    }
}

fn split_query(s: &str) -> (&str, Option<&str>) {
    match s.find('?') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

fn with_query(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

/// RFC 3986 §5.2.4 dot-segment removal.
fn remove_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let trailing_slash = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut result = format!("/{}", out.join("/"));
    if trailing_slash && !result.ends_with('/') {
        result.push('/');
    }
    result
}

// ------------------------------------------------------------- method

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
}

impl Method {
    pub fn parse(s: &str) -> NkResult<Method> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(Method::Get),
            "HEAD" => Ok(Method::Head),
            "POST" => Ok(Method::Post),
            "PUT" => Ok(Method::Put),
            "DELETE" => Ok(Method::Delete),
            _ => Err((
                ERR_INVALID_ARG,
                format!("unsupported method '{s}' (GET, HEAD, POST, PUT, DELETE)"),
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }

    /// POST is the only non-idempotent method NetKit speaks; it
    /// is never auto-retried or replayed by the retry engine.
    pub fn is_idempotent(&self) -> bool {
        !matches!(self, Method::Post)
    }
}

// ------------------------------------------------------------- config

#[derive(Debug, Clone)]
pub struct Config {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    /// Fully materialized request body (a `body_file` is read
    /// once, up front, so retries and 307/308 redirects can
    /// replay it).
    pub body: Vec<u8>,
    /// Per-attempt budget for connect+send+receive, enforced by
    /// the transport. 0 = no total cap.
    pub timeout_ms_total: u64,
    pub timeout_ms_connect: u64,
    pub max_bytes: u64,
    pub max_redirects: u32,
    pub retries: u32,
    pub allow_http: bool,
    pub sha256: Option<String>,
    pub download_to: Option<String>,
}

const CONFIG_KEYS: &[&str] = &[
    "method",
    "url",
    "headers",
    "body",
    "body_file",
    "timeout_ms_total",
    "timeout_ms_connect",
    "max_bytes",
    "max_redirects",
    "retries",
    "allow_http",
    "sha256",
    "download_to",
];

/// A valid HTTP header name (RFC 9110 token).
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn cfg_req_str(v: &json::Value, key: &str) -> NkResult<String> {
    match v.get(key) {
        Some(json::Value::Str(s)) => Ok(s.clone()),
        Some(other) => Err((
            ERR_PARSE,
            format!("\"{key}\" must be a string, got {}", other.type_name()),
        )),
        None => Err((ERR_PARSE, format!("\"{key}\" is required"))),
    }
}

fn cfg_opt_str(v: &json::Value, key: &str) -> NkResult<Option<String>> {
    match v.get(key) {
        None | Some(json::Value::Null) => Ok(None),
        Some(json::Value::Str(s)) => Ok(Some(s.clone())),
        Some(other) => Err((
            ERR_PARSE,
            format!("\"{key}\" must be a string, got {}", other.type_name()),
        )),
    }
}

fn cfg_opt_bool(v: &json::Value, key: &str, default: bool) -> NkResult<bool> {
    match v.get(key) {
        None | Some(json::Value::Null) => Ok(default),
        Some(json::Value::Bool(b)) => Ok(*b),
        Some(other) => Err((
            ERR_PARSE,
            format!("\"{key}\" must be a boolean, got {}", other.type_name()),
        )),
    }
}

fn cfg_opt_u64(v: &json::Value, key: &str, default: u64) -> NkResult<u64> {
    match v.get(key) {
        None | Some(json::Value::Null) => Ok(default),
        Some(n) => match n.as_i64() {
            Some(i) if i >= 0 => Ok(i as u64),
            _ => Err((
                ERR_PARSE,
                format!("\"{key}\" must be a non-negative integer"),
            )),
        },
    }
}

fn cfg_opt_u32(v: &json::Value, key: &str, default: u32) -> NkResult<u32> {
    let n = cfg_opt_u64(v, key, default as u64)?;
    u32::try_from(n).map_err(|_| (ERR_PARSE, format!("\"{key}\" is too large")))
}

pub fn parse_config(text: &str) -> NkResult<Config> {
    let v = json::parse(text).map_err(|e| (ERR_PARSE, format!("config is not valid JSON: {e}")))?;
    if v.as_object().is_none() {
        return Err((ERR_PARSE, "config must be a JSON object".into()));
    }
    for key in v.keys() {
        if !CONFIG_KEYS.contains(&key) {
            return Err((ERR_PARSE, format!("unknown config key \"{key}\"")));
        }
    }

    let method = match cfg_opt_str(&v, "method")? {
        Some(m) => Method::parse(&m)?,
        None => Method::Get,
    };
    let url = Url::parse(&cfg_req_str(&v, "url")?)?;

    let mut headers: Vec<(String, String)> = Vec::new();
    match v.get("headers") {
        None | Some(json::Value::Null) => {}
        Some(json::Value::Object(pairs)) => {
            for (name, val) in pairs {
                let val = val.as_str().ok_or((
                    ERR_PARSE,
                    format!("header \"{name}\" must have a string value"),
                ))?;
                if !valid_header_name(name) {
                    return Err((ERR_INVALID_ARG, format!("invalid header name \"{name}\"")));
                }
                if val.chars().any(|c| c.is_control() && c != '\t') {
                    return Err((
                        ERR_INVALID_ARG,
                        format!(
                            "header \"{name}\" value contains control characters (CR/LF injection refused)"
                        ),
                    ));
                }
                headers.push((name.clone(), val.to_string()));
            }
        }
        Some(other) => {
            return Err((
                ERR_PARSE,
                format!("\"headers\" must be an object, got {}", other.type_name()),
            ))
        }
    }

    let body_str = cfg_opt_str(&v, "body")?;
    let body_file = cfg_opt_str(&v, "body_file")?;
    let body = match (body_str, body_file) {
        (Some(_), Some(_)) => {
            return Err((
                ERR_INVALID_ARG,
                "\"body\" and \"body_file\" are mutually exclusive".into(),
            ))
        }
        (Some(s), None) => s.into_bytes(),
        (None, Some(path)) => std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                (ERR_NOT_FOUND, format!("body_file not found: '{path}'"))
            } else {
                (ERR_PLATFORM, format!("cannot read body_file '{path}': {e}"))
            }
        })?,
        (None, None) => Vec::new(),
    };

    let cfg = Config {
        method,
        url,
        headers,
        body,
        timeout_ms_total: cfg_opt_u64(&v, "timeout_ms_total", DEFAULT_TIMEOUT_MS_TOTAL)?,
        timeout_ms_connect: cfg_opt_u64(&v, "timeout_ms_connect", DEFAULT_TIMEOUT_MS_CONNECT)?,
        max_bytes: cfg_opt_u64(&v, "max_bytes", DEFAULT_MAX_BYTES)?,
        max_redirects: cfg_opt_u32(&v, "max_redirects", DEFAULT_MAX_REDIRECTS)?,
        retries: cfg_opt_u32(&v, "retries", DEFAULT_RETRIES)?,
        allow_http: cfg_opt_bool(&v, "allow_http", false)?,
        sha256: match cfg_opt_str(&v, "sha256")? {
            Some(h) => {
                if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err((
                        ERR_INVALID_ARG,
                        "\"sha256\" must be 64 hex characters".into(),
                    ));
                }
                Some(h.to_lowercase())
            }
            None => None,
        },
        download_to: cfg_opt_str(&v, "download_to")?,
    };
    if cfg.max_bytes == 0 {
        return Err((ERR_INVALID_ARG, "\"max_bytes\" must be at least 1".into()));
    }
    if cfg.max_redirects > 100 {
        return Err((
            ERR_INVALID_ARG,
            "\"max_redirects\" must be at most 100".into(),
        ));
    }
    if cfg.retries > 10 {
        return Err((ERR_INVALID_ARG, "\"retries\" must be at most 10".into()));
    }
    if !cfg.url.secure && !cfg.allow_http {
        return Err((
            ERR_INVALID_ARG,
            "http:// URL refused: NetKit requires https unless \"allow_http\": true is set per request"
                .into(),
        ));
    }
    Ok(cfg)
}

// ---------------------------------------------------------- transport

/// One single HTTP exchange — no redirects, no retries. Policy
/// lives in the executor; transports are dumb pipes with timeouts.
pub struct TransportRequest {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timeout_ms_total: u64,
    pub timeout_ms_connect: u64,
}

/// Status + headers of one exchange. The body is delivered
/// through the sink passed to `round_trip` BEFORE this returns.
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

pub trait Transport {
    /// Perform one request. Body bytes arrive through `sink` as
    /// they are received; if the sink returns an error the
    /// transport MUST stop reading and return that same error
    /// unchanged (this is how the size cap aborts mid-stream).
    fn round_trip(
        &self,
        req: &TransportRequest,
        sink: &mut dyn FnMut(&[u8]) -> NkResult<()>,
    ) -> NkResult<RawResponse>;
}

// ------------------------------------------------------------ results

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub final_url: String,
    pub headers: Vec<(String, String)>,
    /// Body bytes. Empty when `file_written` is set (download_to).
    pub body: Vec<u8>,
    pub bytes: u64,
    pub attempts: u32,
    pub redirects: u32,
    /// Hex SHA-256 of the body (or of the downloaded file).
    pub sha256: String,
    pub file_written: Option<String>,
}

impl Response {
    pub fn to_json(&self) -> String {
        // Headers as a JSON object, last-wins on duplicate names
        // (compared case-insensitively, latest casing kept).
        let mut hdrs: Vec<(&String, &String)> = Vec::new();
        for (k, v) in &self.headers {
            if let Some(slot) = hdrs.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
                *slot = (k, v);
            } else {
                hdrs.push((k, v));
            }
        }
        let mut out = String::with_capacity(256 + self.body.len() * 2);
        out.push_str("{\"status\":");
        out.push_str(&self.status.to_string());
        out.push_str(",\"final_url\":\"");
        out.push_str(&json_escape(&self.final_url));
        out.push_str("\",\"headers\":{");
        for (i, (k, v)) in hdrs.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(&json_escape(k));
            out.push_str("\":\"");
            out.push_str(&json_escape(v));
            out.push('"');
        }
        out.push_str("},\"bytes\":");
        out.push_str(&self.bytes.to_string());
        out.push_str(",\"attempts\":");
        out.push_str(&self.attempts.to_string());
        out.push_str(",\"redirects\":");
        out.push_str(&self.redirects.to_string());
        out.push_str(",\"sha256\":\"");
        out.push_str(&self.sha256);
        out.push('"');
        match &self.file_written {
            Some(path) => {
                out.push_str(",\"file_written\":\"");
                out.push_str(&json_escape(path));
                out.push('"');
            }
            None => {
                out.push_str(",\"body_base64\":\"");
                out.push_str(&base64_encode(&self.body));
                out.push('"');
            }
        }
        out.push('}');
        out
    }
}

/// Standard base64 (RFC 4648, with padding).
pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ----------------------------------------------------------- executor

/// Where a hop's response body accumulates: memory, or a
/// `<target>.part` file for downloads. Reset before every attempt
/// so retries and redirects re-stream from scratch.
enum BodyStore {
    Memory {
        buf: Vec<u8>,
        hasher: Sha256,
        len: u64,
    },
    File {
        file: Option<std::fs::File>,
        hasher: Sha256,
        len: u64,
    },
}

impl BodyStore {
    fn reset(&mut self) -> NkResult<()> {
        match self {
            BodyStore::Memory { buf, hasher, len } => {
                buf.clear();
                *hasher = Sha256::new();
                *len = 0;
            }
            BodyStore::File { file, hasher, len } => {
                use std::io::{Seek, SeekFrom};
                let f = file
                    .as_mut()
                    .ok_or((ERR_INTERNAL, "partial file already finalized".to_string()))?;
                f.set_len(0)
                    .and_then(|_| f.seek(SeekFrom::Start(0)))
                    .map_err(|e| (ERR_PLATFORM, format!("cannot reset partial file: {e}")))?;
                *hasher = Sha256::new();
                *len = 0;
            }
        }
        Ok(())
    }

    fn push(&mut self, chunk: &[u8]) -> NkResult<()> {
        match self {
            BodyStore::Memory { buf, hasher, len } => {
                buf.extend_from_slice(chunk);
                hasher.update(chunk);
                *len += chunk.len() as u64;
            }
            BodyStore::File { file, hasher, len } => {
                let f = file
                    .as_mut()
                    .ok_or((ERR_INTERNAL, "partial file already finalized".to_string()))?;
                f.write_all(chunk)
                    .map_err(|e| (ERR_PLATFORM, format!("write to partial download: {e}")))?;
                hasher.update(chunk);
                *len += chunk.len() as u64;
            }
        }
        Ok(())
    }

    fn len(&self) -> u64 {
        match self {
            BodyStore::Memory { len, .. } => *len,
            BodyStore::File { len, .. } => *len,
        }
    }

    fn digest(&self) -> String {
        let hasher = match self {
            BodyStore::Memory { hasher, .. } => hasher,
            BodyStore::File { hasher, .. } => hasher,
        };
        sha256::hex(&hasher.clone().finalize())
    }
}

/// SplitMix64 — tiny deterministic PRNG for backoff jitter. The
/// executor is seeded by the caller (the FFI layer uses the clock;
/// tests use a fixed seed), so the core never touches an RNG.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Delay before retry number `retry_index` (1-based): base
/// 200 ms × 2^(n−1) plus deterministic jitter in [0, base/2].
pub fn backoff_ms(retry_index: u32, rng_state: &mut u64) -> u64 {
    let pow = retry_index.saturating_sub(1).min(20);
    let base = BACKOFF_BASE_MS << pow;
    let jitter = splitmix64(rng_state) % (base / 2 + 1);
    base + jitter
}

/// Parse a `Retry-After` header (seconds form only in v0.1),
/// capped at RETRY_AFTER_CAP_MS. HTTP-date values return None.
pub fn retry_after_ms(headers: &[(String, String)]) -> Option<u64> {
    let v = header_value(headers, "retry-after")?.trim();
    let secs: u64 = v.parse().ok()?;
    Some(secs.saturating_mul(1000).min(RETRY_AFTER_CAP_MS))
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn is_retryable_status(status: u16) -> bool {
    status == 408 || status == 429 || (500..=599).contains(&status)
}

/// Method/body after a redirect of the given status. 303 always
/// becomes GET (except HEAD stays HEAD); 301/302 rewrite POST →
/// GET (the browser convention); 307/308 preserve both.
fn redirect_method(status: u16, method: Method) -> (Method, bool) {
    match status {
        303 => {
            if method == Method::Head {
                (Method::Head, false)
            } else {
                (Method::Get, true)
            }
        }
        301 | 302 => {
            if method == Method::Post {
                (Method::Get, true)
            } else {
                (method, false)
            }
        }
        _ => (method, false),
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers for the next hop: hop-by-hop headers are always
/// stripped (including any header NAMED by the Connection
/// header); on an origin change, Authorization, Cookie and Host
/// are dropped — credentials never cross origins.
fn sanitize_headers(headers: &[(String, String)], cross_origin: bool) -> Vec<(String, String)> {
    let mut named: Vec<String> = Vec::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("connection") {
            for tok in v.split(',') {
                named.push(tok.trim().to_lowercase());
            }
        }
    }
    headers
        .iter()
        .filter(|(k, _)| {
            let lk = k.to_lowercase();
            if HOP_BY_HOP.contains(&lk.as_str()) || named.iter().any(|n| n == &lk) {
                return false;
            }
            if cross_origin && matches!(lk.as_str(), "authorization" | "cookie" | "host") {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

/// Run a configured request to completion: retries, redirects,
/// size cap, digest check, download finalization. `seed` drives
/// backoff jitter; `sleep` is invoked with each inter-retry delay
/// in milliseconds (the FFI layer really sleeps; tests record).
pub fn execute(
    cfg: &Config,
    transport: &dyn Transport,
    seed: u64,
    sleep: &mut dyn FnMut(u64),
) -> NkResult<Response> {
    let part_path: Option<PathBuf> = cfg
        .download_to
        .as_ref()
        .map(|t| PathBuf::from(format!("{t}.part")));
    let mut store = match &part_path {
        Some(p) => BodyStore::File {
            file: Some(std::fs::File::create(p).map_err(|e| {
                (
                    ERR_PLATFORM,
                    format!("cannot create partial download '{}': {e}", p.display()),
                )
            })?),
            hasher: Sha256::new(),
            len: 0,
        },
        None => BodyStore::Memory {
            buf: Vec::new(),
            hasher: Sha256::new(),
            len: 0,
        },
    };
    let result = execute_inner(cfg, transport, seed, sleep, &mut store);
    if result.is_err() {
        if let Some(p) = &part_path {
            let _ = std::fs::remove_file(p);
        }
    }
    result
}

fn execute_inner(
    cfg: &Config,
    transport: &dyn Transport,
    seed: u64,
    sleep: &mut dyn FnMut(u64),
    store: &mut BodyStore,
) -> NkResult<Response> {
    let mut rng = seed;
    let mut method = cfg.method;
    let mut url = cfg.url.clone();
    let mut headers = sanitize_headers(&cfg.headers, false);
    let mut body = cfg.body.clone();
    let mut attempts: u32 = 0;
    let mut redirects: u32 = 0;

    loop {
        // ---- one hop, with retries ------------------------------
        let mut attempt: u32 = 0;
        let raw: RawResponse = loop {
            attempt += 1;
            attempts += 1;
            store.reset()?;
            let mut received: u64 = 0;
            let max = cfg.max_bytes;
            let mut sink = |chunk: &[u8]| -> NkResult<()> {
                if received + chunk.len() as u64 > max {
                    return Err((
                        ERR_TOO_LARGE,
                        format!("response exceeds max_bytes ({max}) — aborted mid-stream"),
                    ));
                }
                received += chunk.len() as u64;
                store.push(chunk)
            };
            let req = TransportRequest {
                method,
                url: url.clone(),
                headers: headers.clone(),
                body: body.clone(),
                timeout_ms_total: cfg.timeout_ms_total,
                timeout_ms_connect: cfg.timeout_ms_connect,
            };
            match transport.round_trip(&req, &mut sink) {
                Ok(raw) => {
                    if is_retryable_status(raw.status)
                        && method.is_idempotent()
                        && attempt <= cfg.retries
                    {
                        let delay = retry_after_ms(&raw.headers)
                            .unwrap_or_else(|| backoff_ms(attempt, &mut rng));
                        sleep(delay);
                        continue;
                    }
                    break raw;
                }
                Err(e) => {
                    // The size cap is a verdict, not a transient
                    // failure: never retried.
                    if e.0 == ERR_TOO_LARGE {
                        return Err(e);
                    }
                    if method.is_idempotent() && attempt <= cfg.retries {
                        let delay = backoff_ms(attempt, &mut rng);
                        sleep(delay);
                        continue;
                    }
                    return Err(e);
                }
            }
        };

        // ---- redirect? ------------------------------------------
        if is_redirect_status(raw.status) {
            if let Some(location) = header_value(&raw.headers, "location") {
                if redirects >= cfg.max_redirects {
                    return Err((
                        ERR_TOO_MANY_REDIRECTS,
                        format!(
                            "redirect limit exceeded (max_redirects = {}) at '{url}'",
                            cfg.max_redirects
                        ),
                    ));
                }
                let next = url.resolve(location)?;
                if url.secure && !next.secure {
                    return Err((
                        ERR_REDIRECT_DOWNGRADE,
                        format!("redirect downgrades https → http ('{url}' → '{next}'); refused"),
                    ));
                }
                let cross = !url.same_origin(&next);
                let (new_method, drop_body) = redirect_method(raw.status, method);
                headers = sanitize_headers(&headers, cross);
                if drop_body {
                    headers.retain(|(k, _)| {
                        !k.eq_ignore_ascii_case("content-length")
                            && !k.eq_ignore_ascii_case("content-type")
                    });
                    body = Vec::new();
                }
                method = new_method;
                url = next;
                redirects += 1;
                continue;
            }
        }

        // ---- final response -------------------------------------
        let digest = store.digest();
        if let Some(expected) = &cfg.sha256 {
            if !digest.eq_ignore_ascii_case(expected) {
                return Err((
                    ERR_DIGEST,
                    format!(
                        "SHA-256 mismatch for '{url}': expected {}, got {}",
                        expected.to_lowercase(),
                        digest
                    ),
                ));
            }
        }
        let bytes = store.len();
        let (resp_body, file_written) = match store {
            BodyStore::Memory { buf, .. } => (std::mem::take(buf), None),
            BodyStore::File { file, .. } => {
                let target = cfg.download_to.clone().unwrap_or_default();
                let part = PathBuf::from(format!("{target}.part"));
                {
                    let f = file
                        .as_mut()
                        .ok_or((ERR_INTERNAL, "partial file already finalized".to_string()))?;
                    f.sync_all().map_err(|e| {
                        (ERR_PLATFORM, format!("cannot fsync partial download: {e}"))
                    })?;
                }
                // Close the handle before renaming — Windows
                // refuses to replace an open file.
                let _ = file.take();
                platform::atomic_replace(&part, &PathBuf::from(&target))?;
                (Vec::new(), Some(target))
            }
        };
        return Ok(Response {
            status: raw.status,
            final_url: url.to_string(),
            headers: raw.headers,
            body: resp_body,
            bytes,
            attempts,
            redirects,
            sha256: digest,
            file_written,
        });
    }
}

// ------------------------------------------------------------ helpers

/// Escape a string for inclusion inside JSON double quotes.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Perform a request described by a JSON config against the real
/// platform transport and return the result JSON. Off Windows the
/// transport reports NK_ERR_NOT_SUPPORTED; policy errors (bad
/// config, bad URL, http without opt-in) are reported everywhere.
pub fn request_json(config_json: &str) -> NkResult<String> {
    let cfg = parse_config(config_json)?;
    let transport = platform::PlatformTransport;
    let seed = clock_seed();
    let mut sleeper = |ms: u64| std::thread::sleep(std::time::Duration::from_millis(ms));
    let resp = execute(&cfg, &transport, seed, &mut sleeper)?;
    Ok(resp.to_json())
}

fn clock_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x853c_49e6_748f_ea9b);
    nanos ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

// -------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    // -- scripted fake transport -----------------------------------
    struct Step {
        status: u16,
        headers: Vec<(String, String)>,
        chunks: Vec<Vec<u8>>,
        error: Option<(i32, String)>,
    }

    fn step(status: u16, headers: Vec<(&str, &str)>, body: &str) -> Step {
        Step {
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            chunks: if body.is_empty() {
                vec![]
            } else {
                vec![body.as_bytes().to_vec()]
            },
            error: None,
        }
    }

    fn ok(body: &str) -> Step {
        step(200, vec![], body)
    }

    fn err_step(code: i32) -> Step {
        Step {
            status: 0,
            headers: vec![],
            chunks: vec![],
            error: Some((code, "scripted transport failure".into())),
        }
    }

    struct Seen {
        method: Method,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    struct Scripted {
        steps: RefCell<VecDeque<Step>>,
        seen: RefCell<Vec<Seen>>,
        sink_error_codes: RefCell<Vec<i32>>,
    }

    impl Scripted {
        fn new(steps: Vec<Step>) -> Scripted {
            Scripted {
                steps: RefCell::new(steps.into()),
                seen: RefCell::new(Vec::new()),
                sink_error_codes: RefCell::new(Vec::new()),
            }
        }
        fn seen(&self) -> std::cell::Ref<'_, Vec<Seen>> {
            self.seen.borrow()
        }
    }

    impl Transport for Scripted {
        fn round_trip(
            &self,
            req: &TransportRequest,
            sink: &mut dyn FnMut(&[u8]) -> NkResult<()>,
        ) -> NkResult<RawResponse> {
            self.seen.borrow_mut().push(Seen {
                method: req.method,
                url: req.url.to_string(),
                headers: req.headers.clone(),
                body: req.body.clone(),
            });
            let step = self
                .steps
                .borrow_mut()
                .pop_front()
                .expect("script exhausted: executor made more requests than scripted");
            if let Some(e) = step.error {
                return Err(e);
            }
            for chunk in &step.chunks {
                if let Err(e) = sink(chunk) {
                    self.sink_error_codes.borrow_mut().push(e.0);
                    return Err(e);
                }
            }
            Ok(RawResponse {
                status: step.status,
                headers: step.headers,
            })
        }
    }

    fn run(cfg: &Config, t: &Scripted) -> (NkResult<Response>, Vec<u64>) {
        let mut sleeps: Vec<u64> = Vec::new();
        let r = execute(cfg, t, 42, &mut |ms| sleeps.push(ms));
        (r, sleeps)
    }

    fn cfg(json: &str) -> Config {
        parse_config(json).unwrap()
    }

    fn has_header(headers: &[(String, String)], name: &str) -> bool {
        headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    // -- URL --------------------------------------------------------

    #[test]
    fn url_parse_matrix() {
        let u = Url::parse("https://Example.COM/a/b?x=1#frag").unwrap();
        assert!(u.secure);
        assert_eq!(u.host, "example.com"); // lowercased, fragment dropped
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/a/b?x=1");
        assert_eq!(u.to_string(), "https://example.com/a/b?x=1");

        let u = Url::parse("http://localhost:8080").unwrap();
        assert!(!u.secure);
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/");
        assert_eq!(u.to_string(), "http://localhost:8080/");

        // Explicit default port normalizes away in display.
        let u = Url::parse("https://example.com:443/x").unwrap();
        assert_eq!(u.to_string(), "https://example.com/x");

        // Query with no path.
        let u = Url::parse("https://example.com?x=1").unwrap();
        assert_eq!(u.path, "/?x=1");
    }

    #[test]
    fn url_rejects() {
        for (raw, why) in [
            ("ftp://example.com/x", "scheme"),
            ("example.com/x", "no scheme"),
            ("https://user@example.com/x", "userinfo"),
            ("https://user:pw@example.com/x", "userinfo"),
            ("https://exämple.com/x", "non-ASCII host"),
            ("https:///x", "empty host"),
            ("https://example.com:0/x", "port 0"),
            ("https://example.com:99999/x", "port range"),
            ("https://example.com:abc/x", "port not numeric"),
            ("https://[::1]/x", "IPv6 literal"),
            ("https://exa mple.com/x", "space"),
            ("", "empty"),
        ] {
            match Url::parse(raw) {
                Err((code, _)) => assert_eq!(code, ERR_URL, "{why}: {raw}"),
                Ok(u) => panic!("{why}: {raw} parsed as {u}"),
            }
        }
    }

    #[test]
    fn url_resolve_cases() {
        let base = Url::parse("https://a.com/dir/page?old=1").unwrap();
        assert_eq!(
            base.resolve("next").unwrap().to_string(),
            "https://a.com/dir/next"
        );
        assert_eq!(
            base.resolve("../up").unwrap().to_string(),
            "https://a.com/up"
        );
        assert_eq!(
            base.resolve("/abs").unwrap().to_string(),
            "https://a.com/abs"
        );
        assert_eq!(
            base.resolve("?q=2").unwrap().to_string(),
            "https://a.com/dir/page?q=2"
        );
        assert_eq!(
            base.resolve("//b.com/x").unwrap().to_string(),
            "https://b.com/x"
        );
        assert_eq!(
            base.resolve("https://c.com/y").unwrap().to_string(),
            "https://c.com/y"
        );
        assert_eq!(
            base.resolve("/a/b/../c").unwrap().to_string(),
            "https://a.com/a/c"
        );
        assert_eq!(
            base.resolve("deep/./x").unwrap().to_string(),
            "https://a.com/dir/deep/x"
        );
        // Non-HTTP absolute targets are refused.
        assert_eq!(base.resolve("ftp://b.com/x").unwrap_err().0, ERR_URL);
        // Downgrade is detectable by the executor (resolve itself
        // happily produces the http URL; execute() refuses).
        assert!(!base.resolve("http://a.com/x").unwrap().secure);
    }

    // -- config ------------------------------------------------------

    #[test]
    fn config_defaults_and_validation() {
        let c = cfg(r#"{"url":"https://example.com/x"}"#);
        assert_eq!(c.method, Method::Get);
        assert_eq!(c.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(c.max_redirects, 5);
        assert_eq!(c.retries, 2);
        assert!(!c.allow_http);
        assert_eq!(c.timeout_ms_total, 30_000);
        assert_eq!(c.timeout_ms_connect, 10_000);

        // http requires the per-request opt-in.
        assert!(parse_config(r#"{"url":"http://example.com/x"}"#).is_err());
        assert!(parse_config(r#"{"url":"http://example.com/x","allow_http":true}"#).is_ok());

        // Unknown key and duplicate key are parse errors.
        assert_eq!(
            parse_config(r#"{"url":"https://e.com","bogus":1}"#)
                .unwrap_err()
                .0,
            ERR_PARSE
        );
        assert_eq!(
            parse_config(r#"{"url":"https://e.com","url":"https://e.com"}"#)
                .unwrap_err()
                .0,
            ERR_PARSE
        );
        // body + body_file conflict.
        assert!(parse_config(r#"{"url":"https://e.com","body":"x","body_file":"y"}"#).is_err());
        // Bad digest shape.
        assert!(parse_config(r#"{"url":"https://e.com","sha256":"xyz"}"#).is_err());
        // CR/LF in a header value is injection: refused.
        assert!(parse_config(
            "{\"url\":\"https://e.com\",\"headers\":{\"X-A\":\"ok\\r\\nInjected: 1\"}}"
        )
        .is_err());
        // Bad header name.
        assert!(parse_config(r#"{"url":"https://e.com","headers":{"Bad Name":"v"}}"#).is_err());
        // Unsupported method.
        assert!(parse_config(r#"{"url":"https://e.com","method":"PATCH"}"#).is_err());
        // Missing url.
        assert_eq!(parse_config(r#"{}"#).unwrap_err().0, ERR_PARSE);
        // Negative cap.
        assert!(parse_config(r#"{"url":"https://e.com","max_bytes":-1}"#).is_err());
        // Case-insensitive method.
        assert_eq!(
            cfg(r#"{"url":"https://e.com","method":"post"}"#).method,
            Method::Post
        );
    }

    // -- redirects ---------------------------------------------------

    #[test]
    fn redirect_303_rewrites_post_to_get() {
        let t = Scripted::new(vec![
            step(303, vec![("Location", "/done")], ""),
            ok("finished"),
        ]);
        let c = cfg(
            r#"{"method":"POST","url":"https://a.com/start","body":"payload","headers":{"Content-Type":"text/plain"}}"#,
        );
        let (r, _) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.redirects, 1);
        assert_eq!(r.attempts, 2);
        assert_eq!(r.final_url, "https://a.com/done");
        assert_eq!(r.body, b"finished");
        let seen = t.seen();
        assert_eq!(seen[0].url, "https://a.com/start");
        assert_eq!(seen[1].url, "https://a.com/done");
        assert_eq!(seen[1].method, Method::Get);
        assert!(seen[1].body.is_empty());
        assert!(!has_header(&seen[1].headers, "content-type"));
    }

    #[test]
    fn redirect_301_post_becomes_get_but_307_preserves() {
        let t = Scripted::new(vec![step(301, vec![("Location", "/new")], ""), ok("")]);
        let c = cfg(r#"{"method":"POST","url":"https://a.com/old","body":"b"}"#);
        let (r, _) = run(&c, &t);
        r.unwrap();
        assert_eq!(t.seen()[1].method, Method::Get);

        let t = Scripted::new(vec![step(307, vec![("Location", "/new")], ""), ok("")]);
        let (r, _) = run(&c, &t);
        r.unwrap();
        let seen = t.seen();
        assert_eq!(seen[1].method, Method::Post);
        assert_eq!(seen[1].body, b"b");
    }

    #[test]
    fn redirect_downgrade_refused() {
        let t = Scripted::new(vec![step(
            302,
            vec![("Location", "http://a.com/insecure")],
            "",
        )]);
        // allow_http is on: the refusal is about the DOWNGRADE,
        // not about http itself.
        let c = cfg(r#"{"url":"https://a.com/start","allow_http":true}"#);
        let (r, _) = run(&c, &t);
        assert_eq!(r.unwrap_err().0, ERR_REDIRECT_DOWNGRADE);
    }

    #[test]
    fn redirect_cross_origin_drops_credentials() {
        let t = Scripted::new(vec![
            step(302, vec![("Location", "https://b.com/x")], ""),
            ok(""),
        ]);
        let c = cfg(
            r#"{"url":"https://a.com/start","headers":{"Authorization":"Bearer s3cret","Cookie":"sid=1","Host":"a.com","X-Keep":"yes","Connection":"X-Drop","X-Drop":"1"}}"#,
        );
        let (r, _) = run(&c, &t);
        r.unwrap();
        let seen = t.seen();
        // Hop-by-hop (incl. Connection-named) headers never leave.
        assert!(!has_header(&seen[0].headers, "x-drop"));
        assert!(!has_header(&seen[0].headers, "connection"));
        let h2 = &seen[1].headers;
        assert!(!has_header(h2, "authorization"));
        assert!(!has_header(h2, "cookie"));
        assert!(!has_header(h2, "host"));
        assert!(has_header(h2, "x-keep"));
    }

    #[test]
    fn redirect_relative_chain_and_limit() {
        let t = Scripted::new(vec![
            step(302, vec![("Location", "step2")], ""),
            step(302, vec![("Location", "/final")], ""),
            ok("landed"),
        ]);
        let c = cfg(r#"{"url":"https://a.com/dir/step1"}"#);
        let (r, _) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.redirects, 2);
        assert_eq!(r.final_url, "https://a.com/final");
        assert_eq!(r.body, b"landed");

        let t = Scripted::new(vec![
            step(302, vec![("Location", "/a")], ""),
            step(302, vec![("Location", "/b")], ""),
            ok("never reached"),
        ]);
        let c = cfg(r#"{"url":"https://a.com/start","max_redirects":1}"#);
        let (r, _) = run(&c, &t);
        assert_eq!(r.unwrap_err().0, ERR_TOO_MANY_REDIRECTS);
    }

    #[test]
    fn redirect_without_location_is_a_final_response() {
        let t = Scripted::new(vec![step(302, vec![], "no location")]);
        let c = cfg(r#"{"url":"https://a.com/x"}"#);
        let (r, _) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.status, 302);
        assert_eq!(r.redirects, 0);
    }

    // -- retries -----------------------------------------------------

    #[test]
    fn retry_post_never_retried() {
        let t = Scripted::new(vec![step(503, vec![], "busy")]);
        let c = cfg(r#"{"method":"POST","url":"https://a.com/submit","body":"x"}"#);
        let (r, sleeps) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.status, 503);
        assert_eq!(r.attempts, 1);
        assert!(sleeps.is_empty());
    }

    #[test]
    fn retry_idempotent_status_then_success() {
        let t = Scripted::new(vec![step(503, vec![], "busy"), ok("recovered")]);
        let c = cfg(r#"{"url":"https://a.com/flaky"}"#);
        let (r, sleeps) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.attempts, 2);
        assert_eq!(r.body, b"recovered");
        // The delay is exactly the core's deterministic backoff
        // for retry #1 under the run's seed.
        let mut rng = 42u64;
        assert_eq!(sleeps, vec![backoff_ms(1, &mut rng)]);
    }

    #[test]
    fn retry_404_not_retried() {
        let t = Scripted::new(vec![step(404, vec![], "nope")]);
        let c = cfg(r#"{"url":"https://a.com/missing"}"#);
        let (r, sleeps) = run(&c, &t);
        assert_eq!(r.unwrap().status, 404);
        assert_eq!(t.seen().len(), 1);
        assert!(sleeps.is_empty());
    }

    #[test]
    fn retry_transport_errors() {
        let t = Scripted::new(vec![err_step(ERR_PLATFORM), ok("second try")]);
        let c = cfg(r#"{"url":"https://a.com/flaky"}"#);
        let (r, _) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.attempts, 2);
        assert_eq!(r.body, b"second try");

        // Exhaustion returns the last transport error.
        let t = Scripted::new(vec![err_step(ERR_PLATFORM), err_step(ERR_TIMEOUT)]);
        let c = cfg(r#"{"url":"https://a.com/down","retries":1}"#);
        let (r, _) = run(&c, &t);
        assert_eq!(r.unwrap_err().0, ERR_TIMEOUT);
        assert_eq!(t.seen().len(), 2);
    }

    #[test]
    fn retry_after_seconds_honored_and_capped() {
        let t = Scripted::new(vec![step(429, vec![("Retry-After", "2")], ""), ok("")]);
        let c = cfg(r#"{"url":"https://a.com/limited"}"#);
        let (_, sleeps) = run(&c, &t);
        assert_eq!(sleeps, vec![2000]);

        let t = Scripted::new(vec![step(503, vec![("Retry-After", "999")], ""), ok("")]);
        let (_, sleeps) = run(&c, &t);
        assert_eq!(sleeps, vec![RETRY_AFTER_CAP_MS]);

        // HTTP-date form is not parsed in v0.1 → backoff fallback.
        let t = Scripted::new(vec![
            step(
                503,
                vec![("Retry-After", "Wed, 21 Oct 2099 07:28:00 GMT")],
                "",
            ),
            ok(""),
        ]);
        let (_, sleeps) = run(&c, &t);
        let mut rng = 42u64;
        assert_eq!(sleeps, vec![backoff_ms(1, &mut rng)]);
    }

    #[test]
    fn backoff_is_deterministic_and_bounded() {
        let seq = |seed: u64| {
            let mut s = seed;
            (1..=5).map(|i| backoff_ms(i, &mut s)).collect::<Vec<_>>()
        };
        assert_eq!(seq(7), seq(7));
        assert_ne!(seq(7), seq(8));
        let mut s = 7u64;
        for i in 1..=5u32 {
            let base = BACKOFF_BASE_MS << (i - 1);
            let d = backoff_ms(i, &mut s);
            assert!((base..=base + base / 2).contains(&d), "attempt {i}: {d}");
        }
    }

    // -- size cap / digest -------------------------------------------

    #[test]
    fn size_cap_aborts_mid_stream() {
        let mut s = step(200, vec![], "");
        s.chunks = vec![vec![b'x'; 100], vec![b'y'; 100], vec![b'z'; 100]];
        let t = Scripted::new(vec![s]);
        let c = cfg(r#"{"url":"https://a.com/big","max_bytes":250,"retries":0}"#);
        let (r, _) = run(&c, &t);
        assert_eq!(r.unwrap_err().0, ERR_TOO_LARGE);
        // The transport was told to stop (sink error) on chunk 3,
        // and TOO_LARGE is never retried (one request seen).
        assert_eq!(t.sink_error_codes.borrow().as_slice(), &[ERR_TOO_LARGE]);
        assert_eq!(t.seen().len(), 1);

        // A body exactly at the cap succeeds.
        let mut s = step(200, vec![], "");
        s.chunks = vec![vec![b'x'; 250]];
        let t = Scripted::new(vec![s]);
        let (r, _) = run(&c, &t);
        assert_eq!(r.unwrap().bytes, 250);
    }

    #[test]
    fn digest_checked_for_memory_body() {
        // sha256("abc") — standard vector.
        let good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let t = Scripted::new(vec![ok("abc")]);
        let c = cfg(&format!(r#"{{"url":"https://a.com/f","sha256":"{good}"}}"#));
        let (r, _) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.sha256, good);

        let t = Scripted::new(vec![ok("abc")]);
        let c = cfg(&format!(
            r#"{{"url":"https://a.com/f","sha256":"{}"}}"#,
            "0".repeat(64)
        ));
        let (r, _) = run(&c, &t);
        assert_eq!(r.unwrap_err().0, ERR_DIGEST);
    }

    // -- downloads ----------------------------------------------------

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nk-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn download_writes_file_via_part_and_rename() {
        let dir = temp_dir("dl-ok");
        let target = dir.join("f.bin");
        let target_s = target.to_string_lossy().into_owned();
        let t = Scripted::new(vec![ok("hello")]);
        let c = cfg(&format!(
            r#"{{"url":"https://a.com/f.bin","download_to":"{}"}}"#,
            target_s.replace('\\', "\\\\")
        ));
        let (r, _) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.file_written.as_deref(), Some(target_s.as_str()));
        assert!(r.body.is_empty());
        assert_eq!(r.bytes, 5);
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        assert!(!PathBuf::from(format!("{target_s}.part")).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn download_digest_mismatch_deletes_part() {
        let dir = temp_dir("dl-bad");
        let target = dir.join("f.bin");
        let target_s = target.to_string_lossy().into_owned();
        let t = Scripted::new(vec![ok("hello")]);
        let c = cfg(&format!(
            r#"{{"url":"https://a.com/f.bin","download_to":"{}","sha256":"{}"}}"#,
            target_s.replace('\\', "\\\\"),
            "0".repeat(64)
        ));
        let (r, _) = run(&c, &t);
        assert_eq!(r.unwrap_err().0, ERR_DIGEST);
        assert!(!target.exists());
        assert!(!PathBuf::from(format!("{target_s}.part")).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- combined / result shape --------------------------------------

    #[test]
    fn end_to_end_redirect_then_retry_then_ok() {
        let t = Scripted::new(vec![
            step(302, vec![("Location", "/b")], ""),
            step(503, vec![], "busy"),
            ok("done"),
        ]);
        let c = cfg(r#"{"url":"https://a.com/a"}"#);
        let (r, _) = run(&c, &t);
        let r = r.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.redirects, 1);
        assert_eq!(r.attempts, 3);
        assert_eq!(r.final_url, "https://a.com/b");
        assert_eq!(r.body, b"done");
        let seen = t.seen();
        assert_eq!(seen[0].url, "https://a.com/a");
        assert_eq!(seen[1].url, "https://a.com/b");
        assert_eq!(seen[2].url, "https://a.com/b"); // the 503 retry
    }

    #[test]
    fn response_json_shape_and_header_last_wins() {
        let t = Scripted::new(vec![step(
            200,
            vec![
                ("Set-Cookie", "a=1"),
                ("set-cookie", "b=2"),
                ("Content-Type", "text/plain"),
            ],
            "hi",
        )]);
        let c = cfg(r#"{"url":"https://a.com/x"}"#);
        let (r, _) = run(&c, &t);
        let j = r.unwrap().to_json();
        assert!(j.contains("\"status\":200"), "{j}");
        assert!(j.contains("\"body_base64\":\"aGk=\""), "{j}");
        // Duplicate header: only the last value survives.
        assert!(j.contains("\"set-cookie\":\"b=2\""), "{j}");
        assert!(!j.contains("a=1"), "{j}");
        assert!(j.contains("\"attempts\":1"), "{j}");
    }

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn head_and_delete_methods_pass_through() {
        let t = Scripted::new(vec![ok("")]);
        let c = cfg(r#"{"method":"HEAD","url":"https://a.com/x"}"#);
        let (r, _) = run(&c, &t);
        r.unwrap();
        assert_eq!(t.seen()[0].method, Method::Head);
    }

    #[test]
    fn request_json_policy_errors_are_platform_free() {
        // Bad config fails the same way everywhere.
        assert_eq!(request_json("{not json").unwrap_err().0, ERR_PARSE);
        assert_eq!(
            request_json(r#"{"url":"http://a.com/x"}"#).unwrap_err().0,
            ERR_INVALID_ARG
        );
        // A well-formed https request reaches the transport: off
        // Windows that is NK_ERR_NOT_SUPPORTED.
        #[cfg(not(windows))]
        assert_eq!(
            request_json(r#"{"url":"https://a.com/x"}"#).unwrap_err().0,
            ERR_NOT_SUPPORTED
        );
    }
}
