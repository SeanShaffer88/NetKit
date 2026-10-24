//! Platform layer: HTTP(S) transport via WinHTTP on Windows, plus
//! the atomic-replace primitive downloads finalize with.
//!
//! This generalizes UpdateKit's hand-rolled WinHTTP download
//! layer (`uk_download`) into the one reviewed transport for the
//! whole family — with three deliberate differences:
//!
//! - Redirects are NEVER followed here. WinHTTP's redirect
//!   policy is pinned to NEVER on every request; the executor in
//!   lib.rs owns redirect policy (downgrade refusal, credential
//!   stripping, hop limit) and sees every 3xx itself.
//! - Requests carry any method, headers, and body — not just GET.
//! - The body is streamed through the caller's sink as it
//!   arrives, so the size cap aborts mid-stream.
//!
//! TLS certificate validation is WinHTTP's, with its defaults.
//! There is intentionally NO code path here — no option, flag, or
//! security-flag override — that weakens it: WINHTTP_FLAG_SECURE
//! is set for https and SECURITY_FLAG_IGNORE_* is never used.
//!
//! On non-Windows targets the transport reports
//! NK_ERR_NOT_SUPPORTED so the pure logic and the FFI contract
//! stay testable anywhere; the transport itself is then exercised
//! end-to-end by CI on windows-latest against a loopback server
//! (tests/loopback.rs). Public-internet HTTPS is not CI-tested.
//!
//! Every extern block carries #[link(name = "...")] — without it
//! the build fails at LINK time with LNK2019, which check/clippy
//! cannot catch; CI's real build can.

use crate::{NkResult, RawResponse, Transport, TransportRequest, ERR_PLATFORM};
use std::path::Path;

/// The production transport used by `nk_request` / `request_json`.
pub struct PlatformTransport;

impl Transport for PlatformTransport {
    fn round_trip(
        &self,
        req: &TransportRequest,
        sink: &mut dyn FnMut(&[u8]) -> NkResult<()>,
    ) -> NkResult<RawResponse> {
        #[cfg(windows)]
        {
            win::round_trip(req, sink)
        }
        #[cfg(not(windows))]
        {
            let _ = (req, sink);
            Err((
                crate::ERR_NOT_SUPPORTED,
                "HTTP transport is only available on Windows (WinHTTP) in v0.1".into(),
            ))
        }
    }
}

/// Atomically replace `target` with the fully-written `part`
/// file (same directory, so same volume). Windows:
/// MoveFileExW with REPLACE_EXISTING | WRITE_THROUGH. Elsewhere:
/// rename(2), which replaces atomically on POSIX.
pub fn atomic_replace(part: &Path, target: &Path) -> NkResult<()> {
    #[cfg(windows)]
    {
        win::move_replace(part, target)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(part, target).map_err(|e| {
            (
                ERR_PLATFORM,
                format!(
                    "cannot rename '{}' over '{}': {e}",
                    part.display(),
                    target.display()
                ),
            )
        })
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use crate::ERR_TIMEOUT;
    use std::ffi::c_void;
    use std::time::{Duration, Instant};

    type HInternet = *mut c_void;

    #[link(name = "winhttp")]
    extern "system" {
        fn WinHttpOpen(
            agent: *const u16,
            access_type: u32,
            proxy_name: *const u16,
            proxy_bypass: *const u16,
            flags: u32,
        ) -> HInternet;
        fn WinHttpSetTimeouts(
            h: HInternet,
            resolve: i32,
            connect: i32,
            send: i32,
            recv: i32,
        ) -> i32;
        fn WinHttpConnect(h: HInternet, server: *const u16, port: u16, reserved: u32) -> HInternet;
        fn WinHttpOpenRequest(
            connect: HInternet,
            verb: *const u16,
            object: *const u16,
            version: *const u16,
            referrer: *const u16,
            accept_types: *const *const u16,
            flags: u32,
        ) -> HInternet;
        fn WinHttpSetOption(h: HInternet, option: u32, buffer: *const c_void, len: u32) -> i32;
        fn WinHttpSendRequest(
            h: HInternet,
            headers: *const u16,
            headers_len: u32,
            optional: *const c_void,
            optional_len: u32,
            total_len: u32,
            context: usize,
        ) -> i32;
        fn WinHttpReceiveResponse(h: HInternet, reserved: *mut c_void) -> i32;
        fn WinHttpQueryHeaders(
            h: HInternet,
            info_level: u32,
            name: *const u16,
            buffer: *mut c_void,
            len: *mut u32,
            index: *mut u32,
        ) -> i32;
        fn WinHttpQueryDataAvailable(h: HInternet, bytes: *mut u32) -> i32;
        fn WinHttpReadData(h: HInternet, buffer: *mut c_void, want: u32, got: *mut u32) -> i32;
        fn WinHttpCloseHandle(h: HInternet) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
    const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
    const WINHTTP_OPTION_REDIRECT_POLICY: u32 = 88;
    /// The executor owns redirects; the transport must surface
    /// 3xx responses, never follow them.
    const WINHTTP_OPTION_REDIRECT_POLICY_NEVER: u32 = 0;
    const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
    const WINHTTP_QUERY_RAW_HEADERS_CRLF: u32 = 22;
    const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const ERROR_WINHTTP_TIMEOUT: u32 = 12002;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    const READ_CHUNK: usize = 64 * 1024;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_no_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn last_err(what: &str) -> (i32, String) {
        let code = unsafe { GetLastError() };
        if code == ERROR_WINHTTP_TIMEOUT {
            (ERR_TIMEOUT, format!("{what} timed out (WinHTTP 12002)"))
        } else {
            (
                ERR_PLATFORM,
                format!("{what} failed (WinHTTP error {code})"),
            )
        }
    }

    fn timeout_i32(ms: u64) -> i32 {
        if ms == 0 {
            -1 // WinHttpSetTimeouts: -1 means no timeout.
        } else {
            ms.min(i32::MAX as u64) as i32
        }
    }

    struct Session {
        session: HInternet,
        connect: HInternet,
        request: HInternet,
    }

    impl Drop for Session {
        fn drop(&mut self) {
            unsafe {
                if !self.request.is_null() {
                    WinHttpCloseHandle(self.request);
                }
                if !self.connect.is_null() {
                    WinHttpCloseHandle(self.connect);
                }
                if !self.session.is_null() {
                    WinHttpCloseHandle(self.session);
                }
            }
        }
    }

    pub fn round_trip(
        req: &TransportRequest,
        sink: &mut dyn FnMut(&[u8]) -> NkResult<()>,
    ) -> NkResult<RawResponse> {
        let started = Instant::now();
        let deadline = if req.timeout_ms_total > 0 {
            Some(started + Duration::from_millis(req.timeout_ms_total))
        } else {
            None
        };
        let agent = wide("NetKit/0.1");
        let session = unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if session.is_null() {
            return Err(last_err("WinHttpOpen"));
        }
        let mut s = Session {
            session,
            connect: std::ptr::null_mut(),
            request: std::ptr::null_mut(),
        };
        // Resolve/connect bounded by the connect timeout;
        // send/receive by the total timeout.
        unsafe {
            WinHttpSetTimeouts(
                session,
                timeout_i32(req.timeout_ms_connect),
                timeout_i32(req.timeout_ms_connect),
                timeout_i32(req.timeout_ms_total),
                timeout_i32(req.timeout_ms_total),
            );
        }
        let host = wide(&req.url.host);
        s.connect = unsafe { WinHttpConnect(session, host.as_ptr(), req.url.port, 0) };
        if s.connect.is_null() {
            return Err(last_err("WinHttpConnect"));
        }
        let verb = wide(req.method.as_str());
        let path = wide(&req.url.path);
        s.request = unsafe {
            WinHttpOpenRequest(
                s.connect,
                verb.as_ptr(),
                path.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                if req.url.secure {
                    WINHTTP_FLAG_SECURE
                } else {
                    0
                },
            )
        };
        if s.request.is_null() {
            return Err(last_err("WinHttpOpenRequest"));
        }
        // Pin redirect policy to NEVER (see module docs). NOTE:
        // deliberately NO WinHttpSetOption call anywhere adjusts
        // TLS security flags — certificate validation keeps the
        // platform defaults, unconditionally.
        let policy: u32 = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        unsafe {
            WinHttpSetOption(
                s.request,
                WINHTTP_OPTION_REDIRECT_POLICY,
                &policy as *const u32 as *const c_void,
                4,
            );
        }
        // One header block: "Name: value\r\n" per header.
        let mut block = String::new();
        for (k, v) in &req.headers {
            block.push_str(k);
            block.push_str(": ");
            block.push_str(v);
            block.push_str("\r\n");
        }
        let headers_w = wide_no_nul(&block);
        let (hptr, hlen) = if headers_w.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (headers_w.as_ptr(), headers_w.len() as u32)
        };
        let sent = unsafe {
            WinHttpSendRequest(
                s.request,
                hptr,
                hlen,
                if req.body.is_empty() {
                    std::ptr::null()
                } else {
                    req.body.as_ptr() as *const c_void
                },
                req.body.len() as u32,
                req.body.len() as u32,
                0,
            )
        };
        if sent == 0 {
            return Err(last_err("WinHttpSendRequest"));
        }
        if unsafe { WinHttpReceiveResponse(s.request, std::ptr::null_mut()) } == 0 {
            return Err(last_err("WinHttpReceiveResponse"));
        }
        let mut status: u32 = 0;
        let mut len: u32 = 4;
        if unsafe {
            WinHttpQueryHeaders(
                s.request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                std::ptr::null(),
                &mut status as *mut u32 as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_err("WinHttpQueryHeaders(status)"));
        }
        let headers = query_raw_headers(s.request)?;
        // Stream the body through the sink. A sink error (size
        // cap) aborts the read immediately and propagates
        // unchanged — dropping the session closes the handles.
        loop {
            if let Some(d) = deadline {
                if Instant::now() > d {
                    return Err((
                        ERR_TIMEOUT,
                        format!(
                            "request exceeded timeout_ms_total ({})",
                            req.timeout_ms_total
                        ),
                    ));
                }
            }
            let mut avail: u32 = 0;
            if unsafe { WinHttpQueryDataAvailable(s.request, &mut avail) } == 0 {
                return Err(last_err("WinHttpQueryDataAvailable"));
            }
            if avail == 0 {
                break;
            }
            let want = (avail as usize).min(READ_CHUNK) as u32;
            let mut buf = vec![0u8; want as usize];
            let mut got: u32 = 0;
            if unsafe {
                WinHttpReadData(s.request, buf.as_mut_ptr() as *mut c_void, want, &mut got)
            } == 0
            {
                return Err(last_err("WinHttpReadData"));
            }
            if got == 0 {
                break;
            }
            buf.truncate(got as usize);
            sink(&buf)?;
        }
        Ok(RawResponse {
            status: status as u16,
            headers,
        })
    }

    fn query_raw_headers(request: HInternet) -> NkResult<Vec<(String, String)>> {
        let mut len: u32 = 0;
        let first = unsafe {
            WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
            )
        };
        if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || len == 0 {
            // No headers is not fatal (should not happen after a
            // response), but a real failure should be visible.
            if first == 0 && len == 0 {
                return Err(last_err("WinHttpQueryHeaders(raw)"));
            }
            return Ok(Vec::new());
        }
        let mut buf = vec![0u16; (len as usize) / 2];
        if unsafe {
            WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_err("WinHttpQueryHeaders(raw)"));
        }
        let text = String::from_utf16_lossy(&buf);
        let mut out: Vec<(String, String)> = Vec::new();
        for (i, line) in text.split("\r\n").enumerate() {
            if i == 0 {
                continue; // status line ("HTTP/1.1 200 OK")
            }
            if line.is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                out.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
        Ok(out)
    }

    pub fn move_replace(part: &Path, target: &Path) -> NkResult<()> {
        let p = wide(&part.to_string_lossy());
        let t = wide(&target.to_string_lossy());
        let ok = unsafe {
            MoveFileExW(
                p.as_ptr(),
                t.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err((
                ERR_PLATFORM,
                format!(
                    "cannot rename '{}' over '{}' (Win32 error {code})",
                    part.display(),
                    target.display()
                ),
            ));
        }
        Ok(())
    }
}
