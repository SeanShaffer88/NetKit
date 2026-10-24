//! C ABI surface — everything declared in include/netkit.h.
//! Conventions:
//! - Result JSON is written into a CALLER-OWNED buffer
//!   (`out_buf`/`out_cap`/`out_len`): on entry *out_len is set
//!   to 0; on success it holds the JSON length in bytes
//!   (excluding the NUL terminator, which is always written when
//!   the buffer fits). If the buffer is too small the call
//!   returns NK_ERR_BUFFER_TOO_SMALL and *out_len holds the
//!   required length — call once with out_cap = 0 to size it.
//! - Failures set a thread-local last-error (code + message)
//!   and return the NK_ERR_* code.
//! - Nothing unwinds across the FFI boundary (catch_unwind
//!   everywhere; release profile also sets panic = "abort").
//! - `nk_free_string` exists for house consistency (results of
//!   this kit use the caller buffer, so it is rarely needed).

// The exported functions ARE the raw-pointer C ABI declared in
// include/netkit.h; pointer validity is the documented contract.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;

use crate::{
    NkResult, ERR_BUFFER_TOO_SMALL, ERR_INTERNAL, ERR_INVALID_ARG, NK_OK, VERSION_MAJOR,
    VERSION_MINOR, VERSION_PATCH,
};

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> =
        RefCell::new((0, CString::new("").unwrap()));
}

pub fn set_error(code: i32, msg: &str) {
    let clean: String = msg.chars().filter(|&c| c != '\0').collect();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = (
            code,
            CString::new(clean).unwrap_or_else(|_| CString::new("error").unwrap()),
        );
    });
}

fn clear_error() {
    set_error(NK_OK, "");
}

fn fail(code: i32, msg: &str) -> c_int {
    set_error(code, msg);
    code as c_int
}

fn panic_code() -> c_int {
    set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
    ERR_INTERNAL as c_int
}

fn guard<T, F: FnOnce() -> T>(f: F) -> std::thread::Result<T> {
    catch_unwind(std::panic::AssertUnwindSafe(f))
}

fn cstr<'a>(ptr: *const c_char, what: &str) -> NkResult<&'a str> {
    if ptr.is_null() {
        return Err((ERR_INVALID_ARG, format!("{what} must not be null")));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| (ERR_INVALID_ARG, format!("{what} must be valid UTF-8")))
}

fn opt_cstr<'a>(ptr: *const c_char, what: &str) -> NkResult<Option<&'a str>> {
    if ptr.is_null() {
        Ok(None)
    } else {
        cstr(ptr, what).map(Some)
    }
}

/// Write `json` (+ NUL) into the caller's buffer per the
/// convention at the top of this file. Returns NK_OK, or
/// NK_ERR_BUFFER_TOO_SMALL with *out_len set to the required
/// byte length. Factored out of nk_request so the buffer
/// contract is unit-testable without a network.
fn write_result(out_buf: *mut c_char, out_cap: usize, out_len: *mut usize, json: &str) -> c_int {
    if out_len.is_null() {
        return fail(ERR_INVALID_ARG, "out_len must not be null");
    }
    unsafe { *out_len = 0 };
    if out_buf.is_null() && out_cap > 0 {
        return fail(ERR_INVALID_ARG, "out_buf must not be null when out_cap > 0");
    }
    let bytes = json.as_bytes();
    unsafe { *out_len = bytes.len() };
    if out_cap < bytes.len() + 1 {
        return fail(
            ERR_BUFFER_TOO_SMALL,
            &format!(
                "result buffer too small: need {} bytes (incl. NUL), have {out_cap}",
                bytes.len() + 1
            ),
        );
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, bytes.len());
        *out_buf.add(bytes.len()) = 0;
    }
    clear_error();
    NK_OK as c_int
}

fn request_impl(
    config_json: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if out_len.is_null() {
        return fail(ERR_INVALID_ARG, "out_len must not be null");
    }
    unsafe { *out_len = 0 };
    let inner = (|| -> NkResult<String> {
        let text = cstr(config_json, "config_json")?;
        crate::request_json(text)
    })();
    match inner {
        Ok(json) => write_result(out_buf, out_cap, out_len, &json),
        Err((code, msg)) => fail(code, &msg),
    }
}

#[no_mangle]
pub extern "C" fn nk_version() -> *const c_char {
    static VERSION_C: &[u8] = b"0.1.0\0";
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn nk_version_major() -> c_int {
    VERSION_MAJOR as c_int
}

#[no_mangle]
pub extern "C" fn nk_version_minor() -> c_int {
    VERSION_MINOR as c_int
}

#[no_mangle]
pub extern "C" fn nk_version_patch() -> c_int {
    VERSION_PATCH as c_int
}

#[no_mangle]
pub extern "C" fn nk_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}

#[no_mangle]
pub extern "C" fn nk_last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0) as c_int
}

/// # Safety (caller contract): `p` is null or a string this
/// library returned and has not been freed yet. Documented in
/// the header.
#[no_mangle]
pub extern "C" fn nk_free_string(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

/// Perform the request described by `config_json` and write the
/// result JSON into the caller's buffer (see the file header for
/// the buffer contract).
#[no_mangle]
pub extern "C" fn nk_request(
    config_json: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    match guard(|| request_impl(config_json, out_buf, out_cap, out_len)) {
        Ok(code) => code,
        Err(_) => panic_code(),
    }
}

fn download_impl(
    url: *const c_char,
    dest_path: *const c_char,
    expected_sha256: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if out_len.is_null() {
        return fail(ERR_INVALID_ARG, "out_len must not be null");
    }
    unsafe { *out_len = 0 };
    let inner = (|| -> NkResult<String> {
        let url = cstr(url, "url")?;
        let dest = cstr(dest_path, "dest_path")?;
        if dest.is_empty() {
            return Err((ERR_INVALID_ARG, "dest_path must not be empty".into()));
        }
        let sha = opt_cstr(expected_sha256, "expected_sha256")?;
        // Sugar over nk_request: a GET with download_to. Passing
        // an http:// URL here IS the caller's explicit opt-in
        // (they named the scheme), so allow_http follows the URL;
        // the https → http redirect downgrade refusal still
        // applies inside the executor.
        let mut config = String::from("{\"method\":\"GET\",\"url\":\"");
        config.push_str(&crate::json_escape(url));
        config.push_str("\",\"download_to\":\"");
        config.push_str(&crate::json_escape(dest));
        config.push('"');
        if let Some(h) = sha {
            config.push_str(",\"sha256\":\"");
            config.push_str(&crate::json_escape(h));
            config.push('"');
        }
        if url.len() >= 7 && url[..7].eq_ignore_ascii_case("http://") {
            config.push_str(",\"allow_http\":true");
        }
        config.push('}');
        crate::request_json(&config)
    })();
    match inner {
        Ok(json) => write_result(out_buf, out_cap, out_len, &json),
        Err((code, msg)) => fail(code, &msg),
    }
}

/// Sugar for the common case: GET `url` into `dest_path`,
/// verifying `expected_sha256` when non-null. Same result JSON
/// and buffer contract as nk_request. The file lands via a
/// `.part` sibling and an atomic rename; on failure nothing is
/// left behind.
#[no_mangle]
pub extern "C" fn nk_download(
    url: *const c_char,
    dest_path: *const c_char,
    expected_sha256: *const c_char,
    out_buf: *mut c_char,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    match guard(|| download_impl(url, dest_path, expected_sha256, out_buf, out_cap, out_len)) {
        Ok(code) => code,
        Err(_) => panic_code(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ERR_PARSE;
    use std::ffi::CString;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn ffi_request_config_errors() {
        let mut buf = vec![0u8; 64];
        let mut len: usize = 999;
        // Bad JSON → NK_ERR_PARSE, no result.
        let bad = cs("{nope");
        assert_eq!(
            nk_request(
                bad.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut len
            ),
            ERR_PARSE as c_int
        );
        assert_eq!(len, 0);
        assert_eq!(nk_last_error_code(), ERR_PARSE as c_int);
        // Null config → NK_ERR_INVALID_ARG.
        assert_eq!(
            nk_request(
                std::ptr::null(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut len
            ),
            ERR_INVALID_ARG as c_int
        );
        // Null out_len → NK_ERR_INVALID_ARG.
        assert_eq!(
            nk_request(
                bad.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                std::ptr::null_mut()
            ),
            ERR_INVALID_ARG as c_int
        );
    }

    #[test]
    fn ffi_request_reaches_transport() {
        // A valid https config passes policy and reaches the
        // transport; off Windows that is NK_ERR_NOT_SUPPORTED.
        #[cfg(not(windows))]
        {
            let mut buf = vec![0u8; 256];
            let mut len: usize = 0;
            let cfg = cs(r#"{"url":"https://example.com/x"}"#);
            assert_eq!(
                nk_request(
                    cfg.as_ptr(),
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len(),
                    &mut len
                ),
                crate::ERR_NOT_SUPPORTED as c_int
            );
            assert_eq!(nk_last_error_code(), crate::ERR_NOT_SUPPORTED as c_int);
        }
    }

    #[test]
    fn ffi_write_result_buffer_contract() {
        let json = "{\"status\":200}";
        // Size query: null buf, cap 0 → BUFFER_TOO_SMALL + length.
        let mut len: usize = 0;
        assert_eq!(
            write_result(std::ptr::null_mut(), 0, &mut len, json),
            ERR_BUFFER_TOO_SMALL as c_int
        );
        assert_eq!(len, json.len());
        assert_eq!(nk_last_error_code(), ERR_BUFFER_TOO_SMALL as c_int);
        // One byte short (no room for NUL) → still too small.
        let mut buf = vec![0u8; json.len()];
        assert_eq!(
            write_result(buf.as_mut_ptr() as *mut c_char, buf.len(), &mut len, json),
            ERR_BUFFER_TOO_SMALL as c_int
        );
        // Exact fit: len + NUL.
        let mut buf = vec![0u8; json.len() + 1];
        assert_eq!(
            write_result(buf.as_mut_ptr() as *mut c_char, buf.len(), &mut len, json),
            NK_OK as c_int
        );
        assert_eq!(len, json.len());
        assert_eq!(buf[json.len()], 0);
        assert_eq!(
            unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) }
                .to_str()
                .unwrap(),
            json
        );
        // Null out_len refused.
        assert_eq!(
            write_result(
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                std::ptr::null_mut(),
                json
            ),
            ERR_INVALID_ARG as c_int
        );
    }

    #[test]
    fn ffi_download_bad_args() {
        let mut buf = vec![0u8; 64];
        let mut len: usize = 0;
        let url = cs("https://example.com/f.bin");
        // Null dest → invalid.
        assert_eq!(
            nk_download(
                url.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut len
            ),
            ERR_INVALID_ARG as c_int
        );
        // Bad sha shape fails in config validation (before the
        // transport is reached, on every platform).
        let dest = cs("out.bin");
        let sha = cs("not-hex");
        assert_eq!(
            nk_download(
                url.as_ptr(),
                dest.as_ptr(),
                sha.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut len
            ),
            ERR_INVALID_ARG as c_int
        );
    }

    #[test]
    fn ffi_version_and_error_surface() {
        let v = unsafe { CStr::from_ptr(nk_version()) }.to_str().unwrap();
        assert_eq!(v, "0.1.0");
        assert_eq!(nk_version_major(), 0);
        assert_eq!(nk_version_minor(), 1);
        assert_eq!(nk_version_patch(), 0);
        nk_free_string(std::ptr::null_mut()); // no-op, must not crash
    }
}
