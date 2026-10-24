/* NetKit.dll — a hardened HTTP(S) client behind one C ABI.
 *
 * One reviewed transport instead of every consumer hand-rolling
 * WinHTTP (UpdateKit's uk_download is the per-consumer layer this
 * kit generalizes). The hardening is specific:
 *
 *   - HTTPS is required unless the caller opts in per request
 *     ("allow_http": true). There is NO option anywhere in
 *     NetKit to disable TLS certificate verification — not a
 *     config key, not a flag. That is permanent.
 *   - Redirects are followed by NetKit, not the transport:
 *     https -> http downgrades are REFUSED
 *     (NK_ERR_REDIRECT_DOWNGRADE); Authorization and Cookie
 *     headers never cross origins; hop-by-hop headers are
 *     stripped; 303 (and 301/302 for POST) rewrite to GET;
 *     307/308 preserve method and body; the hop limit is
 *     enforced (NK_ERR_TOO_MANY_REDIRECTS).
 *   - Retries cover transport errors and 408/429/5xx, ONLY for
 *     idempotent methods — POST is never auto-retried. Backoff
 *     is 200 ms x 2^n plus jitter; Retry-After (seconds) is
 *     honored, capped at 30 s.
 *   - The response cap (max_bytes) is enforced WHILE streaming:
 *     the transfer aborts the moment it is exceeded
 *     (NK_ERR_TOO_LARGE), never after buffering everything.
 *   - Downloads write to "<dest>.part", are fsynced, verified
 *     against the expected SHA-256 when given (mismatch =
 *     NK_ERR_DIGEST and the partial file is DELETED), then
 *     atomically renamed over the destination.
 *
 * A request is configured by ONE JSON object:
 *
 *   {"method": "GET", "url": "https://example.com/f.bin",
 *    "headers": {"Authorization": "Bearer ..."},
 *    "body": "...", "body_file": "payload.json",
 *    "timeout_ms_total": 30000, "timeout_ms_connect": 10000,
 *    "max_bytes": 67108864, "max_redirects": 5, "retries": 2,
 *    "allow_http": false, "sha256": "<64 hex>",
 *    "download_to": "C:/out/f.bin"}
 *
 *   method           (string, default "GET") GET, HEAD, POST,
 *                     PUT or DELETE.
 *   url              (string, required) http/https only;
 *                     userinfo is rejected; the host must be
 *                     ASCII (use punycode for IDN).
 *   headers          (object of strings, default {}) — CR/LF in
 *                     a value is refused (header injection).
 *   body             (string) request body, UTF-8.
 *   body_file        (string) read the body from this file
 *                     instead; mutually exclusive with body.
 *   timeout_ms_total (uint, default 30000) per-attempt budget
 *                     for connect+send+receive; 0 = no cap.
 *   timeout_ms_connect (uint, default 10000).
 *   max_bytes        (uint, default 67108864) response cap,
 *                     enforced mid-stream.
 *   max_redirects    (uint, default 5).
 *   retries          (uint, default 2) idempotent methods only.
 *   allow_http       (bool, default false) per-request opt-in
 *                     to plain http://.
 *   sha256           (string, optional) expected hex digest of
 *                     the response body / downloaded file.
 *   download_to      (string, optional) stream the body to
 *                     this file (via "<path>.part" + rename)
 *                     instead of returning it.
 *
 * Unknown keys are an error (NK_ERR_PARSE), never ignored.
 *
 * The result is ONE JSON object, written into the caller's
 * buffer (see nk_request for the buffer contract):
 *
 *   {"status": 200, "final_url": "https://...",
 *    "headers": {"Content-Type": "text/plain"},
 *    "bytes": 1234, "attempts": 1, "redirects": 0,
 *    "sha256": "<hex>", "body_base64": "..."}
 *
 *   headers is an object with LAST-WINS semantics for repeated
 *   header names (compared case-insensitively). "body_base64"
 *   is present when the body was returned in memory;
 *   "file_written" replaces it when download_to was used. Any
 *   HTTP status is a RESULT, not a call failure — a 404 comes
 *   back as a result with "status": 404. Call failures are
 *   policy/transport problems (bad config, downgrade refusal,
 *   cap exceeded, timeout, ...).
 *
 * All strings are UTF-8, NUL-terminated. Errors set a
 * thread-local nk_last_error() (message + code).
 */
#ifndef NETKIT_H
#define NETKIT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(NK_BUILD)
#define NK_API __declspec(dllexport)
#elif defined(_WIN32)
#define NK_API __declspec(dllimport)
#else
#define NK_API
#endif

enum {
    NK_OK = 0,
    NK_ERR_INVALID_ARG = 1,     /* bad values, null pointers, http without opt-in */
    NK_ERR_NOT_SUPPORTED = 2,   /* transport off Windows (v0.1) */
    NK_ERR_NOT_FOUND = 3,       /* body_file does not exist */
    NK_ERR_ACCESS_DENIED = 4,
    NK_ERR_PLATFORM = 5,        /* transport/OS failure; see nk_last_error() */
    NK_ERR_INTERNAL = 6,
    NK_ERR_PARSE = 7,           /* config is not valid JSON / unknown key */
    NK_ERR_DIGEST = 8,          /* body does not match the configured sha256 */
    NK_ERR_REDIRECT_DOWNGRADE = 9, /* https -> http redirect; always refused */
    NK_ERR_TOO_MANY_REDIRECTS = 10,
    NK_ERR_TOO_LARGE = 11,      /* response exceeded max_bytes mid-stream */
    NK_ERR_BUFFER_TOO_SMALL = 12, /* *out_len receives the required size */
    NK_ERR_TIMEOUT = 13,
    NK_ERR_URL = 14             /* scheme/userinfo/host/port validation */
};

NK_API const char *nk_version(void);
NK_API int nk_version_major(void);
NK_API int nk_version_minor(void);
NK_API int nk_version_patch(void);
NK_API const char *nk_last_error(void);
NK_API int nk_last_error_code(void);
NK_API void nk_free_string(char *p);

/* Perform the request described by config_json and write the
 * result JSON into the caller's buffer.
 *
 * Buffer contract: out_len must not be NULL; it is set to 0 on
 * entry, and on success to the JSON length in bytes (excluding
 * the NUL terminator, which is also written). If out_cap is
 * too small, the call returns NK_ERR_BUFFER_TOO_SMALL and
 * *out_len holds the required JSON length; calling with
 * out_buf NULL and out_cap 0 is the size query. (out_buf NULL
 * with out_cap > 0 is NK_ERR_INVALID_ARG.) On any other
 * failure *out_len is 0 and the return
 * value is the NK_ERR_* code, with nk_last_error() set. */
NK_API int nk_request(const char *config_json, char *out_buf,
                      size_t out_cap, size_t *out_len);

/* Sugar for the common case: GET url into dest_path, verifying
 * expected_sha256 when non-NULL. Same result JSON ("file_written"
 * set) and the same buffer contract as nk_request. Passing an
 * http:// URL here is the caller's explicit opt-in to plain
 * HTTP; the https -> http redirect refusal still applies. On
 * failure the partial file is removed — nothing is left behind. */
NK_API int nk_download(const char *url, const char *dest_path,
                       const char *expected_sha256, char *out_buf,
                       size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* NETKIT_H */
