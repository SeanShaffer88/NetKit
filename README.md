# NetKit

## TL;DR

One clean C ABI for HTTP(S) — the hardened transport every app in the family used to hand-roll over WinHTTP, deciding the same policy questions each time and not always safely. Describe a request in one JSON object, get one JSON result: redirects followed under strict rules, retries only where they are safe, a size cap enforced mid-stream, and downloads that land atomically with their SHA-256 verified. Zero dependencies, one small DLL.

**There is no way to disable TLS certificate verification in NetKit.** No config key, no flag, no environment variable — HTTPS means the platform validates the certificate, always. If a use case seems to need otherwise, it needs a different tool, deliberately.

```c
char buf[8192];
size_t len = 0;
if (nk_request("{\"url\":\"https://example.com/appcast.json\"}",
               buf, sizeof buf, &len) == NK_OK) {
    printf("%.*s\n", (int)len, buf);
    /* {"status":200,"final_url":"...","headers":{...},"bytes":...,
        "attempts":1,"redirects":0,"sha256":"...","body_base64":"..."} */
}
```

## Quickstart

```c
#include "netkit.h"

/* Fetch into memory. The result JSON lands in YOUR buffer:
 * call with out_cap 0 first if you don't know the size —
 * NK_ERR_BUFFER_TOO_SMALL tells you the required length. */
char *buf = malloc(1 << 20);
size_t len = 0;
int rc = nk_request(
    "{\"url\":\"https://example.com/releases/latest.zip\","
    "\"max_bytes\":104857600}",
    buf, 1 << 20, &len);
if (rc == NK_OK) { /* parse buf[0..len) as JSON */ }
else { fprintf(stderr, "%s\n", nk_last_error()); }

/* Or download straight to disk (via "<dest>.part" + atomic
 * rename, SHA-256 verified, nothing left behind on failure): */
rc = nk_download("https://example.com/releases/latest.zip",
                 "C:/out/latest.zip",
                 "9f86d081884c7d659a2feaa0c55ad015...", /* or NULL */
                 buf, 1 << 20, &len);
```

From Rust, the same config/result pair is `net_kit::request_json(&str)`.

## Why this exists

UpdateKit grew a hand-rolled WinHTTP download layer because it needed exactly one; the next consumer would have written a second, with its own answers to questions that have safe and unsafe answers (WinDevKit pain point #21). NetKit is that layer, generalized and reviewed once: any method, headers and body, redirects and retries — with the policy in a platform-free core that is fully unit-tested, and a thin WinHTTP transport that does what it is told.

## The hardening, specifically

- **HTTPS by default.** An `http://` URL fails unless the request sets `"allow_http": true`. The opt-in is per request, never global.
- **No certificate-verification bypass.** TLS validation is WinHTTP's with platform defaults; no NetKit surface can weaken it (see AGENTS.md — this is load-bearing).
- **Redirects are executor policy, not transport behavior.** WinHTTP's redirect policy is pinned to NEVER; NetKit's core sees every 3xx and decides: https → http downgrades are **refused** (`NK_ERR_REDIRECT_DOWNGRADE`); `Authorization`, `Cookie` and `Host` never cross an origin boundary; hop-by-hop headers (and anything named by `Connection`) are stripped; 303 rewrites to GET with the body dropped, 301/302 rewrite POST → GET (the browser convention), 307/308 preserve method and body; relative `Location` values resolve per RFC 3986; the chain stops at `max_redirects` (`NK_ERR_TOO_MANY_REDIRECTS`).
- **Retries only where safe.** Transport errors and 408/429/5xx are retried — only for idempotent methods (GET/HEAD/PUT/DELETE). **POST is never auto-retried.** Backoff is 200 ms × 2^n plus jitter; `Retry-After` (seconds form) overrides it, capped at 30 s.
- **The size cap aborts mid-stream.** `max_bytes` is checked as each chunk arrives; the transfer stops the moment it is exceeded (`NK_ERR_TOO_LARGE`) instead of buffering the whole body first.
- **Downloads are all-or-nothing.** The body streams to `"<dest>.part"`, is fsynced, checked against the configured SHA-256 (mismatch: `NK_ERR_DIGEST`, partial file deleted), then atomically renamed over the destination (MoveFileExW replace on Windows).
- **Header injection is refused.** CR/LF (or other control characters) in a header value is a config error, and URLs with userinfo (`user@host`) are rejected outright. Non-ASCII hosts are rejected with a named error — use the punycode form; NetKit does not guess at IDN.

## The config

One JSON object for `nk_request` (unknown keys are `NK_ERR_PARSE`, never ignored):

| Key | Type | Default | Meaning |
|---|---|---|---|
| `method` | string | `"GET"` | GET, HEAD, POST, PUT or DELETE |
| `url` | string | *(required)* | http/https only; no userinfo; ASCII host |
| `headers` | object | `{}` | Header name → value (strings) |
| `body` | string | — | Request body (UTF-8) |
| `body_file` | string | — | Read the body from a file; mutually exclusive with `body` |
| `timeout_ms_total` | uint | `30000` | Per-attempt connect+send+receive budget; 0 = no cap |
| `timeout_ms_connect` | uint | `10000` | Resolve/connect budget |
| `max_bytes` | uint | `67108864` | Response cap, enforced while streaming |
| `max_redirects` | uint | `5` | Redirect hop limit (max 100) |
| `retries` | uint | `2` | Retries per hop, idempotent methods only (max 10) |
| `allow_http` | bool | `false` | Per-request opt-in to plain http:// |
| `sha256` | string | — | Expected hex digest of the body/downloaded file |
| `download_to` | string | — | Stream to this file instead of returning the body |

## The result

One JSON object in the caller's buffer:

```json
{"status": 200, "final_url": "https://example.com/f.bin",
 "headers": {"Content-Type": "application/octet-stream"},
 "bytes": 1234, "attempts": 1, "redirects": 0,
 "sha256": "<hex>", "body_base64": "..."}
```

- `headers` is an object with **last-wins** semantics for repeated names (compared case-insensitively) — a response that sets two cookies reports the second; use a future cookie jar (see ROADMAP) if you need them all.
- With `download_to`, `body_base64` is replaced by `file_written`.
- **Any HTTP status is a result, not a call failure** — a 404 comes back as `"status": 404` with `NK_OK`. Call failures are policy/transport problems: bad config, downgrade refusal, cap exceeded, digest mismatch, timeout.

## Errors

| Code | Name | Meaning |
|---|---|---|
| 0 | `NK_OK` | Result produced |
| 1 | `NK_ERR_INVALID_ARG` | Bad values, null pointers, http:// without opt-in, header injection |
| 2 | `NK_ERR_NOT_SUPPORTED` | Transport off Windows (v0.1) |
| 3 | `NK_ERR_NOT_FOUND` | `body_file` does not exist |
| 4 | `NK_ERR_ACCESS_DENIED` | OS denied access |
| 5 | `NK_ERR_PLATFORM` | Transport/OS failure; `nk_last_error()` has the WinHTTP error number |
| 6 | `NK_ERR_INTERNAL` | Internal error (incl. a panic caught at the FFI boundary) |
| 7 | `NK_ERR_PARSE` | Config is not valid JSON, or has an unknown/duplicate key |
| 8 | `NK_ERR_DIGEST` | Body bytes do not match the configured `sha256` |
| 9 | `NK_ERR_REDIRECT_DOWNGRADE` | An https → http redirect was refused |
| 10 | `NK_ERR_TOO_MANY_REDIRECTS` | Chain exceeded `max_redirects` |
| 11 | `NK_ERR_TOO_LARGE` | Response exceeded `max_bytes` (aborted mid-stream) |
| 12 | `NK_ERR_BUFFER_TOO_SMALL` | Result buffer too small; `*out_len` has the required size |
| 13 | `NK_ERR_TIMEOUT` | Connect/send/receive/total timeout |
| 14 | `NK_ERR_URL` | URL failed validation (scheme, userinfo, host, port) |

## Honest limits (v0.1)

- **Windows transport only.** Off Windows the policy core, config and FFI all work (and are tested), but an actual request returns `NK_ERR_NOT_SUPPORTED`. A second transport backend is a roadmap item, not a silent gap.
- **HTTPS is verified by platform TLS + code review, not by CI.** CI exercises the real WinHTTP transport against a loopback HTTP server on 127.0.0.1 (200s, redirect chains, 404, timeout, download). Public-internet HTTPS from CI runners is not a meaningful test, so it isn't claimed.
- **Check/clippy do not link.** The local gate proves logic; the Windows CI build is the link gate for the WinHTTP bindings (LNK2019 class), and its loopback suite is the transport's functional gate.
- `Retry-After` is parsed in seconds form only (HTTP-date returns are ignored). Request bodies are materialized in memory so retries/redirects can replay them; `body_file` is read once up front. IPv6 literal hosts are not supported. Total timeout is per attempt (each retry gets its own budget).

## Building

Zero dependencies; Win32 bindings are hand-declared in `src/platform.rs` with `#[link]` on every extern block. The gate is WinDevKit's `tools/gate.sh` (fmt, clippy on host **and** `x86_64-pc-windows-msvc`, full test suite) — green locally; CI additionally links and runs the loopback e2e on windows-latest.

MIT licensed.
