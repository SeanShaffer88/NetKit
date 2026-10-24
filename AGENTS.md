# NetKit — agent notes

- **No certificate-verification bypass. Ever.** There is no config
  key, flag, or code path that weakens TLS validation, and there
  must never be one: do not add `SECURITY_FLAG_IGNORE_*`, do not
  set `WINHTTP_OPTION_SECURITY_FLAGS`, do not propose an
  "insecure" mode for testing. This is the kit's founding rule —
  an app that needs to talk to a broken-TLS endpoint needs a
  different, deliberate decision outside NetKit.
- **Credentials never cross origins.** On a redirect to a
  different origin (scheme/host/port), Authorization, Cookie and
  Host are dropped in `sanitize_headers` (lib.rs). Same-origin
  redirects keep them. Do not "simplify" this into always-keep or
  always-drop; both are wrong.
- **https → http downgrades are refused unconditionally**
  (NK_ERR_REDIRECT_DOWNGRADE) — `allow_http: true` opts a request
  into *starting* on http; it never licenses a downgrade.
- **POST is never auto-retried** (it is the one non-idempotent
  method NetKit speaks). Retryable = transport error or
  408/429/5xx, idempotent methods only, `retries` budget per hop.
- **The size cap is enforced mid-stream.** The executor's sink
  errors with NK_ERR_TOO_LARGE and transports MUST stop and
  propagate that error unchanged (the WinHTTP read loop does;
  the test fake does). Never change this to buffer-then-check,
  and NK_ERR_TOO_LARGE is never retried.
- **Backoff is deterministic in the core.** The executor takes a
  seed and a sleep callback; the clock/RNG live at the FFI/Rust
  API edge (`clock_seed`). Tests use seed 42 and assert exact
  delays — do not introduce wall-clock or RNG into `execute`.
- **Redirects belong to the executor, not the transport.** The
  WinHTTP redirect policy is pinned to NEVER on every request so
  3xx responses surface. If a future transport auto-follows, the
  policy core is bypassed and the hardening story collapses.
- **Downloads are all-or-nothing:** `<dest>.part` → fsync →
  digest check → atomic rename. Any failure removes the `.part`;
  a digest mismatch is NK_ERR_DIGEST and must never leave a file
  at the destination.
- Zero dependencies; the JSON engine and SHA-256 are the family
  hand-rolled modules. Duplicate keys in a config object are a
  PARSE ERROR by design — do not "fix" that into last-wins.
  (Response *headers* are last-wins in the result JSON; that is a
  different, documented contract.)
- The WinHTTP code cannot be exercised on this Linux host: the
  loopback e2e (tests/loopback.rs, cfg(windows)) runs only on
  Windows CI and is the transport's real gate. Do not claim
  transport behavior is verified from the host gate — the gate
  proves the policy around the transport; CI proves the
  transport. HTTPS/public-internet behavior is verified by
  platform TLS + code review only; say so.
- Gate: WinDevKit tools/gate.sh (fmt + clippy BOTH targets +
  full tests). Hand-declared externs carry #[link(name = "...")]
  — winhttp and kernel32 here; LNK2019 only shows in CI's real
  link.
