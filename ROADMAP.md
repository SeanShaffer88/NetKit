# NetKit — roadmap

## v0.2 candidates

- **Cookie jar.** An opt-in, per-process jar (parse Set-Cookie,
  honor Domain/Path/Secure/expires, send on matching requests).
  The result JSON's last-wins header object deliberately does
  not carry cookies today; the jar is where they belong. Secure
  cookies must never be sent over http, including after an
  `allow_http` start — the executor's origin rules already give
  the jar its enforcement point.
- **Resume / Range downloads.** Honor a pre-existing `.part`
  with `Range: bytes=N-` + If-Range against the recorded ETag,
  falling back to a clean restart on any mismatch. The `.part`
  discipline in v0.1 (fsync, digest, atomic rename) is the
  foundation; resume must not weaken the all-or-nothing rule —
  a resumed file is still digest-verified before the rename.
- **Proxy authentication helpers.** WinHTTP automatic proxy
  covers discovery; explicit proxy + credentials config (with
  the credentials kept out of the config JSON's error paths and
  out of `nk_last_error`) is the missing piece for corporate
  networks.
- **Cross-attempt total budget.** `timeout_ms_total` is per
  attempt in v0.1; an optional whole-operation budget (spanning
  retries and redirects) needs a clock abstraction in the
  executor without breaking its determinism rule.

## Later

- **HTTP/2 via the platform.** WinHTTP negotiates HTTP/2 where
  the OS supports it; exposing the negotiated protocol in the
  result JSON (and pinning it per request) waits on a real
  consumer needing it.
- **Second transport backend** (non-Windows) behind the same
  `Transport` trait — the trait and the fake-transport test
  suite are the seam; the policy core does not change.
- **Response header fidelity.** A raw-headers result variant
  (ordered pairs, duplicates intact) beside the last-wins
  object, for consumers that need Set-Cookie multiplicity
  without the full jar.

## Explicitly not planned

- **A certificate-verification bypass.** Not a missing feature —
  a permanent exclusion. See AGENTS.md.
- **A general-purpose URL fetcher API** (string-in/string-out
  helpers that hide status, caps, or digests). The JSON
  config/result pair is the API; sugar that hides policy knobs
  is how the unsafe defaults this kit exists to remove creep
  back in.
