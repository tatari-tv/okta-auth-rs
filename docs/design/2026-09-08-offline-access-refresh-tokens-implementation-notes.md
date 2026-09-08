# Implementation Notes: `offline_access` and Refresh Tokens for the okta-auth Fleet

Companion to `docs/design/2026-09-08-offline-access-refresh-tokens.md`.
Append-only. A later entry supersedes an earlier one; nothing is rewritten.

## Phase 0: Prove the tenant issues and revokes a refresh token (zero code)

Run 2026-09-08 against `0oa144xsutkeO1nev698` on
`https://tatari.okta.com/oauth2/default`, device grant, Scott approved in a browser.
Nothing touched `~/.cache/okta`.

Observed, in order:

| step | result |
|---|---|
| `POST /v1/device/authorize` scope `openid email profile offline_access` | HTTP 200, `user_code`, `interval` 5, `expires_in` 600 |
| `POST /v1/token` device_code (approved after 430s) | HTTP 200; `refresh_token` **present**; `scope` = `offline_access email openid profile`; `expires_in` 43200 (12h); access token `scp` = `[offline_access, email, openid, profile]`, `aud` `api://default` |
| `POST /v1/token` `grant_type=refresh_token` | HTTP 200, new access token, `scp` unchanged |
| `POST /v1/introspect` refresh token, `client_id` only | `active: true` |
| `POST /v1/revoke` refresh token, `client_id` + `token_type_hint=refresh_token`, no auth header | HTTP 200, zero-length body |
| `POST /v1/introspect` refresh token again | `active: false` |
| `POST /v1/introspect` the access token minted by the refresh | `active: false` |
| `POST /v1/revoke` the same dead token again | HTTP 200 |
| `POST /v1/token` `grant_type=refresh_token` with the dead token | HTTP 400 `{"error":"invalid_grant","error_description":"The refresh token is invalid or expired."}` |

### Design decisions
- None. Phase 0 is a read-only spike; no code, no config, no commit of its own.

### Deviations
- **The design doc's persistent-token claim is factually wrong in one clause, and it
  is corrected here rather than in the code.** Architecture says: Okta's
  persistent-token behavior "means the response omits `refresh_token`; `refresh()`
  already falls back to the token it sent (`src/lib.rs:295-298`). That fallback is
  load-bearing." Observed: the refresh response **does** carry `refresh_token`, and
  it is **byte-identical** to the token that was sent (`same_refresh_token: True`).
  So persistence is confirmed - the tenant is not rotating - but by echo, not by
  omission. Consequences, all of which leave the plan intact:
  - No code change. `refresh()` persists whatever comes back; when that equals the
    token it sent, the saved cache is identical either way.
  - The `src/lib.rs:295-298` fallback is still correct and still worth keeping (it is
    what protects against a tenant or a mock that omits the field), but it is **not**
    exercised by this tenant's happy path. "Load-bearing" overstated it.
  - Phase 1's `refresh_keeps_sent_refresh_token_when_response_omits_it` stays as
    written: `MockOkta` serves a body without the field, which is exactly the case
    the fallback exists for. It is now understood as a defensive test, not a
    reproduction of live tenant behavior.

### Tradeoffs
- Ran the device grant rather than the browser redirect. Device is the flow that can
  be driven entirely from `curl` with no local callback listener, and it exercises
  the same `/v1/token` scope grant. The redirect path shares the token endpoint, so
  nothing about `offline_access` issuance is left unproven by the choice.

### Extra findings not required by the phase, recorded because later phases lean on them
- **Revoking the refresh token killed its associated access token** (`active: false`
  on a token minted moments earlier). This is the live confirmation of the Okta docs
  claim quoted in Architecture, and it is why `logout()` makes one revoke call rather
  than two.
- **Revoke is idempotent**: a second revoke of an already-dead token returned HTTP
  200 with an empty body. Confirms the doc's "already revoked returns 200 OK", and
  confirms Phase 1's `logout_treats_200_with_error_body_as_success` is testing the
  right shape (this tenant returns an empty body, not an error body; the test's
  200-with-error-body case is the defensive superset).
- **A dead refresh token returns HTTP 400 with `error == "invalid_grant"`** - exactly
  the discriminator Phase 1's dead-token detection keys on
  (`BasicErrorResponseType::InvalidGrant` in Rust, HTTP 400 + `invalid_grant` body in
  Python). The tenant's live wire format matches the design's assumption, so
  `refresh_clears_cache_on_invalid_grant` is testing the real error, not an invented
  one.
- Revoke as a public client with `client_id` in the body and **no** authorization
  header returned 200. The doc's request shape needed no adjustment.

### Open questions
- **Did a consent screen appear?** The phase asks that this be recorded and it is the
  one item only Scott can answer: the approval happened in his browser, out of band
  from the polling loop. Not a gate on any later phase (the doc already rules both
  outcomes acceptable: "Either outcome is acceptable"), but the record is incomplete
  until he says. To be filled in.

## Phase 1: okta-auth-rs

### Design decisions
- **One private `fresh_grant()` helper is the only writer of a fresh interactive
  grant** (`src/lib.rs:fresh_grant`), called from `login()`, `login_device()`, and
  `get_token()`'s interactive fallthrough. Order matches Architecture exactly: guard
  the shared-cache invariant -> read the old refresh token into memory -> run the
  injected `flow` -> save the new grant -> best-effort revoke the old token. The old
  token is read once, before `flow` runs, and never re-read from disk after the save,
  so this call can never revoke the grant it just wrote.
- **`LoginFlow` seam** (`src/lib.rs:LoginFlow`/`PkceFlow`): a private trait with two
  methods (`interactive`, `device`) wrapping `pkce::authorize` / `pkce::authorize_device`
  respectively. `OktaAuth` holds `flow: Box<dyn LoginFlow + Send + Sync>`; `new()`
  installs the production `PkceFlow`; `#[cfg(test)] with_flow()` swaps in a
  `CountingFlow` fake. This is what makes "flow invoked / not invoked" and call-count
  assertions possible without touching Okta.
- **`MockOkta` test harness** (`src/lib.rs:tests::MockOkta`) replaces the old one-shot
  `spawn_token_server`: an ordered script of `(status, body)` responses served over a
  real local `tiny_http` listener, recording each request's path and parsed form body,
  and - for any request whose path contains `/v1/revoke` - a snapshot of the cache
  file's `access_token` at the instant that request landed. That snapshot is what makes
  `login_saves_new_grant_before_revoking_old` an assertion instead of a hope, per the
  design doc's own framing.
- **Dead-token detection inspects the typed `oauth2` error before the existing
  `.map_err` stringifies it** (`src/lib.rs:refresh`): `if let Err(RequestTokenError::
  ServerResponse(ref resp)) = result && resp.error() == &BasicErrorResponseType::
  InvalidGrant`, then `cache::clear(...)?` (propagating `CacheWrite` on a failed clear),
  then the original `result.map_err(...)?` runs unchanged for every other error. This
  keeps the normal error path completely intact for every non-`invalid_grant` case
  (network, parse, other `ServerResponse` codes) with no branching duplication.
- **`revoke()`** (`src/lib.rs:revoke`) is a raw `reqwest::blocking` form POST to
  `{issuer}/v1/revoke` with `client_id`, `token`, `token_type_hint=refresh_token`, no
  auth header, 30s timeout - the same hand-built pattern `pkce::device` already uses
  against this issuer, per the design doc's explicit choice not to thread the `oauth2`
  crate's `RevocationUrl` typestate through `BasicClient` for one call site.
- **`logout()`** loads the cache once, revokes the refresh token if present, then calls
  `cache::clear(&dir)?` - the `?` gives `CacheWrite` precedence for free (it returns
  before the revoke result is even inspected), and the revoke result is only consulted
  if the clear succeeded. This is the same three-line shape the design doc's
  Architecture ASCII sketch describes.
- **Shared-cache guard** lives at the top of `fresh_grant()`, keyed on
  `self.config.cache_dir.is_none() && !scopes.contains("offline_access")`, checked
  before any cache read or network call - matches "checked before URL building and
  before any HTTP" in Architecture.

### Deviations
- **Same effect, correct seam: a small private `try_silent_refresh()` helper was
  added to `login_or_reuse`** (`src/lib.rs:try_silent_refresh`) rather than inlining
  the load-refresh-save sequence directly in the Architecture ASCII sketch's
  `login_or_reuse` branch. The doc's sketch is prose-level ("refresh set? -> refresh
  ok -> save -> Refreshed"); the helper is that same logic factored out so
  `login_or_reuse` reads as one guarded `if let` rather than three nested `if`s. No
  behavior differs from the sketch.
- **`refresh_keeps_sent_refresh_token_when_response_omits_it` is confirmed (per the
  Phase 0 notes) to be a defensive test, not a live-tenant reproduction.** Phase 0
  observed the real tenant echoes the refresh token rather than omitting it. `MockOkta`
  is scripted to omit the field regardless, per the parent's explicit instruction to
  keep this test and its name unchanged; the fallback at the equivalent of
  `src/lib.rs:295-298` (now the `new_refresh` binding in `refresh()`) is unchanged and
  still exercised by this test.
- **`OKTA_AUTH_TAG` is not recorded here.** The design doc's Phase 1 success criteria
  ask for `git tag --points-at HEAD` after "the release", but tagging/bumping the
  version is explicitly the parent orchestrator's job at the finalization checkpoint,
  not this phase's. This commit lands untagged at `v0.6.0` (`Cargo.toml` unchanged);
  the tag value must be recorded by whichever step actually cuts the release.

### Tradeoffs
- **`MockOkta` serves an ordered `Vec<(status, body)>` on one thread rather than a
  full request router.** Every Phase 1 test needs at most one scripted response (a
  single refresh or revoke call per test); a fuller router keyed on path/method would
  be more general but nothing here calls for it, and the ordered-script shape is
  exactly what the design doc's Phase 1 bullet names.
- **Shared-cache-guard tests mutate the process-global `XDG_CACHE_HOME`** (via a local
  `with_xdg_cache_home` helper) rather than adding a way to inject the resolved default
  directory. This reuses `cache.rs`'s own established pattern (`#[serial_test::serial]`,
  restore-on-exit) instead of widening `OktaAuthConfig`'s public surface just for three
  tests to exercise `cache_dir: None`.
- **Read-only-directory tests (`CacheWrite` precedence) are `#[cfg(unix)]` only**,
  matching `cache.rs`'s existing `save_sets_0600_permissions` convention; Windows CI
  doesn't have an equivalent permission model to exercise the same failure.

### Open questions
- **`OKTA_AUTH_TAG` / release tag.** See Deviations above - the parent needs to tag and
  record the value before Phase 3 can pin to it.
- **`otto ci`/`sccache` flakiness observed in this session, unrelated to this phase's
  code.** Running `otto ci` (which runs `check` and `test` concurrently) intermittently
  failed both tasks with `sccache: error: Operation not permitted (os error 1)` from
  `sccache <rustc> -vV`; the same failure reproduced with two bare `cargo check` /
  `cargo test --no-run` processes launched concurrently outside `otto` entirely, and
  disappeared running the same commands sequentially or with `RUSTC_WRAPPER=` unset.
  This points at the shared `sccache` server choking under concurrent client load in
  this sandboxed session, not at anything in this phase's diff. `otto -j 1 ci` with
  `RUSTC_WRAPPER=` unset ran clean (102/102 tests, lint/check/clippy/fmt all green);
  worth a look if it recurs for other agents in this environment.
