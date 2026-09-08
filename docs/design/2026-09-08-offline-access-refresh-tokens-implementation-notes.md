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

## Phase 2: okta-auth-py parity

Implemented in `okta-auth-py` (sibling repo, `okta-auth-py:e4a023d`). CI:
`otto ci` (lint + check [ruff format/check + mypy] + test), green:
`ruff format --check .` clean, `ruff check .` clean, `mypy src/okta_auth` "Success:
no issues found in 10 source files", `pytest -v` 107 passed. All twenty-three named
tests from the Phase 1 bullet list exist as `test_<name>` in `tests/test_auth.py` and
pass (verified individually and as part of the full 107-test run):
`logout_revokes_refresh_token_then_clears_cache`,
`logout_clears_cache_and_returns_revoke_failed_when_endpoint_unreachable`,
`logout_makes_no_revoke_call_without_refresh_token`,
`logout_treats_200_with_error_body_as_success`,
`login_or_reuse_refreshes_instead_of_prompting`,
`login_or_reuse_runs_flow_when_expired_without_refresh_token`,
`refresh_keeps_sent_refresh_token_when_response_omits_it`,
`refresh_clears_cache_on_invalid_grant`, `refresh_keeps_cache_on_other_oauth_error`,
`refresh_keeps_cache_on_non_json_5xx`, `refresh_keeps_cache_on_unparseable_body`,
`refresh_keeps_cache_on_transport_error`, `login_saves_new_grant_before_revoking_old`,
`login_with_shared_cache_requires_offline_access`,
`login_device_with_shared_cache_requires_offline_access`,
`get_token_fallthrough_with_shared_cache_requires_offline_access`,
`login_with_explicit_cache_dir_allows_any_scopes`,
`get_token_read_path_is_not_guarded`, `login_or_reuse_reports_revoke_failure_in_message`,
`logout_returns_cache_write_when_clear_fails`,
`refresh_invalid_grant_with_failed_clear_returns_cache_write`,
`get_token_propagates_cache_write_instead_of_opening_browser`,
`login_or_reuse_happy_path_has_no_revoke_warning`.

### Design decisions
- **One private `_fresh_grant(flow)` helper is the only writer of a fresh
  interactive grant** (`auth.py:OktaAuth._fresh_grant`), called from `login()`,
  `login_device()`, and `get_token()`'s interactive fallthrough - the Python twin of
  Rust's `fresh_grant`. Order matches Architecture exactly: guard the shared-cache
  invariant -> read the previous refresh token into memory (`cache.load`, not
  re-read after) -> run the injected `flow` callable -> `cache.save` the new grant
  -> best-effort `_revoke` the old token. `flow` is a zero-arg `Callable[[],
  TokenCache]` (a lambda closing over `pkce.authorize`/`authorize_device` and the
  config), the natural Python shape for "inject the interactive step" - Rust needed
  a `LoginFlow` trait + `with_flow` test constructor because Rust has no first-class
  closures over `&self`; Python's `pkce.authorize`/`.authorize_device` module
  attribute lookups are directly `monkeypatch`-able, so no such seam object was
  needed for production code, only for tests (see Test seam below).
- **Test seam**: `monkeypatch.setattr("okta_auth.auth.pkce.authorize", ...)` and
  `.authorize_device` swap in a `_CountingFlow` (`tests/test_auth.py`) - a dataclass
  with `interactive`/`device` methods that return a canned `TokenCache` and count
  calls. This works because `auth.py` imports `pkce` as a module and calls
  `pkce.authorize(...)` / `pkce.authorize_device(...)` (never `from ... import
  authorize`), so the module-attribute lookup is patchable per test, exactly the seam
  the design doc named.
- **`ScriptedPost`** (`tests/test_auth.py`) replaces `requests.post` wholesale via
  `monkeypatch.setattr(requests, "post", scripted)`: an ordered `list[(status, body)]`
  consumed one call at a time, recording each call's URL and form `dict`, and - for
  any URL containing `/v1/revoke` - a snapshot of the cache file's `access_token` at
  the instant that call lands (via `cache.load`). That snapshot is what makes
  `test_login_saves_new_grant_before_revoking_old` an assertion rather than a hope,
  the Python twin of Rust's `MockOkta`.
- **Dead-token detection reads the response body before `raise_for_status()`**
  (`auth.py:OktaAuth._refresh`): on HTTP 400, parse the JSON body and check
  `error == "invalid_grant"` before anything else runs; only then does
  `cache.clear()` fire, and only then does the function fall into the second
  `try/except` that calls `raise_for_status()` (which raises for the still-400
  response, caught and reraised as `RefreshFailedError`). Every other 400
  (`invalid_client`, etc.), 5xx, unparseable body, or transport error skips the
  clear entirely and keeps the cache - matching Rust's typed-error inspection before
  its own `.map_err` stringifies.
- **`_revoke()`** (`auth.py:OktaAuth._revoke`) is a raw `requests.post` form POST to
  `{issuer}/v1/revoke` with `client_id`, `token`, `token_type_hint=refresh_token`, no
  auth header, 30s timeout, checking `200 <= status_code < 300` explicitly (not
  `requests.Response.ok`, which is also `True` for 3xx - the design doc says "any
  2xx", so the check is written to match that literally rather than piggyback on a
  looser stdlib property).
- **`logout()`** loads the cache once, attempts `_revoke` if a refresh token is
  present (catching only `RevokeFailedError`, storing it rather than raising
  immediately), then unconditionally calls `cache.clear(directory)` - which, if it
  raises `CacheWriteError`, propagates immediately and pre-empts the stored
  `revoke_error`, giving `CacheWriteError` precedence for free without an explicit
  `if/elif` chain, matching the design doc's stated precedence.
- **Shared-cache guard** lives at the top of `_fresh_grant()`, keyed on
  `self._config.cache_dir is None and "offline_access" not in self._config.scopes`,
  checked before any cache read or HTTP call - matches Rust exactly, including the
  "checked before URL building and before any HTTP" placement.
- **`LoginOutcomeKind.REFRESHED`** added alongside `ALREADY_LOGGED_IN`/`LOGGED_IN`;
  `LoginOutcome` (frozen dataclass, `auth.py:44` before this phase) gains
  `revoke_warning: str | None = None` as a fourth positional-with-default field
  (after the existing `since`), plus `LoginOutcome.refreshed(cache_path)` and an
  updated `logged_in(cache_path, revoke_warning=None)` classmethod. `message()`
  gains a `REFRESHED` branch and appends the same warning clause as Rust when
  `revoke_warning` is set.

### Deviations
- **None from the shipped Rust behavior.** Two differences from the design doc's
  own Python paragraph, both "same effect, correct seam", recorded per the parent's
  instruction:
  1. The doc's Python paragraph says `_refresh` reads the body before
     `raise_for_status()` "and matches HTTP 400 with `error == 'invalid_grant'`" -
     implemented exactly as described; no deviation here, just confirming the doc
     and the code agree (unlike the Rust side, nothing in Phase 0 contradicted this
     clause for Python, since Python's HTTP-status-code discriminator was always the
     doc's stated mechanism, not the `oauth2` crate's typed enum).
  2. Rust needed a `LoginFlow` trait + `Box<dyn LoginFlow + Send + Sync>` field on
     `OktaAuth` plus a `#[cfg(test)] with_flow` constructor as its test seam, because
     Rust has no way to monkeypatch a free function. Python's test seam is lighter
     (`monkeypatch.setattr` on the `pkce` module attribute) and needed no production
     code changes to `OktaAuth` at all - `_fresh_grant` takes a plain
     `Callable[[], TokenCache]` built by its three callers via `lambda`, never a
     stored strategy object. Functionally identical test guarantees (flow
     invoked/not-invoked counts, canned grants), different seam shape because the
     languages differ in what "inject a function" costs.
- Per Phase 0's already-recorded correction (echoed here for the Python side too):
  the design doc's Architecture clause "the response omits `refresh_token`" is
  factually wrong per the live tenant (it echoes the same token back). No code
  change follows from this on the Python side either - `_refresh`'s
  `token_data.get("refresh_token", refresh_token)` fallback is unchanged and is
  exercised by `test_refresh_keeps_sent_refresh_token_when_response_omits_it` as a
  defensive test (mocked body that omits the field), not a live-tenant
  reproduction, exactly as Phase 0/Phase 1 notes describe for Rust.

### Tradeoffs
- **`ScriptedPost` and `_CountingFlow` are defined once in `tests/test_auth.py`**
  rather than factored into a shared `conftest.py` fixture module. Every Phase 2 test
  needs at most one scripted HTTP response and one counting flow; nothing outside
  this phase's 23 tests currently needs them, so a shared fixture module would be
  premature factoring for a single consumer file.
- **No `serial_test`-equivalent guard needed for the `XDG_CACHE_HOME` guard tests**
  (`test_login_with_shared_cache_requires_offline_access` and its two siblings).
  Rust's equivalent tests use `#[serial_test::serial]` plus a manual
  save/restore-on-exit helper because Rust test binaries run tests concurrently by
  default and mutating `std::env::set_var` is process-global, unsafe, racy across
  threads. `pytest`'s `monkeypatch.setenv` is scoped to the single test function and
  auto-restores on teardown, and this repo's `pytest` runs single-threaded by
  default (no `-n auto`/xdist configured in `pyproject.toml` or `.otto.yml`), so no
  additional locking was needed to keep these three tests from stepping on each
  other or on unrelated tests.
- **Permission-based `CacheWriteError`-precedence tests are guarded with
  `@pytest.mark.skipif(os.name != "posix", ...)`** rather than a hard `#[cfg(unix)]`
  equivalent, mirroring Rust's own choice to skip on non-Unix rather than attempt an
  equivalent Windows ACL dance for three tests.

### Open questions
- None beyond what Phase 1 already surfaced (`OKTA_AUTH_TAG` / release tag remains
  the parent orchestrator's job at the finalization checkpoint, not this phase's -
  this commit lands untagged, `pyproject.toml` version unchanged at `0.3.0`).
