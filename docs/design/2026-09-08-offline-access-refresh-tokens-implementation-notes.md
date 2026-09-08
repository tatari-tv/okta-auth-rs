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
- **Consent screen: not recorded, and closed as immaterial.** The phase asked whether
  a consent page appeared during the browser approval. It was not captured at the time
  and the question is now closed rather than chased: the design doc already rules both
  outcomes acceptable ("Either outcome is acceptable"), nothing in either port branches
  on it, and no later phase reads it. Recorded here as unanswered by choice, not as an
  oversight to revisit.

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

---

## Audit remediation (Phases 0-2)

Remediation pass over the already-committed Phase 1 (`okta-auth-rs:5465ce8`) and Phase 2
(`okta-auth-py:e4a023d`) work, driven by the implementation audit. Not a new phase: no
Phase 3/4 work, no version bump, no tag, no push. Two commits, one per repo.

CI after the pass:
- `okta-auth-rs`: `otto ci` green - `whitespace -r` clean, no `_variable` bindings,
  `cargo check --all-targets --all-features`, `cargo clippy -- -D warnings`,
  `cargo fmt --all --check`, `cargo test --all-features` **104 passed, 0 failed**
  (102 before this pass; +2 new tests).
- `okta-auth-py`: `otto ci` green - `ruff format --check .`, `ruff check .`,
  `mypy src/okta_auth`, `pytest -v` **109 passed** (107 before this pass; +2 new tests).

### Break-to-prove runs, Phase 1 (okta-auth-rs)

`doc:668-671` requires these four recorded here; the Phase 1 entry recorded only CI
green and a test inventory. Run against the remediated tree. Each mutation was applied
to a pristine copy of `src/lib.rs`, the single test run with
`cargo test --all-features tests::<name> -- --exact`, and the file restored - sha256
`24a1aace425e42851e01b6ccc2cec517cf6ee4eaa85ff4f4e78c505d9727bb37` verified identical
before the first mutation and after the last.

| # | mutation | test | exit | observed failure |
|---|---|---|---|---|
| R1 | `cache::clear(&dir)?;` commented out of `logout()` | `logout_revokes_refresh_token_then_clears_cache` | 101 | `panicked at src/lib.rs:1036: assertion failed: !tmp.path().join("tokens.json").exists()` |
| R2 | silent-refresh arm in `login_or_reuse` wrapped in `if false { ... }` | `login_or_reuse_refreshes_instead_of_prompting` | 101 | `panicked at src/lib.rs:1184: got LoggedIn { cache_path: "/tmp/.tmpmRDCRh/tokens.json", revoke_warning: None }` |
| R3 | `cache::clear(&self.cache_dir())?;` commented out of `refresh()`'s `invalid_grant` arm | `refresh_clears_cache_on_invalid_grant` | 101 | `panicked at src/lib.rs:1283: assertion failed: !tmp.path().join("tokens.json").exists()` |
| R4 | shared-cache guard removed from `fresh_grant()` | `login_with_shared_cache_requires_offline_access` | 101 | `panicked at src/lib.rs:1479: got Ok(())` |

R2 uses `if false { ... }` rather than a plain comment-out because commenting the arm
out leaves `try_silent_refresh` uncalled, which `#![deny(dead_code)]` rejects at compile
time - the mutation would never reach the test.

A fifth, non-required mutation was run to verify the `MockOkta::finish()` fix below:
neutralizing `logout()`'s revoke (`refresh_token.map(|_| Ok(()))`) and running
`logout_treats_200_with_error_body_as_success` now **fails in 6.4s** with
`MockOkta::finish: script held 1 request(s), received 0 within 5s`. Before the fix the
auditor ran the same mutation and it hung for over nine minutes without producing a
result.

### Break-to-prove runs, Phase 2 (okta-auth-py)

`doc:700` requires the same four. Same method: mutation applied to a pristine copy of
`src/okta_auth/auth.py`, single test run with
`uv run pytest -q tests/test_auth.py::<name>`, file restored - sha256
`3e4b90bcc150814195a3206379c7f188c90cd9b45a131b6ba352ab81c00ac252` verified identical
before and after.

| # | mutation | test | exit | observed failure |
|---|---|---|---|---|
| P1 | `logout()`'s revoke disabled: `if False and refresh_token is not None:` | `test_logout_revokes_refresh_token_then_clears_cache` | 1 | `tests/test_auth.py:413: assert len(scripted.recorded) == 1` -> `assert 0 == 1  where 0 = len([])` |
| P2 | silent refresh disabled in `login_or_reuse`: `new_cache = None` | `test_login_or_reuse_refreshes_instead_of_prompting` | 1 | `tests/test_auth.py:518: assert <LoginOutcomeKind.LOGGED_IN: 3> is <LoginOutcomeKind.REFRESHED: 2>` |
| P3 | `cache.clear(self.cache_dir())` disabled in `_refresh`'s `invalid_grant` branch | `test_refresh_clears_cache_on_invalid_grant` | 1 | `tests/test_auth.py:573: assert not True  where True = exists()` (the dead token stayed cached) |
| P4 | `raise SharedCacheRequiresOfflineAccessError()` disabled in `_fresh_grant` | `test_login_with_shared_cache_requires_offline_access` | 1 | `tests/test_auth.py:683: Failed: DID NOT RAISE SharedCacheRequiresOfflineAccessError` |

All eight runs match what the audit reported. None differed.

### Tests added by this pass

Beyond the twenty-three parity names, both trees now carry:
- `fresh_grant_skips_revoke_when_token_unchanged` /
  `test_fresh_grant_skips_revoke_when_token_unchanged` - the equality guard below. The
  inequality half (revoke still fires when the tokens differ) is already pinned by
  `login_saves_new_grant_before_revoking_old`, which records the outgoing `/v1/revoke`.
- `login_or_reuse_propagates_cache_write_instead_of_opening_browser` /
  `test_login_or_reuse_propagates_cache_write_instead_of_opening_browser` - the
  `CacheWrite` precedence deviation below.

### Design decisions
- **`fresh_grant` never revokes a token equal to the one it just saved**
  (`src/lib.rs:fresh_grant`, `auth.py:OktaAuth._fresh_grant`). Phase 0 proved this
  tenant runs "Use persistent token" and echoes the refresh token back byte-identically
  on `POST /v1/token grant_type=refresh_token` (`implementation-notes.md:36-40`). Phase
  0 never ran a *second interactive authorization* for the same user+client, so nothing
  establishes that re-authorization mints a *distinct* refresh token - yet
  `doc:554` ("each login mints its own refresh token") asserts it, and `fresh_grant`
  depended on it totally: read old -> flow -> save new -> revoke old. If persistence
  extends to re-authorization the way it demonstrably extends to refresh, the revoke
  destroys the credential the `save` on the previous line just wrote, and with it the
  access token (Phase 0 also proved a revoke kills the associated access token,
  `implementation-notes.md:53-56`). Comparing the two tokens first is correct whichever
  way the tenant behaves, costs one string comparison, and does not wait on the
  empirical answer. The comparison lives at the revoke site with a comment explaining
  the tenant behavior it defends against, because nothing in the surrounding code makes
  the hazard visible.
- **The old test could not have caught it.** `login_saves_new_grant_before_revoking_old`
  hardcodes `old-refresh` against `new-refresh` (`src/lib.rs:1369`, `:1389` at audit
  time); the equal-token case was unrepresented in both trees. The new test uses an
  unreachable issuer (Rust) / `_post_must_not_be_called` (Python) so that any revoke
  attempt is observable, and asserts the saved grant is still on disk afterwards.
- **`MockOkta::finish()` fails instead of deadlocking** (`src/lib.rs`, test module). The
  server thread now uses `tiny_http::Server::recv_timeout(MOCK_RECV_TIMEOUT)` (5s) and
  `finish()` asserts `recorded.len() == expected`, naming both counts. Previously the
  thread blocked in `recv()` forever and `finish()` joined it, so a mutation that
  removed a request hung the suite rather than failing it - the doc comment claimed
  otherwise ("or the caller has made all its requests"), and that parenthetical was
  never implemented. This is the root cause of the Rust half of the missing
  break-to-prove record: the runs were impractical, not merely unwritten.

### Deviations
- **`login_or_reuse` now propagates `CacheWrite` instead of swallowing it and opening a
  browser** (`src/lib.rs:try_silent_refresh`, `auth.py:OktaAuth._try_silent_refresh`).
  This is a **deliberate deviation from `doc:406-409`**, which names only `get_token()`
  and `get_token_noninteractive()` as the `CacheWrite`-propagating paths, and from the
  `login_or_reuse` sketch at `doc:362-365`, where a failed refresh always falls through
  to the flow. The design's own justification for the other two paths applies verbatim
  to this one: an `invalid_grant` whose cache-clear failed means the filesystem is the
  fault, so the browser login it would fall through to would just fail at `cache::save`
  with the same error, after taking the user through a login. Both audit seats found
  this independently. **This entry is the evidence for amending `doc:406-409` at
  finalization** to name all three paths; the doc was not edited here.
- Everything else in this pass is a fix to shipped code or docs, not a departure from
  the design.

### Tradeoffs
- **Equality guard now vs. a Phase 0 addendum first.** The addendum (two back-to-back
  device grants, compare the two `refresh_token` values) is what actually settles how
  the tenant behaves, but it needs two browser approvals from a human and is being run
  separately. The guard is correct under either answer, so it ships now and the
  addendum stays owed. Cost if the tenant does rotate on re-authorization: one wasted
  string comparison per fresh grant.
- **5s `MOCK_RECV_TIMEOUT` rather than a shorter one.** Every request in these tests is
  local and immediate, so the timeout only elapses on a genuine shortfall; 5s is slack
  for a loaded CI box without making a real failure slow to surface (6.4s wall for the
  verification run above, including compile).
- **Python `get_token` moves `cache.save` into an `else:` clause** rather than
  restructuring the try/except. Behavior is unchanged (a `CacheWriteError` from the save
  still propagates); what changes is that it is no longer logged as "refresh failed to
  clear a dead cache entry", which was simply false for a save failure. Rust already had
  the save outside that arm (`src/lib.rs:244`), so this is Python catching up.
- **Python README brought to Rust parity by porting the Rust prose**, not by writing a
  Python-native document. The two ports describing the same product in the same words is
  worth more than independent phrasing; the only intentional divergences are the
  language-level ones (`SharedCacheRequiresOfflineAccessError` vs the Rust variant,
  `LoginOutcomeKind.REFRESHED` vs `LoginOutcome::Refreshed`, and a source-compatibility
  note about branching on the enum rather than Rust's `#[non_exhaustive]` note).

### Open questions
- **Does a second interactive authorization for the same user+client mint a distinct
  refresh token on this tenant?** Unresolved, and it needs two browser approvals from a
  human to answer. The guard above makes the code correct either way, but the answer
  decides whether `doc:554` ("Two machines: each login mints its own refresh token") is
  true as written or needs correcting. If the tenant echoes the same token, `doc:554` is
  wrong and the "logout on one machine leaves the other logged in" claim beneath it is
  wrong too - a `logout` would kill both machines. That is a behavioral claim in the
  shipped Rust README ("7 idle days, an explicit revoke...") and in the Python one now,
  so it should be settled before either is tagged.
- **`doc:406-409` needs amending** to name `login_or_reuse` alongside the two
  `get_token*` paths, per the Deviations entry above. Doc edits are the parent's call at
  finalization; not done here.
- Release tags for both repos remain owed and unowned by this pass, as Phase 1 and
  Phase 2 already recorded.

## Regression fix: corrupt cache blocked both recovery paths

A regression this feature introduced in both ports, found by CodeRabbit on
`tatari-tv/okta-auth-py#7` and confirmed against the Rust baseline: on `origin/main`
before this work, `logout()` was `cache::clear(&dir)?` and nothing else, so it was
self-healing against a corrupt token cache. The offline_access work inserted a
`cache::load(&dir)?` ahead of the recovery action at two sites per port - `logout` and
`fresh_grant`/`_fresh_grant`. Because `load` propagates `CacheParse`/`CacheRead`
(`CacheParseError`/`CacheReadError`) on an unreadable or corrupt file, both escape
hatches disappeared at once:

- `logout` could no longer delete a corrupt cache: the command whose whole job is
  deleting the bad file refused because it could not read the bad file.
- `fresh_grant` reads the old token before running the flow and calling `cache::save`,
  so `login`, `login_device`, and a forced `login_or_reuse` could no longer overwrite a
  corrupt cache either.

The user's only remaining fix was `rm` by hand, with nothing in the error pointing
there.

Fixed in `okta-auth-rs` on `feat/offline-access-refresh-tokens` as `e2592e3`, which
landed on `main` in the `#19` squash (`d830c40`) and shipped in the annotated tag
`v0.7.0` (dereferences to `d830c40`, `origin/main`'s tip). Fixed in `okta-auth-py` on
`feat-auth-request-offline-access-refresh` as `39b5e41`, PR `#7`.

CI after the fix:
- `okta-auth-rs`: `otto ci` green at `d830c40` - `cargo test --all-features`
  **106 passed, 0 failed** (104 before, +2 new tests), `[ci] OK: All CI checks passed!`.
- `okta-auth-py`: `otto ci` green at `39b5e41` - `pytest` **111 passed** (109 before,
  +2 new tests), `[ci] All CI checks passed!`.

### Design decisions
- **An unreadable cache reads as "no refresh token", not as an error** -
  `src/lib.rs:logout`, `src/lib.rs:fresh_grant`, `src/okta_auth/auth.py:logout`,
  `src/okta_auth/auth.py:_fresh_grant` - a cache we cannot parse holds no refresh token
  we could revoke anyway, so best-effort-`None` is the honest reading of the file and it
  is what restores the recovery path. Both call sites carry a comment saying exactly
  that: this is the non-obvious case the comments rule says to comment.
- **Only the two read errors are absorbed; every other error still propagates** - in
  particular the `CacheWrite`/`CacheWriteError` precedence in `logout` (a failed `clear`
  beats a failed revoke, because a revoked token still on disk is what `is_valid()`
  would hand out) is untouched. Proven still to hold by the four pre-existing tests
  that pin it, all still green in both ports: `logout_returns_cache_write_when_clear_fails`,
  `refresh_invalid_grant_with_failed_clear_returns_cache_write`,
  `get_token_propagates_cache_write_instead_of_opening_browser`,
  `login_or_reuse_propagates_cache_write_instead_of_opening_browser`.
- **Two parity-named tests per port, identical snake_case names across both trees** -
  `logout_clears_cache_when_cache_file_is_unreadable` and
  `fresh_grant_proceeds_when_cache_file_is_unreadable`. Each writes a genuinely invalid
  JSON cache file (`{ not json` / `{ this is not json`) and asserts the recovery
  *outcome*, not the absence of an exception: logout asserts `tokens.json` is gone
  afterward; fresh_grant asserts the flow ran (`interactive_calls == 1`) and that the
  new grant is the file on disk.
- **No revoke may go out on either path** - both tests point the issuer at an
  unreachable `127.0.0.1:1` (Rust) or assert on a `requests.post` that raises on any
  call (Python), so "no attempted revoke" is an assertion rather than an assumption: a
  corrupt cache yields no token, therefore no revoke request.

### Deviations
- **The two ports absorb the same errors by different means, and the difference is
  unintended.** Python catches `CacheParseError`/`CacheReadError` by name; Rust
  `v0.7.0`, and `main`, match `Err(e)` for every variant. Narrow was asked for in both;
  Rust went wide because it was written that way while the fix was being made in-flight,
  not because anyone chose the looser shape. It is not a defect today: `cache::load` has
  exactly two error surfaces, `CacheRead` at `src/cache.rs:80` (the `read_to_string`
  failure) and `CacheParse` at `src/cache.rs:81` (the `serde_json::from_str` failure),
  and every other path through the function returns `Ok`, so no error the catch-all
  absorbs is one the named match would have propagated. It is still the weaker shape -
  it silently widens the first time `load` grows a variant, on the credential path - so
  it resolves toward Python, narrow, in the next change that touches `src/lib.rs`. It is
  deliberately not being fixed on its own: the diff changes nothing observable, and it
  would spend an SRE CODEOWNER review on a no-op in the repo that owns the credential
  path. **Direction is fixed: Rust converges toward Python, never the reverse.**
- **The Rust warnings log the error but not the cache path; Python's name the path.**
  Python logs `cache.cache_path(directory)` in both messages so the operator reading the
  log is told which file to remove; Rust logs the error only. Operator-facing gap, never
  behavioral, and it rides along with the narrowing above whenever `src/lib.rs` is next
  touched.
- **This entry is not a phase.** No version bump, no tag, no status flip - it documents
  a defect fix against already-committed Phase 1/Phase 2 work.

### Tradeoffs
- **Absorb the read error at the two recovery call sites** vs **make `cache::load`
  itself lenient**. Absorbing at the call site keeps `load` honest for its other
  callers - `cached_valid_token` still propagates `CacheParse` rather than silently
  reporting "logged out", which is the behavior the audit already pinned. Only the two
  functions whose next action destroys or overwrites the file get to shrug at it.
- **Inline `try`/`match` at each of the two sites** vs **one shared best-effort helper
  per port**. The duplicated block is five lines and the two comments are genuinely
  different (one is "the clear must still run", the other is "the flow and save must
  still run"). A shared helper would have collapsed both into one name and cost the
  site-specific reasoning.
- **Warn rather than silently continue.** A corrupt cache is a real event the operator
  should see in `--debug` output even though it is not fatal here; swallowing it
  entirely would make "why did it re-prompt me?" unanswerable.

### Break-to-prove runs

Each fix was reverted to the exact pre-fix expression, the matching test run, the
failure observed, and the file restored. Rust was mutated in a throwaway `git worktree`
at `d830c40` so the shared checkout was never left dirty; Python was mutated in place
from a saved pristine copy and restored byte-for-byte.

| # | mutation | test | observed failure |
|---|---|---|---|
| 1 | rs: `logout` best-effort match -> `cache::load(&dir)?` | `logout_clears_cache_when_cache_file_is_unreadable` | `panicked at src/lib.rs:860:23: called Result::unwrap() on an Err value: CacheParse("key must be a string at line 1 column 3")` - `test result: FAILED. 1 passed; 1 failed` |
| 2 | rs: `fresh_grant` best-effort match -> `cache::load(&dir)?` | `fresh_grant_proceeds_when_cache_file_is_unreadable` | `panicked at src/lib.rs:883:22: called Result::unwrap() on an Err value: CacheParse("key must be a string at line 1 column 3")` - `test result: FAILED. 1 passed; 1 failed` |
| 3 | py: `logout` `try`/`except` -> `cached = cache.load(directory)` | `test_logout_clears_cache_when_cache_file_is_unreadable` | `okta_auth.error.CacheParseError: Failed to parse token cache: Expecting property name enclosed in double quotes: line 1 column 3 (char 2)` raised from `src/okta_auth/cache.py:181` - `1 failed, 1 passed` |
| 4 | py: `_fresh_grant` `try`/`except` -> `old_cached = cache.load(directory)` | `test_fresh_grant_proceeds_when_cache_file_is_unreadable` | same `CacheParseError` from `src/okta_auth/cache.py:181` - `1 failed, 1 passed` |

In every run the *other* test of the pair still passed, so each test binds its own site
rather than both tests riding on one fix.

### Open questions
- **One known follow-up, deliberately deferred rather than open:** narrow the two Rust
  matches to `CacheRead`/`CacheParse` and name the cache path in the two Rust warnings,
  both to match Python. Neither changes behavior (see the Deviations entries and
  `src/cache.rs:80-81`), so neither justifies its own PR against the repo that owns the
  credential path, nor a re-cut of the `v0.7.0` tag that consumer repos are pinning.
  It lands with the next change that touches `src/lib.rs`. Recorded here so that change
  knows to carry it, and so a future parity pass resolves the difference toward Python
  rather than away from it.


## Phase 3: Rust consumers bump together

### Design decisions

- Pinned all four consumers to `tag = "v0.7.0"`, tag-only, with no `version` field — `slack-cli/Cargo.toml:30`, `marquee/cli/Cargo.toml:29`, `sdv/Cargo.toml:19`, `persona-cli/Cargo.toml:23` — one shape across the fleet, so the tag grep and cargo's resolver agree about what is pinned. On slack-cli the `version = "0.5.0"` field made the requirement parse as `^0.5.0`, which no v0.7.0 tag can satisfy, while a tag-only grep still reported success.
- Cleared the Slack token cache before propagating the Okta result — `slack-cli/src/auth.rs:logout` — `OktaAuth::logout` deletes the Okta cache and *then* returns `RevokeFailed`, so the previous early `?` produced the one state worse than either failure alone: a stale Slack token on disk with no Okta token left to re-vend one.
- Produced the revoke failure in the test from a real closed port (`http://127.0.0.1:1`) rather than a mock — `slack-cli/src/auth/tests.rs:logout_clears_slack_cache_even_when_okta_revoke_fails` — `logout` takes a concrete `&OktaAuth` with no injection seam, and an unroutable issuer exercises the true `revoke()` error path with no network and no HTTP fixture.
- Moved the test-only `ENV_LOCK` and `set_env` into a shared `crate::test_env` — `slack-cli/src/lib.rs` — see Deviations.
- Named every branch `pin-okta-auth-v0-7-0-for-offline-access-refresh-tokens`, the slug of the shared commit subject, so the `branch-pr-title-guard` hook accepts the commit subject verbatim as the PR title.

### Deviations

- Spec said to keep the phrase "Unattended runs reuse the existing silent-refresh Okta path" in `slack-cli/README.md` while adding the refresh-token-death case, but the acceptance criterion greps for `silent-refresh Okta path` and requires 0 lines. Both cannot hold. Kept the claim, reworded the sentence to "reuse the same Okta token refresh an interactive run uses", satisfying the intent and the criterion.
- Spec scoped the sdv doc fix to the prose at `sdv.yml:33-34` and `CLAUDE.md:78-79`. Also updated the `scopes:` example directly below that prose and the scope list at `CLAUDE.md:74`, both of which still read `openid email profile`. v0.7.0 fail-closes at `lib.rs:416` when the shared default cache is used without `offline_access`, so the example as written was a live trap for anyone who uncommented it.
- Spec scoped slack-cli to one code change plus one test. Also moved `ENV_LOCK`/`set_env` from per-module statics in `config/tests.rs` and `valet/tests.rs` into a shared `crate::test_env`. Unit tests run as threads in a single binary, so three independent mutexes guarding the same `XDG_CACHE_HOME` serialize nothing; without this the new test could have its cache path moved mid-run by another module and flake. Same effect, correct seam.
- Branches were created as `deps/okta-auth-v0.7.0` and renamed to `pin-okta-auth-v0-7-0-for-offline-access-refresh-tokens`. The `branch-pr-title-guard` hook slugifies a PR title by collapsing every non-alphanumeric run to `-` and demands exact equality with the branch, so a branch containing `/` can never be matched by any title.
- persona-cli's `Cargo.lock` is gitignored (`.gitignore:8`), so its commit contains only `Cargo.toml`. The lock was still regenerated and CI compiled against v0.7.0. The other three track and committed their lockfiles.
- marquee was built and committed in a detached `git worktree` at `main` rather than in the primary checkout, which held another agent's large in-flight change. Its `main` advanced from `8002b4e` to `0be08e2` mid-build; the branch was rebased onto `0be08e2` and CI re-run green on the rebased commit.

### Tradeoffs

- Closed local port vs. a `mockito` server for the revoke failure — mockito is already a dev-dependency, but a connection-refused error needs no server lifecycle, no port binding, and no risk of a hung test; the assertion is on `logout`'s ordering, not on Okta's wire format.
- Reworded the README sentence vs. relaxing the acceptance criterion — the criterion is what the phase is graded on, and the phrase was the stale wording it was written to catch; the claim survives, only the targeted words are gone.
- Shared `test_env` module vs. leaving three per-module locks and accepting a rare flake — a test that passes for timing reasons is the failure mode this phase's audit was already cleaning up, so the small refactor was preferred over adding to it.
- Branch named from the commit subject vs. the shorter `deps-okta-auth-v0-7-0` — the guard requires the PR title to slugify to exactly the branch name, and `deps-okta-auth-v0-7-0` would force the nonsense title "deps okta auth v0 7 0".

### Open questions

- None.

### Verification

Acceptance criteria, run against the committed branch content (marquee's working tree is on `main`, so reading its file in place shows the old pin):

```
$ rg -N --no-filename -o 'okta-auth = .*tag = "[^"]*"' <the four Cargo.toml at their branch> \
    | sed 's/.*tag = "//; s/".*//' | sort -u
v0.7.0
count: 1

$ rg -c 'okta-auth = .*version =' <the four Cargo.toml at their branch> | wc -l
0

$ rg -c 'no `offline_access`|silent-refresh Okta path' slack-cli/README.md sdv/sdv.yml sdv/CLAUDE.md
(no output; rg exit 1; 0 lines)
```

Every consumer was verified to BUILD against the new crate, not a cached artifact: `cargo clean -p okta-auth` then a full `otto ci` in each repo.

```
slack-cli    [test] Compiling okta-auth v0.7.0 (https://github.com/tatari-tv/okta-auth-rs?tag=v0.7.0#d830c400)      [ci] All CI checks passed!
sdv          [test] Compiling okta-auth v0.7.0 (https://github.com/tatari-tv/okta-auth-rs.git?tag=v0.7.0#d830c400)  [ci] All CI checks passed!
persona-cli  [test] Compiling okta-auth v0.7.0 (https://github.com/tatari-tv/okta-auth-rs.git?tag=v0.7.0#d830c400)  [ci] All CI checks passed!
marquee      Checking okta-auth v0.7.0 (https://github.com/tatari-tv/okta-auth-rs.git?tag=v0.7.0#d830c400)          (fresh worktree + empty target dir)
```

All four lockfiles resolve the tag to the same commit, matching the annotated tag:
`?tag=v0.7.0#d830c400a6b5ee408c794e92e6350ddbd4c9ecf6`.

Break-to-prove on the slack-cli `logout` fix. Restoring the original `auth.logout()?` as the first statement and running the new test:

```
test auth::tests::logout_clears_slack_cache_even_when_okta_revoke_fails ... FAILED

thread 'auth::tests::logout_clears_slack_cache_even_when_okta_revoke_fails' panicked at src/auth/tests.rs:119:5:
the Slack token cache must be deleted even when Okta's revoke fails

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 808 filtered out
```

It fails on the assertion, not on a panic, and passes again once the fix is restored.

### Environment note for later phases

A cargo hazard in the same class as the shared-`target/` staleness seen in okta-auth-rs, but a distinct mechanism. A `cargo` run under a sandbox that denies `sccache` caches the FAILED rustc probe in `target/.rustc_info.json`:

```json
{"rustc_fingerprint":4608563470856345331,"outputs":{"9168926135673273736":
{"success":false,"status":"exit status: 2","code":2,"stdout":"",
"stderr":"sccache: error: Operation not permitted (os error 1)\n"}},"successes":{}}
```

Cargo then replays that cached failure on every later run in that repo, sandbox or not, so the repo looks permanently broken while its neighbours build fine. It hit sdv and persona-cli here. The tell is a 221-byte `.rustc_info.json` against ~1.3k in a healthy repo. Deleting the file fixes it; no code change is warranted.
