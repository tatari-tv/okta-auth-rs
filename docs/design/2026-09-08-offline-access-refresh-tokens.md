# Design Document: `offline_access` and Refresh Tokens for the okta-auth Fleet

**Author:** Scott Idler
**Date:** 2026-09-08
**Status:** Implemented
**Review Passes Completed:** 5/5
**Revision:** r4. Three panel rounds (Architect via Gemini, Staff Engineer via Codex),
plus two independent panel-agent syntheses per round. Every finding is dispositioned
in the Review Log; Open Questions is empty; every acceptance criterion carries an
"Observed on main" line measured against the tree.

## Review Log

- **Panel r4 (2026-09-08):** Run by the original panel agent on the r4 snapshot. All
  four r3 findings confirmed closed in the live doc. Two must-fix, both in Phase 2
  (Python parity), both verified here and folded:
  1. Python's `LoginOutcome` is a frozen dataclass with only `kind`, `cache_path`,
     `since` (`okta-auth-py/src/okta_auth/auth.py:44-58`); the Phase 2 bullet never
     added `revoke_warning`, so two of the twenty-three parity tests were unwritable
     and the port would have stayed silent on a failed revoke. Field and `message()`
     clause added to Phase 2.
  2. Phase 2 named only the HTTP mock (`monkeypatch` of `requests.post`), which cannot
     produce flow-invocation counts; Python hard-calls `pkce.authorize` /
     `pkce.authorize_device` at `auth.py:165`, `:226`, `:241`. Phase 2 now names the
     seam: monkeypatch `okta_auth.auth.pkce.authorize` and `.authorize_device` with
     counting fakes, plus an ordered `requests.post` recorder that snapshots the cache
     file when `/v1/revoke` lands (the Python twin of `MockOkta`).
  Cheap win: Alternative 10 still said "for now" and pointed at an open question
  that no longer exists; reworded. Also from this round: the Staff Engineer ran the
  resolver on the `version =` finding rather than reasoning about it (slack-cli parses
  as `^0.5.0`, the tag-only three as `*`), confirming a tag-only bump is
  unsatisfiable; both seats endorse dropping the field over bumping in lockstep.
  Process note recorded for next time: the doc was edited while seats were reading it
  in r3 and r4 (70 and 87 diff lines); freezing the file until both seats return
  would cost nothing and save a seat's attention per round.
- **Panel r3, second agent's report (2026-09-08):** Same two seats read by a second
  synthesis agent; corroborated the first agent's r3 item for item (Architect
  conceded to (a) with the "entitled invariant" framing; Staff on (a); the seam and
  `get_token` CacheWrite tests; variant-level `#[non_exhaustive]`; happy-path
  `revoke_warning: None` test; the two citation widenings). Nothing new. Both seats
  noted they ran no build or test commands, so every claim about what a test can
  assert is a reading of the code; Phase 1's break-to-prove runs are where that gets
  settled.
- **Panel r3 (2026-09-08):** Both seats completed (Architect 25m cap, one attempt).
  **The open question closes on (a).** Both seats independently recommend keeping the
  rule inside `fresh_grant()` keyed on `cache_dir: None`. The Architect withdrew its
  r2 objection after reading the `default_cache_dir` doc comment (`src/cache.rs:47-53`:
  the default dir is "shared across every CLI that uses okta-auth ... A tool that
  needs isolation can still pass an explicit `cache_dir`"), and stated the
  entitlement line now recorded in Resolved Decisions: the crate may enforce
  invariants on its own default shared directory and may not on a consumer-supplied
  `cache_dir`. The Staff Engineer's argument against (b): `OktaAuth::new()` is
  infallible (`src/lib.rs:97`), so nothing at runtime proves `validate()` ran, and
  crate CI cannot catch a fifth consumer that forgets. Against (c): a future
  consumer can still build `OktaAuthConfig { scopes: ["openid"], cache_dir: None }`
  directly. Two must-fix, folded:
  1. (Staff) The doc promised both `get_token` entry points propagate `CacheWrite`
     but named a test only for the noninteractive one; `get_token()` is the harder
     half because today it swallows every refresh error and falls to the browser
     (`src/lib.rs:162-164`). Test added.
  2. (Both, third round raised) The named tests assert "flow invoked / not invoked"
     and "saved before revoked", but `login_or_reuse` hard-calls `login()` /
     `login_device()` (`src/lib.rs:138-141`), `pkce::authorize` /
     `authorize_device` hardcode production runners (`src/pkce.rs:131`, `:160`), and
     `spawn_token_server` (`src/lib.rs:317`) serves one static request. Phase 1 now
     adds a `LoginFlow` seam on `OktaAuth` and an ordered multi-request mock that
     snapshots the cache file when `/v1/revoke` lands.
  Cheap wins folded: `#[non_exhaustive]` goes on the `LoggedIn` variant as well as the
  enum (the enum attribute does not cover added fields); a happy-path test asserts
  `revoke_warning` is `None` and `message()` omits the warning; three citations
  widened to the lines the claims rest on (`src/pkce/tests.rs:355-361`,
  `src/pkce/device.rs:82/:149/:158`, slack-cli `src/mcp.rs:212` + `src/valet.rs:57`);
  the `get_token`/`get_token_noninteractive` sentence now names the refresh arm so
  the line numbers stop being misread as function starts. Not acted on: the
  Architect's repeat claim that `src/lib.rs:155`/`:202` are wrong (they are the
  refresh arm, which is the claim).
- **Panel r2, second agent's report (2026-09-08):** A duplicate r2 dispatch (started
  when the first agent looked stalled) also completed against the r2 snapshot with
  both seats. Its seats corroborated the first agent's r2 findings one for one. One
  NEW must-fix, verified: slack-cli is the only consumer whose dependency line carries
  a `version` field (`Cargo.toml:30`: `tag = "v0.5.0", version = "0.5.0"`; marquee
  `cli/Cargo.toml:29`, sdv `Cargo.toml:19`, persona-cli `Cargo.toml:23` are tag-only).
  Bumping only `tag` to the next minor leaves a caret requirement (`>=0.5.0, <0.6.0`
  for a 0.x crate) the new tag does not satisfy, cargo fails to resolve, and the
  Phase 3 criterion (which greps `tag =`) would PASS on a broken build. Fixed: Phase 3
  drops the `version` field from slack-cli so all four lines have one shape, with an
  acceptance criterion that no `okta-auth` line carries `version =`, and Phase 3's
  `otto ci` (which builds) is the real gate. Cheap wins folded: `src/cache.rs` comment
  cite is `:98-101` (rename at `:102`), `oauth2 basic.rs` cite is exactly `:117`; the
  earlier "citations off by two lines" wording was wrong: `:304/:83/:83/:70` is the
  `let scopes = file` binding and `:306/:85/:85/:72` is the `.unwrap_or_else`
  fallback, both valid, so that was a re-aim, not a fix. Confirmed again that
  `#[non_exhaustive]` on `LoginOutcome` buys nothing today (sdv's `match` at
  `src/main.rs:101` is on the `Result`); it stays as forward hardening only.
- **Panel r2 synthesis report (2026-09-08):** The panel agent's own pass over the live
  doc found three items neither seat had named, all verified here and folded in:
  1. The "best-effort revoke, `warn!`" on forced re-login is invisible: all four
     consumers route `env_logger` to a file (`Target::Pipe`: slack-cli
     `src/main.rs:37`, marquee `cli/src/main.rs:422`, sdv `src/main.rs:257`,
     persona-cli `src/main.rs:50`). A dead network during `login --force` would orphan
     a refresh token for 7 days and say nothing. Fixed: `fresh_grant()` returns the
     revoke outcome and `LoginOutcome::LoggedIn` carries `revoke_warning`, which
     `message()` prints. The log line stays as well.
  2. `cache::clear` can fail (`src/cache.rs:136`, `Err(CacheWrite)`) and the doc said
     nothing about it on the two paths that now depend on it. Fixed: `CacheWrite`
     wins over `RevokeFailed` on logout (a revoked token still on disk is the worse
     outcome, since `is_valid()` checks only `expires_at`); on `invalid_grant` a failed
     clear returns `CacheWrite` instead of `RefreshFailed`, and both `get_token*`
     entry points propagate `CacheWrite` unchanged rather than collapsing it to
     `NonInteractive`. Two tests added.
  3. Four consumer scope-override citations re-aimed from the `let scopes = file`
     binding to the `.unwrap_or_else(tatari::SCOPES)` fallback line: slack-cli
     `src/config.rs:306`, marquee `cli/src/config.rs:85`, sdv `src/config.rs:85`,
     persona-cli `src/config.rs:72`. The original lines were also valid.
  The agent also named the Architect's middle path the doc had not engaged: a
  `validate()` on the config that consumers call, keeping the rule out of the login
  execution path. Added as Alternative 10 and as option (b) in Open Questions.
- **Panel r2 (2026-09-08):** Both seats completed. Both verified all five non-test
  `cache::save` sites in `src/lib.rs`: the two refresh-path saves (`:159`, `:206`)
  cannot downgrade the cache because a refresh preserves the original grant's scopes
  and the fallback keeps the sent refresh token; the three fresh-grant saves (`:176`,
  `:248`, `:263`) are exactly the guarded set. Both confirmed save-before-revoke
  closes the strand window and that two concurrent `login --force` runs now only
  ever revoke the token that was old when each started. Folded in:
  1. (Staff) The Pass 4 log entry still read "flow -> revoke old -> save new";
     annotated as superseded so the doc has one ordering.
  2. (Staff) Three hand-placed guards replaced by one private `fresh_grant()` helper
     (guard -> read old -> flow -> save -> revoke) called from `login`,
     `login_device`, and `get_token`'s fallthrough. One seam, one test surface.
  3. (Both) Named tests extended from eleven to eighteen: guard on all three fresh
     paths; every non-`invalid_grant` `RequestTokenError` variant keeps the cache
     (`Request`, `Parse`, `Other`, other `ServerResponse` codes); `login_or_reuse`
     with an expired token and no refresh token runs the flow; a revoke `200` with an
     OAuth error body is still success (Okta returns 200 for invalid tokens by
     design). Rotated-refresh persistence stays covered by the existing
     `get_token_noninteractive_refreshes_expired_token`.
  4. (Staff) Phase 2 parity criterion now asserts the same eighteen test names exist
     in `tests/`; Phase 3 asserts the exact Phase 1 tag, not merely one distinct tag.
  5. (Staff) `oauth2` citation `basic.rs:113 -> :117`.
  6. (Staff) The invariant is stated precisely: "a fresh interactive grant written to
     the shared default cache carries a refresh token", nothing broader.
  7. (r1 synthesis) `src/cache.rs:98-101` says "every token minted for the same client
     is equivalent"; revoke-on-relogin makes that false. Comment updated in Phase 1.
  **Pushed back, with rationale, to the Architect:** its Qe position that the guard
  is over-opinionated for a generic crate and that Alternative 8 (delete the
  `scopes:` knob from four consumers) is the right seam. See Resolved Decisions;
  Scott decides.
- **Panel r1, Architect retry (2026-09-08):** After the 10-minute hang the seat was
  re-run with a 25-minute wall clock against the r1 snapshot and completed. It
  independently reached the Staff Engineer's two largest findings (the `scopes:`
  config override defeats "ship together"; the old refresh token must be read before
  the flow or a concurrent `login --force` revokes the other terminal's new grant),
  both already fixed in r2. New from the Architect, folded in: (1) `invalid_client` /
  `unauthorized_client` responses keep the cache by design (config breakage, not
  token death) and an HTML 503 lands in `RequestTokenError::Other`, also kept; noted
  in Architecture. (2) The AC5 baseline was measured against the installed binary,
  not the tree; re-measured against a `cargo build` of slack-cli main (06e5111),
  same result, recorded. (3) Two citations pointed at the `#[test]` attribute /
  function signature rather than the statement: `src/lib.rs:549 -> 550`,
  `src/pkce/tests.rs:353 -> 355`. Confirmed `LoginOutcome` is not
  `#[non_exhaustive]` today (`src/lib.rs:42`) and no consumer matches on it.
- **Panel r1 (2026-09-08):** Architect (Gemini) hung and was killed at the 10-minute
  wall clock (retried above). Staff Engineer (Codex) returned six findings, all
  verified against the code and all folded in:
  1. `invalid_grant` match must happen before the `.map_err` at `src/lib.rs:283`
     erases the typed error, and compares `&BasicErrorResponseType`. Fixed in API
     Design. Confirmed no other Okta token-endpoint code means "refresh token dead".
  2. Ordering hole: flow -> revoke -> save strands the user if `cache::save` fails
     after the revoke. Fixed: flow -> save new -> revoke old (old token read into
     memory before the flow, never re-read from disk after the save).
  3. `#[non_exhaustive]` semver framing was loose. Reworded: adding a variant is
     source-breaking in general; the fleet is safe because every consumer is
     tag-pinned and bumped in Phase 3, and no exhaustive match exists (verified).
  4. **Shared-cache downgrade survives the tag bump**: every consumer's config file
     has a `scopes:` override that replaces `tatari::SCOPES`, so one user YAML can
     still write `refresh_token: null` into the shared cache. Fixed with a fail-closed
     guard in the crate (Overview item 5, Resolved Decisions).
  5. `rg -c` prints nothing and exits 1 on zero matches; criteria now normalize with
     `|| echo 0`. Phase criteria rewritten as named-test asserts. slack-cli's `logout`
     only clears the Slack token cache after the Okta logout succeeds
     (`src/auth.rs:106`), which would contradict Phase 4 on `RevokeFailed`; Phase 3
     now changes slack-cli to clear both caches before propagating the error.
  6. Citation precision: `src/lib.rs:549` is where the rotated-refresh test starts;
     the assertions are at `:579-582`. `src/pkce/tests.rs:353` covers device-grant
     scope joining, not `tatari::SCOPES`.
- **Pass 5 (excellence):** Acceptance criteria cut from seven to five (the
  `refresh_token` non-null check is a precondition of the unattended probe; the
  `login` no-browser check lives in Phase 1 and Phase 4 success criteria); explicit
  blast-radius line added; voice lint (adverbs, dashes) clean.
- **Pass 4 (edge cases):** (1) Revoking the old refresh token BEFORE the interactive
  flow on `login --force` would leave a user with no token at all if they abandon the
  browser (Okta: revoking a refresh token revokes its access token too). Pass 4 set
  the order to flow -> revoke old -> save new; panel r1 finding 2 superseded that
  with flow -> save new -> revoke old, which is the order everywhere else in this
  doc. (2) A dead refresh token (Okta `invalid_grant`:
  7 idle days, revoked elsewhere, user deactivated) stayed in the cache and was
  retried on every call, one failing POST per systemd tick. `refresh()` now clears the
  cache on `invalid_grant` only; network and 5xx keep it. (3) Two machines hold two
  refresh tokens; logout on one does not touch the other. (4) MCP servers load the
  cache per call, so a `login --force` in another terminal is picked up without a
  restart. (5) A refresh keepalive for timer-only hosts considered and parked
  (Alternative 9).
- **Pass 3 (clarity):** Summary now names all changes; dropped the false
  "smallest first"; specified the revoke request (URL, form fields, success = 2xx,
  failure mapping); spelled out the Phase 4 expiry simulation and that it also
  exercises a valet re-vend; `cargo update -p okta-auth` named; README sections to
  touch enumerated; `pytest` criteria mirror the Rust ones.
- **Pass 2 (correctness):** Two gaps in the draft. (1) `login_or_reuse(false, _)`
  only checks `cached_valid_token()`, so with an expired access token and a live
  refresh token `<tool> login` would open a browser for nothing: added a silent
  refresh arm and a `LoginOutcome::Refreshed` variant. (2) A forced or stale-binary
  re-login replaces the cache without revoking the previous refresh token, leaving a
  live orphan for up to 7 idle days: `login()`/`login_device()` now revoke the cached
  refresh token best-effort before caching the new grant. Also recorded Okta's
  persistent-token refresh semantics (response echoes the SAME `refresh_token`; the crate's
  keep-the-old-token fallback is load-bearing), fixed Phase 0 to poll until approved,
  and pinned the AC6 observation to the installed `slack v0.8.0`.

## Summary

Every Tatari CLI built on `okta-auth` (Rust and Python) requests `openid email
profile` and therefore never receives a refresh token. Access tokens last 12 hours,
then a human logs in again. The crate's silent-refresh code exists on both entry
points and is unreachable. This doc adds `offline_access` to the shared default
scopes, makes `login_or_reuse` refresh before it prompts, revokes the refresh token
on `logout()` and on forced re-login, drops a dead refresh token from the cache on
`invalid_grant`, fixes the docs, and ships the change to every consumer together so
the shared token cache never regresses.

## Problem Statement

### Background

- `okta-auth-rs` (v0.6.0) and `okta-auth-py` (0.3.0) are the fleet's Okta PKCE
  libraries. Consumers: `slack-cli`, `marquee` (cli), `persona-cli`, `sdv` (Rust);
  `persona-mcp`, the `search-loki` token script (Python).
- All Rust consumers default to `okta_auth::tatari::SCOPES` and share one cache,
  `~/.cache/okta/tokens.json`, mode 0600: one login, many tools.
- Shared Okta app: `Okta Auth {rs,py} CLI`, client id `0oa144xsutkeO1nev698`, Native,
  client auth None, PKCE required, grants Authorization Code + Refresh Token + Device
  Authorization, refresh behavior "Use persistent token", Require consent checked.
  Verified in the Admin Console 2026-09-08.
- Authorization server `default` (audience `api://default`), one policy (All Clients),
  one rule (Any scopes): access token 12h, refresh token Unlimited, expires if not
  used every 7 days. Verified in the Admin Console 2026-09-08.
- Cached token today: `refresh_token: null`, `scp: [openid, profile, email]`,
  lifetime 12h (`iat` 10:48Z, `exp` 22:48Z).

### Problem

- No consumer ever holds a refresh token, so the refresh arm inside `get_token()`
  (the `if let Some(ref refresh_token)` at `src/lib.rs:155`) and the one inside
  `get_token_noninteractive()` (`src/lib.rs:202`) can never be taken. The README's
  "transparent refresh" is aspirational.
- Headline casualty: `slack scheduled deliver` under a systemd timer. The Confluence
  guidance the feature serves is "don't post at 11pm, schedule it for the morning."
  A 10-hour gap against a 12-hour token means the parent posts (Slack holds it) and
  the threaded follow-ups wait for a human login. Observed 2026-09-08.
- Same class for long Claude Code sessions: `persona mcp`, `marquee mcp`, `slack mcp`
  all fail with a login hint after 12h.
- The docs are stale in three places and say different things: okta-auth-rs README
  promises refresh; slack-cli `README.md:162` says unattended runs "reuse the
  existing silent-refresh Okta path"; sdv `sdv.yml:32` and `CLAUDE.md:78` say
  "no offline_access, ~12h".

### Goals

- Every consumer of `tatari::SCOPES` receives a refresh token on login. (Scott,
  2026-09-08: "deep dive investigation into offline access and refresh tokens for
  okta-auth-rs and its consumers".)
- An expired access token refreshes silently in every context the crate supports:
  interactive CLI, MCP server, systemd timer with no controlling terminal.
- `logout()` revokes the refresh token at Okta before deleting the local cache, so a
  long-lived credential never outlives the user's intent to end the session.
  (Claude proposal in the 2026-09-08 investigation, carried into the plan Scott took
  to `/create-design-doc`.)
- Rust and Python ports stay at parity.
- Docs in the crate and every consumer describe the shipped behavior.

### Non-Goals

- Refresh token rotation. The app is on "Use persistent token"; rotation needs a
  cross-process lock around refresh that does not exist. Parked; revisit condition:
  anyone flips the app to "Rotate token after every use".
- Changing which entry point each MCP server calls (`get_token` vs
  `get_token_noninteractive`). Behavior in a no-tty process is already fail-fast.
- `persona-mcp`. It vendors an `okta_auth-0.1.0` wheel and points at client
  `0oa11b1u7nzZd5EaW698`, which Okta now reports as `invalid_client`. Its Okta login
  path is already broken independently of scopes. Separate fix, separate ticket.
- `search-loki`. Already requests `offline_access groups` in its own cache dir.
- Adding `groups` or any scope beyond `offline_access` to the shared default.
- Okta admin changes. None are needed; both app and policy already permit this.
- Cross-process locking of the shared cache. Not needed while tokens are persistent.
- Removing the `scopes:` config knob from consumers. It stays; the crate guard makes
  the harmful value unwritable (Alternative 8).

## Proposed Solution

### Overview

"The flow" below means the interactive login: browser redirect or device grant.

Seven coordinated changes:

1. `tatari::SCOPES` gains `offline_access` (Rust + Python).
2. `login_or_reuse(false, _)` tries a silent refresh before falling to the flow,
   returning `LoginOutcome::Refreshed`. Today it only checks for a still-valid access
   token, so `<tool> login` at hour 13 would open a browser even with a live refresh
   token on disk.
3. `logout()` revokes the cached refresh token via RFC 7009 `/v1/revoke`, then clears
   the cache (Rust + Python). Revocation failure still clears the cache and surfaces
   as a new `RevokeFailed` error. `login()` and `login_device()` read the previous
   refresh token into memory, run the flow, save the new grant, then revoke the
   previous token best-effort: a revoke failure never fails the login, and it is
   reported in the `LoginOutcome` message the consumer prints (the log line alone is
   invisible: every consumer pipes `env_logger` to a file). Save-before-revoke means
   no failure mode strands the user: an abandoned browser leaves the old grant
   untouched; a crash or failed revoke after the save leaves at worst an orphan that
   dies after 7 idle days, and the user is told so.
4. `refresh()` clears the cache when Okta answers `invalid_grant` (the refresh token
   is dead: 7 idle days, revoked, or user deactivated). Any other failure (network,
   5xx, unparseable body) keeps the cache so a transient blip does not force a
   re-login.
5. Shared-cache guard. The invariant, stated exactly: **a fresh interactive grant
   written to the shared default cache (`cache_dir: None`) carries a refresh token**,
   which means the requested scopes include `offline_access`. Nothing broader: it is
   not "no underscoped token ever touches the cache". One private helper,
   `fresh_grant()`, is the only path that writes a fresh grant; `login`,
   `login_device`, and `get_token`'s interactive fallthrough all call it. It checks
   the invariant first and returns `Err(SharedCacheRequiresOfflineAccess)` before any
   network call. This closes the hole a user's `scopes:` config override leaves open
   after every binary is bumped. Refresh-path saves are not guarded: a refresh
   preserves the original grant's scopes and keeps the sent refresh token, so it
   cannot downgrade the cache (verified by both seats, r2). Read paths are not
   guarded: reading cannot corrupt. An explicit `cache_dir` is not guarded: an
   isolated cache is the consumer's own business (search-loki).
6. Docs: crate READMEs describe refresh as real; consumer docs drop the "no
   refresh / 12h" claims; the one shipped example config (`sdv.yml`) says the shared
   cache requires `offline_access`.
7. Every Rust consumer bumps to the new crate tag in one campaign, because the
   shared cache is only as strong as its weakest writer; slack-cli's `logout` also
   changes to clear the Slack token cache even when the Okta revoke fails.

Nothing else changes. The cache schema already carries `refresh_token: Option`, the
refresh arms already persist a rotated token, and the existing tests already cover
device-grant scope joining with `offline_access` (`src/pkce/tests.rs:355-361`) and
rotated-refresh persistence (test at `src/lib.rs:550`, assertions at `:579-582`).

### Architecture

```text
login (browser | device)  ->  Okta /v1/token  ->  { access, refresh, expires_in }
                                                   -> ~/.cache/okta/tokens.json (0600)

get_token* :  cache valid?  -> yes: return access
              refresh set?  -> POST /v1/token grant_type=refresh_token
                                 2xx           -> save -> return
                                 invalid_grant -> clear cache -> fall through
                                 other error   -> keep cache  -> fall through
              fall through  -> get_token: run flow | get_token_noninteractive: Err

login_or_reuse(force=false):
              cache valid?  -> AlreadyLoggedIn
              refresh set?  -> refresh ok -> save -> Refreshed
              else / force  -> login | login_device -> LoggedIn

fresh_grant(flow)   [the ONLY writer of a fresh grant; called by login,
                     login_device, and get_token's interactive fallthrough]:
              shared cache && scopes lack offline_access? -> Err(SharedCacheRequiresOfflineAccess)
              old := cache.refresh_token (read once, into memory)
              run flow      -> new grant in hand
              save new grant
              old is Some?  -> POST /v1/revoke (best-effort; failure text returned to
                               the caller as revoke_warning, and logged)

logout     :  refresh set?  -> POST /v1/revoke token_type_hint=refresh_token (client_id only)
              clear cache   -> clear failed: Err(CacheWrite)   [wins: a revoked token is
                                                                still on disk and is_valid()
                                                                would hand it out]
                               clear ok, revoke failed: Err(RevokeFailed)
                               both ok: Ok(())
```

Revoke request, both ports: `POST {issuer}/v1/revoke`, form body
`client_id=<id>&token=<refresh>&token_type_hint=refresh_token`, no auth header,
30s timeout. Success is any 2xx. Non-2xx maps to `RevokeFailed("HTTP <status>")`;
a transport error maps to `RevokeFailed(<reqwest error>)`.

- Refresh uses the client's existing `refresh()` (`src/lib.rs:274`): public client,
  `client_id` in the body, no secret. Unchanged. Okta's persistent-token behavior
  (refresh-tokens guide: "If the lifetime setting hasn't expired, when a client makes
  a request for a new access token, Okta only returns the new access token") means
  the response echoes the SAME `refresh_token` back rather than omitting it.
  **Corrected 2026-09-08 by Phase 0 against the live tenant: the returned token is
  byte-identical to the one sent (`same_refresh_token: True`).** Persistence is
  confirmed - the tenant does not rotate - but by echo, not by omission. `refresh()`
  already falls back to the token it sent (`src/lib.rs:295-298`); that fallback stays as
  defence against a tenant or mock that omits the field and is covered by
  `refresh_keeps_sent_refresh_token_when_response_omits_it`, but it is NOT exercised by
  this tenant's happy path. The original wording ("omits", "load-bearing") overstated
  it and is corrected here.
- Dead-token detection uses the typed error the `oauth2` crate already returns, and
  must inspect it BEFORE the existing `.map_err(|e| RefreshFailed(e.to_string()))` at
  `src/lib.rs:283` flattens it to a string: `RequestTokenError::ServerResponse(r)` with
  `r.error() == &BasicErrorResponseType::InvalidGrant` (oauth2 5.0.0: `error()`
  returns a reference; `invalid_grant` maps to `InvalidGrant` in `basic.rs:117`). The
  crate's other variants (`Request`, `Parse`, `Other`, which is where an HTML 503 page
  lands) all keep the cache, and so do other `ServerResponse` codes such as
  `invalid_client` / `unauthorized_client`: those mean the app or config is broken,
  not that the token is dead, and a human has to fix them either way. Python reads
  the body before `raise_for_status()` and matches HTTP 400 with
  `error == "invalid_grant"`. Only that case clears the cache. If that clear itself
  fails, `refresh()` returns `CacheWrite` (the filesystem is the fault, and the dead
  token is still on disk), and both `get_token()` and `get_token_noninteractive()`
  propagate `CacheWrite` unchanged instead of collapsing it into a browser
  fallthrough or `NonInteractive`. This is a behavior change on both: today
  `get_token()` swallows every refresh error and falls to the browser
  (`src/lib.rs:162-164`) and `get_token_noninteractive()` collapses every refresh
  error to `NonInteractive` (`src/lib.rs:213-220`). After: `CacheWrite` is returned
  as-is; every other refresh error keeps today's behavior.
- Shared-cache guard: `self.config.cache_dir.is_none() && !scopes.contains("offline_access")`
  checked once, at the top of `fresh_grant()`. It is a config error, so it is checked
  before URL building and before any HTTP. It is not keyed on `tatari::*` (that
  module stays unwired from the flow, per its own doc comment): the invariant is
  about the shared default cache being a multi-consumer resource, not about Tatari.
- `src/cache.rs:98-101` ("Concurrent writers => last writer wins, which is correct
  here: every token minted for the same client is equivalent") stops being true once
  a re-login revokes its predecessor. The comment is rewritten in Phase 1 to say:
  last writer wins; the loser's grant is revoked by nobody and dies after 7 idle
  days; no writer ever revokes a token it did not itself read as "old" before its
  flow began.
- Every consumer loads the cache per call (`persona-cli src/mcp.rs:163`, `marquee
  cli/src/mcp.rs:87`, slack-cli `src/mcp.rs:212` calling `build_source` at
  `src/valet.rs:57` per tool call, which reaches `get_token()` at `src/valet.rs:43`),
  so a `login --force` in another terminal is picked up by running MCP servers
  without a restart.
- Revoke is a raw form POST built the same way `src/pkce/device.rs` builds its
  device-authorization POST (form at `:82`, 30s client at `:149`, POST at `:158`):
  `reqwest::blocking`, 30s timeout, `client_id`, `token`, `token_type_hint`. This copies the in-house pattern instead of threading the
  `oauth2` crate's `RevocationUrl` typestate through `BasicClient`.
- Okta semantics that shape the design (developer.okta.com, revoke-tokens guide):
  "revoking a refresh token does revoke the associated access token", and "Revoking
  a token that is invalid, expired, or already revoked returns a 200 OK". So one
  revoke call is sufficient and idempotent; the access token needs no separate call.

### Data Model

`TokenCache { access_token, refresh_token: Option<String>, expires_at }` is
unchanged. After this ships, `refresh_token` is `Some` for any login through
`tatari::SCOPES`. A cache written by an older binary still parses (`None`).

### API Design

Rust (`okta-auth-rs`):

```rust
// src/tatari.rs
pub const SCOPES: &[&str] = &["openid", "email", "profile", "offline_access"];

// src/error.rs  (enum is already #[non_exhaustive]; consumers carry a wildcard arm)
#[error("Refresh token revocation failed: {0}")]
RevokeFailed(String),
#[error(
    "scopes omit `offline_access` but the token cache is the shared default \
     (~/.cache/okta): a login here would strip the refresh token every sibling CLI \
     relies on. Add `offline_access` to `scopes`, or set an explicit `cache_dir`."
)]
SharedCacheRequiresOfflineAccess,

// src/lib.rs
#[non_exhaustive]              // new. Adding `Refreshed` is source-breaking for any
                               // exhaustive downstream match in general; none exists in
                               // the four consumers (verified), and all are tag-pinned
                               // and bumped in Phase 3. The attribute forces a wildcard
                               // arm from here on.
pub enum LoginOutcome {
    AlreadyLoggedIn { cache_path, since },
    /// Access token was expired; a silent refresh produced a new one. No flow ran.
    Refreshed { cache_path },  // new; message(): "Refreshed Okta token (cached at <path>)."
    /// revoke_warning is Some when the previous refresh token could not be revoked.
    /// message() then appends: "Warning: the previous refresh token could not be
    /// revoked (<err>); it expires on its own after 7 idle days."
    #[non_exhaustive]          // on the VARIANT too: the enum attribute covers added
                               // variants, not added fields (both seats, r3)
    LoggedIn { cache_path, revoke_warning: Option<String> },  // field is new
}

// Test seam (r3 must-fix): the interactive flow becomes injectable so tests can
// assert "flow invoked / not invoked" and ordering without touching Okta.
trait LoginFlow {
    fn interactive(&self, cfg: &OktaAuthConfig) -> Result<TokenCache, OktaAuthError>; // pkce::authorize
    fn device(&self, cfg: &OktaAuthConfig) -> Result<TokenCache, OktaAuthError>;      // pkce::authorize_device
}
pub struct OktaAuth { config: OktaAuthConfig, flow: Box<dyn LoginFlow + Send + Sync> }
impl OktaAuth {
    pub fn new(config) -> Self            // unchanged; installs the production PkceFlow
    #[cfg(test)]
    fn with_flow(config, flow: Box<dyn LoginFlow + Send + Sync>) -> Self
}
// login/login_device/login_or_reuse/get_token fallthrough all reach the flow only
// through self.flow inside fresh_grant().

/// force=false: valid cache -> AlreadyLoggedIn; else live refresh token -> Refreshed;
/// else (or force=true) run the flow -> LoggedIn.
pub fn login_or_reuse(&self, force: bool, device: bool) -> Result<LoginOutcome, OktaAuthError>

/// Revoke the cached refresh token at Okta (RFC 7009), then delete the cache.
/// The cache is cleared even when revocation fails. Error precedence: a failed clear
/// returns CacheWrite (a revoked token is still on disk); otherwise a failed revoke
/// returns RevokeFailed (the server-side token may still be live).
pub fn logout(&self) -> Result<(), OktaAuthError>

/// login() / login_device(): unchanged signatures; both delegate to fresh_grant()
/// and log any revoke_warning (their only external caller is the loki script).
/// login_or_reuse(): delegates to fresh_grant() and puts revoke_warning into
/// LoginOutcome::LoggedIn so the consumer prints it.
/// get_token(): its interactive fallthrough also delegates to fresh_grant().
fn fresh_grant(&self, flow: impl FnOnce() -> Result<TokenCache, OktaAuthError>)
    -> Result<(TokenCache, Option<String>), OktaAuthError>
/// Guard (shared cache needs offline_access) -> read the old refresh token into
/// memory -> run `flow` -> save the new grant -> revoke the old token best-effort.
/// A revoke failure is returned as Some(text) in the tuple and warn!-logged; it is
/// never an Err. The old token is never re-read from disk after the save, so the
/// new grant can never be the one revoked.

/// refresh(): unchanged signature. On Okta `invalid_grant` it clears the cache before
/// returning Err(RefreshFailed); every other error leaves the cache alone.
```

Python (`okta-auth-py`): `tatari.SCOPES` gains `"offline_access"`;
`LoginOutcomeKind.REFRESHED` + `LoginOutcome.refreshed(path)`; the frozen dataclass
(`auth.py:44-58`) gains `revoke_warning: str | None = None` and `message()` appends
the same warning clause as Rust when it is set; `login_or_reuse` gains the refresh
arm; `logout()` gains revoke-then-clear with the same `CacheWrite` precedence;
`login`/`login_device` gain guard -> read old -> flow -> save -> best-effort revoke
through one `_fresh_grant(flow)` helper; `_refresh` clears the cache on
`invalid_grant`; `RevokeFailedError` and `SharedCacheRequiresOfflineAccessError`
added under `OktaAuthError`.

Consumer-facing behavior:

- `<tool> login` (no `--force`): valid token prints "Already logged in ..."; expired
  token with a live refresh token prints "Refreshed Okta token ..." with no browser;
  otherwise the flow runs as today. If Okta's `offline_access` scope is set to
  "consent required", a one-time consent page appears in the browser (both flows
  already go through a browser). Either outcome is acceptable.
- `<tool> login --force`: runs the flow, caches the new grant, revokes the old refresh
  token. If that revoke fails the printed line ends with the warning that the old
  token expires on its own after 7 idle days. Abandoning the browser leaves the old
  grant intact.
- `<tool> logout` when the cache file cannot be deleted: prints the `CacheWrite`
  error naming the path; the user must remove it by hand because a revoked token
  would otherwise be handed out until its `expires_at`.
- `<tool> login` with a user config whose `scopes:` omit `offline_access`: fails
  before any network call with the `SharedCacheRequiresOfflineAccess` message. The
  fix is in the message.
- `<tool> whoami | any call` after 12h: succeeds without a prompt. After the refresh
  token itself dies (7 idle days, revoked, deactivated): interactive CLIs open the
  flow once; no-tty processes fail fast with the existing `NonInteractive` hint, and
  the dead token is gone from disk so the next `login` goes straight to the flow.
- Two machines: each login mints its own refresh token; `logout` on one leaves the
  other logged in. **Verified 2026-09-08 on real hardware rather than assumed.** A device
  grant authorized from `ltl-7007.lan` and the live grant on `desk.lan` - same user, same
  client - produced DISTINCT refresh tokens (sha256 `3e14edf4...` vs `8447231c...`, both
  43 chars). Revoking the laptop's token returned HTTP 200 and flipped it to
  `active: false`, while the desktop's token stayed `active: true` and still completed an
  unattended `setsid slack whoami` refresh (exit 0). So the persistent-token echo proven
  in Phase 0 is confined to the REFRESH path and does not extend to re-authorization.
- `<tool> logout`: one extra HTTP call. On failure prints
  `logout failed: Refresh token revocation failed: ...`; the local cache is gone
  regardless.

### Implementation Plan

Blast radius: six repos. `okta-auth-rs` and `okta-auth-py` (the change), then
`slack-cli`, `marquee`, `sdv`, `persona-cli` (tag bumps + doc fixes). Ship order is
forced by the shared cache: crate tags first, then all Rust consumers before anyone
relies on the refresh token. A consumer left on the old tag downgrades the shared
cache to `refresh_token: null` on its next login.

#### Phase 0: Prove the tenant issues and revokes a refresh token (zero code)
**Model:** sonnet (Scott approves in a browser)
- `curl` the device grant against `0oa144xsutkeO1nev698` with
  `scope=openid email profile offline_access`; Scott approves the code.
- Poll `/v1/token` at the returned `interval` until approved; record `scp`, presence
  of `refresh_token`, `expires_in`. Note whether a consent screen appeared.
- Exercise a refresh with that token: POST `/v1/token grant_type=refresh_token`;
  record whether the response carries `refresh_token` (pre-verification hypothesis was
  "absent, persistent token"; **the run disproved it - the response carries the SAME
  token back, byte-identical**) and that the new access token's `scp` matches.
- `/v1/introspect` the refresh token with `client_id` only: expect `active: true`.
- `/v1/revoke` it with `client_id` + `token_type_hint=refresh_token`: expect 200.
- `/v1/introspect` again: expect `active: false`.
- Nothing touches `~/.cache/okta`.
- **Success criteria:** token response carries `refresh_token` and `scp` includes
  `offline_access`; the refresh call returns a new access token; revoke returns 200
  as a public client; introspect flips `true -> false`.

#### Phase 1: okta-auth-rs
**Model:** sonnet
- `src/tatari.rs`: append `offline_access`; update the `defaults_are_populated` test.
- `src/error.rs`: add `RevokeFailed(String)` and `SharedCacheRequiresOfflineAccess`;
  extend `error_display_messages`.
- `src/lib.rs`: new private `revoke(&self, token)` mirroring `refresh()` in shape,
  raw POST like `device.rs`. New private `fresh_grant(&self, flow)`: guard -> read
  old refresh token -> `flow()` -> save -> best-effort revoke of the old token.
  `login()`, `login_device()`, and `get_token()`'s interactive fallthrough each become
  a one-line call into it. `logout()` loads the cache, revokes `refresh_token` if
  `Some`, clears the cache, returns the revoke error if any. `refresh()` matches
  `invalid_grant` on the typed error before stringifying, and clears the cache in
  that one case. `login_or_reuse` gains the refresh arm; `LoginOutcome` gains
  `Refreshed` and `#[non_exhaustive]`.
- `src/cache.rs:98-101`: comment rewritten (see Architecture).
- Test seam: private `LoginFlow` trait with a production `PkceFlow` impl wrapping
  `pkce::authorize` / `pkce::authorize_device`; `OktaAuth` holds
  `flow: Box<dyn LoginFlow + Send + Sync>`; `#[cfg(test)] with_flow(...)`. Tests use
  a `CountingFlow` that returns a canned `TokenCache` and counts calls.
- Test harness: replace the one-shot `spawn_token_server` (`src/lib.rs:317`) with a
  `MockOkta` that serves an ordered script of `(path, status, body)` responses,
  records each request's path and form body, and for `/v1/revoke` also records the
  `access_token` currently in the cache file at the moment the request lands. That
  last capture is what makes `login_saves_new_grant_before_revoking_old` an
  assertion rather than a hope.
- Tests, named so the success criteria can call them:
  - `logout_revokes_refresh_token_then_clears_cache`: POST body has `client_id`,
    `token`, `token_type_hint=refresh_token`; no cache file after.
  - `logout_clears_cache_and_returns_revoke_failed_when_endpoint_unreachable`
    (`127.0.0.1:1`).
  - `logout_makes_no_revoke_call_without_refresh_token`.
  - `logout_treats_200_with_error_body_as_success`: Okta answers `200` even for a
    bogus token; a `200 {"error":"invalid_token"}` body is `Ok`.
  - `login_or_reuse_refreshes_instead_of_prompting`: expired access + refresh token ->
    `Refreshed`, flow never invoked (fake runner call count 0).
  - `login_or_reuse_runs_flow_when_expired_without_refresh_token`: `LoggedIn`, flow
    invoked once.
  - `refresh_keeps_sent_refresh_token_when_response_omits_it`.
  - `refresh_clears_cache_on_invalid_grant`: `400 {"error":"invalid_grant"}` -> no
    cache file; `get_token_noninteractive` -> `NonInteractive`.
  - `refresh_keeps_cache_on_other_oauth_error`: `400 {"error":"invalid_client"}`
    (`ServerResponse`, not `InvalidGrant`) -> cache intact.
  - `refresh_keeps_cache_on_non_json_5xx`: `503` with an HTML body (`Other`) ->
    cache intact.
  - `refresh_keeps_cache_on_unparseable_body`: `200` with a non-JSON body (`Parse`)
    -> cache intact.
  - `refresh_keeps_cache_on_transport_error`: `127.0.0.1:1` (`Request`) -> cache
    intact.
  - `login_saves_new_grant_before_revoking_old`: the revoke POST arrives after the
    cache holds the new access token; the revoked token is the OLD one.
  - `login_with_shared_cache_requires_offline_access`: `cache_dir: None` + scopes
    without `offline_access` -> `SharedCacheRequiresOfflineAccess`, zero HTTP.
  - `login_device_with_shared_cache_requires_offline_access`: same, device path.
  - `get_token_fallthrough_with_shared_cache_requires_offline_access`: expired cache,
    no refresh token, shared dir, scopes without `offline_access` -> the error, zero
    HTTP.
  - `login_with_explicit_cache_dir_allows_any_scopes`.
  - `get_token_read_path_is_not_guarded`: valid shared cache + scopes without
    `offline_access` -> returns the token.
  - `login_or_reuse_reports_revoke_failure_in_message`: forced login, revoke endpoint
    unreachable -> `LoggedIn { revoke_warning: Some(_) }` and `message()` contains
    "could not be revoked".
  - `logout_returns_cache_write_when_clear_fails`: cache dir made read-only (unix
    `0o500`) -> `CacheWrite`, even though the revoke returned 200.
  - `refresh_invalid_grant_with_failed_clear_returns_cache_write`: same read-only dir,
    `400 invalid_grant` -> `CacheWrite`; `get_token_noninteractive` returns
    `CacheWrite`, not `NonInteractive`.
  - `get_token_propagates_cache_write_instead_of_opening_browser`: same setup through
    `get_token()` with a `CountingFlow`: returns `CacheWrite`, flow count 0.
  - `login_or_reuse_happy_path_has_no_revoke_warning`: forced login, revoke `200` ->
    `LoggedIn { revoke_warning: None }` and `message()` does not contain "could not
    be revoked".
  - Existing and kept: `get_token_noninteractive_refreshes_expired_token` (a rotated
    refresh token in the response is persisted, `src/lib.rs:579-582`).
- README: "Usage" (scopes line), "Token cache location", "Idempotent login" (the
  `Refreshed` outcome), "Non-interactive sessions" (7-day idle expiry replaces the
  12h cliff), and a "Release notes" entry: refresh tokens issued by default, revoked
  on logout and forced re-login, dropped on `invalid_grant`.
- `otto ci` green, one commit, tag the next minor.
- **Success criteria:** `rg -c offline_access src/tatari.rs || echo 0` prints >= 1;
  `rg -c 'v1/revoke' src/lib.rs || echo 0` prints >= 1; the twenty-three named tests
  above exist and `cargo test <name> -- --exact` passes for each; four of them
  (`logout_revokes_refresh_token_then_clears_cache`,
  `login_or_reuse_refreshes_instead_of_prompting`,
  `refresh_clears_cache_on_invalid_grant`,
  `login_with_shared_cache_requires_offline_access`) were each shown to fail with
  their guarded line commented out (recorded in implementation notes);
  `rg -c 'fn fresh_grant' src/lib.rs` prints 1 and `rg -c 'fresh_grant\(' src/lib.rs`
  prints >= 4 (definition plus three callers); `git tag --points-at HEAD` is non-empty
  after the release and its value is recorded in the implementation notes as
  `OKTA_AUTH_TAG` for Phase 3.

#### Phase 2: okta-auth-py parity
**Model:** sonnet
- `tatari.py:38` append `offline_access`; `tests/test_tatari.py:10` updated.
- `auth.py`: `LoginOutcome` gains `revoke_warning: str | None = None` and the
  `message()` clause; `_fresh_grant(flow)` helper (guard -> read old -> flow -> save ->
  best-effort revoke) called from `login`, `login_device`, and `get_token`'s
  fallthrough (`auth.py:165`, `:226`, `:241` today); `logout()` revoke-then-clear
  with `CacheWrite` precedence; `login_or_reuse` refresh arm; `_refresh` reads the
  body before `raise_for_status()` and clears the cache on HTTP 400 `invalid_grant`;
  `LoginOutcomeKind.REFRESHED`; `RevokeFailedError`;
  `SharedCacheRequiresOfflineAccessError`.
- Test seams, the Python twins of Phase 1's: the flow seam is
  `monkeypatch.setattr("okta_auth.auth.pkce.authorize", counting_fake)` and the same
  for `authorize_device`, returning a canned `TokenCache` and counting calls (this is
  what makes the "flow invoked / not invoked" names writable; patching `requests.post`
  alone cannot). The HTTP seam is `monkeypatch.setattr(requests, "post", recorder)`
  where the recorder serves an ordered script of `(path, status, body)`, records each
  request's form body, and on `/v1/revoke` records the `access_token` in the cache
  file at that moment.
- Tests: the same twenty-three cases as Phase 1, `test_` + identical snake_case name.
- README example scopes updated. Tag the next minor.
- **Success criteria:** `rg -c offline_access src/okta_auth/tatari.py || echo 0`
  prints >= 1; for each of the twenty-three Phase 1 names `n`,
  `rg -q "def test_${n}\b" tests/` exits 0 (parity is by name, not by count);
  `pytest` passes; the same four break-to-prove runs as Phase 1 recorded;
  `git tag --points-at HEAD` non-empty after the release.

#### Phase 3: Rust consumers bump together
**Model:** sonnet
- slack-cli, marquee (cli), sdv, persona-cli: `Cargo.toml` pin to the Phase 1 tag,
  `cargo update -p okta-auth` to regenerate `Cargo.lock`, `otto ci` green, one PR
  each, release per repo's normal flow (`bump`).
- slack-cli only: its dependency line (`Cargo.toml:30`) also carries
  `version = "0.5.0"`, which the other three do not. Drop the field so all four lines
  have one shape; left in place, a tag-only bump fails to resolve (caret on a 0.x
  crate) while the tag-grep criterion still passes.
- Doc fixes in the same PRs: slack-cli `README.md:162` (the silent-refresh sentence
  becomes true; reword to say what happens when the refresh token itself is dead:
  unused 7 days or revoked); sdv `sdv.yml:32-33` becomes "the shared cache requires
  `offline_access`; omit it only with an explicit `cache-dir`" and `CLAUDE.md:78-79`
  drops "no offline_access, ~12h".
- One consumer code change, slack-cli `src/auth.rs:104-111`: `logout` clears the
  Slack token cache unconditionally, then propagates the Okta result. Today the `?`
  on `auth.logout()` skips the Slack clear when Okta returns an error, which after
  this change includes `RevokeFailed` with the Okta cache already gone. Test:
  `logout_clears_slack_cache_even_when_okta_revoke_fails`.
- No other consumer code changes: each already reads `tatari::SCOPES` and each config
  test asserts equality with it.
- **Success criteria:** the distinct-tag command from Acceptance Criteria prints `1`
  AND the one value it prints equals `OKTA_AUTH_TAG` from Phase 1 (uniformity on the
  old tag would also print `1`; the equality is the assertion);
  `rg -c 'okta-auth.*version =' <the four Cargo.toml> || echo 0` prints 0; `otto ci`
  (which builds) is green in all four repos; `rg` for the three stale-doc phrases
  returns 0 lines; slack-cli test
  `logout_clears_slack_cache_even_when_okta_revoke_fails` passes; each repo has a
  release tag containing the bump (`git tag --contains <bump-sha>` non-empty).

#### Phase 4: Live verification
**Model:** sonnet (Scott on the keyboard for the login)
- Install the new binaries (`bin/install` or `cargo install --path .` per repo). Run
  every probe below against the freshly built binary by path (`target/debug/slack` or
  the installed path after confirming `--version` shows the new tag), never a bare
  name on `$PATH`.
- `slack login --force`: `~/.cache/okta/tokens.json` has a non-null `refresh_token`.
- Simulate expiry without touching the real cache: `T=$(mktemp -d); mkdir $T/okta;
  jq '.expires_at = 0' ~/.cache/okta/tokens.json > $T/okta/tokens.json; chmod 600
  $T/okta/tokens.json`, then `XDG_CACHE_HOME=$T setsid -w slack whoami </dev/null`.
  Expect the email, exit 0, and `$T/okta/tokens.json` rewritten with a future
  `expires_at`. Because `$T/slack/token.json` does not exist, this run also proves a
  valet re-vend succeeds on a refreshed Okta token.
- `slack logout`: save the refresh token first; after logout, introspect it: `active:
  false`. `~/.cache/slack/token.json` and `~/.cache/okta/tokens.json` are gone.
- Repeat `whoami` for persona, marquee, sdv against the shared cache: no prompt.
- With the same expired copy, `XDG_CACHE_HOME=$T slack login` (no `--force`) prints
  the `Refreshed` message with no browser.
- **Success criteria:** the `setsid` probe exits 0 and prints the email; `login`
  on the expired copy prints `Refreshed` and opens nothing; `persona whoami`,
  `marquee whoami`, `sdv whoami` each exit 0 with no prompt on the shared cache; after
  `slack logout` the introspect is `active: false` and both
  `~/.cache/okta/tokens.json` and `~/.cache/slack/token.json` are absent.

## Acceptance Criteria

- [x] Both ports request the scope: `rg -c 'offline_access' src/tatari.rs || echo 0`
  in okta-auth-rs and `rg -c 'offline_access' src/okta_auth/tatari.py || echo 0` in
  okta-auth-py each print >= 1. Observed on main: `0` and `0` (bare `rg -c` prints
  nothing and exits 1 on zero matches; the `|| echo 0` makes the baseline literal).
  **VERIFIED post-ship 2026-09-08: `3` and `2`. PASS.**
- [x] `rg -c 'v1/revoke' src/lib.rs || echo 0` in okta-auth-rs prints >= 1.
  Observed on main: `0`. **VERIFIED post-ship 2026-09-08: `8`. PASS.**
- [x] All four consumers pin the Phase 1 tag. Distinct `okta-auth` tags across
  slack-cli, marquee/cli, persona-cli, sdv `Cargo.toml`:
  ```text
  rg --no-filename -o 'okta-auth.*tag = "v[0-9.]+"' <the four Cargo.toml> | rg -o 'v[0-9]+\.[0-9]+\.[0-9]+' | sort -u
  ```
  prints exactly one line, and that line equals `OKTA_AUTH_TAG` (the tag Phase 1
  cut; recorded in implementation notes); and
  `rg -c 'okta-auth.*version =' <the four Cargo.toml> || echo 0` prints `0` (a stale
  `version` field beside the tag breaks resolution while passing the tag grep).
  Observed on main: two lines, `v0.5.0` and `v0.6.0`; no `OKTA_AUTH_TAG` exists yet;
  the `version =` grep prints `1` (slack-cli `Cargo.toml:30`).
  **VERIFIED post-ship 2026-09-08: the distinct-tag command prints exactly one line,
  `v0.7.0`, which equals `OKTA_AUTH_TAG`; the `version =` grep prints `0`. PASS.**
- [x] Stale claims gone. Over slack-cli `README.md`, sdv `sdv.yml`, sdv `CLAUDE.md`:
  ```text
  rg -c 'no `offline_access`|silent-refresh Okta path' <the three files>
  ```
  returns 0 lines. Observed on main: 1 line in each of the three files.
  **VERIFIED post-ship 2026-09-08: 0 lines. PASS.**
- [x] Unattended refresh works: after one post-ship `login`,
  `jq -r .refresh_token ~/.cache/okta/tokens.json` is a non-null string, and with a
  cache copy whose `expires_at` is 0:
  ```text
  XDG_CACHE_HOME=<copy> setsid -w slack whoami </dev/null
  ```
  exits 0 and prints the email. Observed on main: `refresh_token` is `null`; the probe
  run against a tree build of slack-cli main (`cargo build`, `target/debug/slack`,
  reports `v0.8.0-1-g06e5111`) with an isolated copy of the cache under the session
  scratchpad exits 1 with `Okta token is missing or expired and no controlling
  terminal is available (non-interactive session)`. An earlier run against the
  installed `slack v0.8.0` gave the same result and was replaced because a baseline
  belongs to the tree, not to whatever is on `$PATH` (Architect, r1).
  **VERIFIED post-ship 2026-09-08 against the installed `slack v0.11.0`:
  `jq -r .refresh_token ~/.cache/okta/tokens.json` returns a non-null 43-char string;
  the access token's `scp` is `[offline_access, email, openid, profile]`; and
  `XDG_CACHE_HOME=<copy> setsid -w slack whoami </dev/null` on a cache with
  `expires_at = 0` exits 0, prints `scott.idler@tatari.tv`, and rewrites `expires_at`
  to now + 12h. This is the criterion that exited 1 on main with "no controlling
  terminal"; it is the headline fix and it now passes. PASS.**

## Resolved Decisions

- **2026-09-08, one shared scope change, not a slack-cli override.** slack-cli could
  set `scopes:` in its config, but the cache is shared and siblings must behave
  identically. The crate constant changes; every consumer follows. (Scott's
  framing: "okta-auth-rs and its consumers of which slack-cli is but just one".)
- **2026-09-08, persistent tokens, no rotation, no lock.** The app is on "Use
  persistent token"; the Marquee MCP app made the same call. Rotation without a
  cross-process lock races the shared cache. Revisit only if rotation is enabled.
- **2026-09-08, revoke on logout, cache cleared even on failure.** Deleting the file
  without revoking leaves a live credential nobody references. Clearing the file on
  a failed revoke keeps `logout` meaning "I am logged out locally" while the returned
  error tells the user the server may disagree.
- **2026-09-08, raw POST for revoke, not the `oauth2` crate's revocation API.**
  `device.rs` already does raw form POSTs against the same issuer; one pattern.
- **2026-09-08, consent screen outcome is not a blocker.** Whether Okta's
  `offline_access` scope is "implicit" or "required" consent, both login flows
  already run in a browser. Phase 0 records which it is.
- **2026-09-08, persona-mcp excluded.** Its Okta client is deleted; that is a
  persona-mcp bug, not a scopes question.
- **2026-09-08, `login_or_reuse` refreshes before it prompts.** An idempotent login
  that ignores a live refresh token is not idempotent. (Author, pass 2.)
- **2026-09-08, forced re-login revokes the token it replaces, best-effort, AFTER the
  new grant is saved.** Logout fails loud on a revoke error because the user asked to
  end the session; login warns and proceeds because the user asked for a new one and
  a stale revoke must not block it. Revoke runs after the flow because Okta revokes
  the access token along with the refresh token, and a user who closes the browser
  must not lose the session they had; it runs after the save because a failed save
  after a revoke would leave the user with nothing (Staff Engineer, panel r1). The
  old token is read into memory before the flow so the save can never be re-read as
  "old". (Author passes 2 and 4; Staff Engineer r1.)
- **2026-09-08, the crate refuses to write a refresh-token-less grant into the
  shared cache.** Every consumer's `scopes:` config override replaces
  `tatari::SCOPES`, so bumping binaries alone cannot make `offline_access` a fleet
  invariant (Staff Engineer, panel r1, verified at slack-cli `src/config.rs:306`,
  marquee `cli/src/config.rs:85`, sdv `src/config.rs:85`, persona-cli
  `src/config.rs:72`). Options weighed: (a) fail-closed guard in the crate at the
  write boundary, keyed on `cache_dir: None`; (b) key the cache filename by scope set;
  (c) delete the `scopes:` knob from all four consumers. (a) chosen: one place, fails
  loud with the fix in the message, leaves isolated caches free, and the knob stays
  part of the standard precedence chain. (b) rejected: silently forks "one login,
  many tools" into per-scope logins. (c) rejected: four consumer changes to remove a
  knob that is harmless once (a) exists. **Author decision; flagged for Scott.**
  **Architect dissent (r2):** the guard puts a fleet-coordination policy into a
  generic crate whose own `tatari.rs` says Tatari specifics stay out of the flow; a
  third-party consumer using the default cache dir without wanting refresh tokens
  would be broken; prefer (c), enforced at each consumer's config-loading boundary.
  **Author pushback:** the guard is keyed on `cache_dir: None`, not on Tatari
  constants, so it encodes "the shared default cache is a multi-consumer resource",
  which is true of any fleet using this crate. The crate is private with no
  third-party consumer, so the broken hypothetical user does not exist, and if one
  appears the message tells them to set `cache_dir`. Enforcing in four consumers is
  four copies of one rule plus a fifth consumer that forgets; the owner's standard is
  a fail-closed write guard at the narrowest chokepoint that covers future paths, and
  `fresh_grant()` is that chokepoint. Both seats agree the guard is complete and
  correctly placed relative to `cache::save`; the disagreement is only about which
  layer owns the rule.
  **Closed in panel r3, both seats on (a).** The Architect withdrew after reading
  `src/cache.rs:47-53` (the default dir is documented as shared across every
  consumer, with `cache_dir` as the isolation escape hatch) and stated the rule to
  keep: the crate may enforce invariants on its own default shared directory and may
  not on a consumer-supplied `cache_dir`, which is exactly what keying on
  `cache_dir: None` does. The Staff Engineer rejected (b) because `OktaAuth::new()`
  is infallible (`src/lib.rs:97`) so nothing proves `validate()` ran, and (c) because
  a future consumer can still construct the config directly. Settled; Scott may
  override on taste, in which case Alternative 10 is the fallback shape.
- **2026-09-08, `invalid_grant` clears the cache; nothing else does.** It is the one
  Okta answer that means the refresh token is dead for good. Clearing on network
  errors would turn a wifi blip into a re-login. (Author, pass 4.)
- **2026-09-08, `LoginOutcome` becomes `#[non_exhaustive]`.** Adding `Refreshed` is a
  source-breaking change for any downstream exhaustive match in general. None exists:
  all four consumers call only `.message()` (verified by grep, re-verified by the
  Staff Engineer in r1), and all are tag-pinned and bumped in Phase 3. The attribute
  forces wildcard arms from here on so the next variant is not this conversation
  again.

## Alternatives Considered

### Alternative 1: slack-cli sets `offline_access` in its own config
- **Description:** Add `scopes:` to `~/.config/slack/slack.yml`; leave the crate alone.
- **Pros:** No cross-repo campaign.
- **Cons:** Shared cache downgrades on the next persona/marquee/sdv login; sister CLIs
  diverge on auth semantics.
- **Why not chosen:** Violates "siblings behave identically" and does not survive the
  shared cache.

### Alternative 2: Enable refresh token rotation
- **Description:** Flip the app to "Rotate token after every use".
- **Pros:** Okta's recommended posture for public clients.
- **Cons:** Three MCP servers plus a systemd timer refresh the same token within the
  same second at expiry. Needs a cross-process lock in the crate. Marquee MCP
  deliberately stayed persistent for the same reason.
- **Why not chosen:** Not needed for the goal; parked with a named revisit trigger.

### Alternative 3: Raise the access token lifetime
- **Description:** Policy rule access token 12h -> 24h (Okta's maximum).
- **Pros:** One admin click.
- **Cons:** Still finite; still a human every day; changes every client on the
  `default` server.
- **Why not chosen:** Does not solve unattended operation.

### Alternative 4: Downgrade guard in the crate
- **Description:** When saving a cache with `refresh_token: None`, keep the refresh
  token already on disk.
- **Pros:** Protects against a stale consumer.
- **Cons:** Mixes tokens from two logins; hides the real problem (an unbumped
  consumer); invents behavior nobody asked for.
- **Why not chosen:** Ship the consumers together instead.

### Alternative 5: Separate cache dir for the slack timer
- **Description:** `cache_dir` override so the daemon holds its own credential.
- **Pros:** Isolates the daemon.
- **Cons:** Breaks one-login-many-tools; a second login for the same client and user.
- **Why not chosen:** The shared cache is the design; fix the token, not the sharing.

### Alternative 6: Schedule all follow-up chunks server-side as top-level posts
- **Description:** slack-cli design doc alternative 6: `post_at + i`, no thread.
- **Pros:** Zero credential needed at fire time.
- **Cons:** Loses the thread, which is the feature.
- **Why not chosen:** Rejected in the scheduled-follow-ups doc; unchanged here.

### Alternative 7: Key the shared cache filename by scope set
- **Description:** `tokens-<hash of sorted scopes>.json` so differing scope sets never
  collide.
- **Pros:** No guard needed; any scopes work.
- **Cons:** A user who trims `scopes:` gets a silent second login instead of an
  error; "one login, many tools" quietly forks; `cache_path()` reporting and the
  loki script's isolation comment both change.
- **Why not chosen:** Fail loud beats silent divergence. See Resolved Decisions.

### Alternative 8: Remove the `scopes:` knob from all four consumers
- **Description:** Scopes become a crate constant; config cannot override.
- **Pros:** The hazard cannot be expressed.
- **Cons:** Four consumer changes; breaks the uniform flags/env/file precedence chain
  every field follows; the knob is legitimate with an explicit `cache_dir`.
- **Why not chosen:** The crate guard achieves the invariant in one place.

### Alternative 10: `OktaAuthConfig::validate()` that consumers call
- **Description:** The Architect's middle path. The crate exposes a validator that
  returns `SharedCacheRequiresOfflineAccess`; each consumer calls it after resolving
  config, before building `OktaAuth`. The login execution path stays generic.
- **Pros:** The rule lives once, in the crate. The flow has no fleet policy in it.
- **Cons:** Enforcement depends on every consumer remembering the call; a fifth
  consumer that forgets reopens the hole. Same failure shape as Alternative 8 with
  less duplication.
- **Why not chosen:** `fresh_grant()` is the chokepoint that covers future callers
  without their cooperation, and `OktaAuth::new()` is infallible so nothing would
  prove `validate()` ran. Closed as option (b) of the question both seats settled on
  (a) in panel r3; it remains the fallback shape if Scott overrides on taste.

### Alternative 9: Refresh keepalive for timer-only hosts
- **Description:** A no-op tick refreshes proactively when the cache mtime is older
  than N days, so a host that only runs the systemd timer never idles past 7 days.
- **Pros:** Removes the last human touch on a dedicated timer host.
- **Cons:** A background process minting credentials nobody is using; no such host
  exists today (the timer runs where `write --at` ran, which is a workstation).
- **Why not chosen:** Parked. Revisit condition: a timer-only host becomes real.

## Technical Considerations

### Dependencies
- Okta tenant: app grants and policy already permit this (verified 2026-09-08).
- `reqwest::blocking` via `oauth2`'s `reqwest-blocking` feature, already a dep.
- Consumers: git-tag pins; each release workflow already handles the private dep.

### Performance
- One extra HTTP call on `logout`. Refresh replaces a browser round-trip with one
  POST every 12h.

### Security
- Delta: a 12h bearer at rest becomes a refresh token that lives until 7 days unused
  or revoked. Same file, same 0600, same host.
- Mitigations: revoke on logout; Okta admin can revoke per-user tokens under the app;
  deactivating the user revokes everything; persistent (not rotating) means no
  reuse-detection surprises across processes.
- The client id stays public (PKCE public client, cited in `tatari.rs`).
- Refreshed access tokens carry the same `iss`, `aud` (`api://default`), `sub`, and
  `scp` as the original grant, so valet, marquee, persona, and the Istio edge validate
  them unchanged. `whoami` reads `email`/`sub` from the access token; unaffected.
- Orphaned refresh tokens (a login from a pre-bump binary, or a revoke that failed)
  die on their own after 7 idle days; an admin can revoke them under the app's Tokens
  tab before that.

### Testing Strategy
- Unit (the twenty-three named tests in Phase 1, mirrored in Phase 2): revoke request
  shape, cache-cleared-on-success, cache-cleared-plus-error on failure, no-op without
  a refresh token, `200`-with-error-body is success; `login_or_reuse` returns
  `Refreshed` without running the flow and runs the flow without a refresh token;
  persistent-token refresh keeps the sent refresh token; `invalid_grant` clears the
  cache and every other error variant does not; save-before-revoke ordering;
  shared-cache guard on all three fresh-grant paths, absent on the read path and on
  explicit `cache_dir`; SCOPES literal tests updated. Four named tests broken once
  to prove they bite.
- slack-cli: `logout_clears_slack_cache_even_when_okta_revoke_fails`.
- Existing: `get_token_noninteractive_refreshes_expired_token` and the persona-cli
  single-refresh test already cover the refresh arm; unchanged.
- Live: Phase 0 (tenant behavior, zero code) and Phase 4 (fleet behavior, real
  binaries).

### Rollout Plan
1. Phase 0 spike.
2. okta-auth-rs tag, okta-auth-py tag.
3. Four consumer PRs, merged and released in any order, all before anyone depends
   on unattended refresh.
4. Reinstall locally; `login --force` once per machine that runs a timer; Phase 4
   checks.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| A consumer left on the old tag logs in and nulls the shared refresh token | Med | Med | Phase 3 ships all four together; acceptance criterion counts distinct tags; a pre-bump binary has no guard, so this window closes only when all four are installed |
| A user's `scopes:` override omits `offline_access` and nulls the shared refresh token | Med | Med | Crate guard refuses the write before any network call; message names the fix |
| `cache::save` fails after the old token was revoked | Low | High | Save runs before revoke; a failure leaves an orphan, never a stranded user |
| Okta refuses `offline_access` at token time despite the grant being on | Low | High | Phase 0 proves it before any code |
| Revoke fails on logout (network) and a live refresh token remains | Low | Med | Cache cleared anyway; error surfaced; token dies after 7 idle days; admin revoke available |
| Someone enables rotation later without a lock | Low | High | Recorded as the revisit trigger; persona-cli test models rotation |
| Consent screen surprises a first-time user | Med | Low | Phase 0 records it; login already opens a browser |
| Refresh token idles past 7 days on a timer-only machine | Med | Low | Existing fail-fast path; queue stays intact; dead token dropped on `invalid_grant`; documented in slack-cli README; Alternative 9 parked |
| A transient Okta outage is misread as a dead token and forces a re-login | Low | Med | Only `invalid_grant` clears the cache; 5xx and transport errors keep it (tested) |
| User abandons the browser on `login --force` and is left with nothing | Low | Med | Revoke runs after the flow succeeds, never before |

## Open Questions

None. The guard-placement question was closed in panel r3 with both seats on option
(a); see Resolved Decisions. Tenant facts were read from the Admin Console
2026-09-08; the remaining behavioral proof is Phase 0.

## References

- okta-auth-rs `src/tatari.rs`, `src/lib.rs`, `src/cache.rs`, `src/pkce/device.rs`
- okta-auth-py `src/okta_auth/tatari.py`, `src/okta_auth/auth.py`
- slack-cli `docs/design/2026-09-06-scheduled-follow-ups.md` (the unattended case)
- marquee `docs/design/2026-08-03-mcp-auth-and-runtime-cutover-implementation-notes.md`
  (Refresh Token grant enabled by hand; persistent token decision)
- Okta: Refresh tokens guide; Revoke tokens guide (`developer.okta.com/docs/guides/`)
- RFC 6749 §6 (refresh), RFC 7009 (revocation), RFC 8628 (device grant)
