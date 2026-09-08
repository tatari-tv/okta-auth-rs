# okta-auth-rs

Rust library for Okta OAuth2 PKCE authentication in CLI tools - browser login,
token caching, and transparent refresh.

## Usage

```rust
use okta_auth::{OktaAuth, OktaAuthConfig};

let auth = OktaAuth::new(OktaAuthConfig {
    okta_issuer: "https://myorg.okta.com/oauth2/default".to_string(),
    client_id: "0oa...".to_string(),
    redirect_uri: "http://local.myorg.tools:11313/callback".to_string(),
    // `offline_access` is required on the shared default cache (`cache_dir: None`):
    // without it, `OktaAuthError::SharedCacheRequiresOfflineAccess` refuses the write
    // before any network call. See "Token cache location" below.
    scopes: vec!["openid".to_string(), "email".to_string(), "offline_access".to_string()],
    app_name: "my-cli".to_string(),
    cache_dir: None, // defaults to the shared ~/.cache/okta/
});

// Returns a valid access token, refreshing or re-authenticating as needed.
let token = auth.get_token()?;
```

`get_token()` checks the token cache first, then tries a transparent refresh, and
only starts an interactive browser login as a last resort. `login()` forces an
interactive login, revoking the refresh token it replaces (best-effort);
`logout()` revokes the cached refresh token at Okta, then clears the cache.

## Consuming this crate in CI (private git dependency)

`okta-auth-rs` is a **private** repo, pulled as a git dependency:

```toml
okta-auth = { git = "https://github.com/tatari-tv/okta-auth-rs", tag = "v0.5.0" }
```

A GitHub Actions runner's built-in `GITHUB_TOKEN` is scoped to the *workflow's own*
repo, so it cannot clone this *second* private repo. Cargo then fails with:

```
failed to authenticate when downloading repository
revision <sha> not found
```

The "revision not found" is a **symptom of the auth failure**, not a missing commit.
Note that **`otto ci` / `cargo build` passing locally is NOT sufficient** - your
machine has git credentials the runner does not.

Every consuming workflow (both `ci` and `release`) needs the same two pieces:

1. Tell cargo to fetch git deps via the `git` CLI, which honors global config:

   ```yaml
   env:
     CARGO_NET_GIT_FETCH_WITH_CLI: true
   ```

2. Rewrite the GitHub URL with a token that can read this repo, in **every job**,
   after `actions/checkout` and before the Rust/build steps:

   ```yaml
   - name: Configure git for private deps
     run: git config --global url."https://x-access-token:${{ secrets.ACTIONS_CLONE_SUBMODULE_TOKEN }}@github.com/".insteadOf "https://github.com/"
   ```

`ACTIONS_CLONE_SUBMODULE_TOKEN` is the org secret provisioned for exactly this
cross-repo read. For tag-driven releases, the org reusable workflow
`tatari-tv/github-actions/.github/workflows/rust-cli-release.yml` wires this up when
you pass `private-deps: true` and `private-deps-token: ${{ secrets.ACTIONS_CLONE_SUBMODULE_TOKEN }}`.

Reference consumers to copy from: `persona-cli`, `marquee`, `sdv`, `slack-cli`.

## Token cache location

By default the token cache is the **shared** `~/.cache/okta/tokens.json` (honoring
`$XDG_CACHE_HOME`), at mode `0600`. It is keyed by neither app name nor client, so
every CLI built on this crate that authenticates with the same Okta client shares one
cached credential - **one login, many tools**. A consumer that needs an isolated cache
can set `cache_dir`. Use `auth.cache_dir()` / `auth.cache_path()` to report the real
location in your own `--help`/status output instead of hardcoding a path.

**The shared default cache requires `offline_access`.** A fresh interactive login
written to `cache_dir: None` must request `offline_access`, or the crate refuses the
write with `OktaAuthError::SharedCacheRequiresOfflineAccess` before any network call -
one consumer's underscoped `scopes:` override would otherwise strip the refresh token
every sibling CLI relies on. An explicit `cache_dir` is exempt: an isolated cache is
that consumer's own business.

## Idempotent login (`login_or_reuse`)

`login_or_reuse(force, device)` is a no-op when a valid token is already cached
(reporting how long ago you logged in); with an expired access token and a live
refresh token it refreshes silently (`LoginOutcome::Refreshed`, no browser); otherwise,
or with `force = true` (wire it to a `--force` flag), it runs the flow anew - revoking
the refresh token it replaces, best-effort. It returns a `LoginOutcome` whose
`message()` is a ready-to-print status line carrying the real cache path (and, on a
forced login, a warning if the previous token could not be revoked) - so the "already
logged in" and truthful-path behavior lives here once, not re-implemented per CLI.

## Authentication over SSH / headless hosts

The PKCE flow binds a localhost callback listener on the host running the CLI. When
the CLI runs on a **remote host over SSH**, your browser is on a *different* machine,
so the callback cannot reach the listener directly. The library detects this and
adapts - there is **no mandatory wait**:

- It classifies the session as **Local**, **Headless** (SSH or no local GUI), or
  **NonInteractive** (no controlling terminal).
- In **Headless** mode it prints the authorize URL and immediately accepts a pasted
  callback URL. Open the URL on your laptop; if the browser shows "can't be reached"
  or a DNS error, copy the **full address-bar URL** and paste it back into the prompt:

  ```
  Open this URL to authenticate:
  https://myorg.okta.com/oauth2/default/v1/authorize?...

  Open this on your machine. If it shows "can't be reached", paste the address-bar URL here:
  > http://local.myorg.tools:11313/callback?code=...&state=...
  ```

- The paste reader reads the **controlling terminal** (`/dev/tty`), never the
  process's `stdin`, so it never steals input from your CLI and works even when
  `stdin` is piped (`my-cli | grep ...`).

### Optional: SSH local-port-forward tunnel

If you forward the callback port, the listener auto-captures the callback and you
type nothing - same zero-touch experience as local:

```sh
ssh -L 11313:localhost:11313 user@remote-host
```

The listener and the paste prompt run concurrently, so whichever delivers the
authorization code first wins - a tunnel just makes the listener win.

## Non-interactive sessions (agents, CI)

In a non-interactive session (agent Bash tool, CI, `stdin`/tty both unavailable),
interactive auth is impossible. Rather than hanging on a timeout and then emitting a
cryptic parse error, `get_token()` fails fast with `OktaAuthError::NonInteractive`
*if and only if* a genuine interactive login is required.

The contract for headless automation: **keep the token warm (or refreshable) and it
just works** - a valid cached token or a working refresh token never reaches the
interactive path. Only a real re-login (which needs a human) fails fast. So the fix
for a `NonInteractive` error is to re-authenticate once in a terminal; the cached
token then serves subsequent non-interactive runs until the refresh token itself dies -
**7 idle days**, an explicit revoke, or user deactivation - not the access token's 12h
lifetime. A dead refresh token is dropped from the cache automatically on its next use
(Okta's `invalid_grant`), so the next `login` goes straight to the flow instead of
retrying a token that can never succeed.

## Release notes

### Refresh tokens by default

- **`offline_access` is now in the default scopes** (`tatari::SCOPES` and any consumer
  using the crate's own defaults), so every login mints a refresh token. Silent refresh
  - always present in the code - is finally reachable.
- **`login_or_reuse` refreshes before it prompts.** An expired access token with a live
  refresh token now returns `LoginOutcome::Refreshed` (no browser) instead of always
  running the interactive flow.
- **`logout()` revokes the cached refresh token at Okta** (RFC 7009) before clearing
  the cache. The cache is cleared even when the revoke call fails; the failure surfaces
  as `OktaAuthError::RevokeFailed`.
- **`login()` / `login_device()` revoke the token they replace**, best-effort, after
  saving the new grant. A failed revoke never fails the login; it comes back as a
  warning in `LoginOutcome::LoggedIn.revoke_warning`, appended to `message()`.
- **`refresh()` drops a dead refresh token from the cache** on Okta's `invalid_grant`
  (7 idle days, revoked, or the user was deactivated). Any other refresh failure
  (network, 5xx, unparseable body) keeps the cache, so a transient blip never forces a
  re-login.
- **New error variants:** `RevokeFailed(String)` and `SharedCacheRequiresOfflineAccess`
  (see "Token cache location" above). `LoginOutcome` gains `Refreshed` and is now
  `#[non_exhaustive]`; the existing `LoggedIn` variant gains `revoke_warning: Option<String>`.

  > **Source-compatibility note.** External consumers matching on `LoginOutcome` need a
  > wildcard arm from this release on.

### Non-blocking headless / SSH authentication

- **SSH/headless logins no longer wait.** The old flow always burned a fixed 60s
  callback timeout before offering a paste fallback; the paste path is now available
  immediately, and the listener still auto-captures when reachable (local or via an
  `ssh -L` tunnel).
- **New error variant `OktaAuthError::NonInteractive`.** Returned when interactive
  auth is required but no controlling terminal is available.

  > **Source-compatibility note.** `OktaAuthError` is now annotated
  > `#[non_exhaustive]`, so external consumers must include a wildcard arm
  > (`_ => ...`) when matching it. This release adds `NonInteractive` and marks the
  > now-unused `BindFailed` variant deprecated (bind failure is non-fatal - the flow
  > falls back to the paste path); `BindFailed` is retained for compatibility and is
  > no longer constructed.
- **`CallbackTimeout` message reworded** (dropped the hardcoded "60s"): the timeout
  is now only a generous backstop, not the primary control path. Match on the
  variant, not the string.

No public API signatures changed; consuming CLIs pick up the fix on a version bump.
