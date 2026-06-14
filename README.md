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
    scopes: vec!["openid".to_string(), "email".to_string()],
    app_name: "my-cli".to_string(),
    cache_dir: None, // defaults to the shared ~/.cache/okta/
});

// Returns a valid access token, refreshing or re-authenticating as needed.
let token = auth.get_token()?;
```

`get_token()` checks the token cache first, then tries a transparent refresh, and
only starts an interactive browser login as a last resort. `login()` forces an
interactive login; `logout()` clears the cache.

## Token cache location

By default the token cache is the **shared** `~/.cache/okta/tokens.json` (honoring
`$XDG_CACHE_HOME`), at mode `0600`. It is keyed by neither app name nor client, so
every CLI built on this crate that authenticates with the same Okta client shares one
cached credential - **one login, many tools**. A consumer that needs an isolated cache
can set `cache_dir`. Use `auth.cache_dir()` / `auth.cache_path()` to report the real
location in your own `--help`/status output instead of hardcoding a path.

## Idempotent login (`login_or_reuse`)

`login_or_reuse(force, device)` is a no-op when a valid token is already cached
(reporting how long ago you logged in); pass `force = true` (wire it to a `--force`
flag) to run the flow anew. It returns a `LoginOutcome` whose `message()` is a
ready-to-print status line carrying the real cache path - so the "already logged in"
and truthful-path behavior lives here once, not re-implemented per CLI.

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
token then serves subsequent non-interactive runs until it (and its refresh token)
expire.

## Release notes

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
