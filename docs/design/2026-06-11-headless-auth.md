# Design Document: Non-Blocking Headless / SSH Authentication

**Author:** Scott Idler
**Date:** 2026-06-11
**Status:** Implemented
**Review Passes Completed:** 5/5
**Revision:** r3 - three review rounds with Architect (Gemini) + Staff Engineer
(Codex), plus an author self-verification pass (round 4) that re-verified all
cited sources and fixed two doc inconsistencies

## Review Consensus Log

- **r0 → r1:** Both reviewers independently flagged the detached `stdin` reader as
  the core defect, plus the `Option<Server>` bind gap. Codex added config-error
  masking, `is_terminal()` being too narrow, and test-implementability; the
  Architect added the stray-request `?`-abort and the silent-Local UX bug. r1
  switched to reading `/dev/tty` in a single-threaded loop, reordered
  config-validation first, and added DI seams.
- **r1 → r2 (consensus round):**
  - **Architect: Approved.** Verified the `pkce.rs:131` abort bug, the `lib.rs`
    `InvalidUrl` test reliance, and that `OktaAuthError` lacks `#[non_exhaustive]`.
    Agreed to defer the non-SSH-remote-macOS edge. Added: bound the read buffer,
    `try_recv()` naming, confirm `#[non_exhaustive]`, generous wait when
    `server = None`.
  - **Staff Engineer: blocked r1** on a verified portability fact - `rustix::poll()`
    does not work on `/dev/tty` on macOS (rustix's own source says use `select()`).
    Also: `?error=` callbacks must surface (not be ignored), `try_recv()` naming,
    and the bind/`NonInteractive` doc inconsistency.
  - **Disposition:** Claude sided with the Staff Engineer's blocker (it is a fact,
    and the target runs macOS). r2 removes `poll()`/`select()` on the tty entirely
    in favor of **non-blocking reads + `POLL_INTERVAL` sleep**, surfaces `?error=`
    via a `Capture` enum, bounds the buffer, fixes naming, makes `#[non_exhaustive]`
    firm, and corrects the bind wording. The one divergence (non-SSH-remote-macOS)
    is deferred with **both** reviewers' agreement.
- **r2 re-confirmation (round 3):**
  - **Staff Engineer: Approved for implementation.** Verified all four r1 blockers
    closed against the on-disk sources: `rustix-1.1.4/src/event/poll.rs:12` (the
    macOS `/dev/tty` poll limitation), `tiny_http-0.12.0/src/lib.rs:397`
    (`try_recv() -> IoResult<Option<Request>>`), `rustix-1.1.4/src/fs/fcntl.rs`
    (`fcntl_getfl/setfl`), and `src/pkce.rs:23/47/131/183`. Two non-blocking
    tightenings folded into r2: the `try_recv` `Result` type and byte-buffer /
    `from_utf8_lossy` handling in the loop pseudocode; canonical-mode and one-shot
    EOF semantics documented; the risk-table `#[non_exhaustive]` wording made firm.
  - **Outcome: both reviewers approve.** Status → Approved.
- **Author self-verification (round 4):** All cited sources re-verified
  independently (rustix poll.rs macOS note, `try_recv` signature,
  `fcntl_getfl/setfl`, every `pkce.rs`/`lib.rs`/`error.rs` line reference). Two
  fixes applied: (1) the loop pseudocode's paste arm swallowed a pasted
  `?error=` URL as a retryable parse failure, contradicting the Edge Cases /
  Security promise that it surfaces as `OktaError` - an explicit
  `Err(e @ OktaAuthError::OktaError { .. })` arm now returns it; (2) the `ssh`
  classifier input had no specified signal - now defined as
  `SSH_CONNECTION`/`SSH_TTY`/`SSH_CLIENT`. Minor tightenings: `lib.rs:254`/`281`
  wording corrected (those tests assert `is_err()`, not the `InvalidUrl` variant
  specifically), the existing `error_display_messages` exact-string test called
  out for update, the now-unconstructed `BindFailed` variant flagged for an
  implementer decision, and a `POLL_INTERVAL` value range suggested.

## Summary

`okta-auth-rs` binds its OAuth2 PKCE callback listener on `127.0.0.1:<port>` of
whatever host runs the CLI. When the CLI runs over SSH, the user's browser is on
a *different* machine, so the callback can never reach the listener - the flow
eats a fixed 60s timeout before offering a manual paste fallback. This redesign
removes the mandatory wait: it classifies the session (local / headless / non-
interactive) and runs the listener and a manual-paste reader *concurrently* in a
**single-threaded poll loop**, so whichever delivers the authorization code first
wins. The paste reader reads the **controlling terminal (`/dev/tty`)**, never the
process's `stdin`, so it can never steal input from the consuming CLI and works
even when `stdin` is piped. Non-interactive sessions (CI, agent shells) fail fast
with an actionable error instead of hanging for 60s and then emitting a cryptic
parse failure.

## Problem Statement

### Background

`pkce::authorize()` (`src/pkce.rs`) implements the standard "localhost redirect"
OAuth2 PKCE flow:

1. Build the authorize URL + PKCE challenge + CSRF state.
2. Bind a `tiny_http` listener on `127.0.0.1:<port>`, where `<port>` comes from
   the configured `redirect_uri` (e.g. `http://local.tatari.tools:11313/callback`,
   a DNS name that resolves to `127.0.0.1`).
3. Print the URL and call `open::that()` to launch a browser.
4. Block in `wait_for_callback()` on `server.recv_timeout(60s)`.
5. On timeout only, prompt the user to paste the callback URL from their address
   bar (`src/pkce.rs:63-75`).
6. Verify CSRF state, exchange the code for tokens.

This is correct when the browser and the listener live on the same host.

### Problem

When the CLI runs on a remote host over SSH (e.g. `persona` on `desk.lan`,
driven from a laptop), the listener binds `127.0.0.1:11313` *on the remote host*.
Okta redirects the laptop's browser to `local.tatari.tools:11313` = the laptop's
own loopback, where nothing is listening. The callback can never reach the remote
listener, so:

- The flow **always** burns the full 60s `CALLBACK_TIMEOUT` before the paste
  prompt appears - the outcome is determined at t=0, yet the user waits 60s.
- In a **non-interactive** shell (agent Bash tool, CI), stdin is `/dev/null`. The
  60s elapses, the paste prompt fires, `read_line` returns EOF instantly, and
  `parse_callback_url("")` fails with `NoQueryParams` - a 60s hang followed by a
  misleading error, when the real situation ("can't auth without a human") was
  knowable immediately.

### Goals

- Eliminate the mandatory 60s wait in the SSH/headless case - the paste path
  must be available at t=0.
- Preserve the zero-touch local experience: browser opens, listener auto-captures
  the callback, user types nothing.
- Continue to support an SSH local-port-forward tunnel (`ssh -L 11313:...`): if a
  tunnel exists, the listener should still auto-capture.
- Fail fast and clearly in non-interactive sessions instead of hanging.
- No changes to the public API or `OktaAuthConfig` - every consuming CLI
  (`persona-cli`, etc.) gets the fix transparently on a version bump.

### Non-Goals

- Switching to the OAuth2 device authorization grant (see Alternatives).
- Adding new config fields or CLI flags - behavior is auto-detected.
- Changing the token cache, refresh, or CSRF logic.
- Solving auth *completion* in non-interactive contexts (impossible without a
  human); only failing fast there.
- Zero new dependencies. (Revised: r1 relaxes this. A single terminal primitive -
  `rustix` for `fcntl(O_NONBLOCK)` on the `/dev/tty` fd - is now in scope, because
  it is what lets us avoid an un-cancellable background reader. r2 narrowed its
  use from `poll()` to `fcntl` after the Staff Engineer found `poll()` is broken
  on `/dev/tty` on macOS. See Dependencies.)

## Proposed Solution

### Overview

Replace the sequential "wait-then-fallback" with five ordered steps. The order
matters and is itself a reviewed decision (see step 1):

1. **Validate config / build the authorize URL first** (issuer, token, redirect
   URLs; PKCE; CSRF state) - exactly as `authorize()` does today
   (`src/pkce.rs:23-44`). A malformed config must still surface as `InvalidUrl`,
   *not* be masked by the interactivity check below. This preserves the existing
   contract the `lib.rs:254` / `lib.rs:281` tests exercise (they assert
   `is_err()` on a garbage issuer/redirect; the ordering keeps the *diagnosis*
   correct, not just the test green).
2. **Classify the session** into `Local`, `Headless`, or `NonInteractive` by
   whether the *controlling terminal* is reachable (not by `stdin`).
3. `NonInteractive` → return `OktaAuthError::NonInteractive` *before* binding or
   opening anything (but after step 1, so config errors win).
4. `Local` / `Headless` → bind the listener (`Option<Server>`; bind failure is
   non-fatal when interactive) and open the browser only in `Local`.
5. **Single-threaded poll loop** races the listener against paste input read from
   `/dev/tty`. First to yield `(code, state)` wins; one CSRF check and one token
   exchange happen after the loop.

The two design changes that drove the r1 revision, both from review consensus:

- **Paste input comes from the controlling terminal (`/dev/tty`), never process
  `stdin`.** This is the load-bearing fix. Reading `stdin` in a background thread
  (a) cannot be cancelled once blocked, so it lingers and can steal a later
  prompt's input from the consuming CLI, and (b) wrongly reports "non-interactive"
  when `stdin` is a pipe but a terminal is present (`persona | grep x`). Reading
  `/dev/tty` fixes both.
- **No background thread at all.** A single loop polls both the HTTP listener and
  the `/dev/tty` fd, so there is nothing un-cancellable to leak.

### Architecture

**Session classification.** Interactivity is "can we open the controlling
terminal," tested by opening `/dev/tty` for read (Unix) / `CONIN$` (Windows). The
classifier itself stays a pure function for testability; the call site supplies
the booleans:

```rust
enum Session { Local, Headless, NonInteractive }

fn classify(has_tty: bool, ssh: bool, gui_likely: bool) -> Session {
    if !has_tty { return Session::NonInteractive; } // no controlling terminal
    if ssh || !gui_likely { Session::Headless } else { Session::Local }
}
```

- `has_tty`: `OpenOptions::new().read(true).open("/dev/tty").is_ok()` (Unix). The
  opened handle is *kept* and used for paste reads, so we test reachability and
  acquire the input source in one step. `stdin().is_terminal()` is **not** used -
  it misfires on piped stdin.
- `gui_likely` is computed **platform-aware**, because the signal differs by OS -
  `DISPLAY` is Linux-only and is *not* set by macOS GUI sessions (using `DISPLAY`
  unconditionally would misclassify a local Mac as `Headless` and suppress the
  browser):

```rust
let gui_likely = if cfg!(target_os = "linux") {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
} else {
    true // macOS/Windows: a non-SSH terminal session has a GUI available
};
```

- `ssh`: any of `SSH_CONNECTION`, `SSH_TTY`, or `SSH_CLIENT` set in the
  environment (sshd sets these for both interactive and forced-command
  sessions).

`ssh` takes precedence over `gui_likely`: an X11-forwarded SSH session has
`DISPLAY` set but is still classified `Headless`. That is correct - and even if it
weren't, the loop below makes the classification *cosmetic only* (it decides
whether to call `open::that()` and which guidance to print, never whether auth can
succeed).

**The single-threaded readiness loop** (runs for every interactive session;
`Local` and `Headless` differ only in browser-open and printed guidance). Both
the listener and the terminal are read **non-blocking**, and the loop sleeps
`POLL_INTERVAL` between idle scans - it does **not** call `poll()`/`select()` on
the tty. This is deliberate: the Staff Engineer verified against the local
`rustix` source that `poll()` does not work on `/dev/tty` on macOS (it points to
`select()` instead), and `select()` carries the `FD_SETSIZE` ceiling. A
non-blocking read plus a short sleep sidesteps both and behaves identically on
Linux and macOS. `rustix` is used only to set `O_NONBLOCK` via `fcntl` (portable),
not for readiness:

```rust
// server: Option<tiny_http::Server>   (None only if bind failed in an interactive session)
// tty:    /dev/tty opened and set O_NONBLOCK via fcntl (Unix) / CONIN$ (Windows)
const MAX_PASTE: usize = 8 * 1024;       // bound the carry buffer (no unbounded growth)
let deadline = Instant::now() + BACKSTOP_TIMEOUT;
let mut buf: Vec<u8> = Vec::new();       // BYTE carry buffer: a non-blocking chunk can split UTF-8
let mut tty_live = true;                 // cleared after EOF so we stop reading a dead source
loop {
    // 1) Listener: non-blocking. Server::try_recv() -> io::Result<Option<Request>>.
    if let Some(ref server) = server {
        match server.try_recv() {
            Ok(Some(req)) => match capture_callback(req) {  // writes HTML response, parses query
                Capture::Code(pair)   => break pair,        // ?code= : win
                Capture::OktaError(e) => return Err(e),     // ?error=... : terminal, surface NOW
                Capture::Ignore       => {}                 // no-query / favicon / preflight
            },
            Ok(None) => {}                                  // no request pending
            Err(e)   => warn!("listener try_recv failed: {e}"), // transient; keep waiting
        }
    }
    // 2) Terminal: non-blocking read of available bytes (WouldBlock => pending). read_available
    //    appends to `buf`, splits on '\n', and decodes each complete line with from_utf8_lossy.
    if tty_live {
        match read_available(&tty, &mut buf, MAX_PASTE)? {
            ReadOutcome::Line(url) => match parse_callback_url(&url) {
                Ok(pair)           => break pair,
                Err(e @ OktaAuthError::OktaError { .. })
                                   => return Err(e),        // pasted ?error= is terminal, surface NOW
                Err(_) if headless => eprintln!("couldn't parse that; paste the full callback URL:"),
                Err(_)             => {}                    // Local: silently ignore junk
            },
            ReadOutcome::Eof     => tty_live = false,       // flush any non-empty buf as a last line, then stop
            ReadOutcome::Pending => {}                      // nothing yet, or partial line still buffering
        }
    }
    if Instant::now() >= deadline { return Err(OktaAuthError::CallbackTimeout); }
    sleep(POLL_INTERVAL);                                   // both sources non-blocking; yield between scans
}
```

Key behaviors encoded above (each is a resolved review finding):

- **Stray HTTP requests do not abort; real OAuth errors still surface.**
  `capture_callback` returns a three-way `Capture`: `Code` for a request bearing
  `?code=` (win), `OktaError` for a request bearing `?error=...` (a terminal auth
  result - surfaced *immediately* as `OktaError`, not waited out to the backstop),
  and `Ignore` for a no-query / `/favicon.ico` / preflight / port-scan request
  (respond and keep waiting). This preserves today's error-before-code precedence
  (`pkce.rs:183`) while fixing the latent bug where a code-less request
  `?`-aborts the whole flow (`pkce.rs:131`).
- **`Local` ignores junk silently; `Headless` prompts and retries.** A stray
  Enter in `Local` produces no "paste a URL" noise, preserving zero-touch. A bad
  paste in `Headless` reprints the instruction and keeps both the listener and
  the tty live - never fatal.
- **EOF on the tty** (Ctrl-D) stops paste reading but lets the listener / backstop
  continue.
- **Cancellation is free.** When the listener wins, we simply stop polling the
  tty; there is no blocked thread to tear down and nothing that can consume the
  consuming CLI's input afterward.

**Implementation notes the reader must honor** (raised by the Staff Engineer at
re-confirmation, so they don't get lost between design and code):

- `Server::try_recv()` returns `io::Result<Option<Request>>`, *not*
  `Option<Request>`. The `Err` arm is handled deliberately (warn-and-continue: a
  transient accept error should not kill an in-progress login).
- The carry buffer is **bytes (`Vec<u8>`)**, not `String` - a non-blocking chunk
  can split a multi-byte UTF-8 sequence. `read_available` splits on `\n` and
  decodes each *complete* line with `from_utf8_lossy`, so junk input can never
  become a fatal decode error (callback URLs are ASCII/percent-encoded anyway).
  This matches the repo's UTF-8 rule (read bytes, lossy-decode for display).
- **Canonical mode is assumed and sufficient.** A cooked tty does not deliver
  bytes until Enter; that is exactly the "paste URL then Enter" flow. Raw mode is
  *not* required, and partial text typed before Enter legitimately stays
  `Pending`.
- **EOF is one-shot.** Ctrl-D on a tty is not necessarily permanent device EOF, so
  on `ReadOutcome::Eof` the loop flushes any non-empty carry buffer as a final
  line, then sets `tty_live = false` and stops calling the source (rather than
  re-reading a dead fd every scan).

After the loop, the **single** CSRF check (`state != csrf_state.secret()` →
`CsrfMismatch`) and the code-for-token exchange run once - unchanged from today.

- `Local`: call `open::that()`; print "browser opening...".
- `Headless`: skip `open::that()`; print the URL plus "open this on your machine;
  if it shows 'can't be reached', paste the address-bar URL here:".

### Edge Cases & Failure Modes

- **`NonInteractive` only fires when interactive auth is truly required.**
  `get_token()` calls `authorize()` *only* after a cache miss and a failed/absent
  refresh (`src/lib.rs:62-90`). A non-interactive caller (agent Bash tool, CI)
  with a valid cached token, or one with a working refresh token, never reaches
  `authorize()` and is unaffected. So the contract for headless automation is
  "keep the token warm (or refreshable) and it just works; only a genuine
  re-login - which needs a human - fails fast." This is the point of the whole
  redesign, not an afterthought.

- **Config errors beat the interactivity check.** Step 1 (build/validate URLs)
  runs before classification, so a malformed `okta_issuer`/`redirect_uri` in CI
  surfaces as `InvalidUrl` - the correct 3am diagnosis - rather than being masked
  as "re-auth in a terminal." The `lib.rs:254` / `lib.rs:281` tests exercise this
  path (note: they assert `is_err()`, not the variant - Phase 2 tightens them to
  assert `InvalidUrl` specifically, which also pins the ordering).

- **Paste reads the controlling terminal, not `stdin`.** The reader operates on
  the `/dev/tty` handle. It therefore (a) never consumes the consuming CLI's
  `stdin`, so it cannot steal a later `[y/N]` prompt, and (b) still works when the
  CLI is invoked with piped `stdin` but a terminal is attached.

- **Bind is interactive-only, so `BindFailed` is never fatal.** Binding runs
  *after* the `NonInteractive` early-return, so any bind attempt is already in an
  interactive session. If the port is held (a stale `ssh -L` tunnel, "another
  login may be running"), the paste path does not need the listener: `warn!`, set
  `server = None`, run the loop tty-only. With `server = None` the gated listener
  branch is skipped and the loop reads the tty non-blocking and sleeps
  `POLL_INTERVAL` - no busy-wait. (The r1 wording "if `NonInteractive`, return as
  today" was removed as contradictory: `NonInteractive` returns before bind.)

- **The paste carry buffer is bounded.** `read_available` enforces `MAX_PASTE`
  (8 KB): input exceeding it without a newline is discarded (and reprompts in
  `Headless`) rather than growing unbounded - no OOM from a runaway pipe.

- **Bad paste is retryable, not fatal** (Headless), **silent** (Local). See the
  loop: a parse failure in `Headless` reprints the instruction and keeps both the
  listener and the tty live; in `Local` it is silently discarded. A pasted URL
  carrying `error=access_denied` is a real Okta failure and *is* surfaced
  (`OktaError`).

- **Wrong pasted `state` is fatal by design (not retried).** A pasted callback
  whose `state` does not match the session CSRF token returns `CsrfMismatch` and
  aborts the whole flow - it is *not* treated as a retryable typo, because a
  state mismatch is the exact signature this check exists to catch. Documented so
  the abort-vs-retry choice is explicit rather than incidental.

- **Ctrl-D / EOF on the tty** stops paste reading; the listener and backstop
  continue.

- **Simultaneous delivery.** The listener branch is checked first each iteration;
  if both a callback and a paste are ready, one is taken and the other ignored -
  harmless, same `(code, state)` semantics.

### Data Model

No data-structure changes. One new error variant:

```rust
#[error("Okta token is missing or expired and no controlling terminal is \
         available (non-interactive session). Re-authenticate in a terminal \
         first, then retry.")]
NonInteractive,
```

`CallbackTimeout`'s message is reworded to drop the hardcoded "60s" since the
timeout is now only a generous backstop, not the primary control path.

**Source compatibility of the new variant.** `OktaAuthError` in `src/error.rs` is
public and is *not* `#[non_exhaustive]` (confirmed by both reviewers). Adding a
variant is a SemVer-breaking change for any external consumer matching
exhaustively. Resolution (both reviewers concur): (a) bump in-tree consumers
(`persona-cli` and siblings) together, **and** (b) add `#[non_exhaustive]` to the
enum in this same release so future variants are non-breaking. Call this out in
the release notes.

### API Design

No public signature changes. `pkce::authorize(issuer, client_id, redirect_uri,
scopes) -> Result<TokenCache, OktaAuthError>` keeps its signature; all changes are
internal. `OktaAuth::get_token()` / `login()` are unchanged and now surface
`NonInteractive` where they previously hung.

**Internal seams for testability** (see Testing Strategy). The input-acquisition
loop is extracted into an inner function that takes injected ports rather than
touching the world directly:

- a `Binder` (produces `Option<Server>` or a fake),
- an `Opener` (browser launch; a no-op fake in tests),
- an `Input` source (the `/dev/tty` handle, or an in-memory fixture),
- a `Clock` (so the backstop is testable without real time).

The `Binder`/listener port yields **parsed `Capture` outcomes**, not raw
`tiny_http::Request` values - tests assert against `Capture::{Code,OktaError,
Ignore}` instead of fabricating HTTP requests (per the Staff Engineer's note that
faking `tiny_http::Request` is awkward; `tiny_http` 0.12 exposes `try_recv()`).
The inner function returns `(code, state)`; the real token exchange stays at the
`authorize()` boundary so unit tests can drive the loop without hitting Okta.

### Implementation Plan

#### Phase 1: Terminal input port + classifier + single-threaded loop
**Model:** opus
- Add the `Input` port: open `/dev/tty` (Unix) / `CONIN$` (Windows), set
  `O_NONBLOCK` via `rustix::fs::fcntl`; a non-blocking `read_available` with a
  bounded carry buffer (`MAX_PASTE`, resets per newline). Declare `rustix` as a
  direct dep (`cargo add rustix --features fs`).
- Add `Session` enum and pure `classify(has_tty, ssh, gui_likely)`; compute
  `gui_likely` platform-aware.
- Add `OktaAuthError::NonInteractive` **and** `#[non_exhaustive]` on the enum;
  reword `CallbackTimeout` (drop "60s").
- Reorder `authorize()`: build/validate URLs first (keep `InvalidUrl` contract),
  then classify, then early-return `NonInteractive` before bind/open.
- Bind to `Option<Server>`; `BindFailed` non-fatal (warn, `server = None`).
  Note: after this change nothing constructs `BindFailed` - keep the variant
  (external consumers may match it; removing it is a second breaking change in
  the same release) and mark it deprecated-in-docs rather than deleting it.
- Add `capture_callback -> Capture::{Code,OktaError,Ignore}` (surface `?error=`
  immediately, ignore no-code/preflight).
- Implement the single-threaded readiness loop: non-blocking listener `try_recv`,
  non-blocking tty `read_available`, Headless-retry / Local-silent, EOF, backstop
  deadline, `sleep(POLL_INTERVAL)` between idle scans. No `poll`/`select` on the
  tty; no background thread.
- Add `POLL_INTERVAL` (50-100ms; anything in that range satisfies the
  "negligible latency" claim), `BACKSTOP_TIMEOUT` (~5 min), `MAX_PASTE` (8 KB)
  consts.
- Add the function-level logging below (per `rules/logging.md`).
- Windows `CONIN$` non-blocking strategy is an explicit, compile-checked impl in
  the `Input` port (or ship Windows listener-only with a documented paste gap).

#### Phase 2: Tests
**Model:** opus
- Extract the loop into an inner fn over injected `Binder`/`Opener`/`Input`/`Clock`.
- Unit-test `classify()` across the full input matrix.
- Test config error precedence: bad issuer → `InvalidUrl`, not `NonInteractive`.
- Test `NonInteractive` returned without binding/opening when `Input` reports no tty.
- Test loop arms with fakes: callback wins; paste wins; `?error=` surfaces as
  `OktaError`; stray no-code request is ignored; bad paste retries (Headless) / is
  silent (Local); EOF; backstop fires; `server = None` (bind-failed) path reads
  tty non-blocking and sleeps `POLL_INTERVAL` (no busy-wait); paste over
  `MAX_PASTE` is discarded.
- Test the reworded error messages. This includes updating the existing
  `error_display_messages` test in `src/error.rs`, which asserts the exact old
  string ("... callback (60s)") and will fail on the reword.
- Test that a pasted `?error=` URL surfaces as `OktaError` (not retried) in
  both `Headless` and `Local`.
- Tighten `lib.rs:254` / `lib.rs:281` to assert the `InvalidUrl` variant (not
  just `is_err()`), pinning config-error precedence over `NonInteractive`.
- Real-socket smoke: bind ephemeral port, hit `/callback?code=..&state=..`, assert capture.

#### Phase 3: Docs
**Model:** sonnet
- README: SSH usage (paste flow + optional `ssh -L` tunnel), non-interactive
  failure mode for agent/CI callers, and the `OktaAuthError` variant addition in
  release notes.

## Alternatives Considered

### Alternative 1: Pure environment detection, no race
- **Description:** Over SSH, skip the listener entirely and go straight to the
  paste prompt; listener only when `Local`.
- **Pros:** Simpler; no background thread.
- **Cons:** SSH tunnel users lose auto-capture; a mis-detected `Headless` (env
  heuristics wrong) breaks the flow with no fallback.
- **Why not chosen:** The race handles all three transports (local browser, SSH
  paste, SSH tunnel) without env detection being load-bearing - detection becomes
  cosmetic-only, which is far more robust.

### Alternative 2: Shorten / remove the 60s timeout
- **Description:** Keep the sequential flow, just lower `CALLBACK_TIMEOUT`.
- **Pros:** Trivial.
- **Cons:** Still a wait; still a cryptic non-interactive failure; doesn't fix
  root cause.
- **Why not chosen:** Treats the symptom.

### Alternative 3: OAuth2 device authorization grant
- **Description:** No localhost callback; show a code, poll the token endpoint.
- **Pros:** Cleanest possible headless story; no listener at all.
- **Cons:** Requires the Okta app to enable the device grant; larger change;
  alters UX for every consumer.
- **Why not chosen:** Out of scope now; viable future direction.

### Alternative 4: Background thread reading `stdin` (the original r0 design)
- **Description:** Spawn a detached thread blocking on `stdin().read_line()`,
  race it against the listener via an `mpsc` channel.
- **Pros:** No new dependency; std-only.
- **Cons:** The blocked read is **un-cancellable**: when the listener wins, the
  thread lingers on the process's `stdin` and can steal a later prompt's input
  from the consuming CLI - unacceptable for a generic library. Also misreports
  "non-interactive" when `stdin` is piped but a terminal exists.
- **Why not chosen:** Both reviewers (Architect, Staff Engineer) independently
  identified this as the core defect. Reading `/dev/tty` via a single-threaded
  `poll` loop (the chosen design) eliminates both problems at the cost of one
  dependency - the right trade.

## Technical Considerations

### Dependencies
One new crate: **`rustix`** (or `libc`/`nix`), used only to **set `O_NONBLOCK` on
the `/dev/tty` fd via `fcntl`** - a portable operation - so the loop can read it
non-blocking. It is *not* used for `poll()`/`select()` (the Staff Engineer found
`poll()` is broken on `/dev/tty` on macOS). Rationale for needing it at all: std
exposes neither `fcntl` nor non-blocking opens portably, and the std-only
alternative is a blocking read on a background thread - the exact un-cancellable
construct both reviewers flagged as the core defect. `rustix` is a widely-used,
audited, pure-Rust syscall wrapper. **It must be declared as a direct dependency
with the `fs` feature** (`cargo add rustix --features fs`) - the Staff Engineer
noted it currently appears only transitively in `Cargo.lock`, not in
`Cargo.toml`. Otherwise unchanged: existing `tiny_http` and `open`.
`std::io::IsTerminal` is *no longer used* (replaced by `/dev/tty` reachability).

### Performance
Poll interval adds negligible latency (sub-second). Local auto-capture latency is
unchanged in practice. The loop is single-threaded; no thread spawn cost.

### Security
CSRF state verification is unchanged and applies to both the listener and paste
paths - a pasted URL must carry the session's random `state` or it is rejected
with `CsrfMismatch` (fatal, not retried), which defends the paste path against a
user being socially engineered into pasting an attacker-supplied callback URL. No
secrets are logged (the logging below logs *classification and lifecycle*, never
codes or tokens). The flow fails closed (`NonInteractive`) rather than open.

### Observability
Per `rules/logging.md`, `authorize()` and the loop emit (no secrets):
- `debug!` the resolved `Session` and the inputs that produced it (`has_tty`,
  `ssh`, `gui_likely`).
- `debug!` chosen mode, whether `open::that()` was attempted/skipped, and bind
  outcome (incl. the `server = None` paste-only fallback).
- `trace!` per poll iteration; `debug!` which source won (listener vs paste).
- `warn!` on bind failure (interactive fallback), tty EOF, and backstop timeout.
- `error!` on `CsrfMismatch` and token-exchange failure.

### Testing Strategy
The loop is extracted into an inner function over injected ports
(`Binder`/`Opener`/`Input`/`Clock`) so every arm is unit-testable without a real
tty, socket, or Okta. Coverage: pure `classify()` across the input matrix; config
error precedence (`InvalidUrl` beats `NonInteractive`); `NonInteractive` taken
when `Input` reports no tty (no bind/open); each loop arm via fakes (callback
wins, paste wins, `?error=` surfaces, stray no-code ignored, Headless retry,
Local silent, EOF, backstop, `server = None` reads tty non-blocking without
busy-waiting, `MAX_PASTE` overflow discarded); reworded error messages; and a
real-socket ephemeral-port smoke for the listener path. `/dev/tty` reachability
is behind the `Input` port, so it is faked rather than mocked at the syscall
layer.

### Rollout Plan
Bump `okta-auth-rs`, then bump consuming CLIs to pick it up. No migration; tokens
and config are untouched.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| New `rustix` dependency (supply chain, build) | Low | Low | Widely-used, audited, pure-Rust; declared direct with `fs` feature; only `fcntl(O_NONBLOCK)` used |
| `poll()`/`select()` not portable on `/dev/tty` (macOS) | Resolved | High | Avoided entirely: non-blocking reads + `POLL_INTERVAL` sleep, no readiness syscall on the tty |
| `/dev/tty` / `CONIN$` portability (esp. Windows) | Med | Med | `Input` port isolates platform code; Windows path compile-checked + smoke-tested, or listener-only with documented gap |
| Partial-line buffering bug in non-blocking reader | Med | Med | Bounded carry buffer (`MAX_PASTE`); fixture tests for split reads, no trailing newline, EOF mid-line, overflow |
| External consumer breaks on new `OktaAuthError` variant | Low | Med | In-tree consumers bumped together; add `#[non_exhaustive]` this release; called out in release notes |
| Config error masked by interactivity check | Low | High | Resolved by ordering: build/validate URLs before classify (tested) |
| Consumer relied on old `CallbackTimeout` text | Low | Low | Match on the variant, not the string |
| macOS/Windows path untested (no Linux CI signal) | Med | Low | `classify()` unit-tested via booleans; `Input` faked; smoke on a Mac |

## Open Questions

All previously-open items are resolved in r1:

- [x] Indefinite wait vs. backstop? **Backstop** (`BACKSTOP_TIMEOUT`, ~5 min).
      Paste is instant, so a human never hits it; the backstop only prevents a
      wedged process in odd pty-wrapped automation.
- [x] Should `NonInteractive` surface the authorize URL? **No - fire it early**
      (after config validation, before bind/open). A non-interactive caller can't
      act on a URL; the guidance is "re-auth in a terminal."
- [x] `BACKSTOP_TIMEOUT` env-overridable? **No** - fixed const; revisit only if it
      bites a real automation case.
- [x] Read `stdin` or the controlling terminal? **`/dev/tty`** - fixes both the
      input-stealing hazard and the piped-stdin false negative.
- [x] Background thread vs. single loop? **Single-threaded `poll` loop** - nothing
      un-cancellable to leak.
- [x] `NonInteractive` vs. config-error precedence? **Config errors win** (ordering).
- [x] Wrong pasted `state`: retry or abort? **Abort** (`CsrfMismatch`) - it is the
      signature this check exists to catch.

Deferred with reviewer agreement (documented limitation, not blocking):

- [x] **Non-SSH remote access to a macOS/Windows host** (serial console, RDP,
      WinRM, exotic agent) sets `gui_likely = true` with no `SSH_*`, classifying
      it `Local` and attempting a doomed `open::that()`. **Resolved: documented
      limitation.** The Architect concurred ("not worth the payload... no
      `OKTA_AUTH_FORCE_HEADLESS=1` until empirical demand"); the fail-safe is the
      same actionable re-auth path. Revisit only if real users hit it.

Open for the implementer (non-blocking):

- [ ] Windows `CONIN$` non-blocking input: implement in the `Input` port, or ship
      Windows as listener-only with a documented paste gap. SSH-to-headless-Windows
      is not a current use case, so either is acceptable for v1.

## References
- `src/pkce.rs` - current flow
- `src/error.rs` - error enum
- `src/lib.rs` - public API (`OktaAuth`, `OktaAuthConfig`)
