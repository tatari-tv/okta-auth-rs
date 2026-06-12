# Implementation Notes: Non-Blocking Headless / SSH Authentication

Running, append-only record of how the implementation interprets or diverges from
`2026-06-11-headless-auth.md`. One section per phase.

## Phase 1: Terminal input port + classifier + single-threaded loop

### Design decisions
- **Module layout** — the flow internals live as submodules of `pkce`:
  `src/pkce/session.rs` (`Session`, `classify`, env detectors),
  `src/pkce/listener.rs` (`Listener` trait, `Capture`, `HttpListener`, query
  parsing), `src/pkce/input.rs` (`Input`/`InputSource` traits, `ReadOutcome`,
  `CarryBuffer`, the Unix `/dev/tty` reader and Windows listener-only stub),
  `src/pkce/clock.rs` (`Clock`/`RealClock`). Single-word filenames per repo rules.
- **`run_loop` takes `backstop` and `poll_interval` as parameters** rather than
  reading the module consts directly — `pkce.rs:run_loop`. `authorize()` passes the
  `BACKSTOP_TIMEOUT`/`POLL_INTERVAL` consts; tests can pass tiny values to drive the
  backstop deterministically without a 5-minute fake clock. The consts remain the
  single source of truth for production behavior.
- **`POLL_INTERVAL = 75ms`** — midpoint of the design's suggested 50-100ms range.
- **EOF flush happens inside the input port, not the loop** — `CarryBuffer::push`
  (`pkce/input.rs`) returns the non-empty partial buffer as a final `Line` on a
  zero-byte read, then reports `Eof` on the next call (tracked via `eof_seen`). The
  design text says "the loop flushes"; encapsulating it in the port is equivalent,
  keeps the loop simple, and is directly testable at the port level. The loop still
  sets `tty_live = false` on `ReadOutcome::Eof`.
- **`ReadOutcome::Overflow` is an explicit variant** (`pkce/input.rs`) rather than
  folding overflow into `Pending`. The loop reprompts in Headless / stays silent in
  Local on `Overflow`, satisfying "input exceeding MAX_PASTE is discarded (and
  reprompts in Headless)" with a testable signal.
- **`authorize_inner` injects `Binder`/`Opener`/`InputSource`/`Clock`** and takes the
  token `exchange` as a `FnOnce(&str) -> Result<TokenCache>` closure
  (`pkce.rs:authorize_inner`). The real `authorize()` builds the oauth2 client and
  passes a closure that performs the exchange; tests can drive classification + the
  loop + CSRF check without hitting Okta. The loop itself (`run_loop`) returns
  `(code, state)`; CSRF check and exchange happen in `authorize_inner` after it.
- **Classification routes through `classify(acquired.is_some(), ssh, gui_likely)`** —
  acquiring the `/dev/tty` handle IS the reachability test, and `classify` remains a
  pure function over the resulting booleans, independently testable across the matrix.
- **A tty *read* error closes the paste path (warn + `tty_live = false`)** rather than
  aborting the flow — `pkce.rs:run_loop`. The listener and backstop continue. This
  avoids inventing an error-variant mapping for an unusual transient read failure and
  matches the "transient, keep waiting" philosophy applied to the listener.

### Deviations
- **`CallbackTimeout` reworded in Phase 1, and the existing `error_display_messages`
  test updated in Phase 1** (not Phase 2). The design slots the message rewording in
  Phase 1 and the test update in Phase 2, but per-phase `otto ci` must stay green, so
  the existing exact-string assertion had to be updated in the same phase that
  reworded the message. Phase 2 still adds the dedicated message tests
  (`NonInteractive`, reworded `CallbackTimeout`).
- **`BindFailed` marked `#[deprecated]` (in-docs), not just doc-flagged** —
  `src/error.rs`. The design says "mark deprecated-in-docs rather than deleting it."
  Used a real `#[deprecated]` attribute (with a note) plus a doc comment, which is
  stronger and self-enforcing; the lone in-tree constructor (the `bind_failed_*`
  test) carries `#[allow(deprecated)]`.

### Tradeoffs
- **`run_loop` params vs. module consts** — parameters add two arguments but make the
  backstop unit-testable in milliseconds. Chosen over reading consts directly because
  the design explicitly prioritizes loop testability.
- **EOF flush in port vs. loop** — port-side is slightly less literal to the
  pseudocode but yields a smaller loop and a port that is fully testable in isolation.
- **Windows listener-only stub** — `pkce/input.rs` `windows` module returns
  `Pending` forever and gates interactivity on `stdin().is_terminal()`. Chosen over
  blocking v1 on a real `CONIN$` non-blocking reader, which the design lists as an
  acceptable implementer choice ("ship Windows as listener-only with a documented
  paste gap"). `std::io::IsTerminal` is used only on this Windows fallback path; the
  Unix path uses `/dev/tty` reachability as specified.

### Open questions
- Windows `CONIN$` non-blocking input remains unimplemented (listener-only). The
  design marks this as acceptable for v1; confirm no current Windows-over-SSH use case
  before investing in a real reader.

## Phase 2: Tests

### Design decisions
- **Test files follow the repo's 2018+ submodule rule** for the new modules:
  `src/pkce/session/tests.rs`, `src/pkce/input/tests.rs`, `src/pkce/tests.rs` (declared
  `#[cfg(test)] mod tests;` in each parent). The pre-existing inline `#[cfg(test)] mod
  tests { .. }` blocks in `src/lib.rs` and `src/error.rs` were left in place (see
  Deviations) and only their assertions updated.
- **`MAX_PASTE` overflow tested at two levels** — the actual discard/recovery is
  unit-tested on `CarryBuffer` (`pkce/input/tests.rs`); the loop's non-fatal handling
  of `ReadOutcome::Overflow` is tested via `FakeInput` (`overflow_is_non_fatal_and_retryable`).
- **Bad-paste retry vs. silent tested by invariant, not by captured stderr** — both
  `bad_paste_is_retryable_in_headless` and `bad_paste_is_silent_in_local` assert the
  substantive behavior (a bad paste is non-fatal; the loop keeps going and later
  succeeds). The only difference between the two modes is the reprompt line printed to
  stderr, which is not worth a stderr-capture harness.
- **`run_loop` and `authorize_inner` are exercised directly** from `pkce/tests.rs`
  (sibling test submodule sees the private items via `use super::*`), with five fakes:
  `FakeListener`, `FakeInput`, `FakeInputSource`, `FakeBinder`, `FakeOpener`, `FakeClock`.
  The token exchange is injected as a plain `fn(&str) -> Result<TokenCache>` (`ok_exchange`
  / `panic_exchange`), so CSRF-mismatch and NonInteractive paths assert the exchange
  never runs.
- **`FakeClock` counts sleeps** so `server_none_reads_tty_without_busy_waiting` can
  assert exactly one sleep per idle scan - a direct test of the "no busy-wait" claim.

### Deviations
- **Existing inline `mod tests` blocks in `lib.rs`/`error.rs` not extracted.** The repo
  rust rule says extract inline test modules on sight, but the skill forbids unrelated
  changes and this repo already uses inline blocks in both files; extracting them is an
  out-of-scope structural churn. Only the assertions the design names were changed
  (CallbackTimeout reword + NonInteractive message in `error.rs`; `is_err()` →
  `matches!(.., InvalidUrl)` in `lib.rs`). New modules follow the separate-file rule.

### Tradeoffs
- **Real-socket smoke test uses a probe-then-bind ephemeral port** (`real_socket_listener_captures_code`):
  bind `127.0.0.1:0`, read the port, drop, rebind via `HttpListener`. There is a
  negligible TOCTOU window; acceptable for a smoke test and far simpler than threading a
  pre-bound socket into `tiny_http`.

### Open questions
- None.

## Phase 3: Docs

### Design decisions
- **README expanded from a one-liner** to cover usage, SSH/headless paste flow, the
  optional `ssh -L` tunnel, the non-interactive (agent/CI) failure mode, and a release
  notes section documenting `NonInteractive`, the `#[non_exhaustive]` source-compat
  note, the deprecated `BindFailed`, and the reworded `CallbackTimeout`.

### Deviations
- None.

### Tradeoffs
- None.

### Open questions
- None.
