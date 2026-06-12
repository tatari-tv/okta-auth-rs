#![allow(clippy::unwrap_used)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use super::*;

// ---------------------------------------------------------------------------
// Fakes for the injected ports.
// ---------------------------------------------------------------------------

struct FakeListener {
    script: RefCell<VecDeque<io::Result<Option<Capture>>>>,
}

impl FakeListener {
    fn new(script: Vec<io::Result<Option<Capture>>>) -> Self {
        Self {
            script: RefCell::new(script.into_iter().collect()),
        }
    }
}

impl Listener for FakeListener {
    fn poll(&self) -> io::Result<Option<Capture>> {
        self.script.borrow_mut().pop_front().unwrap_or(Ok(None))
    }
}

struct FakeInput {
    script: VecDeque<io::Result<ReadOutcome>>,
}

impl FakeInput {
    fn new(script: Vec<io::Result<ReadOutcome>>) -> Self {
        Self {
            script: script.into_iter().collect(),
        }
    }
}

impl Input for FakeInput {
    fn read_available(&mut self) -> io::Result<ReadOutcome> {
        self.script.pop_front().unwrap_or(Ok(ReadOutcome::Pending))
    }
}

struct FakeInputSource {
    reader: RefCell<Option<FakeInput>>,
}

impl FakeInputSource {
    fn with(reader: FakeInput) -> Self {
        Self {
            reader: RefCell::new(Some(reader)),
        }
    }
    fn none() -> Self {
        Self {
            reader: RefCell::new(None),
        }
    }
}

impl InputSource for FakeInputSource {
    type Reader = FakeInput;
    fn acquire(&self) -> Option<FakeInput> {
        self.reader.borrow_mut().take()
    }
}

struct FakeBinder {
    listener: RefCell<Option<FakeListener>>,
    binds: Cell<usize>,
}

impl FakeBinder {
    fn with(listener: FakeListener) -> Self {
        Self {
            listener: RefCell::new(Some(listener)),
            binds: Cell::new(0),
        }
    }
    fn none() -> Self {
        Self {
            listener: RefCell::new(None),
            binds: Cell::new(0),
        }
    }
}

impl Binder for FakeBinder {
    type Listener = FakeListener;
    fn bind(&self, port: u16) -> Option<FakeListener> {
        let _ = port;
        self.binds.set(self.binds.get() + 1);
        self.listener.borrow_mut().take()
    }
}

struct FakeOpener {
    opens: Cell<usize>,
}

impl FakeOpener {
    fn new() -> Self {
        Self { opens: Cell::new(0) }
    }
}

impl Opener for FakeOpener {
    fn open(&self, url: &str) {
        let _ = url;
        self.opens.set(self.opens.get() + 1);
    }
}

struct FakeClock {
    elapsed: Cell<Duration>,
    sleeps: Cell<usize>,
}

impl FakeClock {
    fn new() -> Self {
        Self {
            elapsed: Cell::new(Duration::ZERO),
            sleeps: Cell::new(0),
        }
    }
}

impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        self.elapsed.get()
    }
    fn sleep(&self, dur: Duration) {
        self.sleeps.set(self.sleeps.get() + 1);
        self.elapsed.set(self.elapsed.get() + dur);
    }
}

// ---------------------------------------------------------------------------
// Helpers / fixtures.
// ---------------------------------------------------------------------------

const POLL: Duration = Duration::from_millis(75);
const LONG_BACKSTOP: Duration = Duration::from_secs(60);

fn code_capture() -> Capture {
    Capture::Code("CODE".into(), "STATE".into())
}

fn okta_error_capture() -> Capture {
    Capture::OktaError(OktaAuthError::OktaError {
        error: "access_denied".into(),
        description: "user not assigned".into(),
    })
}

fn paste_line(query: &str) -> io::Result<ReadOutcome> {
    Ok(ReadOutcome::Line(format!("http://local.test:11313/callback?{query}")))
}

fn run<L: Listener, I: Input>(
    server: Option<L>,
    input: &mut I,
    clock: &FakeClock,
    headless: bool,
    backstop: Duration,
) -> Result<(String, String), OktaAuthError> {
    run_loop(server, input, clock, headless, backstop, POLL)
}

// ---------------------------------------------------------------------------
// run_loop arm coverage.
// ---------------------------------------------------------------------------

#[test]
fn listener_callback_wins() {
    let server = FakeListener::new(vec![Ok(Some(code_capture()))]);
    let mut input = FakeInput::new(vec![]); // always Pending
    let clock = FakeClock::new();
    let result = run(Some(server), &mut input, &clock, false, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn paste_wins() {
    let mut input = FakeInput::new(vec![paste_line("code=CODE&state=STATE")]);
    let clock = FakeClock::new();
    let result = run(None::<FakeListener>, &mut input, &clock, true, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn listener_okta_error_surfaces_immediately() {
    let server = FakeListener::new(vec![Ok(Some(okta_error_capture()))]);
    let mut input = FakeInput::new(vec![]);
    let clock = FakeClock::new();
    let err = run(Some(server), &mut input, &clock, false, LONG_BACKSTOP).unwrap_err();
    assert!(matches!(err, OktaAuthError::OktaError { .. }));
}

#[test]
fn pasted_okta_error_surfaces_in_headless() {
    let mut input = FakeInput::new(vec![paste_line("error=access_denied&error_description=nope")]);
    let clock = FakeClock::new();
    let err = run(None::<FakeListener>, &mut input, &clock, true, LONG_BACKSTOP).unwrap_err();
    assert!(matches!(err, OktaAuthError::OktaError { .. }));
}

#[test]
fn pasted_okta_error_surfaces_in_local() {
    let mut input = FakeInput::new(vec![paste_line("error=access_denied")]);
    let clock = FakeClock::new();
    let err = run(None::<FakeListener>, &mut input, &clock, false, LONG_BACKSTOP).unwrap_err();
    assert!(matches!(err, OktaAuthError::OktaError { .. }));
}

#[test]
fn stray_no_code_request_is_ignored() {
    let server = FakeListener::new(vec![Ok(Some(Capture::Ignore)), Ok(Some(code_capture()))]);
    let mut input = FakeInput::new(vec![]);
    let clock = FakeClock::new();
    let result = run(Some(server), &mut input, &clock, false, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn transient_listener_error_does_not_kill_login() {
    let server = FakeListener::new(vec![
        Err(io::Error::other("transient accept failure")),
        Ok(Some(code_capture())),
    ]);
    let mut input = FakeInput::new(vec![]);
    let clock = FakeClock::new();
    let result = run(Some(server), &mut input, &clock, false, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn bad_paste_is_retryable_in_headless() {
    let mut input = FakeInput::new(vec![
        Ok(ReadOutcome::Line("garbage no query".into())),
        paste_line("code=CODE&state=STATE"),
    ]);
    let clock = FakeClock::new();
    let result = run(None::<FakeListener>, &mut input, &clock, true, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn bad_paste_is_silent_in_local() {
    let mut input = FakeInput::new(vec![
        Ok(ReadOutcome::Line("garbage no query".into())),
        paste_line("code=CODE&state=STATE"),
    ]);
    let clock = FakeClock::new();
    let result = run(None::<FakeListener>, &mut input, &clock, false, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn overflow_is_non_fatal_and_retryable() {
    let mut input = FakeInput::new(vec![Ok(ReadOutcome::Overflow), paste_line("code=CODE&state=STATE")]);
    let clock = FakeClock::new();
    let result = run(None::<FakeListener>, &mut input, &clock, true, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn tty_eof_stops_paste_but_listener_still_wins() {
    let server = FakeListener::new(vec![Ok(None), Ok(Some(code_capture()))]);
    let mut input = FakeInput::new(vec![Ok(ReadOutcome::Eof)]);
    let clock = FakeClock::new();
    let result = run(Some(server), &mut input, &clock, true, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn backstop_fires_when_nothing_arrives() {
    let mut input = FakeInput::new(vec![]); // always Pending
    let clock = FakeClock::new();
    // 75ms per sleep, 200ms backstop -> fires after a few scans.
    let err = run(
        None::<FakeListener>,
        &mut input,
        &clock,
        true,
        Duration::from_millis(200),
    )
    .unwrap_err();
    assert!(matches!(err, OktaAuthError::CallbackTimeout));
    assert!(
        clock.sleeps.get() >= 1,
        "loop must sleep between idle scans, not busy-wait"
    );
}

#[test]
fn server_none_reads_tty_without_busy_waiting() {
    // bind-failed path: no listener, paste arrives after two idle scans.
    let mut input = FakeInput::new(vec![
        Ok(ReadOutcome::Pending),
        Ok(ReadOutcome::Pending),
        paste_line("code=CODE&state=STATE"),
    ]);
    let clock = FakeClock::new();
    let result = run(None::<FakeListener>, &mut input, &clock, true, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
    // Exactly one sleep per idle scan: proves it yields rather than spinning.
    assert_eq!(clock.sleeps.get(), 2);
}

// ---------------------------------------------------------------------------
// authorize_inner: classification, bind/open gating, CSRF.
// ---------------------------------------------------------------------------

fn ok_exchange(code: &str) -> Result<TokenCache, OktaAuthError> {
    Ok(TokenCache {
        access_token: format!("tok-{code}"),
        refresh_token: None,
        expires_at: 9_999_999_999,
    })
}

fn panic_exchange(code: &str) -> Result<TokenCache, OktaAuthError> {
    panic!("exchange must not run (got code={code})")
}

#[test]
fn non_interactive_fails_fast_without_binding_or_opening() {
    let binder = FakeBinder::none();
    let opener = FakeOpener::new();
    let source = FakeInputSource::none(); // no controlling terminal
    let clock = FakeClock::new();

    let result = authorize_inner(
        "http://issuer/authorize",
        "STATE",
        11313,
        /* ssh */ false,
        /* gui_likely */ true,
        &binder,
        &opener,
        &source,
        &clock,
        LONG_BACKSTOP,
        POLL,
        panic_exchange,
    );

    assert!(matches!(result, Err(OktaAuthError::NonInteractive)));
    assert_eq!(binder.binds.get(), 0, "must not bind when non-interactive");
    assert_eq!(opener.opens.get(), 0, "must not open browser when non-interactive");
}

#[test]
fn local_session_opens_browser_and_completes() {
    let binder = FakeBinder::none(); // bind-failed -> paste-only
    let opener = FakeOpener::new();
    let source = FakeInputSource::with(FakeInput::new(vec![paste_line("code=CODE&state=STATE")]));
    let clock = FakeClock::new();

    let token = authorize_inner(
        "http://issuer/authorize",
        "STATE",
        11313,
        /* ssh */ false,
        /* gui_likely */ true, // -> Local
        &binder,
        &opener,
        &source,
        &clock,
        LONG_BACKSTOP,
        POLL,
        ok_exchange,
    )
    .unwrap();

    assert_eq!(token.access_token, "tok-CODE");
    assert_eq!(opener.opens.get(), 1, "Local must open the browser");
}

#[test]
fn headless_session_does_not_open_browser() {
    let binder = FakeBinder::none();
    let opener = FakeOpener::new();
    let source = FakeInputSource::with(FakeInput::new(vec![paste_line("code=CODE&state=STATE")]));
    let clock = FakeClock::new();

    let token = authorize_inner(
        "http://issuer/authorize",
        "STATE",
        11313,
        /* ssh */ true, // -> Headless
        /* gui_likely */ true,
        &binder,
        &opener,
        &source,
        &clock,
        LONG_BACKSTOP,
        POLL,
        ok_exchange,
    )
    .unwrap();

    assert_eq!(token.access_token, "tok-CODE");
    assert_eq!(opener.opens.get(), 0, "Headless must not open the browser");
}

#[test]
fn bound_listener_capture_completes_through_authorize_inner() {
    let binder = FakeBinder::with(FakeListener::new(vec![Ok(Some(code_capture()))]));
    let opener = FakeOpener::new();
    let source = FakeInputSource::with(FakeInput::new(vec![])); // tty present, always Pending
    let clock = FakeClock::new();

    let token = authorize_inner(
        "http://issuer/authorize",
        "STATE",
        11313,
        /* ssh */ true, // Headless: no browser, listener (e.g. ssh -L tunnel) still captures
        /* gui_likely */ false,
        &binder,
        &opener,
        &source,
        &clock,
        LONG_BACKSTOP,
        POLL,
        ok_exchange,
    )
    .unwrap();

    assert_eq!(token.access_token, "tok-CODE");
    assert_eq!(binder.binds.get(), 1, "interactive session binds the listener");
}

#[test]
fn wrong_pasted_state_is_fatal_csrf_mismatch() {
    let binder = FakeBinder::none();
    let opener = FakeOpener::new();
    let source = FakeInputSource::with(FakeInput::new(vec![paste_line("code=CODE&state=WRONG")]));
    let clock = FakeClock::new();

    let result = authorize_inner(
        "http://issuer/authorize",
        "STATE", // session csrf secret
        11313,
        false,
        true,
        &binder,
        &opener,
        &source,
        &clock,
        LONG_BACKSTOP,
        POLL,
        panic_exchange, // exchange must NOT run on a CSRF mismatch
    );

    assert!(matches!(result, Err(OktaAuthError::CsrfMismatch)));
}

// ---------------------------------------------------------------------------
// Config-error precedence and a real-socket listener smoke test.
// ---------------------------------------------------------------------------

#[test]
fn bad_issuer_surfaces_invalid_url_before_any_interactivity_check() {
    // authorize() builds/validates URLs first, so a garbage issuer is InvalidUrl
    // regardless of session - and no network/bind/open happens.
    let result = authorize("not a valid url", "client", "http://127.0.0.1:11313/callback", &[]);
    assert!(matches!(result, Err(OktaAuthError::InvalidUrl(_))));
}

#[test]
fn real_socket_listener_captures_code() {
    use std::io::{Read, Write};
    use std::net::{TcpListener as Probe, TcpStream};

    // Find a free ephemeral port, then bind the real HttpListener on it.
    let probe = Probe::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let server = HttpListener::bind(port).expect("bind ephemeral port");

    let client = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let req = "GET /callback?code=abc&state=xyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(req.as_bytes()).unwrap();
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink);
    });

    let mut captured = None;
    for _ in 0..300 {
        if let Ok(Some(cap)) = server.poll() {
            captured = Some(cap);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    client.join().unwrap();

    match captured {
        Some(Capture::Code(code, state)) => {
            assert_eq!(code, "abc");
            assert_eq!(state, "xyz");
        }
        other => panic!("expected Capture::Code, got {other:?}"),
    }
}
