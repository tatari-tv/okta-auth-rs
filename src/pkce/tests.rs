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

/// A device runner that records calls and returns a fixed token.
struct FakeDeviceRunner {
    token: String,
    calls: Cell<usize>,
    last_scope: RefCell<Option<String>>,
}

impl FakeDeviceRunner {
    fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
            calls: Cell::new(0),
            last_scope: RefCell::new(None),
        }
    }
}

impl DeviceRunner for FakeDeviceRunner {
    fn run(&self, issuer: &str, client_id: &str, scope: &str) -> Result<TokenCache, OktaAuthError> {
        let _ = (issuer, client_id);
        self.calls.set(self.calls.get() + 1);
        *self.last_scope.borrow_mut() = Some(scope.to_string());
        Ok(TokenCache {
            access_token: self.token.clone(),
            refresh_token: None,
            expires_at: 9_999_999_999,
        })
    }
}

/// A device runner that must never be invoked (asserts the path didn't fall into it).
struct PanicDeviceRunner;

impl DeviceRunner for PanicDeviceRunner {
    fn run(&self, _: &str, _: &str, _: &str) -> Result<TokenCache, OktaAuthError> {
        panic!("device grant must not run on this path")
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

fn run_local<L: Listener>(
    server: &L,
    clock: &FakeClock,
    backstop: Duration,
) -> Result<(String, String), OktaAuthError> {
    local_loop(server, clock, backstop, POLL)
}

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

// ---------------------------------------------------------------------------
// local_loop arm coverage.
// ---------------------------------------------------------------------------

#[test]
fn listener_callback_wins() {
    let server = FakeListener::new(vec![Ok(Some(code_capture()))]);
    let clock = FakeClock::new();
    let result = run_local(&server, &clock, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn listener_okta_error_surfaces_immediately() {
    let server = FakeListener::new(vec![Ok(Some(okta_error_capture()))]);
    let clock = FakeClock::new();
    let err = run_local(&server, &clock, LONG_BACKSTOP).unwrap_err();
    assert!(matches!(err, OktaAuthError::OktaError { .. }));
}

#[test]
fn stray_no_code_request_is_ignored() {
    let server = FakeListener::new(vec![Ok(Some(Capture::Ignore)), Ok(Some(code_capture()))]);
    let clock = FakeClock::new();
    let result = run_local(&server, &clock, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn transient_listener_error_does_not_kill_login() {
    let server = FakeListener::new(vec![
        Err(io::Error::other("transient accept failure")),
        Ok(Some(code_capture())),
    ]);
    let clock = FakeClock::new();
    let result = run_local(&server, &clock, LONG_BACKSTOP).unwrap();
    assert_eq!(result, ("CODE".into(), "STATE".into()));
}

#[test]
fn backstop_fires_when_nothing_arrives() {
    let server = FakeListener::new(vec![]); // always Ok(None)
    let clock = FakeClock::new();
    // 75ms per sleep, 200ms backstop -> fires after a few scans.
    let err = run_local(&server, &clock, Duration::from_millis(200)).unwrap_err();
    assert!(matches!(err, OktaAuthError::CallbackTimeout));
    assert!(
        clock.sleeps.get() >= 1,
        "loop must sleep between idle scans, not busy-wait"
    );
}

// ---------------------------------------------------------------------------
// authorize_inner: classification and dispatch.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn inner<B: Binder, O: Opener, D: DeviceRunner, C: Clock, X>(
    csrf_secret: &str,
    ssh: bool,
    gui_likely: bool,
    has_tty: bool,
    binder: &B,
    opener: &O,
    device: &D,
    clock: &C,
    exchange: X,
) -> Result<TokenCache, OktaAuthError>
where
    X: FnOnce(&str) -> Result<TokenCache, OktaAuthError>,
{
    inner_scoped(
        csrf_secret,
        "openid email",
        ssh,
        gui_likely,
        has_tty,
        binder,
        opener,
        device,
        clock,
        exchange,
    )
}

#[allow(clippy::too_many_arguments)]
fn inner_scoped<B: Binder, O: Opener, D: DeviceRunner, C: Clock, X>(
    csrf_secret: &str,
    scope: &str,
    ssh: bool,
    gui_likely: bool,
    has_tty: bool,
    binder: &B,
    opener: &O,
    device: &D,
    clock: &C,
    exchange: X,
) -> Result<TokenCache, OktaAuthError>
where
    X: FnOnce(&str) -> Result<TokenCache, OktaAuthError>,
{
    authorize_inner(
        "http://issuer/authorize",
        csrf_secret,
        "https://issuer.example/oauth2/default",
        "client",
        scope,
        11313,
        ssh,
        gui_likely,
        has_tty,
        binder,
        opener,
        device,
        clock,
        LONG_BACKSTOP,
        POLL,
        exchange,
    )
}

#[test]
fn non_interactive_fails_fast_without_binding_opening_or_device() {
    let binder = FakeBinder::none();
    let opener = FakeOpener::new();
    let device = PanicDeviceRunner;
    let clock = FakeClock::new();

    let result = inner(
        "STATE",
        /* ssh */ false,
        /* gui */ true,
        /* has_tty */ false,
        &binder,
        &opener,
        &device,
        &clock,
        panic_exchange,
    );

    assert!(matches!(result, Err(OktaAuthError::NonInteractive)));
    assert_eq!(binder.binds.get(), 0, "must not bind when non-interactive");
    assert_eq!(opener.opens.get(), 0, "must not open browser when non-interactive");
}

#[test]
fn headless_session_uses_device_grant() {
    let binder = FakeBinder::none();
    let opener = FakeOpener::new();
    let device = FakeDeviceRunner::new("DEVICE-TOKEN");
    let clock = FakeClock::new();

    let token = inner(
        "STATE",
        /* ssh */ true,
        /* gui */ true,
        /* has_tty */ true,
        &binder,
        &opener,
        &device,
        &clock,
        panic_exchange,
    )
    .unwrap();

    assert_eq!(token.access_token, "DEVICE-TOKEN");
    assert_eq!(device.calls.get(), 1, "headless must run the device grant");
    assert_eq!(binder.binds.get(), 0, "headless must not bind a listener");
    assert_eq!(opener.opens.get(), 0, "headless must not open a browser");
}

#[test]
fn authorize_device_runs_device_grant_and_joins_scopes() {
    let device = FakeDeviceRunner::new("FORCED-TOKEN");
    let scopes = vec!["openid".to_string(), "email".to_string(), "offline_access".to_string()];

    let token = authorize_device_inner("https://test.okta.com/oauth2/default", "client-123", &scopes, &device).unwrap();

    assert_eq!(token.access_token, "FORCED-TOKEN");
    assert_eq!(device.calls.get(), 1, "forced path must run the device grant");
    assert_eq!(
        device.last_scope.borrow().as_deref(),
        Some("openid email offline_access"),
        "scopes must be space-joined for the device grant"
    );
}

#[test]
fn local_session_opens_browser_and_completes_via_listener() {
    let binder = FakeBinder::with(FakeListener::new(vec![Ok(Some(code_capture()))]));
    let opener = FakeOpener::new();
    let device = PanicDeviceRunner;
    let clock = FakeClock::new();

    let token = inner(
        "STATE",
        /* ssh */ false,
        /* gui */ true,
        /* has_tty */ true,
        &binder,
        &opener,
        &device,
        &clock,
        ok_exchange,
    )
    .unwrap();

    assert_eq!(token.access_token, "tok-CODE");
    assert_eq!(binder.binds.get(), 1, "local binds the listener");
    assert_eq!(opener.opens.get(), 1, "local opens the browser");
}

#[test]
fn local_with_busy_port_falls_back_to_device_grant() {
    let binder = FakeBinder::none(); // bind returns None: port held
    let opener = FakeOpener::new();
    let device = FakeDeviceRunner::new("FALLBACK-TOKEN");
    let clock = FakeClock::new();

    let token = inner(
        "STATE",
        /* ssh */ false,
        /* gui */ true,
        /* has_tty */ true,
        &binder,
        &opener,
        &device,
        &clock,
        panic_exchange,
    )
    .unwrap();

    assert_eq!(token.access_token, "FALLBACK-TOKEN");
    assert_eq!(device.calls.get(), 1, "busy port falls back to the device grant");
    assert_eq!(opener.opens.get(), 0, "no browser opened when the port is busy");
}

#[test]
fn headless_with_no_scopes_passes_empty_scope_to_device_grant() {
    // authorize(..., &[]) joins to "" — exercise the headless path end to end and
    // confirm that "" reaches the device runner (which then omits the form field;
    // see device::tests::device_form_omits_scope_when_empty).
    let binder = FakeBinder::none();
    let opener = FakeOpener::new();
    let device = FakeDeviceRunner::new("DEVICE-TOKEN");
    let clock = FakeClock::new();

    inner_scoped(
        "STATE",
        "", // no scopes
        /* ssh */ true,
        /* gui */ true,
        /* has_tty */ true,
        &binder,
        &opener,
        &device,
        &clock,
        panic_exchange,
    )
    .unwrap();

    assert_eq!(device.calls.get(), 1, "headless must run the device grant");
    assert_eq!(
        device.last_scope.borrow().as_deref(),
        Some(""),
        "empty scope must flow through"
    );
}

#[test]
fn busy_port_fallback_with_no_scopes_passes_empty_scope_to_device_grant() {
    let binder = FakeBinder::none(); // bind returns None: port held -> device fallback
    let opener = FakeOpener::new();
    let device = FakeDeviceRunner::new("FALLBACK-TOKEN");
    let clock = FakeClock::new();

    inner_scoped(
        "STATE",
        "", // no scopes
        /* ssh */ false,
        /* gui */ true,
        /* has_tty */ true,
        &binder,
        &opener,
        &device,
        &clock,
        panic_exchange,
    )
    .unwrap();

    assert_eq!(device.calls.get(), 1, "busy port falls back to the device grant");
    assert_eq!(
        device.last_scope.borrow().as_deref(),
        Some(""),
        "empty scope must flow through"
    );
}

#[test]
fn wrong_callback_state_is_fatal_csrf_mismatch() {
    let binder = FakeBinder::with(FakeListener::new(vec![Ok(Some(Capture::Code(
        "CODE".into(),
        "WRONG".into(),
    )))]));
    let opener = FakeOpener::new();
    let device = PanicDeviceRunner;
    let clock = FakeClock::new();

    let result = inner(
        "STATE", // session csrf secret; listener returned WRONG
        false,
        true,
        true,
        &binder,
        &opener,
        &device,
        &clock,
        panic_exchange, // exchange must NOT run on a CSRF mismatch
    );

    assert!(matches!(result, Err(OktaAuthError::CsrfMismatch)));
}

// ---------------------------------------------------------------------------
// Config-error precedence and a real-socket listener smoke test.
// ---------------------------------------------------------------------------

#[test]
fn bad_issuer_surfaces_invalid_url_before_any_session_check() {
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
