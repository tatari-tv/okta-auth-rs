//! Session classification: decide whether interactive auth is possible, and if so
//! whether to use the local browser-redirect flow or the device authorization grant.

use log::debug;

/// How the current process can complete an OAuth2 login.
///
/// `Local` vs `Headless` selects the *flow*: a local GUI session uses the
/// browser-redirect flow (auto-capture on the loopback listener); anything headless
/// (SSH, no GUI) uses the device authorization grant (show a code, poll for approval),
/// which needs nothing delivered back to this host. `NonInteractive` fails fast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    /// A controlling terminal and a local GUI are both available: open the browser
    /// and auto-capture the callback on `127.0.0.1:<port>`. Zero-touch.
    Local,
    /// A controlling terminal is available but no local GUI (SSH, or no DISPLAY): use
    /// the device authorization grant - print a code and poll, no listener or redirect.
    Headless,
    /// No controlling terminal: interactive auth is impossible, fail fast.
    NonInteractive,
}

/// Whether the controlling terminal (`/dev/tty` on Unix) is reachable. This is the
/// interactivity signal fed to [`classify`] as `has_tty` - *not* `stdin().is_terminal()`,
/// which misfires when stdin is a pipe but a terminal is attached.
#[cfg(unix)]
pub fn controlling_terminal_available() -> bool {
    let available = std::fs::OpenOptions::new().read(true).open("/dev/tty").is_ok();
    debug!("controlling_terminal_available: /dev/tty readable={available}");
    available
}

/// Windows fallback: best-effort terminal check via stdin.
#[cfg(windows)]
pub fn controlling_terminal_available() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Pure classifier so the decision is unit-testable without touching the world.
///
/// - `has_tty`: can we open the controlling terminal (`/dev/tty`)? This is the
///   interactivity signal, *not* `stdin().is_terminal()` (which misfires on a pipe).
/// - `ssh`: is this an SSH session (`SSH_CONNECTION`/`SSH_TTY`/`SSH_CLIENT` set)?
/// - `gui_likely`: is a local GUI plausibly present (platform-aware, see caller)?
///
/// `ssh` takes precedence over `gui_likely`: an X11-forwarded SSH session has
/// `DISPLAY` set but is still `Headless`.
pub fn classify(has_tty: bool, ssh: bool, gui_likely: bool) -> Session {
    let session = if !has_tty {
        Session::NonInteractive
    } else if ssh || !gui_likely {
        Session::Headless
    } else {
        Session::Local
    };
    debug!("classify: has_tty={has_tty} ssh={ssh} gui_likely={gui_likely} -> session={session:?}");
    session
}

/// Whether any SSH environment marker is set. sshd sets these for both interactive
/// and forced-command sessions.
pub fn ssh_from_env() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some()
        || std::env::var_os("SSH_TTY").is_some()
        || std::env::var_os("SSH_CLIENT").is_some()
}

/// Whether a local GUI is likely present, computed platform-aware: `DISPLAY` /
/// `WAYLAND_DISPLAY` is the Linux signal and is *not* set by macOS GUI sessions, so
/// using it unconditionally would misclassify a local Mac as `Headless` and suppress
/// the browser. On macOS/Windows a non-SSH terminal session has a GUI available.
pub fn gui_likely_from_env() -> bool {
    if cfg!(target_os = "linux") {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    } else {
        true
    }
}

#[cfg(test)]
mod tests;
