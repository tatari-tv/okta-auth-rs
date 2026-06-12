//! The paste-input port: a non-blocking reader over the *controlling terminal*
//! (`/dev/tty` on Unix), never the process `stdin`.
//!
//! Reading `/dev/tty` (rather than `stdin`) is the load-bearing fix: it can never
//! steal a later prompt's input from the consuming CLI, and it still works when the
//! CLI is invoked with piped `stdin` but a terminal is attached. The fd is set
//! `O_NONBLOCK` via `fcntl` so the readiness loop can poll it without blocking; no
//! background thread exists, so there is nothing un-cancellable to leak.

use std::io;

/// The result of a single non-blocking scan of the input source.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// A complete line (newline stripped) is available.
    Line(String),
    /// The source reached end-of-file (Ctrl-D). The loop stops reading it.
    Eof,
    /// Nothing available yet, or a partial line is still buffering.
    Pending,
    /// A single line exceeded `MAX_PASTE` without a newline; it was discarded.
    Overflow,
}

/// A non-blocking, line-oriented input source.
pub trait Input {
    /// Read whatever bytes are currently available, buffering partial lines, and
    /// return the next outcome. Never blocks.
    fn read_available(&mut self) -> io::Result<ReadOutcome>;
}

/// Acquires the controlling-terminal input source. `acquire` returning `None` is the
/// interactivity signal: no controlling terminal -> `NonInteractive`.
pub trait InputSource {
    type Reader: Input;
    fn acquire(&self) -> Option<Self::Reader>;
}

/// A byte carry-buffer shared by the real readers: a non-blocking chunk can split a
/// multi-byte UTF-8 sequence, so we accumulate bytes and decode each *complete* line
/// with `from_utf8_lossy` (callback URLs are ASCII/percent-encoded anyway).
struct CarryBuffer {
    buf: Vec<u8>,
    max: usize,
    eof_seen: bool,
}

impl CarryBuffer {
    fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max,
            eof_seen: false,
        }
    }

    /// Pull the first complete line (up to and including `\n`) out of the buffer, if
    /// one is present, returning it with the line terminator stripped.
    fn take_line(&mut self) -> Option<String> {
        let pos = self.buf.iter().position(|&b| b == b'\n')?;
        let line_bytes: Vec<u8> = self.buf.drain(..=pos).collect();
        let mut end = line_bytes.len() - 1; // drop '\n'
        if end > 0 && line_bytes[end - 1] == b'\r' {
            end -= 1; // also drop a CR from CRLF
        }
        Some(String::from_utf8_lossy(&line_bytes[..end]).into_owned())
    }

    /// Feed `n` freshly-read bytes (or 0 for EOF) and compute the next outcome.
    fn push(&mut self, chunk: &[u8]) -> ReadOutcome {
        if let Some(line) = self.take_line() {
            return ReadOutcome::Line(line);
        }
        if chunk.is_empty() {
            // EOF: flush any non-empty partial line as a final line, then report Eof.
            self.eof_seen = true;
            if self.buf.is_empty() {
                return ReadOutcome::Eof;
            }
            let line = String::from_utf8_lossy(&self.buf).into_owned();
            self.buf.clear();
            return ReadOutcome::Line(line);
        }
        self.buf.extend_from_slice(chunk);
        if let Some(line) = self.take_line() {
            ReadOutcome::Line(line)
        } else if self.buf.len() > self.max {
            // A single overlong line with no terminator: discard rather than grow
            // unbounded (no OOM from a runaway pipe).
            self.buf.clear();
            ReadOutcome::Overflow
        } else {
            ReadOutcome::Pending
        }
    }
}

#[cfg(unix)]
pub use unix::TtySource;

#[cfg(unix)]
mod unix {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read};

    use log::debug;
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    use super::{CarryBuffer, Input, InputSource, ReadOutcome};

    const CHUNK: usize = 4096;

    /// Acquires `/dev/tty` for reading and sets it `O_NONBLOCK`. Opening it both
    /// tests reachability (the interactivity signal) and acquires the input source in
    /// one step - `stdin().is_terminal()` is deliberately *not* used (it misfires on
    /// piped stdin).
    pub struct TtySource {
        max_paste: usize,
    }

    impl TtySource {
        pub fn new(max_paste: usize) -> Self {
            Self { max_paste }
        }
    }

    impl InputSource for TtySource {
        type Reader = TtyInput;

        fn acquire(&self) -> Option<Self::Reader> {
            let file = OpenOptions::new().read(true).open("/dev/tty").ok()?;
            // Set O_NONBLOCK via fcntl so read() returns WouldBlock instead of parking.
            match fcntl_getfl(&file).and_then(|flags| fcntl_setfl(&file, flags | OFlags::NONBLOCK)) {
                Ok(()) => {
                    debug!("TtySource::acquire: opened /dev/tty, set O_NONBLOCK");
                    Some(TtyInput {
                        file,
                        carry: CarryBuffer::new(self.max_paste),
                    })
                }
                Err(e) => {
                    log::warn!("TtySource::acquire: opened /dev/tty but fcntl(O_NONBLOCK) failed: {e}");
                    None
                }
            }
        }
    }

    /// A non-blocking reader over `/dev/tty`.
    pub struct TtyInput {
        file: File,
        carry: CarryBuffer,
    }

    impl Input for TtyInput {
        fn read_available(&mut self) -> io::Result<ReadOutcome> {
            // Emit an already-buffered complete line without touching the fd.
            if let Some(line) = self.carry.take_line() {
                return Ok(ReadOutcome::Line(line));
            }
            if self.carry.eof_seen {
                return Ok(ReadOutcome::Eof);
            }
            let mut chunk = [0u8; CHUNK];
            match self.file.read(&mut chunk) {
                Ok(n) => Ok(self.carry.push(&chunk[..n])),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(ReadOutcome::Pending),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(ReadOutcome::Pending),
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(windows)]
pub use windows::TtySource;

#[cfg(windows)]
mod windows {
    //! Windows ships **listener-only**: a local console session still opens the
    //! browser and auto-captures the callback, but the paste path is a documented
    //! gap (SSH-to-headless-Windows is not a current use case). The reader always
    //! reports `Pending` so the loop relies on the listener / backstop.

    use std::io::{self, IsTerminal};

    use super::{Input, InputSource, ReadOutcome};

    pub struct TtySource {
        #[allow(dead_code)] // kept for signature parity with the Unix source
        max_paste: usize,
    }

    impl TtySource {
        pub fn new(max_paste: usize) -> Self {
            Self { max_paste }
        }
    }

    impl InputSource for TtySource {
        type Reader = ConsoleInput;

        fn acquire(&self) -> Option<Self::Reader> {
            // Best-effort interactivity check; a real CONIN$ non-blocking reader is
            // left as a documented follow-up.
            if io::stdin().is_terminal() { Some(ConsoleInput) } else { None }
        }
    }

    pub struct ConsoleInput;

    impl Input for ConsoleInput {
        fn read_available(&mut self) -> io::Result<ReadOutcome> {
            Ok(ReadOutcome::Pending)
        }
    }
}

#[cfg(test)]
mod tests;
