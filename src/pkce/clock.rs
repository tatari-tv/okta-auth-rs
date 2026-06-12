//! The clock port: lets the readiness loop's backstop deadline and inter-scan sleep
//! be driven deterministically in tests without real wall-clock time.

use std::time::{Duration, Instant};

/// A monotonic time source plus a sleep, injected so the loop's backstop is testable.
pub trait Clock {
    /// Time elapsed since the loop started.
    fn elapsed(&self) -> Duration;
    /// Yield for `dur` between idle scans (both sources are non-blocking).
    fn sleep(&self, dur: Duration);
}

/// The production clock: real monotonic time and a real thread sleep.
pub struct RealClock {
    start: Instant,
}

impl RealClock {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }
}

impl Clock for RealClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn sleep(&self, dur: Duration) {
        std::thread::sleep(dur);
    }
}
