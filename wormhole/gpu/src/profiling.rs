//! Structured instrumentation. Consumers install a subscriber; this library
//! never configures logging or stores a history. No witness or challenge values
//! are emitted. Host durations are wall time, not GPU execution time.
use std::time::Instant;

/// A synchronous host operation, recorded only when a subscriber enables it.
pub(crate) struct HostOperation {
    span: tracing::span::EnteredSpan,
    started: Option<Instant>,
}

impl HostOperation {
    #[cfg(feature = "constraint-export")]
    pub(crate) fn phase(phase: &'static str, round: Option<usize>) -> Self {
        let span = tracing::debug_span!(target: "qp_wormhole_gpu::profile", "prover.phase",
            phase, round, elapsed_ns = tracing::field::Empty);
        let started = (!span.is_disabled()).then(Instant::now);
        Self {
            span: span.entered(),
            started,
        }
    }
    pub(crate) fn new(operation: &'static str) -> Self {
        let span = tracing::debug_span!(
            target: "qp_wormhole_gpu::profile", "prover.host", operation,
            elapsed_ns = tracing::field::Empty
        );
        let started = (!span.is_disabled()).then(Instant::now);
        Self {
            span: span.entered(),
            started,
        }
    }
}

impl Drop for HostOperation {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            self.span
                .record("elapsed_ns", started.elapsed().as_nanos() as u64);
        }
    }
}

#[cfg(feature = "constraint-export")]
pub(crate) fn measure<T>(operation: &'static str, f: impl FnOnce() -> T) -> T {
    let _operation = HostOperation::new(operation);
    f()
}
