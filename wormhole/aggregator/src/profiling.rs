//! Host boundaries outside the GPU crate. No subscriber is installed here.
use std::time::Instant;

pub(crate) struct HostOperation {
    span: tracing::span::EnteredSpan,
    started: Option<Instant>,
}

impl HostOperation {
    pub(crate) fn new(operation: &'static str) -> Self {
        let span = tracing::debug_span!(target: "qp_wormhole_aggregator::profile",
            "public_batch.host", operation, elapsed_ns = tracing::field::Empty);
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
