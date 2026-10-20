//! Reusable, workspace-owned timestamp resources. One begin/end pair per
//! compute pass. Copies and queue gaps are not covered by these measurements.
use super::*;

const PASSES_PER_SET: usize = wgpu::QUERY_SET_MAX_QUERIES as usize / 2;

pub(super) fn query_counts(capacity: usize) -> Result<Vec<u32>> {
    ensure!(capacity > 0, "timestamp dispatch capacity must be nonzero");
    ensure!(
        capacity <= u32::MAX as usize / 2,
        "timestamp dispatch capacity overflow"
    );
    Ok((0..capacity.div_ceil(PASSES_PER_SET))
        .map(|index| ((capacity - index * PASSES_PER_SET).min(PASSES_PER_SET) * 2) as u32)
        .collect())
}

pub(super) struct TimestampBuffers {
    sets: Vec<wgpu::QuerySet>,
    resolve: wgpu::Buffer,
    staging: wgpu::Buffer,
    capacity: usize,
    pending: Option<PendingTimestamps>,
}

struct PendingTimestamps {
    labels: Vec<&'static str>,
    mapped: std::sync::mpsc::Receiver<Result<(), wgpu::BufferAsyncError>>,
    span: tracing::Span,
    dispatcher: tracing::Dispatch,
}

impl TimestampBuffers {
    pub(super) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(super) fn prepare(context: &DeviceContext) -> Result<Option<Self>> {
        if !context.options.timestamps {
            return Ok(None);
        }
        let capacity = context.options.timestamp_dispatch_capacity;
        let counts = query_counts(capacity)?;
        let bytes = (capacity as u64)
            .checked_mul(16)
            .context("timestamp buffer size overflow")?;
        ensure!(
            bytes <= context.limits().max_buffer_size,
            "timestamp buffer exceeds device limits"
        );
        let sets = counts
            .into_iter()
            .map(|count| {
                context.device.create_query_set(&wgpu::QuerySetDescriptor {
                    label: Some("prover pass timestamps"),
                    ty: wgpu::QueryType::Timestamp,
                    count,
                })
            })
            .collect();
        let resolve = context.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("prover timestamp resolve"),
            size: bytes,
            usage: wgpu::BufferUsages::QUERY_RESOLVE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let staging = context.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("prover timestamp export"),
            size: bytes,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        context.check_device()?;
        tracing::debug!(target: "qp_wormhole_gpu::profile", profiling_buffer_bytes = bytes * 2,
            timestamp_dispatch_capacity = capacity, "timestamp workspace prepared");
        Ok(Some(Self {
            sets,
            resolve,
            staging,
            capacity,
            pending: None,
        }))
    }

    pub(super) fn writes(&self, index: usize) -> Result<wgpu::ComputePassTimestampWrites<'_>> {
        ensure!(index < self.capacity,
            "timestamp dispatch capacity exceeded; increase DeviceOptions::timestamp_dispatch_capacity during initialization");
        let offset = (index % PASSES_PER_SET) as u32 * 2;
        Ok(wgpu::ComputePassTimestampWrites {
            query_set: &self.sets[index / PASSES_PER_SET],
            beginning_of_pass_write_index: Some(offset),
            end_of_pass_write_index: Some(offset + 1),
        })
    }

    pub(super) fn resolve(&self, commands: &mut wgpu::CommandEncoder, passes: usize) {
        for (index, set) in self
            .sets
            .iter()
            .enumerate()
            .take(passes.div_ceil(PASSES_PER_SET))
        {
            let count = ((passes - index * PASSES_PER_SET).min(PASSES_PER_SET) * 2) as u32;
            commands.resolve_query_set(
                set,
                0..count,
                &self.resolve,
                (index * PASSES_PER_SET * 16) as u64,
            );
        }
        commands.copy_buffer_to_buffer(&self.resolve, 0, &self.staging, 0, (passes * 16) as u64);
    }

    pub(super) fn map(&mut self, labels: Vec<&'static str>, span: tracing::Span) {
        let (tx, mapped) = std::sync::mpsc::channel();
        self.staging.slice(0..(labels.len() * 16) as u64).map_async(
            wgpu::MapMode::Read,
            move |result| {
                let _ = tx.send(result);
            },
        );
        self.pending = Some(PendingTimestamps {
            labels,
            mapped,
            span,
            dispatcher: tracing::dispatcher::get_default(Clone::clone),
        });
    }

    pub(super) fn collect(&mut self, context: &DeviceContext) -> Result<()> {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(());
        };
        pending
            .mapped
            .try_recv()
            .context("timestamp export is pending; wait for the workspace")??;
        let pending = self.pending.take().unwrap();
        let _operation = crate::profiling::HostOperation::new("timestamp_collection");
        let mapped = self
            .staging
            .slice(0..(pending.labels.len() * 16) as u64)
            .get_mapped_range();
        let period = f64::from(context.queue.get_timestamp_period());
        tracing::dispatcher::with_default(&pending.dispatcher, || {
            pending.span.in_scope(|| {
                for (label, pair) in pending.labels.iter().zip(mapped.chunks_exact(16)) {
                    let begin = u64::from_le_bytes(pair[..8].try_into().unwrap());
                    let end = u64::from_le_bytes(pair[8..].try_into().unwrap());
                    if let Some(ns) = duration_ns(begin, end, period) {
                        tracing::debug!(target: "qp_wormhole_gpu::profile", parent: &pending.span, kernel = *label,
                        gpu_ns = ns, timestamp_valid = true, "GPU compute pass");
                    } else {
                        let reason = if end < begin {
                            "nonmonotonic timestamp pair"
                        } else if end == 0 {
                            "unwritten or zero timestamp pair"
                        } else {
                            "invalid timestamp period"
                        };
                        tracing::debug!(target: "qp_wormhole_gpu::profile", parent: &pending.span, kernel = *label,
                        timestamp_valid = false, timestamp_error = reason,
                        "GPU timestamp unavailable");
                    }
                }
            })
        });
        drop(mapped);
        self.staging.unmap();
        Ok(())
    }
}

fn duration_ns(begin: u64, end: u64, period: f64) -> Option<f64> {
    let ticks = end.checked_sub(begin)?;
    let ns = ticks as f64 * period;
    (end != 0 && period > 0.0 && ns.is_finite()).then_some(ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArithmeticKernels, ArithmeticPlan, FieldOperation};
    use tracing_subscriber::{layer::Context as TraceContext, prelude::*, Layer};

    type TimestampSamples = Vec<(Option<f64>, bool)>;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<TimestampSamples>>);

    #[derive(Default)]
    struct Sample {
        duration: Option<f64>,
        valid: Option<bool>,
    }
    impl tracing::field::Visit for Sample {
        fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
            if field.name() == "gpu_ns" {
                self.duration = Some(value);
            }
        }
        fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
            if field.name() == "timestamp_valid" {
                self.valid = Some(value);
            }
        }
        fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    }
    impl<S: tracing::Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &tracing::Event<'_>, _: TraceContext<'_, S>) {
            let mut sample = Sample::default();
            event.record(&mut sample);
            if let Some(valid) = sample.valid {
                self.0.lock().unwrap().push((sample.duration, valid));
            }
        }
    }
    #[test]
    fn queries_split_without_changing_submissions() -> Result<()> {
        assert_eq!(query_counts(1)?, [2]);
        assert_eq!(query_counts(2048)?, [4096]);
        assert_eq!(query_counts(2049)?, [4096, 2]);
        assert_eq!(query_counts(8192)?, [4096; 4]);
        assert!(query_counts(0).is_err());
        assert!(query_counts(usize::MAX).is_err());
        Ok(())
    }
    #[test]
    fn timestamp_conversion_rejects_invalid_not_low_resolution_samples() {
        assert_eq!(duration_ns(10, 14, 2.5), Some(10.0));
        assert_eq!(duration_ns(10, 10, 1.0), Some(0.0));
        for (begin, end, period) in [(10, 9, 1.0), (0, 0, 1.0), (1, 2, 0.0), (1, 2, f64::NAN)] {
            assert_eq!(duration_ns(begin, end, period), None);
        }
    }

    #[test]
    #[ignore = "requires hardware timestamp queries and native u64 shaders"]
    fn timestamp_resources_survive_cancel_capacity_errors_dropped_tokens_and_reuse() -> Result<()> {
        let ordinary = futures::executor::block_on(DeviceContext::new())?;
        assert!(ProofWorkspace::prepare(&ordinary, &[1])?
            .timestamps
            .is_none());
        drop(ordinary);
        let context = futures::executor::block_on(DeviceContext::with_options(DeviceOptions {
            timestamps: true,
            timestamp_dispatch_capacity: 1,
        }))?;
        let rows = 1 << 20;
        let kernels = Arc::new(ArithmeticKernels::prepare(&context)?);
        let plan = ArithmeticPlan::prepare(&context, kernels, rows, FieldOperation::Sbox)?;
        let mut workspace = ProofWorkspace::prepare(&context, &[rows, rows])?;
        let input = workspace.buffer(0)?;
        let output = workspace.buffer(1)?;
        let values = vec![GoldilocksField::from_canonical_u64(7); rows];
        // A second pass exceeds the explicit timing budget before recording.
        // Dropping the encoder cancels both the upload and first pass.
        let mut encoder = workspace.begin(&context)?;
        encoder.upload(&input, &values)?;
        plan.encode(&mut encoder, &input, &output)?;
        assert!(plan
            .encode(&mut encoder, &input, &output)
            .unwrap_err()
            .to_string()
            .starts_with("timestamp dispatch capacity exceeded"));
        drop(encoder);
        let capture = Capture::default();
        let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(capture.clone()));
        tracing::dispatcher::with_default(&dispatch, || -> Result<()> {
            for _ in 0..2 {
                let mut encoder = workspace.begin(&context)?;
                encoder.upload(&input, &values)?;
                plan.encode(&mut encoder, &input, &output)?;
                // Reclaim/collect through wait even when the public token is lost.
                {
                    let _pending = encoder.submit()?;
                }
                workspace.wait(&context)?;
                assert!(context
                    .readback(&output)?
                    .iter()
                    .all(|&value| value == values[0].exp_u64(7)));
            }
            Ok(())
        })?;
        let samples = capture.0.lock().unwrap();
        assert_eq!(samples.len(), 2);
        // Some Metal pass-boundary samples are invalid. That must be visible,
        // never fabricated as zero, and must not affect the arithmetic result.
        assert!(samples.iter().all(|(ns, valid)| *valid == ns.is_some()));
        assert!(samples
            .iter()
            .filter_map(|(ns, _)| *ns)
            .all(|ns| ns >= 0.0 && ns.is_finite()));
        assert!(samples.iter().any(|(ns, _)| ns.is_some_and(|ns| ns > 0.0)));
        Ok(())
    }
}
