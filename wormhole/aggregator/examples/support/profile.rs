//! Benchmark-side telemetry consumer. Never installed by either library.
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing::{field::Visit, span::Attributes, span::Id, span::Record, Event, Subscriber};
use tracing_subscriber::{layer::Context, prelude::*, registry::LookupSpan, Layer};

#[derive(Clone, Default)]
pub struct Profile {
    records: Arc<Mutex<Vec<Value>>>,
}

#[derive(Default)]
struct Fields(Map<String, Value>);

impl Visit for Fields {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), format!("{value:?}").into());
    }
}

fn path<'a, S: Subscriber + for<'lookup> LookupSpan<'lookup>>(
    spans: impl Iterator<Item = tracing_subscriber::registry::SpanRef<'a, S>>,
) -> String {
    spans
        .filter_map(|span| {
            let extensions = span.extensions();
            let fields = &extensions.get::<Fields>()?.0;
            let name = fields
                .get("phase")
                .or_else(|| fields.get("operation"))?
                .as_str()?;
            Some(match fields.get("round") {
                Some(round) => format!("{name}[{round}]"),
                None => name.to_owned(),
            })
        })
        .collect::<Vec<_>>()
        .join("/")
}

impl<S> Layer<S> for Profile
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
        let mut fields = Fields::default();
        attributes.record(&mut fields);
        context.span(id).unwrap().extensions_mut().insert(fields);
    }
    fn on_record(&self, id: &Id, record: &Record<'_>, context: Context<'_, S>) {
        let span = context.span(id).unwrap();
        let mut extensions = span.extensions_mut();
        record.record(extensions.get_mut::<Fields>().unwrap());
    }
    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        if !event.metadata().target().ends_with("::profile") {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let path = context
            .event_scope(event)
            .map(|scope| path(scope.from_root()))
            .unwrap_or_default();
        fields.0.insert("path".into(), path.into());
        self.records.lock().unwrap().push(Value::Object(fields.0));
    }
    fn on_close(&self, id: Id, context: Context<'_, S>) {
        let span = context.span(&id).unwrap();
        if !span.metadata().target().ends_with("::profile") {
            return;
        }
        let mut fields = span.extensions().get::<Fields>().unwrap().0.clone();
        if !fields.contains_key("elapsed_ns") {
            return;
        }
        fields.insert("path".into(), path(span.scope().from_root()).into());
        self.records.lock().unwrap().push(Value::Object(fields));
    }
}

impl Profile {
    pub fn dispatcher(&self) -> tracing::Dispatch {
        tracing::Dispatch::new(tracing_subscriber::registry().with(self.clone()))
    }

    /// Drain between preparation/proofs. Host wall times and GPU compute times
    /// are overlapping views, not additive contributions to total latency.
    pub fn print(&self, sample: &str) {
        let records = std::mem::take(&mut *self.records.lock().unwrap());
        let mut host = BTreeMap::<String, (u64, u64)>::new();
        let mut gpu = BTreeMap::<String, (f64, u64, u64)>::new();
        let mut counters = BTreeMap::<String, u64>::new();
        for record in &records {
            let path = record["path"].as_str().unwrap_or("");
            if let Some(ns) = record["elapsed_ns"].as_u64() {
                let key = if let Some(operation) = record["operation"].as_str() {
                    if path.ends_with(operation) {
                        path.to_owned()
                    } else {
                        format!("{path}/{operation}")
                    }
                } else {
                    path.to_owned()
                };
                let entry = host.entry(key).or_default();
                entry.0 += ns;
                entry.1 += 1;
            }
            if let Some(kernel) = record["kernel"].as_str() {
                let entry = gpu.entry(format!("{path}/{kernel}")).or_default();
                if let Some(ns) = record["gpu_ns"].as_f64() {
                    entry.0 += ns;
                    entry.1 += 1;
                } else {
                    entry.2 += 1;
                }
            }
            for name in [
                "upload_bytes",
                "device_copy_bytes",
                "readback_bytes",
                "dispatches",
                "metal_command_buffers",
                "pow_chunks",
                "pow_trials_dispatched",
                "fixed_buffer_bytes",
                "fixed_upload_bytes",
                "workspace_buffer_bytes",
                "profiling_buffer_bytes",
                "profiling_readback_bytes",
            ] {
                if let Some(value) = record[name].as_u64() {
                    *counters.entry(format!("{path}/{name}")).or_default() += value;
                }
            }
        }
        println!(
            "[profile {sample}] host wall time (nested/overlapping), GPU compute passes only:"
        );
        for (path, (ns, count)) in &host {
            println!("  host {:8.3} ms x{count} {path}", *ns as f64 / 1e6);
        }
        let gpu_ns = gpu.values().fold(0.0, |sum, entry| sum + entry.0);
        let invalid: u64 = gpu.values().map(|entry| entry.2).sum();
        let complete = invalid == 0 && !gpu.is_empty();
        println!(
            "  Valid GPU compute samples: {:.3} ms; unavailable timestamps: {invalid}; complete: {}",
            gpu_ns / 1e6, complete
        );
        println!(
            "[profile] {}",
            serde_json::json!({
                "sample":sample, "host_ns_and_counts":host, "gpu_ns_counts_and_unavailable":gpu,
            "counters":counters, "valid_gpu_compute_ns":gpu_ns, "unavailable_timestamps":invalid,
            "gpu_timings_complete":complete,
            })
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subscriber_captures_parentage_updates_and_events_without_global_installation() {
        let profile = Profile::default();
        tracing::dispatcher::with_default(&profile.dispatcher(), || {
            let span = tracing::debug_span!(target: "example::profile", "phase", phase = "wires",
                elapsed_ns = tracing::field::Empty);
            span.in_scope(|| tracing::debug!(target: "example::profile", upload_bytes = 16u64));
            span.record("elapsed_ns", 25u64);
        });
        let records = profile.records.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["path"], "wires");
        assert_eq!(records[0]["upload_bytes"], 16);
        assert_eq!(records[1]["elapsed_ns"], 25);
    }
}
