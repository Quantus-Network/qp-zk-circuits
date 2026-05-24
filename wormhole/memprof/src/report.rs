//! Phase-by-phase timing + memory tracking and pretty table output.

use std::time::{Duration, Instant};

use crate::memory::{fmt_mb, process_memory, release_memory, PeakSampler};

#[derive(Debug, Clone)]
pub struct PhaseRow {
    pub label: String,
    pub wall: Duration,
    pub start_phys: u64,
    pub end_phys: u64,
    pub peak_phys: u64,
}

pub struct PhaseReport {
    rows: Vec<PhaseRow>,
    sampler: PeakSampler,
    current: Option<(String, Instant, u64)>,
    started_at: Instant,
}

impl PhaseReport {
    pub fn new(sample_period_ms: u64) -> Self {
        let sampler = PeakSampler::start(sample_period_ms);
        let (start, _) = process_memory();
        let rows = vec![PhaseRow {
            label: "startup".to_string(),
            wall: Duration::ZERO,
            start_phys: 0,
            end_phys: start,
            peak_phys: start,
        }];
        Self {
            rows,
            sampler,
            current: None,
            started_at: Instant::now(),
        }
    }

    pub fn phase_start(&mut self, label: &str) {
        if self.current.is_some() {
            self.phase_end();
        }
        let (phys, _) = process_memory();
        self.sampler.snapshot_and_reset();
        eprintln!(">>> phase {} (start phys={}MB)", label, fmt_mb(phys));
        self.current = Some((label.to_string(), Instant::now(), phys));
    }

    pub fn phase_end(&mut self) {
        if let Some((label, t0, start_phys)) = self.current.take() {
            let wall = t0.elapsed();
            let (end_phys, _) = process_memory();
            let peak = self
                .sampler
                .snapshot_and_reset()
                .max(end_phys)
                .max(start_phys);
            eprintln!(
                "<<< phase {} done in {}ms (end phys={}MB peak={}MB)",
                label,
                wall.as_millis(),
                fmt_mb(end_phys),
                fmt_mb(peak)
            );
            self.rows.push(PhaseRow {
                label,
                wall,
                start_phys,
                end_phys,
                peak_phys: peak,
            });
        }
    }

    pub fn release_memory(&mut self, tag: &str) {
        let (released, before, after) = release_memory();
        eprintln!(
            "[release_memory] {} released_reported={}MB phys {}MB -> {}MB (delta {}MB)",
            tag,
            fmt_mb(released),
            fmt_mb(before),
            fmt_mb(after),
            (before as i64 - after as i64) / (1024 * 1024)
        );
    }

    pub fn finish_and_print(mut self, peak_target_mb: Option<u64>) -> u64 {
        if self.current.is_some() {
            self.phase_end();
        }
        let total_wall = self.started_at.elapsed();
        let overall_peak = self.rows.iter().map(|r| r.peak_phys).max().unwrap_or(0);

        println!();
        println!("============================== MEMPROF REPORT ==============================");
        println!(
            "{:<28} | {:>10} | {:>14} | {:>14} | {:>14}",
            "phase", "wall (ms)", "start (MB)", "end (MB)", "peak (MB)"
        );
        println!("{}", "-".repeat(94));
        for r in &self.rows {
            println!(
                "{:<28} | {:>10} | {:>14} | {:>14} | {:>14}",
                r.label,
                r.wall.as_millis(),
                fmt_mb(r.start_phys),
                fmt_mb(r.end_phys),
                fmt_mb(r.peak_phys)
            );
        }
        println!("{}", "-".repeat(94));
        println!("total time:       {:>10} ms", total_wall.as_millis());
        println!("overall peak rss: {:>10} MB", fmt_mb(overall_peak));
        println!("===========================================================================");

        if let Some(target_mb) = peak_target_mb {
            let target_bytes = target_mb * 1024 * 1024;
            if overall_peak > target_bytes {
                eprintln!(
                    "ERROR: peak {} MB exceeded target {} MB",
                    fmt_mb(overall_peak),
                    target_mb
                );
                std::process::exit(1);
            }
        }
        overall_peak
    }
}
