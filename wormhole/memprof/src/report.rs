//! Phase-by-phase timing + memory tracking and pretty table output.

use std::time::{Duration, Instant};

use anyhow::Result;

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
    /// Global peak that is never reset - tracks true maximum across entire run
    /// including inter-phase gaps.
    global_peak: u64,
}

impl PhaseReport {
    pub fn new(sample_period_ms: u64) -> Result<Self> {
        let sampler = PeakSampler::start(sample_period_ms);
        let (start, _) = process_memory()?;
        let rows = vec![PhaseRow {
            label: "startup".to_string(),
            wall: Duration::ZERO,
            start_phys: start,
            end_phys: start,
            peak_phys: start,
        }];
        Ok(Self {
            rows,
            sampler,
            current: None,
            started_at: Instant::now(),
            global_peak: start,
        })
    }

    /// Update global peak from sampler without resetting.
    fn update_global_peak(&mut self) {
        let sampled = self.sampler.peek();
        self.global_peak = self.global_peak.max(sampled);
    }

    pub fn phase_start(&mut self, label: &str) -> Result<()> {
        if self.current.is_some() {
            self.phase_end()?;
        }
        // Capture any inter-phase peak before resetting
        self.update_global_peak();
        let (phys, _) = process_memory()?;
        self.global_peak = self.global_peak.max(phys);
        self.sampler.reset();
        eprintln!(">>> phase {} (start phys={}MB)", label, fmt_mb(phys));
        self.current = Some((label.to_string(), Instant::now(), phys));
        Ok(())
    }

    pub fn phase_end(&mut self) -> Result<()> {
        if let Some((label, t0, start_phys)) = self.current.take() {
            let wall = t0.elapsed();
            let (end_phys, _) = process_memory()?;
            let sampled_peak = self.sampler.peek();
            let phase_peak = sampled_peak.max(end_phys).max(start_phys);
            self.global_peak = self.global_peak.max(phase_peak);
            eprintln!(
                "<<< phase {} done in {}ms (end phys={}MB peak={}MB)",
                label,
                wall.as_millis(),
                fmt_mb(end_phys),
                fmt_mb(phase_peak)
            );
            self.rows.push(PhaseRow {
                label,
                wall,
                start_phys,
                end_phys,
                peak_phys: phase_peak,
            });
        }
        Ok(())
    }

    pub fn release_memory(&mut self, tag: &str) -> Result<()> {
        let (released, before, after) = release_memory()?;
        eprintln!(
            "[release_memory] {} released_reported={}MB phys {}MB -> {}MB (delta {}MB)",
            tag,
            fmt_mb(released),
            fmt_mb(before),
            fmt_mb(after),
            (before as i64 - after as i64) / (1024 * 1024)
        );
        Ok(())
    }

    pub fn finish_and_print(mut self, peak_target_mb: Option<u64>) -> Result<u64> {
        if self.current.is_some() {
            self.phase_end()?;
        }
        // Final update to catch any trailing memory usage
        self.update_global_peak();
        let total_wall = self.started_at.elapsed();

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
        println!("overall peak rss: {:>10} MB", fmt_mb(self.global_peak));
        println!("===========================================================================");

        if let Some(target_mb) = peak_target_mb {
            let target_bytes = target_mb * 1024 * 1024;
            if self.global_peak > target_bytes {
                eprintln!(
                    "ERROR: peak {} MB exceeded target {} MB",
                    fmt_mb(self.global_peak),
                    target_mb
                );
                std::process::exit(1);
            }
        }
        Ok(self.global_peak)
    }
}
