//! Memory profiler for the wormhole proof + aggregation pipeline.
//!
//! This is the CPU-side reproduction of what the Quantus mobile app does when
//! a user hits "Redeem rewards". It runs:
//!
//!   1. build leaf circuit (once)
//!   2. generate N leaf proofs sequentially
//!   3. build the layer-0 aggregation circuit FRESH (no disk binary load)
//!   4. commit + prove the aggregation
//!
//! While doing so it samples `phys_footprint` (Apple) or RSS (Linux) on a
//! background thread and prints a phase-by-phase peak-memory report. We know
//! we've reproduced the iPhone OOM crash when the report shows >3 GB peak.
//!
//! Examples:
//!   cargo run -p wormhole-memprof --release -- --num-leaf-proofs 16
//!   cargo run -p wormhole-memprof --release -- --num-leaf-proofs 16 --rayon-threads 1
//!   cargo run -p wormhole-memprof --release -- --num-leaf-proofs 4 --release-after-each
//!   cargo run -p wormhole-memprof --release -- --skip-leaf-gen --num-leaf-proofs 16
//!   cargo run -p wormhole-memprof --release -- --circuit-only --num-leaf-proofs 16

mod memory;
mod report;
mod workload;

use anyhow::Result;
use clap::Parser;

use crate::report::PhaseReport;

#[derive(Parser, Debug)]
#[command(
    name = "wormhole-memprof",
    about = "Peak-memory profiler for wormhole proof + aggregation"
)]
struct Args {
    /// Number of leaf proofs the aggregation circuit is built for. The mobile
    /// app uses 16 (matches the chain verifier's hard-coded 16-leaf circuit).
    #[arg(long, default_value_t = 16)]
    num_leaf_proofs: usize,

    /// How many real leaf proofs to actually generate before aggregation.
    /// Must be <= num_leaf_proofs. The aggregator will pad the rest with
    /// dummy proofs (matches the mobile flow when there are fewer transfers
    /// than the batch size).
    #[arg(long)]
    real_proofs: Option<usize>,

    /// Limit the rayon thread pool. 1 = single-threaded (lowest peak memory,
    /// slowest); 0 = system default (highest peak memory, fastest).
    #[arg(long, default_value_t = 0)]
    rayon_threads: usize,

    /// Skip leaf-proof generation entirely (use cloned dummy proof). Use this
    /// to isolate the cost of the aggregation step alone.
    #[arg(long, default_value_t = false)]
    skip_leaf_gen: bool,

    /// Only build the aggregation circuit, don't prove anything. Tells you
    /// the cost of the circuit data structure itself.
    #[arg(long, default_value_t = false)]
    circuit_only: bool,

    /// Call malloc_zone_pressure_relief between phases (Apple only).
    #[arg(long, default_value_t = false)]
    release_after_each: bool,

    /// Memory sampler poll period in milliseconds.
    #[arg(long, default_value_t = 25)]
    sample_period_ms: u64,

    /// If set, exits with non-zero status when overall peak exceeds this MB.
    /// Useful for CI guards: --peak-target-mb 1500
    #[arg(long)]
    peak_target_mb: Option<u64>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    eprintln!("wormhole-memprof: args = {:#?}", args);

    if args.rayon_threads > 0 {
        eprintln!("Configuring rayon with {} threads", args.rayon_threads);
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.rayon_threads)
            .build_global()
            .ok();
    }

    let num_leaf_proofs = args.num_leaf_proofs;
    let real_proofs = args.real_proofs.unwrap_or(num_leaf_proofs).min(num_leaf_proofs);

    let mut report = PhaseReport::new(args.sample_period_ms);

    let leaf_ctx = workload::build_leaf_context(&mut report)?;
    if args.release_after_each {
        report.release_memory("after_build_leaf_circuit");
    }

    if args.circuit_only {
        workload::build_agg_circuit_only(&leaf_ctx, num_leaf_proofs, &mut report)?;
        report.finish_and_print(args.peak_target_mb);
        return Ok(());
    }

    let mut leaf_proofs = Vec::with_capacity(real_proofs);
    if args.skip_leaf_gen {
        eprintln!(
            "Skipping leaf-proof generation; cloning dummy proof {} times",
            real_proofs
        );
        for _ in 0..real_proofs {
            leaf_proofs.push(leaf_ctx.dummy_proof.clone());
        }
    } else {
        for i in 0..real_proofs {
            let p = workload::generate_leaf_proof(i, args.release_after_each, &mut report)?;
            leaf_proofs.push(p);
        }
    }

    let _agg = workload::aggregate_fresh(
        &leaf_ctx,
        leaf_proofs,
        num_leaf_proofs,
        args.release_after_each,
        &mut report,
    )?;

    report.finish_and_print(args.peak_target_mb);
    Ok(())
}
