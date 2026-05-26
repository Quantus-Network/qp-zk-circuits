//! Single-shot peak-memory profiler for the wormhole proof + aggregation
//! pipeline.
//!
//! Runs the pipeline ONCE in a fresh process while a background thread samples
//! resident memory, then prints a phase-by-phase peak-memory report. Use this
//! to compare circuit configurations, runtime tuning (rayon thread count,
//! batch sizes), and allocator behavior without firing up a full client.
//!
//! Pipeline phases:
//!   1. build leaf circuit (once)
//!   2. generate N leaf proofs sequentially (or skip & use dummies)
//!   3. build the layer-0 aggregation circuit
//!   4. commit + prove the aggregation
//!
//! See `README.md` for usage examples.

mod config;
mod memory;
mod report;
mod workload;

use anyhow::Result;
use clap::Parser;

use crate::config::{default_agg_config, default_leaf_config, print_config_summary, AggConfigArgs};
use crate::report::PhaseReport;

#[derive(Parser, Debug)]
#[command(
    name = "wormhole-memprof",
    about = "Peak-memory profiler for wormhole proof + aggregation"
)]
struct Args {
    /// Number of leaf proofs the aggregation circuit is built for. Matches
    /// the on-chain verifier's expected batch size.
    #[arg(long, default_value_t = 7)]
    num_leaf_proofs: usize,

    /// How many real leaf proofs to actually generate before aggregation.
    /// Must be <= num_leaf_proofs. The aggregator pads the rest with dummy
    /// proofs.
    #[arg(long)]
    real_proofs: Option<usize>,

    /// Limit the rayon thread pool. `1` = single-threaded; `0` = system
    /// default. Useful for comparing parallel vs serial allocation patterns.
    #[arg(long, default_value_t = 0)]
    rayon_threads: usize,

    /// Skip leaf-proof generation entirely (use cloned dummy proof). Isolates
    /// the cost of the aggregation step alone.
    #[arg(long, default_value_t = false)]
    skip_leaf_gen: bool,

    /// Only build the aggregation circuit, don't prove anything. Reports the
    /// cost of the circuit data structure itself.
    #[arg(long, default_value_t = false)]
    circuit_only: bool,

    /// Call malloc_zone_pressure_relief between phases (Apple only).
    #[arg(long, default_value_t = false)]
    release_after_each: bool,

    /// Memory sampler poll period in milliseconds.
    #[arg(long, default_value_t = 25)]
    sample_period_ms: u64,

    /// If set, exits non-zero when overall peak exceeds this MB. CI guard.
    #[arg(long)]
    peak_target_mb: Option<u64>,

    #[command(flatten)]
    agg_cfg: AggConfigArgs,
}

fn main() -> Result<()> {
    let args = Args::parse();
    eprintln!("wormhole-memprof: args = {:#?}", args);

    if let Err(msg) = args.agg_cfg.validate() {
        eprintln!("ERROR: {}", msg);
        std::process::exit(2);
    }

    let agg_cfg = if args.agg_cfg.is_default() {
        default_agg_config()
    } else {
        args.agg_cfg.build()
    };
    let leaf_cfg = default_leaf_config();
    print_config_summary("leaf", &leaf_cfg);
    print_config_summary("agg", &agg_cfg);

    if args.rayon_threads > 0 {
        eprintln!("Configuring rayon with {} threads", args.rayon_threads);
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.rayon_threads)
            .build_global()
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to configure rayon thread pool with {} threads: {e}",
                    args.rayon_threads
                )
            })?;
    }

    let num_leaf_proofs = args.num_leaf_proofs;
    let real_proofs = args.real_proofs.unwrap_or(num_leaf_proofs);
    if real_proofs > num_leaf_proofs {
        anyhow::bail!(
            "--real-proofs ({}) must be <= --num-leaf-proofs ({})",
            real_proofs,
            num_leaf_proofs
        );
    }

    let mut report = PhaseReport::new(args.sample_period_ms)?;

    let mut leaf_ctx = workload::build_leaf_context(leaf_cfg.clone(), &mut report)?;
    if args.release_after_each {
        report.release_memory("after_build_leaf_circuit")?;
    }

    if args.circuit_only {
        workload::build_agg_circuit_only(&leaf_ctx, num_leaf_proofs, agg_cfg, &mut report)?;
        report.finish_and_print(args.peak_target_mb)?;
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
            let p = workload::generate_leaf_proof(
                &mut leaf_ctx,
                i,
                args.release_after_each,
                &mut report,
            )?;
            leaf_proofs.push(p);
        }
    }

    let _agg = workload::aggregate_fresh(
        &leaf_ctx,
        leaf_proofs,
        num_leaf_proofs,
        agg_cfg,
        args.release_after_each,
        &mut report,
    )?;

    report.finish_and_print(args.peak_target_mb)?;
    Ok(())
}
