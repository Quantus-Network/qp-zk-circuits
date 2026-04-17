//! Generate pre-built circuit artifacts for benchmarks.
//!
//! This binary generates all circuit configurations needed for the benchmark suite.
//! Run this once before running benchmarks to avoid circuit building overhead during timing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --release -p qp-wormhole-aggregator --bin generate_bench_circuits
//! ```
//!
//! # Output Structure
//!
//! Creates directories under `wormhole/generated-bins/bench/`:
//! - `layer0_N/` - First-layer circuits for N leaf proofs
//! - `layer1_M_N/` - Second-layer circuits for M first-layer proofs, each with N leaves
//!
//! Note: Leaf circuit artifacts are copied from `wormhole/generated-bins/` which must
//! already exist (run `cargo run -p qp-wormhole-circuit-builder` first if needed).

use anyhow::{Context, Result};
use std::fs::{self, create_dir_all};
use std::path::Path;
use std::time::Instant;

use qp_wormhole_aggregator::config::CircuitBinsConfig;
use qp_wormhole_aggregator::layer0::circuit::build::generate_layer0_circuit_binaries;
use qp_wormhole_aggregator::layer1::circuit::build::generate_layer1_circuit_binaries;

/// First-layer batch sizes to benchmark (number of leaf proofs)
const LAYER0_BATCH_SIZES: &[usize] = &[2, 4, 8, 16, 32];

/// Second-layer configurations: (M first-layer proofs, N leaves per first-layer proof)
const LAYER1_CONFIGS: &[(usize, usize)] = &[
    (2, 4),
    (2, 8),
    (2, 16),
    (4, 8),
    (4, 16),
    (8, 8),
    (8, 16),
    (16, 8),
    (32, 8),
];

fn main() -> Result<()> {
    let base_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../generated-bins/bench");
    let main_bins_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../generated-bins");

    println!("==============================================");
    println!("  Generating Benchmark Circuit Artifacts");
    println!("==============================================\n");
    println!("Output directory: {}\n", base_dir.display());

    // Check that main generated-bins exists (need leaf artifacts)
    if !main_bins_dir.join("common.bin").exists() {
        anyhow::bail!(
            "Leaf circuit artifacts not found in {}. Run `cargo run -p qp-wormhole-circuit-builder` first.",
            main_bins_dir.display()
        );
    }

    // Clean and create base directory
    if base_dir.exists() {
        println!("Cleaning existing benchmark artifacts...");
        fs::remove_dir_all(&base_dir).context("Failed to remove existing bench directory")?;
    }
    create_dir_all(&base_dir).context("Failed to create bench directory")?;

    // Step 1: Copy leaf circuit artifacts from main generated-bins
    println!("----------------------------------------------");
    println!("Step 1: Copying leaf circuit artifacts");
    println!("----------------------------------------------");
    let leaf_dir = base_dir.join("leaf");
    let start = Instant::now();
    copy_leaf_artifacts_from_main(&main_bins_dir, &leaf_dir)?;
    println!("  Completed in {:.2}s\n", start.elapsed().as_secs_f64());

    // Step 2: Generate first-layer circuits for each batch size
    println!("----------------------------------------------");
    println!("Step 2: Generating first-layer circuits");
    println!("----------------------------------------------");
    for &n in LAYER0_BATCH_SIZES {
        let layer0_dir = base_dir.join(format!("layer0_{}", n));
        create_dir_all(&layer0_dir)?;

        // Copy leaf artifacts
        copy_leaf_artifacts(&leaf_dir, &layer0_dir)?;

        print!("  N={:2} leaf proofs... ", n);
        let start = Instant::now();
        generate_layer0_circuit_binaries(&layer0_dir, n, true)
            .with_context(|| format!("Failed to generate layer0 circuit for N={}", n))?;

        // Save config
        let config = CircuitBinsConfig::new(n, None);
        config.save(&layer0_dir)?;

        println!("done in {:.2}s", start.elapsed().as_secs_f64());
    }
    println!();

    // Step 3: Generate second-layer circuits for each configuration
    println!("----------------------------------------------");
    println!("Step 3: Generating second-layer circuits");
    println!("----------------------------------------------");
    for &(m, n) in LAYER1_CONFIGS {
        let layer1_dir = base_dir.join(format!("layer1_{}_{}", m, n));
        create_dir_all(&layer1_dir)?;

        // Copy leaf artifacts
        copy_leaf_artifacts(&leaf_dir, &layer1_dir)?;

        // First generate layer0 artifacts for this N
        print!("  M={:2} first-layer proofs x N={:2} leaves... ", m, n);
        let start = Instant::now();

        generate_layer0_circuit_binaries(&layer1_dir, n, true)
            .with_context(|| format!("Failed to generate layer0 circuit for N={}", n))?;

        generate_layer1_circuit_binaries(&layer1_dir, m, true)
            .with_context(|| format!("Failed to generate layer1 circuit for M={}, N={}", m, n))?;

        // Save config
        let config = CircuitBinsConfig::new(n, Some(m));
        config.save(&layer1_dir)?;

        println!("done in {:.2}s", start.elapsed().as_secs_f64());
    }
    println!();

    println!("==============================================");
    println!("  All benchmark circuits generated!");
    println!("==============================================");
    println!("\nYou can now run benchmarks with:");
    println!("  cargo bench -p qp-wormhole-aggregator");

    Ok(())
}

/// Copy leaf circuit artifacts from the main generated-bins directory
fn copy_leaf_artifacts_from_main(main_bins_dir: &Path, leaf_dir: &Path) -> Result<()> {
    create_dir_all(leaf_dir)?;

    for file in &[
        "common.bin",
        "verifier.bin",
        "prover.bin",
        "dummy_proof.bin",
    ] {
        let src = main_bins_dir.join(file);
        let dst = leaf_dir.join(file);
        fs::copy(&src, &dst)
            .with_context(|| format!("Failed to copy {} from main generated-bins", file))?;
        println!("  Copied {}", file);
    }

    Ok(())
}

/// Copy leaf circuit artifacts to a target directory
fn copy_leaf_artifacts(leaf_dir: &Path, target_dir: &Path) -> Result<()> {
    for file in &[
        "common.bin",
        "verifier.bin",
        "prover.bin",
        "dummy_proof.bin",
    ] {
        fs::copy(leaf_dir.join(file), target_dir.join(file))
            .with_context(|| format!("Failed to copy {}", file))?;
    }
    Ok(())
}
