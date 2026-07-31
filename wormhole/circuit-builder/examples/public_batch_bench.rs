//! Benchmark public-batch circuit build + proving time across branching factors.
//!
//! For each branching factor M (number of private-batch proofs per public batch):
//! 1. Generates the public-batch circuit binaries (leaf + private-batch circuits are
//!    built once and reused, since they don't depend on M).
//! 2. Loads the prover, which rebuilds the circuit from source (measures aggregator
//!    startup).
//! 3. Proves a public batch with one real private-batch proof, padded with the
//!    dummy template. Proving cost is witness-independent, so this is
//!    representative of full batches.
//!
//! Usage: cargo run --release -p qp-wormhole-circuit-builder --example public_batch_bench -- 32 64 128

use std::{fs, path::Path, time::Instant};

use test_helpers::TestInputs as _;
use wormhole_aggregator::{
    private_batch::prover::PrivateBatchProver,
    public_batch::{
        circuit::generate_public_batch_circuit_binaries,
        prover::{PublicBatchInputs, PublicBatchProver},
    },
    CircuitBinsConfig,
};
use wormhole_circuit::{block_header::header::HeaderInputs, inputs::CircuitInputs};
use zk_circuits_common::circuit::{
    wormhole_leaf_circuit_config, wormhole_private_batch_circuit_config,
    wormhole_public_batch_circuit_config,
};

const NUM_LEAF_PROOFS: usize = 7;

fn zk_label(zero_knowledge: bool) -> &'static str {
    if zero_knowledge {
        "ZK (row blinding)"
    } else {
        "non-ZK"
    }
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn main() -> anyhow::Result<()> {
    let branching_factors: Vec<usize> = std::env::args()
        .skip(1)
        .map(|a| a.parse().expect("branching factors must be integers"))
        .collect();
    let branching_factors = if branching_factors.is_empty() {
        vec![32, 64, 128]
    } else {
        branching_factors
    };

    let dir = std::path::PathBuf::from(
        std::env::var("BENCH_BINS_DIR").unwrap_or_else(|_| "target/public-batch-bench".into()),
    );
    fs::create_dir_all(&dir)?;
    println!("Binaries dir: {}", dir.display());

    // The bench uses the canonical production configs; print the ZK status of
    // each layer so the measured hierarchy is explicit (only the private
    // batch needs blinding: it is the layer whose witnesses are leaf proofs).
    println!(
        "Circuit hierarchy: leaf {}, private batch {}, public batch {}\n",
        zk_label(wormhole_leaf_circuit_config().zero_knowledge),
        zk_label(wormhole_private_batch_circuit_config().zero_knowledge),
        zk_label(wormhole_public_batch_circuit_config().zero_knowledge),
    );

    // Leaf + private-batch circuits don't depend on M; build them once.
    println!("== One-time setup: leaf + private-batch circuits (N={NUM_LEAF_PROOFS}) ==");
    let setup_start = Instant::now();
    qp_wormhole_circuit_builder::generate_circuit_binaries(&dir)?;
    wormhole_aggregator::private_batch::circuit::build::generate_private_batch_circuit_binaries(
        &dir,
        NUM_LEAF_PROOFS,
        true,
    )?;
    println!(
        "Setup done in {:.1}s\n",
        setup_start.elapsed().as_secs_f64()
    );

    // One real private-batch proof (a single real leaf padded with dummy
    // leaves), reused for every M: PublicBatchProver::commit rejects all-dummy
    // batches (they settle nothing on-chain), and the private-batch circuit
    // doesn't depend on M.
    println!("== One-time setup: real private-batch proof ==");
    let proof_start = Instant::now();
    CircuitBinsConfig::new(NUM_LEAF_PROOFS, None)?.save(&dir)?;
    let real_private_batch = {
        let mut inputs = CircuitInputs::test_inputs_0();
        inputs.public.block_hash = HeaderInputs::try_from(&inputs)
            .expect("header inputs from test inputs")
            .block_hash();
        let real_leaf = wormhole_prover::build_fresh().commit(&inputs)?.prove()?;
        PrivateBatchProver::new_from_binaries_dir(&dir)?.aggregate(vec![real_leaf])?
    };
    println!(
        "Real private-batch proof done in {:.1}s\n",
        proof_start.elapsed().as_secs_f64()
    );

    let mut results = Vec::new();

    for &m in &branching_factors {
        println!("== M = {m} ==");

        // 1) Build + serialize the public-batch verifier artifacts.
        let build_start = Instant::now();
        generate_public_batch_circuit_binaries(&dir, m, NUM_LEAF_PROOFS)?;
        let build_time = build_start.elapsed();
        CircuitBinsConfig::new(NUM_LEAF_PROOFS, Some(m))?.save(&dir)?;
        let verifier_bins_size = file_size(&dir.join("public_batch_common.bin"))
            + file_size(&dir.join("public_batch_verifier.bin"));
        println!(
            "  circuit build + serialize: {:.1}s (verifier bins: {:.1} KB)",
            build_time.as_secs_f64(),
            verifier_bins_size as f64 / 1e3
        );

        // 2) Load the prover (aggregator startup cost; rebuilds the circuit
        // from source — no prover.bin exists).
        let load_start = Instant::now();
        let prover = PublicBatchProver::new_from_binaries_dir(&dir)?;
        let load_time = load_start.elapsed();
        println!(
            "  prover load (rebuild):     {:.1}s",
            load_time.as_secs_f64()
        );

        // 3) Prove a batch with one real private-batch proof (M-1 dummy pads).
        let prove_start = Instant::now();
        let prover = prover.commit(PublicBatchInputs {
            proofs: vec![real_private_batch.clone()],
            aggregator_address: Default::default(),
        })?;
        let proof = prover.prove()?;
        let prove_time = prove_start.elapsed();
        let proof_size = proof.to_bytes().len();
        println!(
            "  commit + prove:            {:.1}s (proof: {:.1} KB, {} PIs)",
            prove_time.as_secs_f64(),
            proof_size as f64 / 1e3,
            proof.public_inputs.len()
        );

        results.push((m, build_time, load_time, prove_time, proof_size));
        println!();
    }

    println!("== Summary (N={NUM_LEAF_PROOFS} leaves/private batch, 2N outputs each) ==");
    println!(
        "{:>5} {:>8} {:>12} {:>10} {:>10} {:>12}",
        "M", "outputs", "build (s)", "load (s)", "prove (s)", "proof (KB)"
    );
    for (m, build, load, prove, proof_size) in &results {
        println!(
            "{:>5} {:>8} {:>12.1} {:>10.1} {:>10.1} {:>12.1}",
            m,
            m * NUM_LEAF_PROOFS * 2,
            build.as_secs_f64(),
            load.as_secs_f64(),
            prove.as_secs_f64(),
            *proof_size as f64 / 1e3,
        );
    }

    Ok(())
}
