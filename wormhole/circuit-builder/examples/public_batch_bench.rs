//! Benchmark public-batch circuit build + proving time across branching factors.
//!
//! For each branching factor M (number of private-batch proofs per public batch):
//! 1. Generates the public-batch circuit binaries (leaf + private-batch circuits are
//!    built once and reused, since they don't depend on M).
//! 2. Loads the prover, which rebuilds the circuit from source (measures aggregator
//!    startup).
//! 3. Proves a public batch padded entirely with the dummy private-batch template.
//!    Proving cost is witness-independent, so this is representative of real batches.
//!
//! Usage: cargo run --release -p qp-wormhole-circuit-builder --example public_batch_bench -- 32 64 128

use std::{fs, path::Path, time::Instant};

use plonky2::{
    plonk::{circuit_data::CommonCircuitData, proof::ProofWithPublicInputs},
    util::serialization::DefaultGateSerializer,
};
use wormhole_aggregator::{
    public_batch::{
        circuit::generate_public_batch_circuit_binaries,
        prover::{PublicBatchInputs, PublicBatchProver},
    },
    CircuitBinsConfig,
};
use zk_circuits_common::circuit::{C, D, F};

const NUM_LEAF_PROOFS: usize = 7;

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
    println!("Binaries dir: {}\n", dir.display());

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

    let mut results = Vec::new();

    for &m in &branching_factors {
        println!("== M = {m} ==");

        // 1) Build + serialize the public-batch verifier artifacts.
        let build_start = Instant::now();
        generate_public_batch_circuit_binaries(&dir, m)?;
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

        // 3) Prove an all-dummy-padded batch (1 template proof, M-1 dummies).
        let dummy_bytes = fs::read(dir.join("dummy_private_batch_proof.bin"))?;
        let private_batch_common = CommonCircuitData::<F, D>::from_bytes(
            fs::read(dir.join("private_batch_common.bin"))?,
            &DefaultGateSerializer,
        )
        .map_err(|e| anyhow::anyhow!("failed to load private-batch common data: {e}"))?;
        let template =
            ProofWithPublicInputs::<F, C, D>::from_bytes(dummy_bytes, &private_batch_common)
                .map_err(|e| anyhow::anyhow!("failed to load dummy template: {e}"))?;

        let prove_start = Instant::now();
        let prover = prover.commit(PublicBatchInputs {
            proofs: vec![template],
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
