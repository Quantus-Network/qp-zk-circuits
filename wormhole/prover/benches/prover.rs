//! Leaf prover benchmarks.
//!
//! These benchmarks measure the time to generate and verify a leaf proof.
//!
//! Run benchmarks:
//! ```bash
//! cargo bench -p qp-wormhole-prover
//! ```

use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::iop::witness::PartialWitness;
use wormhole_aggregator::build_dummy_circuit_inputs;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use zk_circuits_common::circuit::wormhole_leaf_circuit_config;

/// Benchmark leaf proof generation (proving only, circuit pre-built)
fn leaf_prove_benchmark(c: &mut Criterion) {
    let config = wormhole_leaf_circuit_config();
    let inputs = build_dummy_circuit_inputs().expect("Failed to build dummy circuit inputs");

    // Pre-build the circuit once (expensive, not measured)
    let wormhole_circuit = WormholeCircuit::new(config);
    let targets = wormhole_circuit.targets();
    let circuit_data = wormhole_circuit.build_prover();

    c.bench_function("leaf_prove", |b| {
        b.iter_batched(
            || {
                // Setup: fill witness (fast)
                let mut pw = PartialWitness::new();
                qp_wormhole_prover::fill_witness(&mut pw, &inputs, &targets)
                    .expect("Failed to fill witness");
                pw
            },
            |pw| {
                // Measured: proving
                circuit_data.prove(pw).unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Benchmark leaf proof verification
fn leaf_verify_benchmark(c: &mut Criterion) {
    let config = wormhole_leaf_circuit_config();
    let inputs = build_dummy_circuit_inputs().expect("Failed to build dummy circuit inputs");

    // Pre-build the circuit and generate a proof (not measured)
    let wormhole_circuit = WormholeCircuit::new(config);
    let targets = wormhole_circuit.targets();
    let verifier_data = wormhole_circuit.build_verifier();

    // Generate a proof to verify
    let prover_data = WormholeCircuit::new(wormhole_leaf_circuit_config()).build_prover();
    let mut pw = PartialWitness::new();
    qp_wormhole_prover::fill_witness(&mut pw, &inputs, &targets).expect("Failed to fill witness");
    let proof = prover_data.prove(pw).expect("Failed to generate proof");

    c.bench_function("leaf_verify", |b| {
        b.iter(|| {
            verifier_data.verify(proof.clone()).unwrap();
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = leaf_prove_benchmark, leaf_verify_benchmark
);
criterion_main!(benches);
