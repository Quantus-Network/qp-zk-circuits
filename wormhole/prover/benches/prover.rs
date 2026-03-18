use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use plonky2::plonk::circuit_data::CircuitConfig;
use qp_wormhole_prover::WormholeProver;
use wormhole_aggregator::build_dummy_circuit_inputs;

const MEASUREMENT_TIME_S: u64 = 88;

fn create_proof_benchmark_zk(c: &mut Criterion) {
    let config = CircuitConfig::standard_recursion_zk_config();
    // Use dummy inputs which are generated fresh and compatible with current hash function
    let inputs = build_dummy_circuit_inputs().expect("Failed to build dummy circuit inputs");

    c.bench_function("prover_create_proof_zk", |b| {
        b.iter_batched(
            // Setup: create a new prover for each iteration (not measured)
            || WormholeProver::new(config.clone()),
            // Measured: commit and prove
            |prover| prover.commit(&inputs).unwrap().prove().unwrap(),
            // Use SmallInput since we're creating a new prover each time
            BatchSize::SmallInput,
        );
    });
}

fn create_proof_benchmark_no_zk(c: &mut Criterion) {
    let config = CircuitConfig::standard_recursion_config();
    // Use dummy inputs which are generated fresh and compatible with current hash function
    let inputs = build_dummy_circuit_inputs().expect("Failed to build dummy circuit inputs");

    c.bench_function("prover_create_proof_no_zk", |b| {
        b.iter_batched(
            // Setup: create a new prover for each iteration (not measured)
            || WormholeProver::new(config.clone()),
            // Measured: commit and prove
            |prover| prover.commit(&inputs).unwrap().prove().unwrap(),
            // Use SmallInput since we're creating a new prover each time
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(MEASUREMENT_TIME_S))
        .sample_size(10);
    targets = create_proof_benchmark_zk, create_proof_benchmark_no_zk
);
criterion_main!(benches);
