use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use plonky2::plonk::circuit_data::CircuitConfig;
use qp_wormhole_prover::WormholeProver;
use test_helpers::TestInputs;
use wormhole_circuit::inputs::CircuitInputs;

const MEASUREMENT_TIME_S: u64 = 88;

fn create_proof_benchmark(c: &mut Criterion) {
    let config = CircuitConfig::standard_recursion_zk_config();
    let inputs = CircuitInputs::test_inputs_0();

    c.bench_function("prover_create_proof", |b| {
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
    targets = create_proof_benchmark
);
criterion_main!(benches);
