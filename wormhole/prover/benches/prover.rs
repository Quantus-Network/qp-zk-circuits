use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::CircuitConfig;
use test_helpers::storage_proof::TestInputs;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

const MEASUREMENT_TIME_S: u64 = 20;

fn create_proof_benchmark(c: &mut Criterion) {
    let config = CircuitConfig::standard_recursion_zk_config();
    c.bench_function("prover_create_proof", |b| {
        b.iter(|| {
            let config = config.clone();
            let prover = WormholeProver::new(config);
            let inputs = CircuitInputs::test_inputs_0();
            prover.commit(&inputs).unwrap().prove().unwrap()
        });
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
