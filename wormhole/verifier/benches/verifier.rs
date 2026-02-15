use std::fs;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use qp_wormhole_verifier::{ProofWithPublicInputs, WormholeVerifier, C, D, F};

const MEASUREMENT_TIME_S: u64 = 20;
const DATA_PATH: &str = "../bench-data";

fn verify_proof_benchmark(c: &mut Criterion) {
    c.bench_function("verifier_verify_proof", |b| {
        let common_bytes = fs::read(format!("{DATA_PATH}/common.bin")).unwrap();
        let verifier_bytes = fs::read(format!("{DATA_PATH}/verifier.bin")).unwrap();
        let proof_bytes = fs::read(format!("{DATA_PATH}/proof.bin")).unwrap();

        let verifier = WormholeVerifier::new_from_bytes(&verifier_bytes, &common_bytes).unwrap();
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            proof_bytes,
            &verifier.circuit_data.common,
        )
        .unwrap();

        b.iter(|| {
            verifier.verify(proof.clone()).unwrap();
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(MEASUREMENT_TIME_S))
        .sample_size(10);
    targets = verify_proof_benchmark
);
criterion_main!(benches);
