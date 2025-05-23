use std::fs;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;
// use wormhole_circuit::inputs::CircuitInputs;
use wormhole_verifier::WormholeVerifier;

const MEASUREMENT_TIME_S: u64 = 20;
const PROOF_PATH: &str = "./benches/proof.bin";

fn verify_proof_benchmark(c: &mut Criterion) {
    c.bench_function("verifier_verify_proof", |b| {
        let common_data = fs::read("./benches/common.bin").unwrap();
        let common_circuit_data = CommonCircuitData::from_bytes(common_data, &DefaultGateSerializer).unwrap();
        let proof_data = fs::read(PROOF_PATH).unwrap();
        let proof = ProofWithPublicInputs::from_bytes(proof_data, &common_circuit_data).unwrap();

        let verifier_circuit_data_bytes = fs::read("./benches/verifier.bin").unwrap();
        let verifier_circuit_data = VerifierCircuitData::from_bytes(verifier_circuit_data_bytes, &DefaultGateSerializer).unwrap();

        // let inputs = CircuitInputs::default();
        // let proof = WormholeProver::new(true)
        //     .commit(&inputs)
        //     .unwrap()
        //     .prove()
        //     .unwrap();

        b.iter(|| {
            let verifier = WormholeVerifier::new(true, Some(verifier_circuit_data.clone()));
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
