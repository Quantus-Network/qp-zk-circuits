use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::DefaultGateSerializer;
use qp_wormhole_aggregator::aggregator::{AggregationBackend, Layer0Aggregator};
use qp_wormhole_aggregator::dummy_proof::load_dummy_proof;
use qp_wormhole_aggregator::layer0::circuit::build::generate_layer0_circuit_binaries;

/// Generate dummy proofs from the circuit config (no external files needed).
const BINS_DIR: &str = "../../generated-bins";

// A macro for creating an aggregation benchmark with a specified number of leaf proofs.
macro_rules! aggregate_proofs_benchmark {
    ($fn_name:ident, $num_leaf_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let gate_serializer = DefaultGateSerializer;
            // load the dummy proof bytes from the file path
            let proof_bytes = std::fs::read(format!("{}/dummy_proof.bin", BINS_DIR))
                .expect("Failed to read dummy proof bytes");
            let common_circuit_data = std::fs::read(format!("{}/common.bin", BINS_DIR))
                .expect("Failed to read common circuit data bytes");
            // 1) Load prebuilt aggregation circuit prover data
            let agg_common =
                CommonCircuitData::from_bytes(common_circuit_data.to_vec(), &gate_serializer)
                    .expect("Failed to deserialize aggregated common data");
            let proof = load_dummy_proof(proof_bytes, &agg_common)
                .expect("Failed to load dummy proof from bytes");

            c.bench_function(&format!("aggregate_proofs_{}", $num_leaf_proofs), |b| {
                b.iter_batched(
                    || {
                        // Call "generate_layer0_circuit_binaries" before we instantiate a new wormhole aggregator,
                        // to ensure the binaries represent the circuit with the correct number of leaf proofs.
                        generate_layer0_circuit_binaries(BINS_DIR, $num_leaf_proofs, true).expect(
                            "Failed to generate layer0 circuit binaries for aggregation benchmark",
                        );
                        let mut aggregator = Layer0Aggregator::new(BINS_DIR).unwrap();
                        for proof in std::iter::repeat(proof.clone()).take($num_leaf_proofs) {
                            aggregator.push_proof(proof).unwrap();
                        }
                        aggregator
                    },
                    |mut aggregator| {
                        aggregator.aggregate().unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    };
}

macro_rules! verify_aggregate_proof_benchmark {
    ($fn_name:ident, $num_leaf_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let gate_serializer = DefaultGateSerializer;
            // load the dummy proof bytes from the file path
            let proof_bytes = std::fs::read(format!("{}/dummy_proof.bin", BINS_DIR))
                .expect("Failed to read dummy proof bytes");
            let common_circuit_data = std::fs::read(format!("{}/common.bin", BINS_DIR))
                .expect("Failed to read common circuit data bytes");
            // 1) Load prebuilt aggregation circuit prover data
            let agg_common =
                CommonCircuitData::from_bytes(common_circuit_data.to_vec(), &gate_serializer)
                    .expect("Failed to deserialize aggregated common data");
            let proof = load_dummy_proof(proof_bytes, &agg_common)
                .expect("Failed to load dummy proof from bytes");

            c.bench_function(
                &format!("verify_aggregate_proof_{}", $num_leaf_proofs),
                |b| {
                    b.iter_batched(
                        || {
                            // Call "generate_layer0_circuit_binaries" before we instantiate a new wormhole aggregator,
                            // to ensure the binaries represent the circuit with the correct number of leaf proofs.
                            generate_layer0_circuit_binaries(BINS_DIR, $num_leaf_proofs, true).expect(
                                "Failed to generate layer0 circuit binaries for aggregation benchmark",
                            );
                            let mut aggregator =
                                Layer0Aggregator::new(BINS_DIR).unwrap();
                            for proof in std::iter::repeat(proof.clone()).take($num_leaf_proofs) {
                                aggregator.push_proof(proof).unwrap();
                            }

                            (aggregator.aggregate().unwrap(), aggregator)
                        },
                        |(aggregated_proof, aggregator)| {
                            aggregator
                                .verify(aggregated_proof)
                                .unwrap();
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

// Various proof counts.
aggregate_proofs_benchmark!(bench_aggregate_2_proofs, 2);
aggregate_proofs_benchmark!(bench_aggregate_4_proofs, 4);
aggregate_proofs_benchmark!(bench_aggregate_8_proofs, 8);
aggregate_proofs_benchmark!(bench_aggregate_16_proofs, 16);
aggregate_proofs_benchmark!(bench_aggregate_32_proofs, 32);

verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_2, 2);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_4, 4);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_8, 8);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_16, 16);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_32, 32);

// Additional proof counts.
aggregate_proofs_benchmark!(bench_aggregate_proofs_9, 9);
aggregate_proofs_benchmark!(bench_aggregate_proofs_25, 25);
aggregate_proofs_benchmark!(bench_aggregate_proofs_36, 36);
aggregate_proofs_benchmark!(bench_aggregate_proofs_49, 49);

verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_9, 9);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_25, 25);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_36, 36);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_49, 49);

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10);
    targets = bench_aggregate_2_proofs, bench_aggregate_4_proofs, bench_aggregate_8_proofs, bench_aggregate_16_proofs, bench_aggregate_32_proofs,
              bench_verify_aggregate_proof_2, bench_verify_aggregate_proof_4, bench_verify_aggregate_proof_8, bench_verify_aggregate_proof_16, bench_verify_aggregate_proof_32,
              bench_aggregate_proofs_9, bench_aggregate_proofs_25, bench_aggregate_proofs_36, bench_aggregate_proofs_49,
              bench_verify_aggregate_proof_9, bench_verify_aggregate_proof_25, bench_verify_aggregate_proof_36, bench_verify_aggregate_proof_49,
);
criterion_main!(benches);
