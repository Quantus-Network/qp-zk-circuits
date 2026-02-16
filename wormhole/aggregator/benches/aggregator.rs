use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_aggregator::aggregator::WormholeProofAggregator;
use qp_wormhole_aggregator::dummy_proof::load_dummy_proof;
use zk_circuits_common::aggregation::AggregationConfig;
use zk_circuits_common::circuit::{C, D, F};

fn load_dummy_proofs(
    common_data: &CommonCircuitData<F, D>,
    len: usize,
) -> Vec<ProofWithPublicInputs<F, C, D>> {
    let dummy_bytes =
        std::fs::read("generated-bins/dummy_proof.bin").expect("failed to read dummy_proof.bin");
    let dummy_proof =
        load_dummy_proof(dummy_bytes, common_data).expect("failed to load dummy proof");
    (0..len).map(|_| dummy_proof.clone()).collect()
}

// A macro for creating an aggregation benchmark with a specified number of leaf proofs.
macro_rules! aggregate_proofs_benchmark {
    ($fn_name:ident, $num_leaf_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let aggregation_config = AggregationConfig::new($num_leaf_proofs);
            let circuit_config = CircuitConfig::standard_recursion_zk_config();

            // Setup proofs.
            let proofs = {
                let temp_aggregator = WormholeProofAggregator::from_circuit_config(
                    circuit_config.clone(),
                    aggregation_config,
                );
                load_dummy_proofs(
                    &temp_aggregator.leaf_circuit_data.common,
                    aggregation_config.num_leaf_proofs,
                )
            };

            c.bench_function(
                &format!("aggregate_proofs_{}", aggregation_config.num_leaf_proofs),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator = WormholeProofAggregator::from_circuit_config(
                                circuit_config.clone(),
                                aggregation_config,
                            );
                            for proof in proofs.clone() {
                                aggregator.push_proof(proof).unwrap();
                            }
                            aggregator
                        },
                        |mut aggregator| {
                            aggregator.aggregate().unwrap();
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

macro_rules! verify_aggregate_proof_benchmark {
    ($fn_name:ident, $num_leaf_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let aggregation_config = AggregationConfig::new($num_leaf_proofs);
            let circuit_config = CircuitConfig::standard_recursion_zk_config();

            // Setup proofs.
            let proofs = {
                let temp_aggregator = WormholeProofAggregator::from_circuit_config(
                    circuit_config.clone(),
                    aggregation_config,
                );
                load_dummy_proofs(
                    &temp_aggregator.leaf_circuit_data.common,
                    aggregation_config.num_leaf_proofs,
                )
            };

            c.bench_function(
                &format!(
                    "verify_aggregate_proof_{}",
                    aggregation_config.num_leaf_proofs
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator = WormholeProofAggregator::from_circuit_config(
                                circuit_config.clone(),
                                aggregation_config,
                            );
                            for proof in proofs.clone() {
                                aggregator.push_proof(proof).unwrap();
                            }

                            aggregator.aggregate().unwrap()
                        },
                        |aggregated_proof| {
                            let proof = aggregated_proof.proof;
                            let circuit_data = aggregated_proof.circuit_data;
                            circuit_data.verify(proof).unwrap();
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
