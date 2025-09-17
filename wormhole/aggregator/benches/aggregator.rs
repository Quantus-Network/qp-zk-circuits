use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::CommonCircuitData;
use qp_wormhole_aggregator::aggregator::WormholeProofAggregator;
use qp_wormhole_aggregator::circuits::tree::TreeAggregationConfig;
use wormhole_verifier::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};

const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../data/dummy_proof_zk.bin");

fn deserialize_proofs(
    common_data: &CommonCircuitData<F, D>,
    len: usize,
) -> Vec<ProofWithPublicInputs<F, C, D>> {
    (0..len)
        .map(|_| {
            ProofWithPublicInputs::from_bytes(DUMMY_PROOF_BYTES.to_vec(), common_data).unwrap()
        })
        .collect()
}

// A macro for creating an aggregation benchmark with a specified number of proofs to
// aggregate. The number of proofs is gotten by the tree branching factor and the tree depth.
macro_rules! aggregate_proofs_benchmark {
    ($fn_name:ident, $tree_branching_factor:expr, $tree_depth:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let config = TreeAggregationConfig::new($tree_branching_factor, $tree_depth);

            // Setup proofs.
            let proofs = {
                let temp_aggregator = WormholeProofAggregator::default().with_config(config);
                deserialize_proofs(
                    &temp_aggregator.leaf_circuit_data.common,
                    config.num_leaf_proofs,
                )
            };

            c.bench_function(
                &format!(
                    "aggregate_proofs_{}_{}",
                    config.tree_branching_factor, config.tree_depth
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator =
                                WormholeProofAggregator::default().with_config(config);
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
    ($fn_name:ident, $tree_branching_factor:expr, $tree_depth:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let config = TreeAggregationConfig::new($tree_branching_factor, $tree_depth);

            // Setup proofs.
            let proofs = {
                let temp_aggregator = WormholeProofAggregator::default().with_config(config);
                deserialize_proofs(
                    &temp_aggregator.leaf_circuit_data.common,
                    config.num_leaf_proofs,
                )
            };

            c.bench_function(
                &format!(
                    "verify_aggregate_proof_{}_{}",
                    config.tree_branching_factor, config.tree_depth
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator =
                                WormholeProofAggregator::default().with_config(config);
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

// Various proof sizes with binary trees.
aggregate_proofs_benchmark!(bench_aggregate_2_proofs, 2, 1);
aggregate_proofs_benchmark!(bench_aggregate_4_proofs, 2, 2);
aggregate_proofs_benchmark!(bench_aggregate_8_proofs, 2, 3);
aggregate_proofs_benchmark!(bench_aggregate_16_proofs, 2, 4);
aggregate_proofs_benchmark!(bench_aggregate_32_proofs, 2, 5);

verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_2, 2, 1);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_4, 2, 2);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_8, 2, 3);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_16, 2, 4);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_32, 2, 5);

// Different tree configurations.
aggregate_proofs_benchmark!(bench_aggregate_proofs_3_2, 3, 2);
aggregate_proofs_benchmark!(bench_aggregate_proofs_4_2, 4, 2);
aggregate_proofs_benchmark!(bench_aggregate_proofs_5_2, 5, 2);
aggregate_proofs_benchmark!(bench_aggregate_proofs_6_2, 6, 2);
aggregate_proofs_benchmark!(bench_aggregate_proofs_7_2, 7, 2);

verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_3_2, 3, 2);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_4_2, 4, 2);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_8_2, 5, 2);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_6_2, 6, 2);
verify_aggregate_proof_benchmark!(bench_verify_aggregate_proof_7_2, 7, 2);

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10);
    targets = bench_aggregate_2_proofs, bench_aggregate_4_proofs, bench_aggregate_8_proofs, bench_aggregate_16_proofs, bench_aggregate_32_proofs,
              bench_verify_aggregate_proof_2, bench_verify_aggregate_proof_4, bench_verify_aggregate_proof_8, bench_verify_aggregate_proof_16, bench_verify_aggregate_proof_32,
              bench_aggregate_proofs_3_2, bench_aggregate_proofs_4_2, bench_aggregate_proofs_5_2, bench_aggregate_proofs_6_2, bench_aggregate_proofs_7_2,
              bench_verify_aggregate_proof_3_2, bench_verify_aggregate_proof_4_2, bench_verify_aggregate_proof_8_2, bench_verify_aggregate_proof_6_2, bench_verify_aggregate_proof_7_2,
);
criterion_main!(benches);
