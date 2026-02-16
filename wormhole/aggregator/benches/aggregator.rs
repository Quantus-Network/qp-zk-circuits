use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_aggregator::aggregator::WormholeProofAggregator;
use zk_circuits_common::aggregation::AggregationConfig;
use zk_circuits_common::circuit::{C, D, F};

/// Generate dummy proofs from the circuit config (no external files needed).
fn make_dummy_proofs(
    aggregator: &WormholeProofAggregator,
    len: usize,
) -> Vec<ProofWithPublicInputs<F, C, D>> {
    use plonky2::iop::witness::PartialWitness;
    use qp_wormhole_aggregator::build_dummy_circuit_inputs;
    use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
    use wormhole_prover::fill_witness;

    let config = aggregator.leaf_circuit_data.common.config.clone();
    let circuit = WormholeCircuit::new(config);
    let targets = circuit.targets();
    let circuit_data = circuit.build_circuit();
    let inputs = build_dummy_circuit_inputs().expect("failed to build dummy inputs");
    let mut pw = PartialWitness::new();
    fill_witness(&mut pw, &inputs, &targets).expect("failed to fill witness");
    let dummy_proof = circuit_data.prove(pw).expect("failed to prove dummy");
    (0..len).map(|_| dummy_proof.clone()).collect()
}

// A macro for creating an aggregation benchmark with a specified number of leaf proofs.
macro_rules! aggregate_proofs_benchmark {
    ($fn_name:ident, $num_leaf_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let aggregation_config = AggregationConfig::new($num_leaf_proofs);
            let circuit_config = CircuitConfig::standard_recursion_zk_config();

            // Setup proofs (generated from circuit config, no external files needed).
            let temp_aggregator = WormholeProofAggregator::from_circuit_config(
                circuit_config.clone(),
                aggregation_config,
            );
            let proofs = make_dummy_proofs(&temp_aggregator, aggregation_config.num_leaf_proofs);

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

            // Setup proofs (generated from circuit config, no external files needed).
            let temp_aggregator = WormholeProofAggregator::from_circuit_config(
                circuit_config.clone(),
                aggregation_config,
            );
            let proofs = make_dummy_proofs(&temp_aggregator, aggregation_config.num_leaf_proofs);

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
