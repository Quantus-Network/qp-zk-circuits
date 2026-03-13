use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;
use qp_wormhole_aggregator::aggregator::{AggregationBackend, Layer0Aggregator, Layer1Aggregator};
use qp_wormhole_aggregator::config::CircuitBinsConfig;
use qp_wormhole_aggregator::dummy_proof::load_dummy_proof;
use qp_wormhole_aggregator::layer0::circuit::build::generate_layer0_circuit_binaries;
use qp_wormhole_aggregator::layer1::circuit::build::generate_layer1_circuit_binaries;
use qp_wormhole_inputs::BytesDigest;
use zk_circuits_common::circuit::{C, D, F};

/// Generate dummy proofs from the circuit config (no external files needed).
const BINS_DIR: &str = "../../generated-bins";
const LAYER1_L0_NUM_LEAVES: usize = 8; // Must be consistent with the layer0 circuit binaries used in layer1 benchmarks.
const LAYER1_AGGREGATOR_ADDRESS: [u8; 32] = [42u8; 32];

type Proof = ProofWithPublicInputs<F, C, D>;

fn load_dummy_leaf_proof() -> Proof {
    let gate_serializer = DefaultGateSerializer;
    let proof_bytes = std::fs::read(format!("{}/dummy_proof.bin", BINS_DIR))
        .expect("Failed to read dummy proof bytes");
    let common_circuit_data = std::fs::read(format!("{}/common.bin", BINS_DIR))
        .expect("Failed to read common circuit data bytes");
    let common = CommonCircuitData::from_bytes(common_circuit_data.to_vec(), &gate_serializer)
        .expect("Failed to deserialize common circuit data");
    load_dummy_proof(proof_bytes, &common).expect("Failed to load dummy proof from bytes")
}
// Implement a helper to generate a dummy layer-0 proof with "LAYER1_L0_NUM_LEAVES"
fn generate_dummy_layer0_proof() -> Proof {
    let dummy_leaf_proof = load_dummy_leaf_proof();
    let mut aggregator = Layer0Aggregator::new(BINS_DIR).unwrap();
    for _ in 0..LAYER1_L0_NUM_LEAVES {
        aggregator.push_proof(dummy_leaf_proof.clone()).unwrap();
    }
    aggregator.aggregate().unwrap()
}

// A macro for creating an aggregation benchmark with a specified number of leaf proofs.
macro_rules! aggregate_proofs_benchmark {
    ($fn_name:ident, $num_leaf_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let proof = load_dummy_leaf_proof();

            // Call "generate_layer0_circuit_binaries" before we instantiate a new wormhole aggregator,
            // to ensure the binaries represent the circuit with the correct number of leaf proofs.
            generate_layer0_circuit_binaries(BINS_DIR, $num_leaf_proofs, true)
                .expect("Failed to generate layer0 circuit binaries for aggregation benchmark");
            let config = CircuitBinsConfig::new(BINS_DIR, $num_leaf_proofs, None)
                .expect("Failed to load circuit bins config for aggregation benchmark");
            config
                .save(BINS_DIR)
                .expect("Failed to save circuit bins config for aggregation benchmark");

            c.bench_function(&format!("aggregate_proofs_{}", $num_leaf_proofs), |b| {
                b.iter_batched(
                    || {
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
            let proof = load_dummy_leaf_proof();

            // Call "generate_layer0_circuit_binaries" before we instantiate a new wormhole aggregator,
            // to ensure the binaries represent the circuit with the correct number of leaf proofs.
            generate_layer0_circuit_binaries(BINS_DIR, $num_leaf_proofs, true)
                .expect("Failed to generate layer0 circuit binaries for aggregation benchmark");
            let config = CircuitBinsConfig::new(BINS_DIR, $num_leaf_proofs, None)
                .expect("Failed to load circuit bins config for aggregation benchmark");
            config
                .save(BINS_DIR)
                .expect("Failed to save circuit bins config for aggregation benchmark");

            c.bench_function(
                &format!("verify_aggregate_proof_{}", $num_leaf_proofs),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator = Layer0Aggregator::new(BINS_DIR).unwrap();
                            for proof in std::iter::repeat(proof.clone()).take($num_leaf_proofs) {
                                aggregator.push_proof(proof).unwrap();
                            }

                            (aggregator.aggregate().unwrap(), aggregator)
                        },
                        |(aggregated_proof, aggregator)| {
                            aggregator.verify(aggregated_proof).unwrap();
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

macro_rules! prove_layer1_benchmark {
    ($fn_name:ident, $num_layer0_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            generate_layer0_circuit_binaries(BINS_DIR, LAYER1_L0_NUM_LEAVES, true)
                .expect("Failed to generate layer0 circuit binaries for layer1 benchmark");

            let proof = generate_dummy_layer0_proof();
            generate_layer1_circuit_binaries(BINS_DIR, $num_layer0_proofs, true)
                .expect("Failed to generate layer1 circuit binaries for layer1 benchmark");

            let config =
                CircuitBinsConfig::new(BINS_DIR, LAYER1_L0_NUM_LEAVES, Some($num_layer0_proofs))
                    .expect("Failed to load circuit bins config for aggregation benchmark");
            config
                .save(BINS_DIR)
                .expect("Failed to save circuit bins config for aggregation benchmark");

            let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
                .expect("Failed to create aggregator address bytes digest");

            c.bench_function(
                &format!(
                    "prove_layer1_{}_l0leaves_{}",
                    $num_layer0_proofs, LAYER1_L0_NUM_LEAVES
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator =
                                Layer1Aggregator::new(BINS_DIR, aggregator_address).unwrap();
                            for proof in std::iter::repeat(proof.clone()).take($num_layer0_proofs) {
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

macro_rules! verify_layer1_benchmark {
    ($fn_name:ident, $num_layer0_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            generate_layer0_circuit_binaries(BINS_DIR, LAYER1_L0_NUM_LEAVES, true)
                .expect("Failed to generate layer0 circuit binaries for layer1 benchmark");

            let proof = generate_dummy_layer0_proof();

            generate_layer1_circuit_binaries(BINS_DIR, $num_layer0_proofs, true)
                .expect("Failed to generate layer1 circuit binaries for layer1 benchmark");

            let config =
                CircuitBinsConfig::new(BINS_DIR, LAYER1_L0_NUM_LEAVES, Some($num_layer0_proofs))
                    .expect("Failed to load circuit bins config for aggregation benchmark");
            config
                .save(BINS_DIR)
                .expect("Failed to save circuit bins config for aggregation benchmark");

            let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
                .expect("Failed to create aggregator address bytes digest");

            c.bench_function(
                &format!(
                    "verify_layer1_{}_l0leaves_{}",
                    $num_layer0_proofs, LAYER1_L0_NUM_LEAVES
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator =
                                Layer1Aggregator::new(BINS_DIR, aggregator_address).unwrap();
                            for proof in std::iter::repeat(proof.clone()).take($num_layer0_proofs) {
                                aggregator.push_proof(proof).unwrap();
                            }
                            (aggregator.aggregate().unwrap(), aggregator)
                        },
                        |(aggregated_proof, aggregator)| {
                            aggregator.verify(aggregated_proof).unwrap();
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

prove_layer1_benchmark!(bench_prove_layer1_2, 2);
prove_layer1_benchmark!(bench_prove_layer1_4, 4);
prove_layer1_benchmark!(bench_prove_layer1_8, 8);
prove_layer1_benchmark!(bench_prove_layer1_16, 16);
prove_layer1_benchmark!(bench_prove_layer1_32, 32);

verify_layer1_benchmark!(bench_verify_layer1_2, 2);
verify_layer1_benchmark!(bench_verify_layer1_4, 4);
verify_layer1_benchmark!(bench_verify_layer1_8, 8);
verify_layer1_benchmark!(bench_verify_layer1_16, 16);
verify_layer1_benchmark!(bench_verify_layer1_32, 32);

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10);
    targets = bench_aggregate_2_proofs, bench_aggregate_4_proofs, bench_aggregate_8_proofs, bench_aggregate_16_proofs, bench_aggregate_32_proofs,
              bench_verify_aggregate_proof_2, bench_verify_aggregate_proof_4, bench_verify_aggregate_proof_8, bench_verify_aggregate_proof_16, bench_verify_aggregate_proof_32,
              bench_aggregate_proofs_9, bench_aggregate_proofs_25, bench_aggregate_proofs_36, bench_aggregate_proofs_49,
              bench_verify_aggregate_proof_9, bench_verify_aggregate_proof_25, bench_verify_aggregate_proof_36, bench_verify_aggregate_proof_49,
              bench_prove_layer1_2, bench_prove_layer1_4, bench_prove_layer1_8, bench_prove_layer1_16, bench_prove_layer1_32,
              bench_verify_layer1_2, bench_verify_layer1_4, bench_verify_layer1_8, bench_verify_layer1_16, bench_verify_layer1_32,
);
criterion_main!(benches);
