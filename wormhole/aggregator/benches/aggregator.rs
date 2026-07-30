use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_aggregator::aggregator::PublicBatchAggregator;
use qp_wormhole_aggregator::common::utils::{
    canonical_leaf_verifier_data, load_canonical_private_batch_verifier_data,
};
use qp_wormhole_aggregator::config::CircuitBinsConfig;
use qp_wormhole_aggregator::private_batch::circuit::build::generate_private_batch_circuit_binaries;
use qp_wormhole_aggregator::private_batch::prover::PrivateBatchProver;
use qp_wormhole_aggregator::public_batch::circuit::build::generate_public_batch_circuit_binaries;
use qp_wormhole_aggregator::public_batch::prover::{PublicBatchInputs, PublicBatchProver};
use qp_wormhole_inputs::BytesDigest;
use std::path::Path;
use zk_circuits_common::circuit::{C, D, F};

/// Generate dummy proofs from the circuit config (no external files needed).
/// Path is relative to CARGO_MANIFEST_DIR (the aggregator crate root).
const BINS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../generated-bins");
const PUBLIC_BATCH_INNER_NUM_LEAVES: usize = 8; // Must be consistent with the private_batch circuit binaries used in public_batch benchmarks.
const LAYER1_AGGREGATOR_ADDRESS: [u8; 32] = [42u8; 32];

type Proof = ProofWithPublicInputs<F, C, D>;

fn make_private_prover() -> PrivateBatchProver {
    PrivateBatchProver::new_from_binaries_dir(Path::new(BINS_DIR))
        .expect("Failed to load private-batch prover from binaries dir")
}

/// Generate a REAL leaf proof (genuine block hash computed from the test
/// header fields) against the canonical leaf circuit.
///
/// The benches need non-dummy leaves because both `PrivateBatchProver::commit`
/// and `PublicBatchProver::commit` reject all-dummy batches (they settle
/// nothing on-chain). Proving cost is witness-independent, so batches built
/// from this proof measure the same work as production batches.
fn generate_real_leaf_proof() -> Proof {
    use test_helpers::TestInputs as _;
    use wormhole_circuit::block_header::header::HeaderInputs;
    use wormhole_circuit::inputs::CircuitInputs;

    let mut inputs = CircuitInputs::test_inputs_0();
    inputs.public.block_hash = HeaderInputs::try_from(&inputs)
        .expect("header inputs from test inputs")
        .block_hash();
    wormhole_prover::build_fresh()
        .commit(&inputs)
        .expect("Failed to commit real leaf inputs")
        .prove()
        .expect("Failed to prove real leaf")
}

/// Generate a REAL private-batch proof: one real leaf padded with dummy
/// leaves; see [`generate_real_leaf_proof`].
fn generate_real_private_batch_proof() -> Proof {
    make_private_prover()
        .aggregate(vec![generate_real_leaf_proof()])
        .expect("Failed to aggregate real leaf into a private batch")
}

// A macro for creating an aggregation benchmark with a specified number of leaf proofs.
macro_rules! aggregate_proofs_benchmark {
    ($fn_name:ident, $num_leaf_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let proof = generate_real_leaf_proof();

            // Call "generate_private_batch_circuit_binaries" before we instantiate a new prover,
            // to ensure the binaries represent the circuit with the correct number of leaf proofs.
            generate_private_batch_circuit_binaries(BINS_DIR, $num_leaf_proofs, true).expect(
                "Failed to generate private_batch circuit binaries for aggregation benchmark",
            );
            let config = CircuitBinsConfig::new($num_leaf_proofs, None)
                .expect("Failed to create circuit bins config for aggregation benchmark");
            config
                .save(BINS_DIR)
                .expect("Failed to save circuit bins config for aggregation benchmark");

            c.bench_function(&format!("aggregate_proofs_{}", $num_leaf_proofs), |b| {
                b.iter_batched(
                    || {
                        let prover = make_private_prover();
                        let proofs = vec![proof.clone(); $num_leaf_proofs];
                        (prover, proofs)
                    },
                    |(prover, proofs)| {
                        prover.aggregate(proofs).unwrap();
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
            let proof = generate_real_leaf_proof();

            generate_private_batch_circuit_binaries(BINS_DIR, $num_leaf_proofs, true).expect(
                "Failed to generate private_batch circuit binaries for aggregation benchmark",
            );
            let config = CircuitBinsConfig::new($num_leaf_proofs, None)
                .expect("Failed to create circuit bins config for aggregation benchmark");
            config
                .save(BINS_DIR)
                .expect("Failed to save circuit bins config for aggregation benchmark");

            let leaf = canonical_leaf_verifier_data();
            let verifier = load_canonical_private_batch_verifier_data(
                &std::fs::read(format!("{}/private_batch_common.bin", BINS_DIR))
                    .expect("Failed to read private_batch common bytes"),
                &std::fs::read(format!("{}/private_batch_verifier.bin", BINS_DIR))
                    .expect("Failed to read private_batch verifier bytes"),
                &leaf,
                $num_leaf_proofs,
            )
            .expect("Failed to load private-batch verifier data");

            c.bench_function(
                &format!("verify_aggregate_proof_{}", $num_leaf_proofs),
                |b| {
                    b.iter_batched(
                        || {
                            make_private_prover()
                                .aggregate(vec![proof.clone(); $num_leaf_proofs])
                                .unwrap()
                        },
                        |aggregated_proof| {
                            verifier.verify(aggregated_proof).unwrap();
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

macro_rules! prove_public_batch_benchmark {
    ($fn_name:ident, $num_private_batch_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            generate_private_batch_circuit_binaries(BINS_DIR, PUBLIC_BATCH_INNER_NUM_LEAVES, true)
                .expect(
                    "Failed to generate private_batch circuit binaries for public_batch benchmark",
                );

            let proof = generate_real_private_batch_proof();
            generate_public_batch_circuit_binaries(
                BINS_DIR,
                $num_private_batch_proofs,
                PUBLIC_BATCH_INNER_NUM_LEAVES,
            )
            .expect(
                "Failed to generate public_batch circuit binaries for public_batch benchmark",
            );

            let config = CircuitBinsConfig::new(
                PUBLIC_BATCH_INNER_NUM_LEAVES,
                Some($num_private_batch_proofs),
            )
            .expect("Failed to create circuit bins config for aggregation benchmark");
            config
                .save(BINS_DIR)
                .expect("Failed to save circuit bins config for aggregation benchmark");

            let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
                .expect("Failed to create aggregator address bytes digest");

            // The prover is driven directly: the benchmark batch reuses one real
            // private-batch proof N times, which the ProofPool would reject as
            // duplicate nullifiers (and generating N distinct private batches
            // would dwarf the benchmark setup).
            c.bench_function(
                &format!(
                    "prove_public_batch_{}_l0leaves_{}",
                    $num_private_batch_proofs, PUBLIC_BATCH_INNER_NUM_LEAVES
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let prover =
                                PublicBatchProver::new_from_binaries_dir(Path::new(BINS_DIR))
                                    .expect("Failed to load public-batch prover");
                            let proofs = vec![proof.clone(); $num_private_batch_proofs];
                            (prover, proofs)
                        },
                        |(prover, proofs)| {
                            prover
                                .commit(PublicBatchInputs {
                                    proofs,
                                    aggregator_address,
                                })
                                .unwrap()
                                .prove()
                                .unwrap();
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

macro_rules! verify_public_batch_benchmark {
    ($fn_name:ident, $num_private_batch_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            generate_private_batch_circuit_binaries(BINS_DIR, PUBLIC_BATCH_INNER_NUM_LEAVES, true)
                .expect(
                    "Failed to generate private_batch circuit binaries for public_batch benchmark",
                );

            let proof = generate_real_private_batch_proof();

            generate_public_batch_circuit_binaries(
                BINS_DIR,
                $num_private_batch_proofs,
                PUBLIC_BATCH_INNER_NUM_LEAVES,
            )
            .expect(
                "Failed to generate public_batch circuit binaries for public_batch benchmark",
            );

            let config = CircuitBinsConfig::new(
                PUBLIC_BATCH_INNER_NUM_LEAVES,
                Some($num_private_batch_proofs),
            )
            .expect("Failed to create circuit bins config for aggregation benchmark");
            config
                .save(BINS_DIR)
                .expect("Failed to save circuit bins config for aggregation benchmark");

            let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
                .expect("Failed to create aggregator address bytes digest");
            let aggregator = PublicBatchAggregator::new(BINS_DIR, aggregator_address)
                .expect("Failed to create public-batch aggregator");

            c.bench_function(
                &format!(
                    "verify_public_batch_{}_l0leaves_{}",
                    $num_private_batch_proofs, PUBLIC_BATCH_INNER_NUM_LEAVES
                ),
                |b| {
                    b.iter_batched(
                        || {
                            PublicBatchProver::new_from_binaries_dir(Path::new(BINS_DIR))
                                .expect("Failed to load public-batch prover")
                                .commit(PublicBatchInputs {
                                    proofs: vec![proof.clone(); $num_private_batch_proofs],
                                    aggregator_address,
                                })
                                .unwrap()
                                .prove()
                                .unwrap()
                        },
                        |aggregated_proof| {
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

prove_public_batch_benchmark!(bench_prove_public_batch_2, 2);
prove_public_batch_benchmark!(bench_prove_public_batch_4, 4);
prove_public_batch_benchmark!(bench_prove_public_batch_8, 8);
prove_public_batch_benchmark!(bench_prove_public_batch_16, 16);
prove_public_batch_benchmark!(bench_prove_public_batch_32, 32);

verify_public_batch_benchmark!(bench_verify_public_batch_2, 2);
verify_public_batch_benchmark!(bench_verify_public_batch_4, 4);
verify_public_batch_benchmark!(bench_verify_public_batch_8, 8);
verify_public_batch_benchmark!(bench_verify_public_batch_16, 16);
verify_public_batch_benchmark!(bench_verify_public_batch_32, 32);

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10);
    targets = bench_aggregate_2_proofs, bench_aggregate_4_proofs, bench_aggregate_8_proofs, bench_aggregate_16_proofs, bench_aggregate_32_proofs,
              bench_verify_aggregate_proof_2, bench_verify_aggregate_proof_4, bench_verify_aggregate_proof_8, bench_verify_aggregate_proof_16, bench_verify_aggregate_proof_32,
              bench_aggregate_proofs_9, bench_aggregate_proofs_25, bench_aggregate_proofs_36, bench_aggregate_proofs_49,
              bench_verify_aggregate_proof_9, bench_verify_aggregate_proof_25, bench_verify_aggregate_proof_36, bench_verify_aggregate_proof_49,
              bench_prove_public_batch_2, bench_prove_public_batch_4, bench_prove_public_batch_8, bench_prove_public_batch_16, bench_prove_public_batch_32,
              bench_verify_public_batch_2, bench_verify_public_batch_4, bench_verify_public_batch_8, bench_verify_public_batch_16, bench_verify_public_batch_32,
);
criterion_main!(benches);
