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
use std::sync::Once;
use zk_circuits_common::circuit::{C, D, F};

/// Per-process artifact directory. Every bench function regenerates circuit
/// binaries sized for its own parameters, so the directory is mutable shared
/// state: pointing it at the checked-in `generated-bins` clobbers those
/// artifacts, and two concurrent bench processes corrupt each other mid-run
/// (e.g. an `aggregate_proofs_*` setup saving a config without
/// `num_private_batch_proofs` while another process measures a public-batch
/// bench). A pid-suffixed temp dir keeps processes isolated.
fn bins_dir() -> &'static str {
    use std::sync::OnceLock;
    static DIR: OnceLock<String> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = format!(
            "{}/aggregator-bench-bins-{}",
            env!("CARGO_TARGET_TMPDIR"),
            std::process::id()
        );
        std::fs::create_dir_all(&dir).expect("Failed to create bench bins dir");
        dir
    })
}
// Must be consistent with the private_batch circuit binaries used in
// public_batch benchmarks. 7 matches the production bins quantus-cli generates
// (num_leaf_proofs=7, num_private_batch_proofs=53).
const PUBLIC_BATCH_INNER_NUM_LEAVES: usize = 7;
const LAYER1_AGGREGATOR_ADDRESS: [u8; 32] = [42u8; 32];

type Proof = ProofWithPublicInputs<F, C, D>;

/// The batch-circuit generators load the leaf artifacts (`common.bin`,
/// `verifier.bin`, `dummy_proof.bin`) from `bins_dir()` and byte-pin them
/// against a canonical rebuild of the current leaf circuit, so artifacts
/// checked in from an older circuit version fail with "does not match the
/// canonical circuit". Regenerate them from source once per bench process.
fn ensure_canonical_leaf_artifacts() {
    static LEAF_BINS: Once = Once::new();
    LEAF_BINS.call_once(|| {
        wormhole_circuit_builder::generate_circuit_binaries(bins_dir())
            .expect("Failed to regenerate canonical leaf circuit binaries");
    });
}

/// Criterion still executes every target function's *setup* when a name
/// filter is passed on the CLI, and setup here means minutes of circuit
/// generation per target. Skip setup for targets whose bench name can't match
/// the filter (the first positional CLI argument). Only literal filters are
/// handled; regex filters fall through to running every target's setup.
fn skip_by_filter(bench_name: &str) -> bool {
    match std::env::args().nth(1) {
        Some(filter)
            if !filter.is_empty()
                && filter
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_') =>
        {
            !bench_name.contains(&filter)
        }
        _ => false,
    }
}

fn make_private_prover() -> PrivateBatchProver {
    PrivateBatchProver::new_from_binaries_dir(Path::new(bins_dir()))
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
            let bench_name = format!("aggregate_proofs_{}", $num_leaf_proofs);
            if skip_by_filter(&bench_name) {
                return;
            }
            ensure_canonical_leaf_artifacts();
            let proof = generate_real_leaf_proof();

            // Call "generate_private_batch_circuit_binaries" before we instantiate a new prover,
            // to ensure the binaries represent the circuit with the correct number of leaf proofs.
            generate_private_batch_circuit_binaries(bins_dir(), $num_leaf_proofs, true).expect(
                "Failed to generate private_batch circuit binaries for aggregation benchmark",
            );
            let config = CircuitBinsConfig::new($num_leaf_proofs, None)
                .expect("Failed to create circuit bins config for aggregation benchmark");
            config
                .save(bins_dir())
                .expect("Failed to save circuit bins config for aggregation benchmark");

            let prover = make_private_prover();

            // One real leaf; the prover pads the remaining slots with dummy
            // proofs (distinct random nullifiers). The circuit always proves
            // all $num_leaf_proofs slots, so this measures the same work as a
            // full batch — duplicating the real proof would be rejected by
            // the pairwise-distinct-nullifier check.
            c.bench_function(&bench_name, |b| {
                b.iter_batched(
                    || vec![proof.clone()],
                    |proofs| {
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
            let bench_name = format!("verify_aggregate_proof_{}", $num_leaf_proofs);
            if skip_by_filter(&bench_name) {
                return;
            }
            ensure_canonical_leaf_artifacts();
            let proof = generate_real_leaf_proof();

            generate_private_batch_circuit_binaries(bins_dir(), $num_leaf_proofs, true).expect(
                "Failed to generate private_batch circuit binaries for aggregation benchmark",
            );
            let config = CircuitBinsConfig::new($num_leaf_proofs, None)
                .expect("Failed to create circuit bins config for aggregation benchmark");
            config
                .save(bins_dir())
                .expect("Failed to save circuit bins config for aggregation benchmark");

            let leaf = canonical_leaf_verifier_data();
            let verifier = load_canonical_private_batch_verifier_data(
                &std::fs::read(format!("{}/private_batch_common.bin", bins_dir()))
                    .expect("Failed to read private_batch common bytes"),
                &std::fs::read(format!("{}/private_batch_verifier.bin", bins_dir()))
                    .expect("Failed to read private_batch verifier bytes"),
                &leaf,
                $num_leaf_proofs,
            )
            .expect("Failed to load private-batch verifier data");

            let prover = make_private_prover();

            c.bench_function(&bench_name, |b| {
                b.iter_batched(
                    || {
                        // One real leaf, dummy-padded (see aggregate_proofs_*).
                        prover.aggregate(vec![proof.clone()]).unwrap()
                    },
                    |aggregated_proof| {
                        verifier.verify(aggregated_proof).unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    };
}

macro_rules! prove_public_batch_benchmark {
    ($fn_name:ident, $num_private_batch_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let bench_name = format!(
                "prove_public_batch_{}_l0leaves_{}",
                $num_private_batch_proofs, PUBLIC_BATCH_INNER_NUM_LEAVES
            );
            if skip_by_filter(&bench_name) {
                return;
            }
            ensure_canonical_leaf_artifacts();
            generate_private_batch_circuit_binaries(
                bins_dir(),
                PUBLIC_BATCH_INNER_NUM_LEAVES,
                true,
            )
            .expect("Failed to generate private_batch circuit binaries for public_batch benchmark");

            generate_public_batch_circuit_binaries(
                bins_dir(),
                $num_private_batch_proofs,
                PUBLIC_BATCH_INNER_NUM_LEAVES,
            )
            .expect("Failed to generate public_batch circuit binaries for public_batch benchmark");

            let config = CircuitBinsConfig::new(
                PUBLIC_BATCH_INNER_NUM_LEAVES,
                Some($num_private_batch_proofs),
            )
            .expect("Failed to create circuit bins config for aggregation benchmark");
            config
                .save(bins_dir())
                .expect("Failed to save circuit bins config for aggregation benchmark");

            // AFTER config.save: the private-batch prover sizes its circuit
            // from config.json, which until now still described the previous
            // bench's leaf count.
            let proof = generate_real_private_batch_proof();

            let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
                .expect("Failed to create aggregator address bytes digest");

            // Built once and reused across iterations, like production
            // (ProvingContext builds the circuit once at aggregator
            // construction and proves many batches against it).
            let prover = PublicBatchProver::new_from_binaries_dir(Path::new(bins_dir()))
                .expect("Failed to load public-batch prover");

            // One real private batch; the prover pads the remaining slots with
            // dummy private-batch proofs. The circuit always proves all
            // $num_private_batch_proofs slots, so this measures the same work
            // as a full batch — duplicating the real proof would be rejected
            // as duplicate nullifiers (and generating N distinct private
            // batches would dwarf the benchmark setup).
            c.bench_function(&bench_name, |b| {
                b.iter_batched(
                    || vec![proof.clone()],
                    |proofs| {
                        prover
                            .prove_batch(PublicBatchInputs {
                                proofs,
                                aggregator_address,
                            })
                            .unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    };
}

macro_rules! verify_public_batch_benchmark {
    ($fn_name:ident, $num_private_batch_proofs:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            let bench_name = format!(
                "verify_public_batch_{}_l0leaves_{}",
                $num_private_batch_proofs, PUBLIC_BATCH_INNER_NUM_LEAVES
            );
            if skip_by_filter(&bench_name) {
                return;
            }
            ensure_canonical_leaf_artifacts();
            generate_private_batch_circuit_binaries(
                bins_dir(),
                PUBLIC_BATCH_INNER_NUM_LEAVES,
                true,
            )
            .expect("Failed to generate private_batch circuit binaries for public_batch benchmark");

            generate_public_batch_circuit_binaries(
                bins_dir(),
                $num_private_batch_proofs,
                PUBLIC_BATCH_INNER_NUM_LEAVES,
            )
            .expect("Failed to generate public_batch circuit binaries for public_batch benchmark");

            let config = CircuitBinsConfig::new(
                PUBLIC_BATCH_INNER_NUM_LEAVES,
                Some($num_private_batch_proofs),
            )
            .expect("Failed to create circuit bins config for aggregation benchmark");
            config
                .save(bins_dir())
                .expect("Failed to save circuit bins config for aggregation benchmark");

            // AFTER config.save: the private-batch prover sizes its circuit
            // from config.json, which until now still described the previous
            // bench's leaf count.
            let proof = generate_real_private_batch_proof();

            let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
                .expect("Failed to create aggregator address bytes digest");
            let aggregator = PublicBatchAggregator::new(bins_dir(), aggregator_address)
                .expect("Failed to create public-batch aggregator");

            let prover = PublicBatchProver::new_from_binaries_dir(Path::new(bins_dir()))
                .expect("Failed to load public-batch prover");

            c.bench_function(&bench_name, |b| {
                b.iter_batched(
                    || {
                        // One real private batch, dummy-padded (see
                        // prove_public_batch_*).
                        prover
                            .prove_batch(PublicBatchInputs {
                                proofs: vec![proof.clone()],
                                aggregator_address,
                            })
                            .unwrap()
                    },
                    |aggregated_proof| {
                        aggregator.verify(aggregated_proof).unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
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
// Production circuit size (quantus-cli generates bins with 53 slots).
prove_public_batch_benchmark!(bench_prove_public_batch_53, 53);

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
              bench_prove_public_batch_53,
              bench_verify_public_batch_2, bench_verify_public_batch_4, bench_verify_public_batch_8, bench_verify_public_batch_16, bench_verify_public_batch_32,
);
criterion_main!(benches);
