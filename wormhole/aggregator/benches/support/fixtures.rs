//! Circuit artifacts and real proofs shared by the aggregator benches.
#![allow(dead_code)]
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_aggregator::config::CircuitBinsConfig;
use qp_wormhole_aggregator::private_batch::circuit::build::generate_private_batch_circuit_binaries;
use qp_wormhole_aggregator::private_batch::prover::{PrivateBatchInputs, PrivateBatchProver};
use qp_wormhole_aggregator::public_batch::circuit::build::generate_public_batch_circuit_binaries;
use qp_wormhole_aggregator::{production, PrivateBatchShape};
use std::path::Path;
use std::sync::Once;
use zk_circuits_common::circuit::{C, D, F};

pub type Proof = ProofWithPublicInputs<F, C, D>;

/// Per-process artifact directory. Every bench function regenerates circuit
/// binaries sized for its own parameters, so the directory is mutable shared
/// state: pointing it at the checked-in `generated-bins` clobbers those
/// artifacts, and two concurrent bench processes corrupt each other mid-run
/// (e.g. an `aggregate_proofs_*` setup saving a config without
/// `num_private_batch_proofs` while another process measures a public-batch
/// bench). A pid-suffixed temp dir keeps processes isolated.
pub fn bins_dir() -> &'static str {
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
// public_batch benchmarks: the production shape quantus-cli generates bins for.
pub const PUBLIC_BATCH_INNER_NUM_LEAVES: usize = production::NUM_LEAF_PROOFS;
pub const PUBLIC_BATCH_INNER_SHAPE: PrivateBatchShape = production::PRIVATE_BATCH_SHAPE;
pub const LAYER1_AGGREGATOR_ADDRESS: [u8; 32] = [42u8; 32];

/// The batch-circuit generators load the leaf artifacts (`common.bin`,
/// `verifier.bin`, `dummy_proof.bin`) from `bins_dir()` and byte-pin them
/// against a canonical rebuild of the current leaf circuit, so artifacts
/// checked in from an older circuit version fail with "does not match the
/// canonical circuit". Regenerate them from source once per bench process.
pub fn ensure_canonical_leaf_artifacts() {
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
pub fn skip_by_filter(bench_name: &str) -> bool {
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

pub fn make_private_prover() -> PrivateBatchProver {
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
pub fn generate_real_leaf_proof() -> Proof {
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
pub fn generate_real_private_batch_proof() -> Proof {
    make_private_prover()
        .aggregate(single_leaf_inputs(generate_real_leaf_proof()))
        .expect("Failed to aggregate real leaf into a private batch")
}

/// Private-batch inputs for one real leaf with no withdrawals (the prover
/// pads the remaining leaf and exit slots). Proving cost is witness-independent.
pub fn single_leaf_inputs(leaf: Proof) -> PrivateBatchInputs {
    PrivateBatchInputs {
        leaf_proofs: vec![leaf],
        outputs: Vec::new(),
        volume_fee_bps: 0,
    }
}

/// Regenerate the private- and public-batch artifacts in `bins_dir()` for a
/// public batch of `num_private_batch_proofs` seven-leaf inner proofs, save the
/// matching config, and return one real private-batch proof to feed it.
///
/// The private-batch prover sizes its circuit from `config.json`, so the
/// proof is generated only after the config is saved.
pub fn prepare_public_batch_fixture(num_private_batch_proofs: usize) -> Proof {
    ensure_canonical_leaf_artifacts();
    generate_private_batch_circuit_binaries(bins_dir(), PUBLIC_BATCH_INNER_SHAPE, true)
        .expect("Failed to generate private_batch circuit binaries for public_batch benchmark");
    generate_public_batch_circuit_binaries(
        bins_dir(),
        num_private_batch_proofs,
        PUBLIC_BATCH_INNER_SHAPE,
    )
    .expect("Failed to generate public_batch circuit binaries for public_batch benchmark");
    CircuitBinsConfig::new(PUBLIC_BATCH_INNER_SHAPE, Some(num_private_batch_proofs))
        .expect("Failed to create circuit bins config for public_batch benchmark")
        .save(bins_dir())
        .expect("Failed to save circuit bins config for public_batch benchmark");
    generate_real_private_batch_proof()
}
