#![cfg(test)]

use circuit_builder::generate_all_circuit_binaries;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::{BytesDigest, PublicCircuitInputs};
use std::path::PathBuf;
use std::sync::{Once, OnceLock};
use test_helpers::block_header::{
    DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_STATE_ROOTS,
};
use test_helpers::{
    compute_zk_leaf_hash, TestInputs, DEFAULT_EXIT_ACCOUNT, DEFAULT_INPUT_AMOUNTS, DEFAULT_SECRETS,
    DEFAULT_TRANSFER_COUNTS, DEFAULT_VOLUME_FEE_BPS,
};
use wormhole_aggregator::aggregator::PublicBatchAggregator;
use wormhole_aggregator::common::utils::{
    load_canonical_leaf_verifier_data, load_canonical_private_batch_verifier_data,
};
use wormhole_aggregator::pool::BatchKey;
use wormhole_aggregator::private_batch::prover::PrivateBatchProver;
use wormhole_circuit::inputs::{CircuitInputs, ParsePublicInputs, PrivateCircuitInputs};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::digest_to_bytes;
use zk_circuits_common::zk_merkle::{hash_node, Hash256, SIBLINGS_PER_LEVEL};

use crate::aggregator::circuit_config;

/// Leaves per private batch in the client-side test artifacts.
const PRIVATE_NUM_LEAVES: usize = 2;

static TEST_INIT: Once = Once::new();
static PUBLIC_TEST_INIT: Once = Once::new();

/// Absolute per-process root for generated circuit artifacts.
///
/// Tests previously used cwd-relative directories, which made every test in
/// the binary sensitive to the working directory and to sibling tests'
/// cleanup. Absolute paths keyed by pid keep parallel test binaries and
/// reruns isolated from each other.
fn test_bins_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        std::env::temp_dir().join(format!(
            "qp-wormhole-aggregator-tests-{}",
            std::process::id()
        ))
    })
}

fn private_bins_dir() -> PathBuf {
    test_bins_root().join("private")
}

fn public_bins_dir() -> PathBuf {
    test_bins_root().join("public")
}

extern "C" fn cleanup_test_bins_root() {
    // Best-effort cleanup (don't panic during shutdown).
    let _ = std::fs::remove_dir_all(test_bins_root());
}

fn setup_test_binaries() {
    TEST_INIT.call_once(|| {
        generate_all_circuit_binaries(private_bins_dir(), true, PRIVATE_NUM_LEAVES, None)
            .expect("Failed to generate test circuit binaries");

        // Register a process-exit cleanup so the directory is removed once all tests finish.
        unsafe {
            // Ignore return value; if registration fails we simply won't auto-clean.
            let _ = libc::atexit(cleanup_test_bins_root);
        }
    });
}

fn setup_public_test_binaries() {
    PUBLIC_TEST_INIT.call_once(|| {
        // Smallest public-batch circuit (1 inner private-batch of 1 leaf) to keep
        // artifact generation fast.
        generate_all_circuit_binaries(public_bins_dir(), true, 1, Some(1))
            .expect("Failed to generate public-batch test circuit binaries");

        unsafe {
            let _ = libc::atexit(cleanup_test_bins_root);
        }
    });
}

fn make_leaf_proof(inputs: &CircuitInputs) -> ProofWithPublicInputs<F, C, D> {
    // The leaf prover is always built from source; it no longer loads a prover.bin,
    // so leaf proofs are independent of any generated artifact directory.
    wormhole_prover::build_fresh()
        .commit(inputs)
        .unwrap()
        .prove()
        .unwrap()
}

fn make_private_batch_prover() -> PrivateBatchProver {
    setup_test_binaries();
    PrivateBatchProver::new_from_binaries_dir(&private_bins_dir())
        .expect("Failed to load private-batch prover from generated binaries")
}

/// Canonical-pinned verifier for the client-side private-batch artifacts.
fn private_batch_verifier() -> VerifierCircuitData<F, C, D> {
    setup_test_binaries();
    let dir = private_bins_dir();
    let leaf = load_canonical_leaf_verifier_data(
        &std::fs::read(dir.join("common.bin")).unwrap(),
        &std::fs::read(dir.join("verifier.bin")).unwrap(),
    )
    .expect("Failed to load leaf verifier data");
    load_canonical_private_batch_verifier_data(
        &std::fs::read(dir.join("private_batch_common.bin")).unwrap(),
        &std::fs::read(dir.join("private_batch_verifier.bin")).unwrap(),
        &leaf,
        PRIVATE_NUM_LEAVES,
    )
    .expect("Failed to load private-batch verifier data")
}

/// Valid leaf inputs like `test_inputs_0` but with a REAL block hash computed
/// from the header fields, so the proof is non-dummy (`test_inputs_0` uses the
/// dummy sentinel `block_hash == 0`, which pools into the dummy bucket that
/// `PublicBatchAggregator` refuses to aggregate).
/// Replace the dummy-sentinel block hash (0) with the genuine hash of the
/// inputs' header fields, making the resulting leaf proof non-dummy. Needed
/// wherever a batch is aggregated: `PrivateBatchProver::commit` rejects
/// all-dummy leaf batches (they settle nothing on-chain).
fn with_real_block(mut inputs: CircuitInputs) -> CircuitInputs {
    use wormhole_circuit::block_header::header::HeaderInputs;

    inputs.public.block_hash = HeaderInputs::try_from(&inputs)
        .expect("header inputs from test inputs")
        .block_hash();
    inputs
}

fn test_inputs_with_real_block() -> CircuitInputs {
    with_real_block(CircuitInputs::test_inputs_0())
}

/// Valid leaf inputs like `test_inputs_0` but for a non-native asset. The asset
/// id is part of the ZK leaf hash, so the tree root must be recomputed.
fn test_inputs_with_asset(asset_id: u32) -> CircuitInputs {
    let mut inputs = CircuitInputs::test_inputs_0();
    inputs.public.asset_id = asset_id;
    inputs.private.zk_tree_root = compute_zk_leaf_hash(
        &inputs.private.unspendable_account,
        inputs.private.transfer_count,
        asset_id,
        inputs.private.input_amount,
    );
    inputs
}

/// Depth-1 merkle proof for `leaf_index` in a 4-child node (arity 4).
fn depth1_merkle_proof(
    leaf_index: usize,
    leaves: &[Hash256; 4],
) -> (Vec<[Hash256; SIBLINGS_PER_LEVEL]>, Vec<u8>, Hash256) {
    let root = hash_node(leaves).expect("test leaves are canonical");
    let mut children = *leaves;
    let current = children[leaf_index];
    children.sort();
    let sorted_position = children.iter().position(|h| *h == current).unwrap() as u8;
    let mut siblings = [[0u8; 32]; SIBLINGS_PER_LEVEL];
    let mut sib_idx = 0;
    for (i, child) in children.iter().enumerate() {
        if i as u8 != sorted_position {
            siblings[sib_idx] = *child;
            sib_idx += 1;
        }
    }
    (vec![siblings], vec![sorted_position], root)
}

/// Two distinct real spends under one shared zk-tree root / block_hash.
///
/// Depth-0 fixtures cannot do this: `block_hash` commits to `zk_tree_root`, and
/// a depth-0 root equals the single leaf hash — so two different spends would
/// get two different blocks. A depth-1 (4-ary) tree lets both leaves share a
/// root. Required now that the private-batch circuit rejects duplicate real
/// nullifiers (replaying one leaf across two slots is no longer valid).
fn two_real_leaves_same_block(asset_id: u32) -> (CircuitInputs, CircuitInputs) {
    let mut leaf_hashes = [[0u8; 32]; 4];
    let mut accounts = [BytesDigest::default(); 2];
    let mut nullifiers = [BytesDigest::default(); 2];
    let mut secrets = [BytesDigest::default(); 2];

    for i in 0..2 {
        let secret: BytesDigest = hex::decode(DEFAULT_SECRETS[i].trim()).unwrap()[..32]
            .try_into()
            .unwrap();
        secrets[i] = secret;
        accounts[i] = digest_to_bytes(UnspendableAccount::from_secret(secret).account_id);
        nullifiers[i] =
            digest_to_bytes(Nullifier::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[i]).hash);
        leaf_hashes[i] = compute_zk_leaf_hash(
            &accounts[i],
            DEFAULT_TRANSFER_COUNTS[i],
            asset_id,
            DEFAULT_INPUT_AMOUNTS[i],
        );
    }
    // Pad the 4-ary node with zero hashes (canonical empty siblings).

    let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();
    let mut out = Vec::with_capacity(2);
    for i in 0..2 {
        let (siblings, positions, root) = depth1_merkle_proof(i, &leaf_hashes);
        let inputs = CircuitInputs {
            public: PublicCircuitInputs {
                asset_id,
                output_amount_1: 0,
                output_amount_2: 0,
                volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
                nullifier: nullifiers[i],
                exit_account_1: exit_account,
                exit_account_2: BytesDigest::default(),
                block_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                block_number: DEFAULT_BLOCK_NUMBERS[0],
            },
            private: PrivateCircuitInputs {
                secret: secrets[i].into(),
                transfer_count: DEFAULT_TRANSFER_COUNTS[i],
                unspendable_account: accounts[i],
                parent_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                state_root: BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
                extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
                digest: DEFAULT_DIGESTS[0],
                input_amount: DEFAULT_INPUT_AMOUNTS[i],
                zk_tree_root: root,
                zk_merkle_siblings: siblings,
                zk_merkle_positions: positions,
            },
        };
        out.push(with_real_block(inputs));
    }
    assert_eq!(out[0].public.block_hash, out[1].public.block_hash);
    assert_ne!(out[0].public.nullifier, out[1].public.nullifier);
    (out.remove(0), out.remove(0))
}

// ============================================================================
// Client-side (private batch): one-shot aggregation, no queue
// ============================================================================

#[test]
fn aggregate_single_proof() {
    let proof = make_leaf_proof(&test_inputs_with_real_block());

    // A single proof in a 2-slot batch exercises dummy padding.
    let aggregated = make_private_batch_prover()
        .aggregate(vec![proof])
        .expect("aggregation must succeed");
    private_batch_verifier()
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn aggregate_proofs_into_tree() {
    // Same block, distinct nullifiers (depth-1 shared zk tree).
    let (inputs_0, inputs_1) = two_real_leaves_same_block(0);

    let proof_0 = make_leaf_proof(&inputs_0);
    let proof_1 = make_leaf_proof(&inputs_1);

    let pi0 = PublicCircuitInputs::try_from_proof(&proof_0).unwrap();
    let pi1 = PublicCircuitInputs::try_from_proof(&proof_1).unwrap();
    assert_eq!(pi0.block_hash, pi1.block_hash);
    assert_ne!(pi0.nullifier, pi1.nullifier);

    let aggregated = make_private_batch_prover()
        .aggregate(vec![proof_0, proof_1])
        .expect("aggregation must succeed");
    private_batch_verifier()
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

#[test]
fn commit_rejects_nonzero_asset_id_when_dummy_padding_is_needed() {
    // A cryptographically valid non-native-asset leaf in a partial batch needs
    // dummy padding (asset_id = 0). Commit must reject that mismatch before
    // proving. (Tampering with asset_id on an existing proof would fail the
    // leaf-verify-at-commit check first; this exercises the padding preflight.)
    let proof = make_leaf_proof(&with_real_block(test_inputs_with_asset(5)));

    let prover = make_private_batch_prover();
    let err = prover.commit(vec![proof]).unwrap_err();
    assert!(
        err.to_string().contains("dummy proofs use asset_id=0"),
        "got: {err}"
    );
}

#[test]
fn aggregate_rejects_empty_batch() {
    // Without leaf proofs, commit would pad the entire batch with the dummy
    // template and prove an all-dummy private batch that settles nothing.
    // The client entry point must reject that instead (the intentional
    // all-dummy template is built on the circuit-build path, not here).
    let err = make_private_batch_prover().aggregate(vec![]).unwrap_err();
    assert!(err.to_string().contains("no leaf proofs"), "got: {err}");
}

#[test]
fn commit_rejects_batch_incompatible_proofs() {
    // Two individually valid proofs whose metadata the private-batch circuit's
    // cross-slot constraints reject (different asset ids) must fail fast at
    // commit time, not a full proving run later.
    let proof_asset_0 = make_leaf_proof(&CircuitInputs::test_inputs_0());
    let proof_asset_5 = make_leaf_proof(&test_inputs_with_asset(5));

    let prover = make_private_batch_prover();
    let err = prover
        .commit(vec![proof_asset_0, proof_asset_5])
        .unwrap_err();
    assert!(err.to_string().contains("asset"), "got: {err}");
}

#[test]
fn full_batch_of_same_nonzero_asset_aggregates() {
    // Sanity check for the fail-fast path: a FULL batch of same-asset proofs
    // needs no dummy padding, so a non-native asset is fine and the
    // compatibility preflight lets it through to real proving. Nullifiers
    // must still be distinct.
    let (inputs_0, inputs_1) = two_real_leaves_same_block(5);
    let proof_0 = make_leaf_proof(&inputs_0);
    let proof_1 = make_leaf_proof(&inputs_1);

    let aggregated = make_private_batch_prover()
        .aggregate(vec![proof_0, proof_1])
        .expect("full same-asset batch must aggregate");
    private_batch_verifier()
        .verify(aggregated)
        .expect("Aggregated proof should verify");
}

/// This simulates a CLI-ish flow without prebuilt binaries:
/// 1. Generate proofs from separate prover instances
/// 2. Serialize proof bytes (hex like the CLI handoff format)
/// 3. Deserialize using a fresh common_data
/// 4. Aggregate them one-shot
#[test]
fn aggregate_proofs_from_separate_prover_instances_hex_serialized() {
    setup_test_binaries();

    let (inputs_1, inputs_2) = two_real_leaves_same_block(0);

    // Proof 1 from prover A
    let prover_a = WormholeProver::new(circuit_config());
    let proof_1 = prover_a.commit(&inputs_1).unwrap().prove().unwrap();
    let proof_1_hex = hex::encode(proof_1.to_bytes());

    // Proof 2 from prover B (same block, distinct nullifier)
    let prover_b = WormholeProver::new(circuit_config());
    let proof_2 = prover_b.commit(&inputs_2).unwrap().prove().unwrap();
    let proof_2_hex = hex::encode(proof_2.to_bytes());

    // Use fresh common_data to deserialize like CLI would
    let deser_common_data = WormholeProver::new(circuit_config()).circuit_data.common;

    let proof_1_bytes = hex::decode(&proof_1_hex).expect("Failed to decode proof 1 hex");
    let proof_2_bytes = hex::decode(&proof_2_hex).expect("Failed to decode proof 2 hex");

    let proof_1_deserialized: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof_1_bytes, &deser_common_data)
            .expect("Failed to deserialize proof 1");

    let proof_2_deserialized: ProofWithPublicInputs<F, C, D> =
        ProofWithPublicInputs::from_bytes(proof_2_bytes, &deser_common_data)
            .expect("Failed to deserialize proof 2");

    let aggregated = make_private_batch_prover()
        .aggregate(vec![proof_1_deserialized, proof_2_deserialized])
        .expect("Aggregation failed");

    private_batch_verifier()
        .verify(aggregated)
        .expect("Aggregated proof verification failed");
}

#[test]
fn private_batch_commit_rejects_malformed_full_batch_at_api_boundary() {
    // A full 2-proof batch where one proof has the wrong public-input length must
    // be rejected at the API boundary instead of panicking in witness assignment.
    // Previously the length check ran only when dummy padding was needed (#97073).
    let mut malformed = make_leaf_proof(&CircuitInputs::test_inputs_0());
    malformed.public_inputs.pop();
    let valid = make_leaf_proof(&CircuitInputs::test_inputs_0());

    let prover = make_private_batch_prover();
    let err = prover.commit(vec![malformed, valid]).unwrap_err();
    assert!(
        err.to_string()
            .contains("leaf proof public input length mismatch"),
        "got: {err}"
    );
}

#[test]
fn private_batch_prover_rejects_poisoned_dummy_template() {
    setup_test_binaries();
    // A tampered dummy_proof.bin must be rejected when the prover loads its
    // binaries. Otherwise the poisoned template would be padded into every
    // partial batch, replaying its payout once per empty slot via the circuit's
    // exit-dedup sum (leaf-level analogue of #97026).
    let poisoned_dir = test_bins_root().join("private-poisoned-dummy");
    let _ = std::fs::remove_dir_all(&poisoned_dir);
    std::fs::create_dir_all(&poisoned_dir).unwrap();
    for entry in std::fs::read_dir(private_bins_dir()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), poisoned_dir.join(entry.file_name())).unwrap();
    }

    // Sentinel-neutral tampering: block_hash, outputs, and exit accounts stay
    // zero (test_inputs_0 carries a nonzero exit_account_1, which the sentinel
    // now rejects on its own), so only the cryptographic check can catch it.
    let mut dummy_inputs = CircuitInputs::test_inputs_0();
    dummy_inputs.public.exit_account_1 = zk_circuits_common::utils::BytesDigest::default();
    let mut poisoned = make_leaf_proof(&dummy_inputs);
    poisoned.public_inputs[4] = F::from_canonical_u64(0xdead_beef); // nullifier felt
    std::fs::write(poisoned_dir.join("dummy_proof.bin"), poisoned.to_bytes()).unwrap();

    let err = PrivateBatchProver::new_from_binaries_dir(&poisoned_dir)
        .expect_err("poisoned dummy template must be rejected at load time");
    assert!(
        err.to_string()
            .contains("dummy leaf proof template failed verification"),
        "got: {err}"
    );

    // A cryptographically VALID dummy proof (over the real leaf circuit) with a
    // nonzero exit account is exactly the poisoned-padding shape from the audit
    // finding (incomplete dummy sentinel): block hash and amounts are zero, yet
    // its exit bytes would mark every padded slot. The sentinel must reject it.
    let marked_exits = make_leaf_proof(&CircuitInputs::test_inputs_0());
    std::fs::write(
        poisoned_dir.join("dummy_proof.bin"),
        marked_exits.to_bytes(),
    )
    .unwrap();

    let err = PrivateBatchProver::new_from_binaries_dir(&poisoned_dir)
        .expect_err("dummy template with a nonzero exit account must be rejected at load time");
    assert!(
        err.to_string().contains("non-zero exit account"),
        "got: {err}"
    );

    // A template with a non-zero payout must be rejected by the sentinel check.
    let mut nonzero_payout = make_leaf_proof(&CircuitInputs::test_inputs_0());
    nonzero_payout.public_inputs[1] = F::from_canonical_u64(7); // output_amount_1
    std::fs::write(
        poisoned_dir.join("dummy_proof.bin"),
        nonzero_payout.to_bytes(),
    )
    .unwrap();

    let err = PrivateBatchProver::new_from_binaries_dir(&poisoned_dir)
        .expect_err("non-zero-payout dummy template must be rejected at load time");
    assert!(
        err.to_string().contains("non-zero output amounts"),
        "got: {err}"
    );

    // The pristine directory still loads fine (sanity check).
    PrivateBatchProver::new_from_binaries_dir(&private_bins_dir())
        .expect("pristine binaries must still load");

    let _ = std::fs::remove_dir_all(&poisoned_dir);
}

#[test]
fn private_batch_prover_ignores_prover_artifact() {
    // The private-batch aggregation prover is rebuilt from source, so it must
    // never read private_batch_prover.bin. ProverOnlyCircuitData carries the
    // witness generators and the public-input target list that decides which
    // witness values are exposed in the returned proof; trusting a serialized
    // prover artifact would let a poisoned file exfiltrate batch witness
    // material (e.g. dummy-nullifier preimages) through the emitted proof. This
    // test poisons and then deletes that artifact and shows loading and proving
    // are unaffected, matching the leaf prover's build-from-source stance.
    setup_test_binaries();

    let dir = test_bins_root().join("private-ignored-prover");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(private_bins_dir()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
    }

    let aggregate_and_verify = |bins: &std::path::Path| {
        let proof = make_leaf_proof(&test_inputs_with_real_block());
        let aggregated = PrivateBatchProver::new_from_binaries_dir(bins)
            .expect("prover must load without a trusted prover artifact")
            .aggregate(vec![proof])
            .expect("aggregation must succeed");
        private_batch_verifier()
            .verify(aggregated)
            .expect("aggregated proof must verify");
    };

    // Garbage in place of the prover artifact must not affect loading or proving.
    std::fs::write(
        dir.join("private_batch_prover.bin"),
        b"not a prover artifact",
    )
    .unwrap();
    aggregate_and_verify(&dir);

    // Nor must its absence: the file is not part of the trusted input set.
    let _ = std::fs::remove_file(dir.join("private_batch_prover.bin"));
    aggregate_and_verify(&dir);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn private_batch_build_rejects_substituted_leaf_artifacts() {
    // Regression (build-time verifier-key substitution): the private-batch build
    // bakes the leaf verifier key into the recursive circuit as constants, so it
    // must pin common.bin/verifier.bin to the canonical Wormhole leaf circuit
    // before embedding them. A same-profile fake leaf circuit (identical config
    // and public-input shape) must be rejected.
    use plonky2::util::serialization::DefaultGateSerializer;
    use test_helpers::fake_leaf::build_fake_leaf_circuit;
    use wormhole_aggregator::private_batch::circuit::build::generate_private_batch_circuit_binaries;

    let dir = test_bins_root().join("substituted-leaf-build");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (fake, _) = build_fake_leaf_circuit();
    std::fs::write(
        dir.join("common.bin"),
        fake.common.to_bytes(&DefaultGateSerializer).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("verifier.bin"),
        fake.verifier_only.to_bytes().unwrap(),
    )
    .unwrap();

    let err = generate_private_batch_circuit_binaries(&dir, 1, false)
        .expect_err("substituted leaf artifacts must be rejected before circuit construction");
    assert!(
        err.to_string().contains("does not match the canonical"),
        "got: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn public_batch_build_rejects_substituted_private_batch_artifacts() {
    // Regression (build-time verifier-key substitution, public layer): the
    // public-batch build must pin private_batch_common.bin/verifier.bin to the
    // canonical private-batch circuit before baking the verifier key in.
    use wormhole_aggregator::public_batch::circuit::generate_public_batch_circuit_binaries;

    setup_test_binaries();
    let dir = test_bins_root().join("substituted-private-batch-build");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(private_bins_dir()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
    }

    // Flip one byte of the verifier key. The artifact still deserializes (the
    // format is fixed-size hashes), so only the canonical comparison catches it.
    let mut vk_bytes = std::fs::read(dir.join("private_batch_verifier.bin")).unwrap();
    let last = vk_bytes.len() - 1;
    vk_bytes[last] ^= 0x01;
    std::fs::write(dir.join("private_batch_verifier.bin"), vk_bytes).unwrap();

    let err = generate_public_batch_circuit_binaries(&dir, 1, PRIVATE_NUM_LEAVES)
        .expect_err("substituted private-batch artifacts must be rejected before baking");
    // `{err:#}` prints the whole context chain; the canonical mismatch is the cause.
    let chain = format!("{err:#}");
    assert!(
        chain.contains("does not match the canonical"),
        "got: {chain}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// Miner-side (public batch): pooled aggregation
// ============================================================================

/// Build (once) a real private-batch proof compatible with the public-batch
/// test artifacts. Cached because private aggregation is expensive.
fn make_private_batch_proof_in_public_dir() -> ProofWithPublicInputs<F, C, D> {
    static PROOF: OnceLock<ProofWithPublicInputs<F, C, D>> = OnceLock::new();
    PROOF
        .get_or_init(|| {
            setup_public_test_binaries();
            let dir = public_bins_dir();
            // Non-dummy inputs: the aggregator refuses the dummy bucket.
            let leaf = make_leaf_proof(&test_inputs_with_real_block());
            PrivateBatchProver::new_from_binaries_dir(&dir)
                .expect("load private-batch prover from public test binaries")
                .aggregate(vec![leaf])
                .expect("private aggregate")
        })
        .clone()
}

#[test]
fn public_batch_prover_ignores_prover_artifact() {
    // Same stance as private_batch_prover_ignores_prover_artifact, one layer
    // up: the public-batch prover is rebuilt from source, so it must never
    // read public_batch_prover.bin. ProverOnlyCircuitData carries the
    // public-input target list that decides which witness values the emitted
    // proof exposes; trusting a serialized prover artifact would let a
    // poisoned file exfiltrate batch witness material through the proof's
    // public inputs. This test plants a garbage artifact (the builder no
    // longer even emits one) and shows loading, proving, and verification are
    // unaffected.
    setup_public_test_binaries();

    let dir = test_bins_root().join("public-ignored-prover");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(public_bins_dir()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
    }

    let private_batch_proof = make_private_batch_proof_in_public_dir();
    let address = BytesDigest::try_from([1u8; 32]).expect("valid address");

    let aggregate_and_verify = |bins: &std::path::Path| {
        let mut aggregator = PublicBatchAggregator::new(bins, address)
            .expect("aggregator must load without a trusted prover artifact");
        let key = aggregator
            .push_proof(private_batch_proof.clone())
            .expect("valid private-batch proof must be admitted");
        let aggregated = aggregator
            .aggregate(&key)
            .expect("public aggregation must succeed");
        aggregator
            .verify(aggregated)
            .expect("public-batch proof must verify");
    };

    // Garbage in place of the prover artifact must not affect loading or proving.
    std::fs::write(
        dir.join("public_batch_prover.bin"),
        b"not a prover artifact",
    )
    .unwrap();
    aggregate_and_verify(&dir);

    // Nor must its absence: the file is not part of the trusted input set.
    let _ = std::fs::remove_file(dir.join("public_batch_prover.bin"));
    aggregate_and_verify(&dir);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn public_batch_aggregator_prove_batch_ignores_bins_dir_after_init() {
    // Audit finding: prove_batch used to rebuild PublicBatchProver from the
    // mutable bins_dir on every call. Replacing artifacts after init could
    // make the aggregator spend a proving window and return a proof its own
    // pinned verifier rejects. Construction must pin every proving input;
    // mutating the directory afterwards must be a no-op for prove_batch.
    setup_public_test_binaries();

    let dir = test_bins_root().join("public-pinned-after-init");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(public_bins_dir()).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
    }

    let private_batch_proof = make_private_batch_proof_in_public_dir();
    let address = BytesDigest::try_from([1u8; 32]).expect("valid address");
    let mut aggregator =
        PublicBatchAggregator::new(&dir, address).expect("aggregator init pins artifacts");
    let key = aggregator
        .push_proof(private_batch_proof)
        .expect("admit private-batch proof");

    // Scrub every artifact prove_batch used to re-read. If it still touches
    // the path, proving or the pinned-verifier check will fail.
    for name in [
        "private_batch_common.bin",
        "private_batch_verifier.bin",
        "dummy_private_batch_proof.bin",
        "public_batch_common.bin",
        "public_batch_verifier.bin",
        "config.json",
    ] {
        std::fs::write(dir.join(name), b"not a trusted artifact").unwrap();
    }

    let aggregated = aggregator
        .aggregate(&key)
        .expect("prove_batch must use pinned artifacts, not the scrubbed bins_dir");
    aggregator
        .verify(aggregated)
        .expect("proof must verify under the verifier pinned at init");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pool_rejects_invalid_proofs_and_aggregates_by_bucket() {
    setup_public_test_binaries();
    let dir = public_bins_dir();
    let address = BytesDigest::try_from([1u8; 32]).expect("valid address");

    let private_batch_proof = make_private_batch_proof_in_public_dir();
    let mut aggregator = PublicBatchAggregator::new(&dir, address).expect("public aggregator");

    // Shape rejection: a leaf proof is not a private-batch proof.
    let leaf = make_leaf_proof(&CircuitInputs::test_inputs_0());
    let err = aggregator.push_proof(leaf).unwrap_err();
    assert!(
        err.to_string().contains("public input length mismatch"),
        "got: {err}"
    );

    // Cryptographic rejection: valid shape, tampered contents. A proof admitted
    // into the pool despite being invalid would wedge its bucket forever, since
    // its nullifiers can never settle on-chain and settlement eviction is the
    // pool's only automatic drain (#97067).
    let mut tampered = private_batch_proof.clone();
    tampered.public_inputs[1] = F::from_canonical_u64(9); // asset_id felt
    let err = aggregator.push_proof(tampered).unwrap_err();
    assert!(
        err.to_string().contains("verification failed"),
        "got: {err}"
    );
    assert_eq!(aggregator.pool_len(), 0, "rejected proofs must not pool");

    // The proof's nullifiers, for simulating its on-chain settlement below.
    let settled: std::collections::HashSet<BytesDigest> = {
        use plonky2::field::types::PrimeField64;
        let u64s: Vec<u64> = private_batch_proof
            .public_inputs
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();
        qp_wormhole_inputs::PrivateBatchPublicInputs::try_from_u64_slice(&u64s)
            .expect("parse private-batch public inputs")
            .nullifiers
            .into_iter()
            .collect()
    };

    // A valid proof is admitted, keyed by its (block, asset, fee) metadata.
    let key = aggregator
        .push_proof(private_batch_proof)
        .expect("valid private-batch proof must be admitted");
    assert_eq!(aggregator.pool_len(), 1);
    let stats = aggregator.bucket_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].key, key);
    assert!(stats[0].is_full(), "batch_size=1 bucket must be full");

    // Aggregating the bucket produces a verifiable public batch. Proving is
    // NON-CONSUMING — a claiming miner's pool may hold the only copy of a
    // proof in the network — so the bucket does not drain on success.
    let aggregated = aggregator.aggregate(&key).expect("public aggregate");
    aggregator
        .verify(aggregated)
        .expect("public-batch proof must verify");
    assert_eq!(
        aggregator.pool_len(),
        1,
        "proofs stay pooled until their segments settle on-chain"
    );

    // On-chain settlement is what retires the proved inputs: the block-import
    // evict_settled cadence sees the batch's nullifiers and drains the bucket.
    assert_eq!(
        aggregator.evict_settled(&settled),
        1,
        "settlement must retire the proved proof"
    );
    assert_eq!(aggregator.pool_len(), 0, "bucket must drain on settlement");

    // Aggregating a now-missing bucket is an error, and the pool stays usable.
    let err = aggregator.aggregate(&key).unwrap_err();
    assert!(err.to_string().contains("no pooled proofs"), "got: {err}");

    // The dummy sentinel bucket (block_hash == 0) is refused outright: an
    // all-dummy public batch settles nothing, so proving it wastes a full
    // proving run.
    let dummy_key = BatchKey {
        block_hash: BytesDigest::default(),
        ..key
    };
    let err = aggregator.aggregate(&dummy_key).unwrap_err();
    assert!(err.to_string().contains("dummy"), "got: {err}");
}

#[test]
fn public_batch_verify_rejects_proof_bound_to_a_different_aggregator_address() {
    setup_public_test_binaries();
    let dir = public_bins_dir();

    let private_batch_proof = make_private_batch_proof_in_public_dir();

    let address_a = BytesDigest::try_from([1u8; 32]).expect("valid address a");
    let address_b = BytesDigest::try_from([2u8; 32]).expect("valid address b");
    assert_ne!(address_a, address_b, "sanity: addresses must differ");

    // Produce a public-batch proof bound to address_a (this also exercises the
    // dummy-template verification + count/shape validation in new_from_bytes).
    let public_batch_proof = {
        let mut agg = PublicBatchAggregator::new(&dir, address_a).expect("public aggregator a");
        let key = agg.push_proof(private_batch_proof.clone()).unwrap();
        agg.aggregate(&key).expect("public aggregate")
    };

    // The producing backend accepts its own proof.
    PublicBatchAggregator::new(&dir, address_a)
        .expect("public aggregator a")
        .verify(public_batch_proof.clone())
        .expect("same-address proof must verify");

    // A backend configured for a different aggregator address must reject it (#96981).
    let err = PublicBatchAggregator::new(&dir, address_b)
        .expect("public aggregator b")
        .verify(public_batch_proof)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match configured aggregator address"),
        "got: {err}"
    );
}
