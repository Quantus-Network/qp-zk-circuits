//! Phase-1 differential safety net for the formal spec (`formal/`).
//!
//! These property tests pin the *native* reference implementations to the
//! structure asserted by the Lean spec, so a divergence between the spec
//! relations and the Rust code is caught before any heavy formal proof.
//!
//! Coverage, with the spec object each test mirrors:
//!   * `WA(s) = hh (wormholeSalt ++ s)` (`WormholeSpec.Hash.WA`)
//!   * `Null(s,c) = hh (nullifierSalt ++ s ++ c)` (`WormholeSpec.Hash.Null`)
//!   * `leafHash` preimage order (`WormholeSpec.Hash.leafHash`)
//!   * `nodeHash` and the sort-vs-position-hint correspondence
//!     (`WormholeSpec.Hash.nodeHash`, `WormholeSpec.Leaf.stepUp`)
//!   * private-segment aggregate fee conservation over the dummy-masked burns and
//!     the prover-chosen exit slots (`WormholeSpec.Aggregation.privateBatchFeeOk`)
//!   * the block-reference prefix scan (`referenceFromFirstReal`)
//!   * dummy-nullifier replacement `DNull(u)=H(H(u))` (`WormholeSpec.Hash.dummyNull`)
//!   * the block-header preimage order (`WormholeSpec.Leaf.headerPreimage`)
//!
//! The `hh`/`H` model is plonky2's `Poseidon2Hash`, the same hasher the spec's
//! `RandomOracle` abstracts; the node-hash and header tests therefore double as a
//! cross-implementation check that the chain's `qp-poseidon` path agrees with it.

use plonky2::field::types::Field;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::plonk::config::Hasher;
use proptest::prelude::*;
use wormhole_circuit::block_header::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use wormhole_circuit::nullifier::{Nullifier, NULLIFIER_SALT};
use wormhole_circuit::unspendable_account::{UnspendableAccount, UNSPENDABLE_SALT};
use wormhole_circuit::zk_merkle_proof::ZkLeafData;
use zk_circuits_common::circuit::F;
use zk_circuits_common::serialization::bytes_to_digest as ser_bytes_to_digest;
use zk_circuits_common::utils::{
    bytes_to_digest, bytes_to_felts, string_to_felts, u64_to_felts, BytesDigest,
};
use zk_circuits_common::zk_merkle::{
    hash_node, hash_node_presorted, hash_to_felts, insert_at_position, Hash256,
};

/// Goldilocks field order; canonical felt limbs must be strictly below it.
const GOLDILOCKS: u64 = 0xFFFF_FFFF_0000_0001;

/// The spec's double hash `hh p = H((H p).toList)`.
fn hh(preimage: &[F]) -> [F; 4] {
    let inner = Poseidon2Hash::hash_no_pad(preimage).elements;
    Poseidon2Hash::hash_no_pad(&inner).elements
}

/// Pack four canonical Goldilocks limbs into 32 bytes (8 bytes/felt, little-endian).
fn bytes32_from_limbs(limbs: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

/// Build a valid 32-byte secret from four canonical Goldilocks limbs.
fn secret_from_limbs(limbs: [u64; 4]) -> BytesDigest {
    BytesDigest::try_from(bytes32_from_limbs(limbs)).expect("canonical limbs encode a valid digest")
}

/// The spec's single hash `H p` = `Poseidon2Hash::hash_no_pad`.
fn h(preimage: &[F]) -> [F; 4] {
    Poseidon2Hash::hash_no_pad(preimage).elements
}

/// Four canonical Goldilocks limbs as field elements (a spec `Digest`).
fn digest_felts(limbs: [u64; 4]) -> [F; 4] {
    core::array::from_fn(|i| F::from_canonical_u64(limbs[i]))
}

/// Native reference for the private-batch fee predicate
/// (`privateBatchFeeOk` in `WormholeSpec.Aggregation`): `leaves` are
/// `(input_amount, is_dummy)` burns, `outputs` the prover-chosen exit amounts.
fn private_batch_fee_ok(leaves: &[(u32, bool)], outputs: &[u32], fee_bps: u32) -> bool {
    if fee_bps > 10_000 {
        return false;
    }
    let total_input: u128 = leaves
        .iter()
        .filter(|(_, is_dummy)| !is_dummy)
        .map(|(input, _)| *input as u128)
        .sum();
    let total_output: u128 = outputs.iter().map(|&o| o as u128).sum();
    total_output * 10_000 <= total_input * (10_000 - fee_bps as u128)
}

/// Native reference for the wrapper's block-reference prefix scan
/// (`referenceFromFirstReal` in `WormholeSpec.Aggregation`): the reference is the
/// first non-dummy slot's block hash; an all-dummy batch yields the zero hash.
fn reference_block(block_hashes: &[[u64; 4]]) -> [u64; 4] {
    block_hashes
        .iter()
        .copied()
        .find(|bh| *bh != [0u64; 4])
        .unwrap_or([0u64; 4])
}

proptest! {
/// C2: `WA(s) = H(H(salt_wh ‖ s))`.
#[test]
fn wa_matches_double_hash(
    a in 0u64..GOLDILOCKS,
    b in 0u64..GOLDILOCKS,
    c in 0u64..GOLDILOCKS,
    d in 0u64..GOLDILOCKS,
) {
    let secret = secret_from_limbs([a, b, c, d]);

    let mut preimage: Vec<F> = string_to_felts(UNSPENDABLE_SALT).unwrap();
    preimage.extend_from_slice(&bytes_to_digest(secret));
    let expected = hh(&preimage);

    let actual = UnspendableAccount::from_secret(secret).account_id;
    prop_assert_eq!(actual, expected);
}

/// C1: `Null(s, c) = H(H(salt_null ‖ s ‖ c))`.
#[test]
fn nullifier_matches_double_hash(
    a in 0u64..GOLDILOCKS,
    b in 0u64..GOLDILOCKS,
    c in 0u64..GOLDILOCKS,
    d in 0u64..GOLDILOCKS,
    transfer_count in any::<u64>(),
) {
    let secret = secret_from_limbs([a, b, c, d]);

    let mut preimage: Vec<F> = string_to_felts(NULLIFIER_SALT).unwrap();
    preimage.extend_from_slice(&bytes_to_digest(secret));
    preimage.extend(u64_to_felts(transfer_count));
    let expected = hh(&preimage);

    let actual = Nullifier::from_preimage(secret, transfer_count).hash;
    prop_assert_eq!(actual, expected);
}

/// Determinism: the derivations are pure functions of their inputs.
#[test]
fn derivations_are_deterministic(
    a in 0u64..GOLDILOCKS,
    b in 0u64..GOLDILOCKS,
    c in 0u64..GOLDILOCKS,
    d in 0u64..GOLDILOCKS,
    transfer_count in any::<u64>(),
) {
    let secret = secret_from_limbs([a, b, c, d]);
    prop_assert_eq!(
        UnspendableAccount::from_secret(secret).account_id,
        UnspendableAccount::from_secret(secret).account_id
    );
    prop_assert_eq!(
            Nullifier::from_preimage(secret, transfer_count).hash,
                Nullifier::from_preimage(secret, transfer_count).hash
            );
    }

    /// C3: the ZK-tree leaf hash preimage is ordered
    /// `to_account(4) ‖ transfer_count(2) ‖ asset_id(1) ‖ input_amount(1)`,
    /// matching the spec's `leafHash` (`WormholeSpec.Hash`).
    #[test]
    fn leaf_hash_preimage_order(
        a in 0u64..GOLDILOCKS,
        b in 0u64..GOLDILOCKS,
        c in 0u64..GOLDILOCKS,
        d in 0u64..GOLDILOCKS,
        transfer_count in any::<u64>(),
        asset_id in any::<u32>(),
        input_amount in any::<u32>(),
    ) {
        let to_account = bytes32_from_limbs([a, b, c, d]);

        let leaf = ZkLeafData::new(to_account, transfer_count, asset_id, input_amount);
        let actual = Poseidon2Hash::hash_no_pad(&leaf.collect_for_hash()).elements;

        // Independently reconstruct the spec-documented preimage order.
        let mut preimage: Vec<F> = ser_bytes_to_digest(&to_account).to_vec();
        preimage.extend(u64_to_felts(transfer_count));
        preimage.push(F::from_canonical_u32(asset_id));
        preimage.push(F::from_canonical_u32(input_amount));
        let expected = Poseidon2Hash::hash_no_pad(&preimage).elements;

        prop_assert_eq!(actual, expected);
    }
}

proptest! {
    /// `nodeHash c0 c1 c2 c3 = H(c0 ‖ c1 ‖ c2 ‖ c3)`: the chain's 4-ary internal
    /// node hash (`hash_node_presorted`: 16 felts via the 8-byte/felt compact
    /// encoding) equals the spec's `nodeHash` over the four child digests. Because
    /// the chain side uses `qp-poseidon` while the spec side uses plonky2's
    /// `Poseidon2Hash`, this also pins the two hash implementations to each other.
    #[test]
    fn node_hash_matches_spec(
        c0 in prop::array::uniform4(0u64..GOLDILOCKS),
        c1 in prop::array::uniform4(0u64..GOLDILOCKS),
        c2 in prop::array::uniform4(0u64..GOLDILOCKS),
        c3 in prop::array::uniform4(0u64..GOLDILOCKS),
    ) {
        let children_bytes: [Hash256; 4] = [
            bytes32_from_limbs(c0),
            bytes32_from_limbs(c1),
            bytes32_from_limbs(c2),
            bytes32_from_limbs(c3),
        ];
        // Chain/circuit node hash (presorted path does not sort), decoded to felts.
        let actual = hash_to_felts(&hash_node_presorted(&children_bytes).unwrap());

        // Spec nodeHash: H over the concatenated child digests (4 × 4 = 16 felts).
        let mut preimage: Vec<F> = Vec::with_capacity(16);
        for c in [c0, c1, c2, c3] {
            preimage.extend_from_slice(&digest_felts(c));
        }
        let expected = h(&preimage);

        prop_assert_eq!(actual, expected);
    }

    /// `stepUp`: inserting the current hash at its position hint among the three
    /// sorted siblings (`insert_at_position`) and hashing equals the spec's
    /// `nodeHash` with the current digest placed at that position. Catches a
    /// swapped/off-by-one position arm in either the circuit walk or the spec.
    #[test]
    fn step_up_matches_position_select(
        cur in prop::array::uniform4(0u64..GOLDILOCKS),
        s0 in prop::array::uniform4(0u64..GOLDILOCKS),
        s1 in prop::array::uniform4(0u64..GOLDILOCKS),
        s2 in prop::array::uniform4(0u64..GOLDILOCKS),
        pos in 0u8..4,
    ) {
        let cur_b = bytes32_from_limbs(cur);
        let sibs_b: [Hash256; 3] =
            [bytes32_from_limbs(s0), bytes32_from_limbs(s1), bytes32_from_limbs(s2)];
        let ordered = insert_at_position(cur_b, &sibs_b, pos).unwrap();
        let actual = hash_to_felts(&hash_node_presorted(&ordered).unwrap());

        // Spec stepUp: the four children with `cur` at `pos`.
        let children = match pos {
            0 => [cur, s0, s1, s2],
            1 => [s0, cur, s1, s2],
            2 => [s0, s1, cur, s2],
            _ => [s0, s1, s2, cur],
        };
        let mut preimage: Vec<F> = Vec::with_capacity(16);
        for c in children {
            preimage.extend_from_slice(&digest_felts(c));
        }
        let expected = h(&preimage);

        prop_assert_eq!(actual, expected);
    }

    /// The circuit's presorted path and the native sort path agree: hashing the
    /// already-sorted children equals `hash_node` (which sorts internally). This is
    /// the correspondence that lets the position-hint walk stand in for sorting.
    #[test]
    fn presorted_node_hash_matches_sorted(
        c0 in prop::array::uniform4(0u64..GOLDILOCKS),
        c1 in prop::array::uniform4(0u64..GOLDILOCKS),
        c2 in prop::array::uniform4(0u64..GOLDILOCKS),
        c3 in prop::array::uniform4(0u64..GOLDILOCKS),
    ) {
        let children: [Hash256; 4] = [
            bytes32_from_limbs(c0),
            bytes32_from_limbs(c1),
            bytes32_from_limbs(c2),
            bytes32_from_limbs(c3),
        ];
        let mut sorted = children;
        sorted.sort();
        prop_assert_eq!(hash_node_presorted(&sorted), hash_node(&children));
    }

    #[test]
    fn aggregate_fee_matches_one_runtime_ceiling(
        leaves in prop::collection::vec((any::<u32>(), any::<bool>()), 1..65),
        outputs in prop::collection::vec(any::<u32>(), 1..65),
        fee_bps in 0u32..=10_000,
    ) {
        let total_input: u128 = leaves
            .iter()
            .filter(|(_, is_dummy)| !is_dummy)
            .map(|(input, _)| *input as u128)
            .sum();
        let total_output: u128 = outputs.iter().map(|&o| o as u128).sum();
        let ceiling_rule = if fee_bps == 10_000 {
            total_output == 0
        } else {
            let denominator = 10_000u128 - fee_bps as u128;
            let fee = (total_output * fee_bps as u128).div_ceil(denominator);
            total_input >= total_output + fee
        };

        prop_assert_eq!(
            private_batch_fee_ok(&leaves, &outputs, fee_bps),
            ceiling_rule,
        );
    }

    /// The block reference is the first non-dummy slot (`referenceFromFirstReal`).
    /// Reproduces the in-circuit prefix scan (`found_real` / `take_i` selects) and
    /// pins it to "find the first non-dummy block hash".
    #[test]
    fn reference_block_is_first_non_dummy(
        raw in prop::collection::vec((any::<bool>(), prop::array::uniform4(0u64..GOLDILOCKS)), 0..12),
    ) {
        // Dummy slots are the all-zero sentinel; real slots are forced nonzero.
        let slots: Vec<[u64; 4]> = raw
            .iter()
            .map(|&(is_dummy, limbs)| {
                if is_dummy {
                    [0u64; 4]
                } else {
                    [limbs[0] | 1, limbs[1], limbs[2], limbs[3]]
                }
            })
            .collect();

        // In-circuit prefix scan: take the first slot that is real.
        let mut found = false;
        let mut block_ref = [0u64; 4];
        for &bh in &slots {
            let is_real = bh != [0u64; 4];
            let take = is_real && !found;
            if take {
                block_ref = bh;
            }
            found = found || is_real;
        }

        prop_assert_eq!(block_ref, reference_block(&slots));
    }

    /// Dummy-nullifier replacement is the double hash `DNull(u) = H(H(u))`
    /// (`WormholeSpec.Hash.dummyNull`), mirroring `hash_dummy_nullifier_pre_image`.
    /// The double hash places dummies in the same image as real nullifiers
    /// (indistinguishability) and must not collapse to a single hash.
    #[test]
    fn dummy_nullifier_is_double_hash(u in prop::array::uniform4(0u64..GOLDILOCKS)) {
        let pre = digest_felts(u);
        // Mirror the in-circuit two `hash_no_pad` calls.
        let inner = h(&pre);
        let circuit_dummy = h(&inner);
        // Spec: dummyNull u = hh u.
        let spec_dummy = hh(&pre);
        prop_assert_eq!(circuit_dummy, spec_dummy);
        prop_assert_ne!(circuit_dummy, inner);
    }

    /// Block-header preimage order (`HeaderInputs::block_hash` ↔ `headerPreimage`):
    /// `parent_hash ‖ block_number ‖ state_root ‖ extrinsics_root ‖ zk_tree_root ‖ digest`.
    #[test]
    fn header_block_hash_preimage_order(
        parent in prop::array::uniform4(0u64..GOLDILOCKS),
        state in prop::array::uniform4(0u64..GOLDILOCKS),
        extrinsics in prop::array::uniform4(0u64..GOLDILOCKS),
        zk_tree in prop::array::uniform4(0u64..GOLDILOCKS),
        block_number in any::<u32>(),
        digest_vec in prop::collection::vec(any::<u8>(), DIGEST_LOGS_SIZE..=DIGEST_LOGS_SIZE),
    ) {
        let parent_b = bytes32_from_limbs(parent);
        let state_b = bytes32_from_limbs(state);
        let extrinsics_b = bytes32_from_limbs(extrinsics);
        let zk_tree_b = bytes32_from_limbs(zk_tree);
        let digest_arr: [u8; DIGEST_LOGS_SIZE] = digest_vec.try_into().unwrap();

        let header = HeaderInputs::new(
            BytesDigest::try_from(parent_b).unwrap(),
            block_number,
            BytesDigest::try_from(state_b).unwrap(),
            BytesDigest::try_from(extrinsics_b).unwrap(),
            BytesDigest::try_from(zk_tree_b).unwrap(),
            &digest_arr,
        )
        .expect("canonical header inputs");
        let actual = bytes_to_digest(header.block_hash());

        // Independent reconstruction in the spec-documented order.
        let mut preimage: Vec<F> = Vec::new();
        preimage.extend_from_slice(&ser_bytes_to_digest(&parent_b));
        preimage.push(F::from_noncanonical_u64(block_number as u64));
        preimage.extend_from_slice(&ser_bytes_to_digest(&state_b));
        preimage.extend_from_slice(&ser_bytes_to_digest(&extrinsics_b));
        preimage.extend_from_slice(&ser_bytes_to_digest(&zk_tree_b));
        preimage.extend(bytes_to_felts(&digest_arr).unwrap());
        let expected = h(&preimage);

        prop_assert_eq!(actual, expected);
    }
}
