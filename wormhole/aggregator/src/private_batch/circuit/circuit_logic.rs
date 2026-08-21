//! Monolithic prebuilt Private-batch aggregation circuit.
//!
//! This circuit verifies `N` leaf wormhole proofs directly (without first building a
//! dynamic merge circuit), then applies the wormhole-specific wrapper logic:
//! - enforce block consistency across real proofs
//! - enforce asset_id / volume_fee_bps consistency
//! - enforce the volume fee once over each private settlement segment
//! - dedupe exit accounts and sum output amounts (2 outputs per proof)
//! - replace dummy nullifiers with hashes of externally provided random preimages
//! - privately permute nullifiers and emit fixed-format aggregated public inputs
//!
//! The leaf verifier key is baked in as constants at circuit build time to prevent
//! verifier key substitution attacks.
//!
//! # Nullifiers: selected and privately permuted
//!
//! This circuit forwards one nullifier per leaf slot into the aggregated public
//! inputs (dummy slots get the hash of a fresh random preimage instead, so
//! padding never produces on-chain nullifier collisions and stays
//! indistinguishable from real slots). The prover privately chooses a
//! permutation for the emitted region. The circuit proves exact multiset
//! preservation without exposing the permutation or comparing digest values.
//!
//! Real nullifiers are constrained to be pairwise DISTINCT across slots (dummy
//! slots exempt). Because the exit-account grouping sums amounts across leaves,
//! replaying one leaf proof into several slots would otherwise aggregate into a
//! single inflated exit while the chain, keying its persistent settled-nullifier
//! set, marks the one shared nullifier spent only once — minting value backed by
//! a single spend. The uniqueness constraint makes such a batch unprovable, so
//! the circuit is a first line of defense; the wormhole pallet's persistent
//! settled-nullifier set remains the cross-batch double-spend boundary and also
//! rejects intra-segment duplicates as defense in depth. See "Nullifiers and
//! Double-Spend Prevention" in `wormhole/README.md`.

use anyhow::{ensure, Result};
use plonky2::{
    field::types::Field,
    hash::poseidon2::Poseidon2Hash,
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
            VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputsTarget,
    },
};
use qp_wormhole_inputs::validate_proof_count;

use zk_circuits_common::{
    circuit::{validate_circuit_config, C, D, F},
    gadgets::{bytes_digest_eq, limb1_at_offset, limbs4_at_offset, permute_digests4},
};

use crate::common::recursive::add_recursive_verifiers;

use super::constants::{
    aggregated_output, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START,
    EXIT_2_START, INPUT_AMOUNT_START, LEAF_PI_LEN, NULLIFIER_START, OUTPUT_AMOUNT_1_START,
    OUTPUT_AMOUNT_2_START, VOLUME_FEE_BPS_START,
};

/// Runtime targets for the prebuilt private-batch aggregation circuit.
#[derive(Debug, Clone)]
pub struct PrivateBatchCircuitTargets {
    /// One proof target per leaf slot.
    pub leaf_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// One dummy-nullifier preimage target (4 felts) per leaf slot.
    pub dummy_nullifier_pre_images: Vec<[Target; 4]>,
    /// Private switch targets for the nullifier permutation network.
    pub nullifier_permutation_switches: Vec<BoolTarget>,
}

pub struct PrivateBatchCircuit {
    builder: CircuitBuilder<F, D>,
    targets: PrivateBatchCircuitTargets,
}

impl PrivateBatchCircuit {
    /// Build a monolithic private-batch aggregation circuit that verifies `n_leaf` wormhole leaf proofs.
    ///
    /// The `leaf_verifier_only` is baked in as constants to prevent verifier key substitution.
    /// Returns an error when `n_leaf` is outside the supported range or when
    /// `config` fails the shared structural policy
    /// ([`validate_circuit_config`]) — an unchecked config would otherwise
    /// panic deep inside plonky2 mid-construction or drive exponential
    /// allocations during the expensive build phase (audit finding).
    pub fn new(
        config: CircuitConfig,
        leaf_common: &CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        n_leaf: usize,
    ) -> Result<Self> {
        validate_circuit_config(&config)?;
        validate_proof_count(n_leaf, "n_leaf")?;

        // Runtime (not debug-only) shape check: the wrapper constraints index
        // fixed offsets (asset id, block hash, nullifier, ...) into each leaf
        // proof's public inputs, so a leaf_common with a different PI length
        // must fail loudly here instead of panicking mid-construction
        // (mirrors the public-batch check, #97071).
        ensure!(
            leaf_common.num_public_inputs == LEAF_PI_LEN,
            "leaf_common.num_public_inputs ({}) != expected wormhole leaf PI len ({}); \
             refusing to build a private-batch circuit over a non-leaf-shaped inner circuit",
            leaf_common.num_public_inputs,
            LEAF_PI_LEN,
        );

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf_proofs = add_recursive_verifiers::<F, C, D>(
            &mut builder,
            leaf_common,
            leaf_verifier_only,
            n_leaf,
        )?;

        // Allocate one dummy-nullifier preimage target (4 felts) per slot.
        let mut dummy_nullifier_pre_images = Vec::with_capacity(n_leaf);
        for _ in 0..n_leaf {
            dummy_nullifier_pre_images.push([
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
            ]);
        }

        let mut targets = PrivateBatchCircuitTargets {
            leaf_proofs,
            dummy_nullifier_pre_images,
            nullifier_permutation_switches: Vec::new(),
        };

        // Build the wormhole-specific wrapper logic directly in this circuit.
        targets.nullifier_permutation_switches =
            build_private_batch_constraints(&mut builder, &targets, n_leaf);

        Ok(Self { builder, targets })
    }

    pub fn targets(&self) -> PrivateBatchCircuitTargets {
        self.targets.clone()
    }

    pub fn build_circuit(self) -> CircuitData<F, C, D> {
        self.builder.build()
    }

    pub fn build_prover(self) -> ProverCircuitData<F, C, D> {
        self.builder.build_prover()
    }

    pub fn build_verifier(self) -> VerifierCircuitData<F, C, D> {
        self.builder.build_verifier()
    }

    /// Build circuit with profiling output. Prints gate counts before building.
    #[cfg(feature = "profile")]
    pub fn build_circuit_profiled(self) -> CircuitData<F, C, D> {
        println!("\n=== Private-batch Gate Instance Counts ===");
        self.builder.print_gate_counts(0);
        self.builder.build()
    }

    /// Returns the current number of gates in the circuit (before building).
    pub fn num_gates(&self) -> usize {
        self.builder.num_gates()
    }
}

fn build_private_batch_constraints(
    builder: &mut CircuitBuilder<F, D>,
    targets: &PrivateBatchCircuitTargets,
    n_leaf: usize,
) -> Vec<BoolTarget> {
    let one = builder.one();
    let zero = builder.zero();

    // We work over the leaf proofs' public inputs directly.
    //
    // `leaf_pi_targets[i]` is the PI vector of proof i, length = LEAF_PI_LEN.
    let leaf_pi_targets: Vec<&[Target]> = targets
        .leaf_proofs
        .iter()
        .map(|p| p.public_inputs.as_slice())
        .collect();

    // Guaranteed by the runtime num_public_inputs check in PrivateBatchCircuit::new;
    // this assertion only guards against future callers bypassing that constructor.
    debug_assert!(leaf_pi_targets.iter().all(|pis| pis.len() == LEAF_PI_LEN));

    // =========================================================================
    // Header / reference values
    // =========================================================================

    // Output: [num_exit_slots, asset_id, volume_fee_bps, block_hash(4), block_number, ...]
    let num_exit_slots_t = builder.constant(F::from_canonical_u64((n_leaf * 2) as u64));

    // `asset_id` must match across every slot, including dummies. This keeps the historical
    // partial-batch rule that dummy padding is only compatible with native-asset (`asset_id = 0`)
    // proofs, which the prover/wrapper preflight enforces before padding.
    let asset_ref = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(leaf_pi_targets[0], 0);

    // Dummy sentinel at the wrapper level is `block_hash == [0;4]`.
    // Leaf circuit itself uses a stronger dummy condition (block_hash==0 && outputs==0).
    // Here we only need the block-hash sentinel for wrapper behavior.
    let dummy_sentinel = [zero, zero, zero, zero];

    // Compute dummy flags for every slot up front. Also kept for the nullifier section.
    let mut is_dummy_flags: Vec<BoolTarget> = Vec::with_capacity(n_leaf);
    let mut block_hashes: Vec<[Target; 4]> = Vec::with_capacity(n_leaf);
    for pis_i in leaf_pi_targets.iter().take(n_leaf) {
        let block_i = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(pis_i, 0);
        let is_dummy_i = bytes_digest_eq(builder, block_i, dummy_sentinel);
        is_dummy_flags.push(is_dummy_i);
        block_hashes.push(block_i);
    }

    // Select the reference block hash / block number / volume_fee_bps from the FIRST
    // NON-DUMMY slot via a prefix scan. This makes the circuit position-independent: the
    // prover may place real and dummy proofs in any order (uniform shuffle), which is
    // required for the privacy argument that real and dummy slots are indistinguishable.
    //
    // If every slot is a dummy, the references remain zero, which the on-chain verifier
    // rejects as a block reference (and an all-dummy batch settles nothing anyway).
    let mut found_real = builder._false();
    let mut block_ref = [zero, zero, zero, zero];
    let mut block_number_ref = zero;
    let mut volume_fee_bps_ref = zero;
    for i in 0..n_leaf {
        let is_real_i = builder.not(is_dummy_flags[i]);
        let not_found_yet = builder.not(found_real);
        let take_i = builder.and(is_real_i, not_found_yet);
        let pis_i = leaf_pi_targets[i];

        for j in 0..4 {
            block_ref[j] = builder.select(take_i, block_hashes[i][j], block_ref[j]);
        }
        block_number_ref = builder.select(take_i, pis_i[BLOCK_NUMBER_START], block_number_ref);
        volume_fee_bps_ref =
            builder.select(take_i, pis_i[VOLUME_FEE_BPS_START], volume_fee_bps_ref);

        found_real = builder.or(found_real, is_real_i);
    }

    let mut output_pis: Vec<Target> = Vec::new();
    output_pis.push(num_exit_slots_t);
    output_pis.push(asset_ref);
    output_pis.push(volume_fee_bps_ref);

    // =========================================================================
    // Block consistency + asset consistency + volume_fee_bps consistency
    // =========================================================================
    //
    // Constraint for each proof i:
    //   is_dummy_i OR (block_i == block_ref)
    //
    // Since block_ref is the first non-dummy slot's block hash, this forces every real
    // proof to share that same block, regardless of slot order.
    //
    // Also enforce:
    //   asset_id_i == asset_ref
    //   is_dummy_i OR (volume_fee_bps_i == volume_fee_bps_ref)

    for (i, pis_i) in leaf_pi_targets.iter().take(n_leaf).enumerate() {
        let matches_ref = bytes_digest_eq(builder, block_hashes[i], block_ref);

        // Enforce `is_dummy_i OR matches_ref == true`
        let valid_block_relation = builder.or(is_dummy_flags[i], matches_ref);
        builder.connect(valid_block_relation.target, one);

        // Enforce asset_id consistency
        let asset_i = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(pis_i, 0);
        builder.connect(asset_i, asset_ref);

        let volume_fee_bps_i = limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(pis_i, 0);

        // Enforce volume_fee_bps consistency across real proofs only; dummy slots use a fixed
        // reusable template fee and must not constrain padded partial batches.
        let fee_matches_ref = builder.is_equal(volume_fee_bps_i, volume_fee_bps_ref);
        let valid_fee_relation = builder.or(is_dummy_flags[i], fee_matches_ref);
        builder.connect(valid_fee_relation.target, one);
    }

    // Output block reference (all-dummy case yields zeros, which is fine)
    output_pis.extend_from_slice(&block_ref);
    output_pis.push(block_number_ref);

    // =========================================================================
    // Exit-account grouping / dedup (Bitcoin-style 2-output leaves)
    // =========================================================================
    //
    // For each of 2*N slots, we:
    // 1) take that slot's exit account as the "key"
    // 2) sum all matching amounts across all 2*N outputs
    // 3) if this exit already appeared in an earlier slot, zero out the slot
    //
    // This makes duplicates indistinguishable from dummy/unused slots in output.
    //
    // Dummy slots are masked to the canonical zero exit account (and zero
    // amount) at ingress, BEFORE the grouping. The leaf circuit leaves exit
    // accounts unconstrained and its dummy sentinel does not cover them, so a
    // valid dummy leaf can carry arbitrary exit bytes; without the mask, a
    // poisoned padding template would mark every padded slot with a visible
    // zero-amount attacker-chosen exit, breaking the indistinguishability of
    // dummy, unused, and duplicate slots (audit finding: incomplete dummy
    // sentinel).

    let num_exit_slots = n_leaf * 2;

    let get_exit_and_amount = |proof_idx: usize, output_idx: usize| -> ([Target; 4], Target) {
        let pis = leaf_pi_targets[proof_idx];

        let exit = if output_idx == 0 {
            limbs4_at_offset::<LEAF_PI_LEN, EXIT_1_START>(pis, 0)
        } else {
            limbs4_at_offset::<LEAF_PI_LEN, EXIT_2_START>(pis, 0)
        };

        let amount = if output_idx == 0 {
            limb1_at_offset::<LEAF_PI_LEN, OUTPUT_AMOUNT_1_START>(pis, 0)
        } else {
            limb1_at_offset::<LEAF_PI_LEN, OUTPUT_AMOUNT_2_START>(pis, 0)
        };

        (exit, amount)
    };

    // Masked per-slot (exit, amount): dummy slots read as (zero account, 0).
    // The amount mask is defense in depth — the leaf circuit already forces
    // dummy amounts to zero, but this gadget should not rely on a
    // cross-circuit invariant it can enforce locally for one select per slot.
    let mut slot_exits: Vec<[Target; 4]> = Vec::with_capacity(num_exit_slots);
    let mut slot_amounts: Vec<Target> = Vec::with_capacity(num_exit_slots);
    for slot in 0..num_exit_slots {
        let proof_idx = slot / 2;
        let (exit_raw, amount_raw) = get_exit_and_amount(proof_idx, slot % 2);
        let is_dummy_i = is_dummy_flags[proof_idx];
        slot_exits.push(core::array::from_fn(|j| {
            builder.select(is_dummy_i, zero, exit_raw[j])
        }));
        slot_amounts.push(builder.select(is_dummy_i, zero, amount_raw));
    }

    // Enforce the fee once over the private settlement segment. Inputs are
    // authenticated by the child leaf proofs and exposed only to this recursive
    // wrapper; neither aggregate proof layer forwards the total.
    let mut total_input = zero;
    for i in 0..n_leaf {
        let input = limb1_at_offset::<LEAF_PI_LEN, INPUT_AMOUNT_START>(leaf_pi_targets[i], 0);
        let masked_input = builder.select(is_dummy_flags[i], zero, input);
        total_input = builder.add(total_input, masked_input);
    }
    let mut total_output = zero;
    for amount in &slot_amounts {
        total_output = builder.add(total_output, *amount);
    }

    let ten_thousand = builder.constant(F::from_canonical_u32(10_000));
    let fee_complement = builder.sub(ten_thousand, volume_fee_bps_ref);
    builder.range_check(fee_complement, 14);
    let lhs = builder.mul(total_output, ten_thousand);
    let rhs = builder.mul(total_input, fee_complement);
    let diff = builder.sub(rhs, lhs);
    // With at most 64 leaves, valid rhs and diff are below
    // 64 * (2^32 - 1) * 10_000 < 2^52. A wrapped negative field
    // difference is near the Goldilocks modulus and cannot pass this check.
    builder.range_check(diff, 52);

    for slot in 0..num_exit_slots {
        let exit_slot = slot_exits[slot];

        // Check whether this exit appeared earlier (for dedupe)
        let mut is_duplicate = builder._false();
        for exit_earlier in slot_exits.iter().take(slot) {
            let matches_earlier = bytes_digest_eq(builder, *exit_earlier, exit_slot);
            is_duplicate = builder.or(is_duplicate, matches_earlier);
        }

        // Sum all matching amounts across all 2*N outputs
        let mut acc = zero;
        for (exit_j, amount_j) in slot_exits.iter().zip(&slot_amounts) {
            let matches = bytes_digest_eq(builder, *exit_j, exit_slot);
            let conditional_amount = builder.select(matches, *amount_j, zero);
            acc = builder.add(acc, conditional_amount);
        }

        // Zero duplicates so they look like dummy/unused slots
        let final_sum = builder.select(is_duplicate, zero, acc);
        let final_exit = [
            builder.select(is_duplicate, zero, exit_slot[0]),
            builder.select(is_duplicate, zero, exit_slot[1]),
            builder.select(is_duplicate, zero, exit_slot[2]),
            builder.select(is_duplicate, zero, exit_slot[3]),
        ];

        // Range check final sum to 32 bits (u32::MAX > the max possible sum on our chain)
        builder.range_check(final_sum, 32);

        output_pis.push(final_sum);
        output_pis.extend_from_slice(&final_exit);
    }

    // =========================================================================
    // Real-nullifier uniqueness (anti-replay within the batch)
    // =========================================================================
    //
    // A legitimate private batch spends each leaf exactly once, so every real
    // slot carries a distinct nullifier. Two real slots sharing a nullifier can
    // only be the SAME leaf proof replayed across multiple slots. Left
    // unconstrained, the exit-account grouping above sums that leaf's amount
    // into a single inflated exit (N copies -> N*amount) while the chain marks
    // the one shared nullifier spent exactly once — minting value backed by a
    // single spend. Enforce pairwise distinctness of real nullifiers here so
    // such a batch is unprovable in the first place.
    //
    // Dummy slots are exempt: their nullifiers are replaced below with hashes
    // of fresh random preimages and never settle on-chain, so a (vanishingly
    // unlikely) dummy/dummy or dummy/real value match is harmless.
    let real_nullifiers: Vec<[Target; 4]> = (0..n_leaf)
        .map(|i| limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(leaf_pi_targets[i], 0))
        .collect();
    for i in 0..n_leaf {
        let is_real_i = builder.not(is_dummy_flags[i]);
        for j in (i + 1)..n_leaf {
            let is_real_j = builder.not(is_dummy_flags[j]);
            let both_real = builder.and(is_real_i, is_real_j);
            let nullifiers_equal = bytes_digest_eq(builder, real_nullifiers[i], real_nullifiers[j]);
            // collision = both_real AND nullifiers_equal must be false.
            let collision = builder.and(both_real, nullifiers_equal);
            builder.connect(collision.target, zero);
        }
    }

    // =========================================================================
    // Nullifiers (replace dummies with hashes of provided random preimages)
    // =========================================================================
    //
    // The selected nullifiers are routed through a privately witnessed
    // permutation. Each network switch either passes through or swaps two
    // complete four-limb digests, proving that the public region is exactly
    // the selected multiset without modifying any nullifier contents.

    let mut selected_nullifiers: Vec<[Target; 4]> = Vec::with_capacity(n_leaf);
    for i in 0..n_leaf {
        let pis_i = leaf_pi_targets[i];
        let real_null_i = limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(pis_i, 0);
        let dummy_null_i =
            hash_dummy_nullifier_pre_image(builder, targets.dummy_nullifier_pre_images[i]);
        let is_dummy_i = is_dummy_flags[i];

        // selected = is_dummy ? hash(dummy_nullifier_pre_image[i]) : real_nullifier[i]
        selected_nullifiers.push([
            builder.select(is_dummy_i, dummy_null_i[0], real_null_i[0]),
            builder.select(is_dummy_i, dummy_null_i[1], real_null_i[1]),
            builder.select(is_dummy_i, dummy_null_i[2], real_null_i[2]),
            builder.select(is_dummy_i, dummy_null_i[3], real_null_i[3]),
        ]);
    }

    let (permuted_nullifiers, nullifier_permutation_switches) =
        permute_digests4(builder, selected_nullifiers);
    for nullifier in permuted_nullifiers {
        output_pis.extend_from_slice(&nullifier);
    }

    // =========================================================================
    // Padding
    // =========================================================================
    //
    // Preserve the historical wrapper output sizing:
    // total length = N * LEAF_PI_LEN + 8
    let expected_len = aggregated_output::pi_len(n_leaf);
    assert!(
        output_pis.len() <= expected_len,
        "private-batch output PI length {} exceeds expected {}",
        output_pis.len(),
        expected_len
    );

    while output_pis.len() < expected_len {
        output_pis.push(zero);
    }

    // Register final public inputs
    builder.register_public_inputs(&output_pis);

    // Optional sanity checks on header offsets
    debug_assert_eq!(aggregated_output::NUM_EXIT_SLOTS_OFFSET, 0);
    debug_assert_eq!(aggregated_output::ASSET_ID_OFFSET, 1);
    debug_assert_eq!(aggregated_output::VOLUME_FEE_BPS_OFFSET, 2);
    debug_assert_eq!(aggregated_output::BLOCK_HASH_OFFSET, 3);
    debug_assert_eq!(aggregated_output::BLOCK_NUMBER_OFFSET, 7);

    nullifier_permutation_switches
}

fn hash_dummy_nullifier_pre_image(
    builder: &mut CircuitBuilder<F, D>,
    pre_image: [Target; 4],
) -> [Target; 4] {
    let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(pre_image.to_vec());
    builder
        .hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec())
        .elements
}

#[cfg(test)]
#[path = "tests/circuit_logic.rs"]
mod tests;
