//! Monolithic prebuilt Layer-0 aggregation circuit.
//!
//! This circuit verifies `N` leaf wormhole proofs directly (without first building a
//! dynamic merge circuit), then applies the wormhole-specific wrapper logic:
//! - enforce block consistency across real proofs
//! - enforce asset_id / volume_fee_bps consistency
//! - dedupe exit accounts and sum output amounts (2 outputs per proof)
//! - replace dummy nullifiers with externally provided random nullifiers
//! - emit fixed-format aggregated public inputs
//!
//! The runtime prover fills:
//! - `leaf_verifier_data`
//! - `leaf_proofs[i]`
//! - `dummy_nullifiers[i]`

use plonky2::{
    field::types::Field,
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
        proof::ProofWithPublicInputsTarget,
    },
};

use zk_circuits_common::{
    circuit::{C, D, F},
    gadgets::{bytes_digest_eq, limb1_at_offset, limbs4_at_offset},
};

use super::constants::{
    aggregated_output, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START,
    EXIT_2_START, LEAF_PI_LEN, NULLIFIER_START, OUTPUT_AMOUNT_1_START, OUTPUT_AMOUNT_2_START,
    VOLUME_FEE_BPS_START,
};

/// Runtime targets for the prebuilt layer-0 aggregation circuit.
///
/// These are serialized separately into `layer0_targets.json` so the prover can
/// reconstruct and fill them later without rebuilding the circuit.
#[derive(Debug, Clone)]
pub struct AggregationCircuitTargets {
    /// Verifier target for the leaf wormhole circuit.
    pub leaf_verifier_data: VerifierCircuitTarget,
    /// One proof target per leaf slot.
    pub leaf_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// One dummy-nullifier target (4 felts) per leaf slot.
    pub dummy_nullifiers: Vec<[Target; 4]>,
}

pub struct Layer0AggregationCircuit {
    builder: CircuitBuilder<F, D>,
    targets: AggregationCircuitTargets,
}

impl Layer0AggregationCircuit {
    /// Build a monolithic layer-0 aggregation circuit that verifies `n_leaf` wormhole leaf proofs.
    ///
    /// # Arguments
    /// - `config`: circuit config for the aggregation circuit itself
    /// - `leaf_common`: common data for the leaf wormhole circuit (used to allocate and verify proof targets)
    /// - `n_leaf`: number of leaf proofs to aggregate
    pub fn new(config: CircuitConfig, leaf_common: CommonCircuitData<F, D>, n_leaf: usize) -> Self {
        assert!(n_leaf > 0, "n_leaf must be > 0");

        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Allocate verifier target for the leaf circuit.
        let leaf_verifier_data =
            builder.add_virtual_verifier_data(leaf_common.fri_params.config.cap_height);

        // Allocate N leaf proof targets and verify each against the same leaf verifier.
        let mut leaf_proofs = Vec::with_capacity(n_leaf);
        for _ in 0..n_leaf {
            let pt = builder.add_virtual_proof_with_pis(&leaf_common);
            builder.verify_proof::<C>(&pt, &leaf_verifier_data, &leaf_common);
            leaf_proofs.push(pt);
        }

        // Allocate one dummy-nullifier target (4 felts) per slot.
        let mut dummy_nullifiers = Vec::with_capacity(n_leaf);
        for _ in 0..n_leaf {
            dummy_nullifiers.push([
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
            ]);
        }

        let targets = AggregationCircuitTargets {
            leaf_verifier_data,
            leaf_proofs,
            dummy_nullifiers,
        };

        // Build the wormhole-specific wrapper logic directly in this circuit.
        build_layer0_wrapper_constraints(&mut builder, &targets, n_leaf);

        Self { builder, targets }
    }

    pub fn targets(&self) -> AggregationCircuitTargets {
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
}

fn build_layer0_wrapper_constraints(
    builder: &mut CircuitBuilder<F, D>,
    targets: &AggregationCircuitTargets,
    n_leaf: usize,
) {
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

    // Sanity check (debug assertion): all proof target PI lengths should match expected leaf PI len.
    debug_assert!(leaf_pi_targets.iter().all(|pis| pis.len() == LEAF_PI_LEN));

    // =========================================================================
    // Header / reference values
    // =========================================================================

    // Output: [num_exit_slots, asset_id, volume_fee_bps, block_hash(4), block_number, ...]
    let num_exit_slots_t = builder.constant(F::from_canonical_u64((n_leaf * 2) as u64));

    // Reference values are taken from slot 0.
    // Prover shuffles to ensure a real proof is in slot 0 if any real proofs exist.
    let asset_ref = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(leaf_pi_targets[0], 0);
    let volume_fee_bps_ref =
        limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(leaf_pi_targets[0], 0);

    let block_ref = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(leaf_pi_targets[0], 0);
    let block_number_ref =
        limb1_at_offset::<LEAF_PI_LEN, BLOCK_NUMBER_START>(leaf_pi_targets[0], 0);

    let mut output_pis: Vec<Target> = Vec::new();
    output_pis.push(num_exit_slots_t);
    output_pis.push(asset_ref);
    output_pis.push(volume_fee_bps_ref);

    // =========================================================================
    // Block consistency + asset consistency + volume_fee_bps consistency
    // =========================================================================
    //
    // Dummy sentinel at the wrapper level is `block_hash == [0;4]`.
    // Leaf circuit itself uses a stronger dummy condition (block_hash==0 && outputs==0).
    // Here we only need the block-hash sentinel for wrapper behavior.
    //
    // Constraint for each proof i:
    //   is_dummy_i OR (block_i == block_ref)
    //
    // Also enforce:
    //   asset_id_i == asset_ref
    //   volume_fee_bps_i == volume_fee_bps_ref

    let dummy_sentinel = [zero, zero, zero, zero];

    // Track dummy flags so we can conditionally replace nullifiers later.
    let mut is_dummy_flags: Vec<BoolTarget> = Vec::with_capacity(n_leaf);

    for pis_i in leaf_pi_targets.iter().take(n_leaf) {
        let block_i = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(pis_i, 0);
        let is_dummy_i = bytes_digest_eq(builder, block_i, dummy_sentinel);
        is_dummy_flags.push(is_dummy_i);

        let matches_ref = bytes_digest_eq(builder, block_i, block_ref);

        // Enforce `is_dummy_i OR matches_ref == true`
        let valid_block_relation = builder.or(is_dummy_i, matches_ref);
        builder.connect(valid_block_relation.target, one);

        // Enforce asset_id consistency
        let asset_i = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(pis_i, 0);
        builder.connect(asset_i, asset_ref);

        // Enforce volume_fee_bps consistency
        let volume_fee_bps_i = limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(pis_i, 0);
        builder.connect(volume_fee_bps_i, volume_fee_bps_ref);
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

    for slot in 0..num_exit_slots {
        let proof_idx = slot / 2;
        let output_idx = slot % 2;
        let (exit_slot, _amount_slot) = get_exit_and_amount(proof_idx, output_idx);

        // Check whether this exit appeared earlier (for dedupe)
        let mut is_duplicate = builder._false();
        for earlier in 0..slot {
            let earlier_proof_idx = earlier / 2;
            let earlier_output_idx = earlier % 2;
            let (exit_earlier, _) = get_exit_and_amount(earlier_proof_idx, earlier_output_idx);

            let matches_earlier = bytes_digest_eq(builder, exit_earlier, exit_slot);
            is_duplicate = builder.or(is_duplicate, matches_earlier);
        }

        // Sum all matching amounts across all 2*N outputs
        let mut acc = zero;
        for j in 0..num_exit_slots {
            let j_proof_idx = j / 2;
            let j_output_idx = j % 2;
            let (exit_j, amount_j) = get_exit_and_amount(j_proof_idx, j_output_idx);

            let matches = bytes_digest_eq(builder, exit_j, exit_slot);
            let conditional_amount = builder.select(matches, amount_j, zero);
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

        // Range check sum (expected u32-safe quantized amount)
        builder.range_check(final_sum, 32);

        output_pis.push(final_sum);
        output_pis.extend_from_slice(&final_exit);
    }

    // =========================================================================
    // Nullifiers (replace dummies with provided random nullifiers)
    // =========================================================================

    for i in 0..n_leaf {
        let pis_i = leaf_pi_targets[i];
        let real_null_i = limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(pis_i, 0);

        let dn = targets.dummy_nullifiers[i];
        let is_dummy_i = is_dummy_flags[i];

        // output = is_dummy ? dummy_nullifier[i] : real_nullifier[i]
        output_pis.extend_from_slice(&[
            builder.select(is_dummy_i, dn[0], real_null_i[0]),
            builder.select(is_dummy_i, dn[1], real_null_i[1]),
            builder.select(is_dummy_i, dn[2], real_null_i[2]),
            builder.select(is_dummy_i, dn[3], real_null_i[3]),
        ]);
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
        "layer-0 output PI length {} exceeds expected {}",
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
}
