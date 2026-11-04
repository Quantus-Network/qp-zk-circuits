//! Monolithic prebuilt Private-batch aggregation circuit.
//!
//! This circuit verifies `N` leaf wormhole proofs directly (without first building a
//! dynamic merge circuit), then applies the wormhole-specific wrapper logic:
//! - enforce block consistency across real proofs
//! - enforce asset_id consistency
//! - bind `M` prover-chosen exit slots (`exit_account`, `amount`) and the batch
//!   `volume_fee_bps` as public outputs
//! - enforce the volume fee once over the whole batch:
//!   `sum(amounts) * 10_000 <= sum(real inputs) * (10_000 - volume_fee_bps)`
//! - replace dummy nullifiers with hashes of externally provided random preimages
//!   and emit fixed-format aggregated public inputs
//!
//! `N` (`shape.num_leaf_proofs`) and `M` (`shape.num_exit_slots`) are independent
//! circuit parameters: a batch may split one burn across many outputs or pool
//! many burns into one.
//!
//! The leaf verifier key is baked in as constants at circuit build time to prevent
//! verifier key substitution attacks.
//!
//! # Nullifiers
//!
//! This circuit forwards one nullifier per leaf slot into the aggregated public
//! inputs (dummy slots get the hash of a fresh random preimage instead, so
//! padding never produces on-chain nullifier collisions and stays
//! indistinguishable from real slots). Leaf slots are private to the batch
//! proof and the prover shuffles them before proving, so the emitted order
//! carries no information about which slots are real or which exit slot a
//! burn funds.
//!
//! Real nullifiers are constrained to be pairwise DISTINCT across slots (dummy
//! slots exempt). Replaying one leaf proof into several slots would otherwise
//! count its `input_amount` several times in the fee check while the chain,
//! keying its persistent settled-nullifier set, marks the one shared nullifier
//! spent only once — minting value backed by a single spend. The uniqueness
//! constraint makes such a batch unprovable, so the circuit is a first line of
//! defense; the wormhole pallet's persistent settled-nullifier set remains the
//! cross-batch double-spend boundary and also rejects intra-segment duplicates
//! as defense in depth. See "Nullifiers and Double-Spend Prevention" in
//! `wormhole/README.md`.

use anyhow::{ensure, Result};
use plonky2::{
    field::types::Field,
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
use qp_wormhole_inputs::PrivateBatchShape;

use zk_circuits_common::{
    circuit::{validate_circuit_config, C, D, F},
    gadget_builder::GadgetBuilder,
    gadgets::{bytes_digest_eq, limb1_at_offset, limbs4_at_offset},
};

use crate::common::recursive::add_recursive_verifiers;

use super::constants::{
    aggregated_output, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START, INPUT_AMOUNT_START,
    LEAF_PI_LEN, NULLIFIER_START,
};

/// Witness targets for one prover-chosen exit slot.
#[derive(Debug, Clone, Copy)]
pub struct ExitSlotTargets {
    pub exit_account: [Target; 4],
    pub amount: Target,
}

/// Runtime targets for the prebuilt private-batch aggregation circuit.
#[derive(Debug, Clone)]
pub struct PrivateBatchCircuitTargets {
    /// One proof target per leaf slot.
    pub leaf_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// Batch-wide volume fee in basis points.
    pub volume_fee_bps: Target,
    /// One `(exit_account, amount)` pair per exit slot.
    pub exit_slots: Vec<ExitSlotTargets>,
    /// One dummy-nullifier preimage target (4 felts) per leaf slot.
    pub dummy_nullifier_pre_images: Vec<[Target; 4]>,
}

impl PrivateBatchCircuitTargets {
    /// Allocate every non-proof witness target for `shape`.
    pub(crate) fn allocate(
        builder: &mut impl GadgetBuilder<F, D>,
        leaf_proofs: Vec<ProofWithPublicInputsTarget<D>>,
        shape: PrivateBatchShape,
    ) -> Self {
        let volume_fee_bps = builder.add_virtual_target();
        let exit_slots = (0..shape.num_exit_slots)
            .map(|_| ExitSlotTargets {
                exit_account: core::array::from_fn(|_| builder.add_virtual_target()),
                amount: builder.add_virtual_target(),
            })
            .collect();
        let dummy_nullifier_pre_images = (0..shape.num_leaf_proofs)
            .map(|_| core::array::from_fn(|_| builder.add_virtual_target()))
            .collect();
        Self {
            leaf_proofs,
            volume_fee_bps,
            exit_slots,
            dummy_nullifier_pre_images,
        }
    }

    pub fn shape(&self) -> PrivateBatchShape {
        PrivateBatchShape::new(self.leaf_proofs.len(), self.exit_slots.len())
    }
}

pub struct PrivateBatchCircuit {
    builder: CircuitBuilder<F, D>,
    targets: PrivateBatchCircuitTargets,
}

impl PrivateBatchCircuit {
    /// Build a monolithic private-batch aggregation circuit that verifies
    /// `shape.num_leaf_proofs` wormhole leaf proofs and exposes
    /// `shape.num_exit_slots` exit slots.
    ///
    /// The `leaf_verifier_only` is baked in as constants to prevent verifier key substitution.
    /// Returns an error when `shape` is outside the supported range or when
    /// `config` fails the shared structural policy
    /// ([`validate_circuit_config`]) — an unchecked config would otherwise
    /// panic deep inside plonky2 mid-construction or drive exponential
    /// allocations during the expensive build phase (audit finding).
    pub fn new(
        config: CircuitConfig,
        leaf_common: &CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        shape: PrivateBatchShape,
    ) -> Result<Self> {
        validate_circuit_config(&config)?;
        shape.validate()?;

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
            shape.num_leaf_proofs,
        )?;

        let targets = PrivateBatchCircuitTargets::allocate(&mut builder, leaf_proofs, shape);

        // Build the wormhole-specific wrapper logic directly in this circuit.
        build_private_batch_constraints(&mut builder, &targets);

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

/// The wrapper logic, written against [`GadgetBuilder`] so the `formal-export` tracing
/// builder can record the exact gadget calls the production `CircuitBuilder` receives.
pub(crate) fn build_private_batch_constraints(
    builder: &mut impl GadgetBuilder<F, D>,
    targets: &PrivateBatchCircuitTargets,
) {
    let one = builder.one();
    let zero = builder.zero();
    let shape = targets.shape();
    let n_leaf = shape.num_leaf_proofs;
    let num_exit_slots = shape.num_exit_slots;

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
    let num_exit_slots_t = builder.constant(F::from_canonical_u64(num_exit_slots as u64));

    // `asset_id` must match across every slot, including dummies. This keeps the historical
    // partial-batch rule that dummy padding is only compatible with native-asset (`asset_id = 0`)
    // proofs, which the prover/wrapper preflight enforces before padding.
    let asset_ref = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(leaf_pi_targets[0], 0);

    // Dummy sentinel is `block_hash == [0;4]`.
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

    // Select the reference block hash / block number from the FIRST NON-DUMMY slot via a
    // prefix scan. This makes the circuit position-independent: the prover may place real
    // and dummy proofs in any order (uniform shuffle), which is required for the privacy
    // argument that real and dummy slots are indistinguishable.
    //
    // If every slot is a dummy, the references remain zero, which the on-chain verifier
    // rejects as a block reference (and an all-dummy batch settles nothing anyway).
    let mut found_real = builder._false();
    let mut block_ref = [zero, zero, zero, zero];
    let mut block_number_ref = zero;
    for i in 0..n_leaf {
        let is_real_i = builder.not(is_dummy_flags[i]);
        let not_found_yet = builder.not(found_real);
        let take_i = builder.and(is_real_i, not_found_yet);
        let pis_i = leaf_pi_targets[i];

        for j in 0..4 {
            block_ref[j] = builder.select(take_i, block_hashes[i][j], block_ref[j]);
        }
        block_number_ref = builder.select(take_i, pis_i[BLOCK_NUMBER_START], block_number_ref);

        found_real = builder.or(found_real, is_real_i);
    }

    let mut output_pis: Vec<Target> = Vec::new();
    output_pis.push(num_exit_slots_t);
    output_pis.push(asset_ref);
    output_pis.push(targets.volume_fee_bps);

    // =========================================================================
    // Block consistency + asset consistency
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

    for (i, pis_i) in leaf_pi_targets.iter().take(n_leaf).enumerate() {
        let matches_ref = bytes_digest_eq(builder, block_hashes[i], block_ref);

        // Enforce `is_dummy_i OR matches_ref == true`
        let valid_block_relation = builder.or(is_dummy_flags[i], matches_ref);
        builder.connect(valid_block_relation.target, one);

        // Enforce asset_id consistency
        let asset_i = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(pis_i, 0);
        builder.connect(asset_i, asset_ref);
    }

    // Output block reference (all-dummy case yields zeros, which is fine)
    output_pis.extend_from_slice(&block_ref);
    output_pis.push(block_number_ref);

    // =========================================================================
    // Volume fee over the whole batch
    // =========================================================================
    //
    // Inputs are authenticated by the child leaf proofs and exposed only to
    // this recursive wrapper; neither aggregate proof layer forwards the total.
    // Exit amounts are prover-chosen witnesses, so each is range-checked to 32
    // bits before being summed.
    let mut total_input = zero;
    for i in 0..n_leaf {
        let input = limb1_at_offset::<LEAF_PI_LEN, INPUT_AMOUNT_START>(leaf_pi_targets[i], 0);
        let masked_input = builder.select(is_dummy_flags[i], zero, input);
        total_input = builder.add(total_input, masked_input);
    }
    let mut total_output = zero;
    for slot in &targets.exit_slots {
        builder.range_check(slot.amount, 32);
        total_output = builder.add(total_output, slot.amount);
    }

    let ten_thousand = builder.constant(F::from_canonical_u32(10_000));
    let fee_complement = builder.sub(ten_thousand, targets.volume_fee_bps);
    builder.range_check(fee_complement, 14);
    let lhs = builder.mul(total_output, ten_thousand);
    let rhs = builder.mul(total_input, fee_complement);
    let diff = builder.sub(rhs, lhs);
    // With at most 64 leaves and 64 exit slots, valid rhs and diff are below
    // 64 * (2^32 - 1) * 10_000 < 2^52. A wrapped negative field
    // difference is near the Goldilocks modulus and cannot pass this check.
    builder.range_check(diff, 52);

    // =========================================================================
    // Exit slots
    // =========================================================================
    //
    // Every slot is a prover-chosen witness, so the prover is responsible for
    // merging outputs to the same account if it wants to; the circuit forwards
    // the slots verbatim. The chain settles each slot independently.
    for slot in &targets.exit_slots {
        output_pis.push(slot.amount);
        output_pis.extend_from_slice(&slot.exit_account);
    }

    // =========================================================================
    // Real-nullifier uniqueness (anti-replay within the batch)
    // =========================================================================
    //
    // A legitimate private batch spends each leaf exactly once, so every real
    // slot carries a distinct nullifier. Two real slots sharing a nullifier can
    // only be the SAME leaf proof replayed across multiple slots. Left
    // unconstrained, the fee check above would count that leaf's input N
    // times while the chain marks the one shared nullifier spent exactly once
    // — minting value backed by a single spend. Enforce pairwise distinctness
    // of real nullifiers here so such a batch is unprovable in the first place.
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

    for i in 0..n_leaf {
        let real_null_i = real_nullifiers[i];
        let dummy_null_i =
            hash_dummy_nullifier_pre_image(builder, targets.dummy_nullifier_pre_images[i]);
        let is_dummy_i = is_dummy_flags[i];

        // selected = is_dummy ? hash(dummy_nullifier_pre_image[i]) : real_nullifier[i]
        for j in 0..4 {
            output_pis.push(builder.select(is_dummy_i, dummy_null_i[j], real_null_i[j]));
        }
    }

    debug_assert_eq!(output_pis.len(), aggregated_output::pi_len(shape));
    builder.register_public_inputs(&output_pis);

    // Optional sanity checks on header offsets
    debug_assert_eq!(aggregated_output::NUM_EXIT_SLOTS_OFFSET, 0);
    debug_assert_eq!(aggregated_output::ASSET_ID_OFFSET, 1);
    debug_assert_eq!(aggregated_output::VOLUME_FEE_BPS_OFFSET, 2);
    debug_assert_eq!(aggregated_output::BLOCK_HASH_OFFSET, 3);
    debug_assert_eq!(aggregated_output::BLOCK_NUMBER_OFFSET, 7);
}

fn hash_dummy_nullifier_pre_image(
    builder: &mut impl GadgetBuilder<F, D>,
    pre_image: [Target; 4],
) -> [Target; 4] {
    let inner_hash = builder.poseidon2_hash_no_pad(pre_image.to_vec());
    builder
        .poseidon2_hash_no_pad(inner_hash.elements.to_vec())
        .elements
}

#[cfg(test)]
#[path = "tests/circuit_logic.rs"]
mod tests;
