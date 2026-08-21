//! Public-batch aggregation circuit (monolithic prebuilt-circuit form).
//!
//! Verifies N private-batch aggregated proofs and emits a public-batch aggregated proof.
//! The private-batch verifier key is baked in as constants to prevent verifier key substitution.
//!
//! # Nullifiers: forwarded, not deduplicated
//!
//! Inner-proof nullifiers are forwarded verbatim into this circuit's public
//! inputs; no uniqueness check is performed here (nor anywhere else in the
//! proof stack), within or across inner proofs. Double-spend prevention is
//! enforced on-chain by the wormhole pallet's persistent settled-nullifier
//! set. See "Nullifiers and Double-Spend Prevention" in `wormhole/README.md`.

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
use qp_wormhole_inputs::validate_proof_count;

use zk_circuits_common::{
    circuit::{validate_circuit_config, C, D, F},
    gadgets::bytes_digest_eq,
};

use crate::common::recursive::add_recursive_verifiers;

use super::constants::AGGREGATOR_ADDRESS_LEN;

use super::constants as pbc;

/// Runtime targets for the prebuilt public-batch aggregation circuit.
#[derive(Debug, Clone)]
pub struct PublicBatchCircuitTargets {
    /// One proof target per private-batch slot.
    pub private_batch_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// Aggregator address (4 felts, 8 bytes/felt) for hash-derived accounts.
    pub aggregator_address: [Target; AGGREGATOR_ADDRESS_LEN],
}

pub struct PublicBatchCircuit {
    builder: CircuitBuilder<F, D>,
    targets: PublicBatchCircuitTargets,
}

impl PublicBatchCircuit {
    /// Build a monolithic public-batch aggregation circuit that verifies `n_inner` private-batch aggregated proofs.
    ///
    /// The `private_batch_verifier_only` is baked in as constants to prevent verifier key substitution.
    /// Returns an error for unsupported counts, an inconsistent private-batch
    /// PI shape, or a `config` failing the shared structural policy
    /// ([`validate_circuit_config`]) — an unchecked config would otherwise
    /// panic deep inside plonky2 mid-construction or drive exponential
    /// allocations during the expensive build phase (audit finding).
    pub fn new(
        config: CircuitConfig,
        private_batch_common: CommonCircuitData<F, D>,
        private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
        n_inner: usize,
        private_batch_num_leaves: usize,
    ) -> Result<Self> {
        validate_circuit_config(&config)?;
        validate_proof_count(n_inner, "n_inner")?;
        validate_proof_count(private_batch_num_leaves, "private_batch_num_leaves")?;

        let expected_l0_pi_len = pbc::private_batch_pi_len(private_batch_num_leaves);

        // Runtime (not debug-only) shape check: the public-batch circuit indexes
        // fixed offsets derived from `private_batch_num_leaves` into each inner
        // proof's public inputs, so a mismatch must fail loudly instead of going
        // out of bounds in release builds (#97071).
        ensure!(
            private_batch_common.num_public_inputs == expected_l0_pi_len,
            "private_batch_common.num_public_inputs ({}) != expected private_batch PI len ({}) for private_batch_num_leaves={}",
            private_batch_common.num_public_inputs,
            expected_l0_pi_len,
            private_batch_num_leaves,
        );

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let private_batch_proofs = add_recursive_verifiers::<F, C, D>(
            &mut builder,
            &private_batch_common,
            private_batch_verifier_only,
            n_inner,
        )?;

        let aggregator_address: [Target; AGGREGATOR_ADDRESS_LEN] = builder
            .add_virtual_targets(AGGREGATOR_ADDRESS_LEN)
            .try_into()
            .unwrap();

        let targets = PublicBatchCircuitTargets {
            private_batch_proofs,
            aggregator_address,
        };

        // Build wrapper constraints and register public inputs.
        build_public_batch_constraints(&mut builder, &targets, n_inner, private_batch_num_leaves);

        Ok(Self { builder, targets })
    }

    pub fn targets(&self) -> PublicBatchCircuitTargets {
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
        println!("\n=== Public-batch Gate Instance Counts ===");
        self.builder.print_gate_counts(0);
        self.builder.build()
    }

    /// Returns the current number of gates in the circuit (before building).
    pub fn num_gates(&self) -> usize {
        self.builder.num_gates()
    }
}

/// Build the public-batch wrapper constraints and register output public inputs.
///
/// Dummy inner proofs (private-batch proofs over all-dummy leaves, identified by
/// `block_hash == 0`) are supported so partial public batches can be padded:
/// - dummies are exempt from asset/fee/block consistency,
/// - reference header values come from the first non-dummy inner (prefix scan),
/// - dummy inners' exit slots and nullifiers are zeroed in the output, so the
///   on-chain verifier can skip them and a single dummy proof template can be
///   reused across slots without nullifier collisions.
///
/// Unlike the private-batch wrapper there is NO shuffling and NO cross-proof
/// grouping: forwarding stays order-preserving so each inner proof owns a
/// contiguous, attributable segment of the output (required for on-chain
/// per-segment denial). Dummies here serve batch-filling, not privacy.
///
/// Output layout (public-batch):
/// [aggregator_address(4),
///  asset_id(1),
///  volume_fee_bps(1),
///  block_hash(4),
///  block_number(1),
///  total_exit_slots(1),
///  [sum(1), exit(4)] * total_exit_slots,
///  nullifier(4) * total_nullifiers]
fn build_public_batch_constraints(
    builder: &mut CircuitBuilder<F, D>,
    targets: &PublicBatchCircuitTargets,
    n_inner: usize,
    private_batch_num_leaves: usize,
) {
    let one = builder.one();
    let zero = builder.zero();

    let private_batch_pi_len = pbc::private_batch_pi_len(private_batch_num_leaves);
    let private_batch_exit_slots_per_proof =
        pbc::private_batch_exit_slots_count(private_batch_num_leaves);
    let private_batch_nullifiers_per_proof =
        pbc::private_batch_nullifiers_count(private_batch_num_leaves);

    // Convenience: references to each child proof's PI slice
    let private_batch_pi_targets: Vec<&[Target]> = targets
        .private_batch_proofs
        .iter()
        .map(|p| p.public_inputs.as_slice())
        .collect();

    // Runtime shape check: each inner proof's PI slice must match the private-batch
    // PI length derived from `private_batch_num_leaves` before fixed-offset indexing.
    assert!(private_batch_pi_targets
        .iter()
        .all(|pis| pis.len() == private_batch_pi_len));

    // -------------------------------------------------------------------------
    // Dummy detection (sentinel: inner block_hash == 0, i.e. an all-dummy
    // private batch, mirroring the leaf-level sentinel one layer down)
    // -------------------------------------------------------------------------
    let dummy_sentinel = [zero, zero, zero, zero];
    let mut is_dummy_flags: Vec<BoolTarget> = Vec::with_capacity(n_inner);
    let mut block_hashes: Vec<[Target; 4]> = Vec::with_capacity(n_inner);
    for pis_i in private_batch_pi_targets.iter().take(n_inner) {
        let block_i: [Target; 4] =
            core::array::from_fn(|j| pis_i[pbc::PRIVATE_BATCH_BLOCK_HASH_OFFSET + j]);
        let is_dummy_i = bytes_digest_eq(builder, block_i, dummy_sentinel);
        is_dummy_flags.push(is_dummy_i);
        block_hashes.push(block_i);
    }

    // -------------------------------------------------------------------------
    // Reference header values from the FIRST NON-DUMMY inner proof (prefix scan).
    // An all-dummy public batch settles to zero references, which the on-chain
    // verifier rejects (block hash 0 never resolves to a real block).
    // -------------------------------------------------------------------------
    let mut found_real = builder._false();
    let mut block_ref = [zero, zero, zero, zero];
    let mut block_number_ref = zero;
    let mut asset_ref = zero;
    let mut fee_ref = zero;
    for i in 0..n_inner {
        let is_real_i = builder.not(is_dummy_flags[i]);
        let not_found_yet = builder.not(found_real);
        let take_i = builder.and(is_real_i, not_found_yet);

        for j in 0..4 {
            block_ref[j] = builder.select(take_i, block_hashes[i][j], block_ref[j]);
        }
        let pis_i = private_batch_pi_targets[i];
        block_number_ref = builder.select(
            take_i,
            pis_i[pbc::PRIVATE_BATCH_BLOCK_NUMBER_OFFSET],
            block_number_ref,
        );
        asset_ref = builder.select(take_i, pis_i[pbc::PRIVATE_BATCH_ASSET_ID_OFFSET], asset_ref);
        fee_ref = builder.select(
            take_i,
            pis_i[pbc::PRIVATE_BATCH_VOLUME_FEE_BPS_OFFSET],
            fee_ref,
        );

        found_real = builder.or(found_real, is_real_i);
    }

    // -------------------------------------------------------------------------
    // Output PIs
    // -------------------------------------------------------------------------
    let mut output_pis: Vec<Target> = Vec::new();

    // 1) Aggregator address (witness target, 4 felts, 8 bytes/felt)
    output_pis.extend_from_slice(&targets.aggregator_address);

    // 2) Reference values (from first non-dummy inner)
    output_pis.push(asset_ref);
    output_pis.push(fee_ref);

    // 3) Enforce asset/fee/block consistency across all non-dummy private-batch
    //    proofs: `is_dummy_i OR matches_ref`.
    //    block_number is not checked here: each inner private-batch proof already
    //    binds block_hash and block_number together (via the leaf header parse), so
    //    block_hash equality transitively pins the number.
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        let asset_matches = builder.is_equal(pis_i[pbc::PRIVATE_BATCH_ASSET_ID_OFFSET], asset_ref);
        let asset_ok = builder.or(is_dummy_flags[i], asset_matches);
        builder.connect(asset_ok.target, one);

        let fee_matches =
            builder.is_equal(pis_i[pbc::PRIVATE_BATCH_VOLUME_FEE_BPS_OFFSET], fee_ref);
        let fee_ok = builder.or(is_dummy_flags[i], fee_matches);
        builder.connect(fee_ok.target, one);

        let block_matches = bytes_digest_eq(builder, block_hashes[i], block_ref);
        let block_ok = builder.or(is_dummy_flags[i], block_matches);
        builder.connect(block_ok.target, one);
    }

    // Output block reference + number
    output_pis.extend_from_slice(&block_ref);
    output_pis.push(block_number_ref);

    // 4) Total exit slots across all private-batch proofs (structural constant;
    //    dummy inners contribute zeroed slots that the chain skips)
    let total_exit_slots = n_inner * private_batch_exit_slots_per_proof;
    output_pis.push(builder.constant(F::from_canonical_usize(total_exit_slots)));

    // 5) Forward exit slots from all private-batch proofs, zeroing dummy inners'
    //    slots. Genuine dummies already carry zero slots; the select makes that
    //    an enforced invariant rather than a construction detail.
    let exit_slots_start = pbc::private_batch_exit_slots_start();
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for slot_idx in 0..private_batch_exit_slots_per_proof {
            let slot_base = exit_slots_start + slot_idx * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
            // [sum(1), exit_account(4)]
            for j in 0..pbc::PRIVATE_BATCH_EXIT_SLOT_LEN {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[slot_base + j]);
                output_pis.push(forwarded);
            }
        }
    }

    // 6) Forward nullifiers from all private-batch proofs, zeroing dummy inners'
    //    nullifiers. This lets the chain skip them (no storage bloat) and lets a
    //    single dummy proof template fill several slots without collisions. Real
    //    nullifiers are hash outputs and are never zero.
    let nullifiers_start = pbc::private_batch_nullifiers_start(private_batch_num_leaves);
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for n_idx in 0..private_batch_nullifiers_per_proof {
            let base = nullifiers_start + n_idx * 4;
            for j in 0..4 {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[base + j]);
                output_pis.push(forwarded);
            }
        }
    }

    // Register output public inputs (fixed length for fixed n_inner and private_batch_num_leaves)
    builder.register_public_inputs(&output_pis);
}

#[cfg(test)]
#[path = "tests/circuit_logic.rs"]
mod tests;
