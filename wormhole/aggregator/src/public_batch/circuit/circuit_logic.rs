//! Public-batch aggregation circuit (monolithic prebuilt-circuit form).
//!
//! Verifies N private-batch aggregated proofs and emits a public-batch aggregated proof.
//! The private-batch verifier key is baked in as constants to prevent verifier key substitution.

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

use zk_circuits_common::{
    circuit::{C, D, F},
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
    pub fn new(
        config: CircuitConfig,
        private_batch_common: CommonCircuitData<F, D>,
        private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
        n_inner: usize,
        private_batch_num_leaves: usize,
    ) -> Self {
        assert!(n_inner > 0, "n_inner must be > 0");
        assert!(
            private_batch_num_leaves > 0,
            "private_batch_num_leaves must be > 0"
        );

        let expected_l0_pi_len = pbc::private_batch_pi_len(private_batch_num_leaves);

        debug_assert_eq!(
            private_batch_common.num_public_inputs,
            expected_l0_pi_len,
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
        );

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

        Self { builder, targets }
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

    debug_assert!(private_batch_pi_targets
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
mod tests {
    use super::*;
    use plonky2::field::types::PrimeField64;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use qp_wormhole_inputs::PUBLIC_INPUTS_FELTS_LEN as LEAF_PI_LEN;

    use super::super::constants::AGGREGATOR_ADDRESS_LEN;
    use crate::private_batch::circuit::circuit_logic::{
        PrivateBatchCircuit, PrivateBatchCircuitTargets,
    };
    use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};

    const NUM_LEAVES: usize = 2; // 2 leaf proofs per private-batch batch (fast)
    const N_INNER: usize = 2; // 2 private-batch proofs aggregated into one public-batch proof

    /// Build one leaf PI array in the Bitcoin-style 2-output layout.
    ///
    /// Layout (21 felts total):
    /// - asset_id(1), output_amount_1(1), output_amount_2(1), volume_fee_bps(1)
    /// - nullifier(4)
    /// - exit_account_1(4) - 4 felts (8 bytes/felt)
    /// - exit_account_2(4) - 4 felts (8 bytes/felt)
    /// - block_hash(4), block_number(1)
    fn make_leaf_pi(
        amount1: u32,
        amount2: u32,
        exit1: [u64; 4],
        exit2: [u64; 4],
        nullifier: [u64; 4],
        block_hash: [u64; 4],
        block_number: u32,
    ) -> [F; LEAF_PI_LEN] {
        let mut out = [F::ZERO; LEAF_PI_LEN];
        out[0] = F::ZERO; // asset_id = 0 (native)
        out[1] = F::from_canonical_u64(amount1 as u64);
        out[2] = F::from_canonical_u64(amount2 as u64);
        out[3] = F::from_canonical_u64(10); // volume_fee_bps = 10 bps

        for j in 0..4 {
            out[4 + j] = F::from_canonical_u64(nullifier[j]);
        }
        for j in 0..4 {
            out[8 + j] = F::from_canonical_u64(exit1[j]);
        }
        for j in 0..4 {
            out[12 + j] = F::from_canonical_u64(exit2[j]);
        }
        for j in 0..4 {
            out[16 + j] = F::from_canonical_u64(block_hash[j]);
        }
        out[20] = F::from_canonical_u64(block_number as u64);

        out
    }

    // ---------------- Private-batch proving helpers ----------------

    /// Prove a private-batch aggregated proof using the monolithic PrivateBatchCircuit.
    fn prove_private_batch_batch(
        private_batch_data: &CircuitData<F, C, D>,
        private_batch_targets: &PrivateBatchCircuitTargets,
        leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        assert_eq!(leaf_proofs.len(), NUM_LEAVES);

        let mut pw = PartialWitness::new();

        // NOTE: leaf_verifier_data is NOT set - it's baked in as constants

        // Fill each leaf proof target
        for (pt, proof) in private_batch_targets
            .leaf_proofs
            .iter()
            .zip(leaf_proofs.iter())
        {
            pw.set_proof_with_pis_target(pt, proof).unwrap();
        }

        // Dummy nullifier preimages: can be anything for non-dummy leaves (is_dummy=false), but must be filled.
        for (i, limbs) in private_batch_targets
            .dummy_nullifier_pre_images
            .iter()
            .enumerate()
        {
            for (j, t) in limbs.iter().enumerate() {
                let v = F::from_canonical_u64(1000 + (i as u64) * 10 + (j as u64));
                pw.set_target(*t, v).unwrap();
            }
        }

        private_batch_data.prove(pw).unwrap()
    }

    // ---------------- Public-batch proving helpers ----------------

    /// Prove a public-batch aggregated proof using PublicBatchCircuit.
    fn prove_public_batch(
        public_batch_data: &CircuitData<F, C, D>,
        public_batch_targets: &PublicBatchCircuitTargets,
        private_batch_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
        aggregator_address: [F; AGGREGATOR_ADDRESS_LEN],
    ) -> Result<ProofWithPublicInputs<F, C, D>, anyhow::Error> {
        assert_eq!(private_batch_proofs.len(), N_INNER);

        let mut pw = PartialWitness::new();

        // NOTE: private_batch_verifier_data is NOT set - it's baked in as constants

        // Fill private-batch proof targets
        for (pt, proof) in public_batch_targets
            .private_batch_proofs
            .iter()
            .zip(private_batch_proofs.iter())
        {
            pw.set_proof_with_pis_target(pt, proof).unwrap();
        }

        // Fill aggregator address (4 felts, 8 bytes/felt)
        for (i, limb) in aggregator_address.iter().enumerate() {
            pw.set_target(public_batch_targets.aggregator_address[i], *limb)
                .unwrap();
        }

        public_batch_data
            .prove(pw)
            .map_err(|e| anyhow::anyhow!("public_batch prove failed: {}", e))
    }

    // ---------------- Tests ----------------

    /// Port of the old `two_layer_aggregation_pipeline` test, updated for:
    /// - monolithic PrivateBatchCircuit
    /// - monolithic PublicBatchCircuit
    /// - aggregator_address is a witness target
    #[test]
    fn two_layer_aggregation_pipeline_monolithic() {
        let block_hash: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
        let block_number = 42u32;

        // ---- 1) Build fake leaf circuit once and generate leaf proofs ----
        let (leaf_data, leaf_targets) = build_fake_leaf_circuit();

        // Batch A: 2 leaf proofs
        let leaf_a0 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                100,
                0,
                [1, 2, 3, 4],
                [0, 0, 0, 0],
                [0x10, 0x11, 0x12, 0x13],
                block_hash,
                block_number,
            ),
        );
        let leaf_a1 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                200,
                50,
                [5, 6, 7, 8],
                [9, 10, 11, 12],
                [0x20, 0x21, 0x22, 0x23],
                block_hash,
                block_number,
            ),
        );

        // Batch B: 2 more leaf proofs (same leaf circuit, same block)
        let leaf_b0 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                300,
                0,
                [13, 14, 15, 16],
                [0, 0, 0, 0],
                [0x30, 0x31, 0x32, 0x33],
                block_hash,
                block_number,
            ),
        );
        let leaf_b1 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                400,
                100,
                [17, 18, 19, 20],
                [21, 22, 23, 24],
                [0x40, 0x41, 0x42, 0x43],
                block_hash,
                block_number,
            ),
        );

        // ---- 2) Build monolithic PrivateBatchCircuit once, prove two batches ----
        let leaf_common = leaf_data.common.clone();
        let leaf_verifier_only = leaf_data.verifier_only.clone();

        // SECURITY: leaf_verifier_only is baked in as constants at build time
        let private_batch_circuit = PrivateBatchCircuit::new(
            CircuitConfig::standard_recursion_config(),
            &leaf_common,
            &leaf_verifier_only,
            NUM_LEAVES,
        );
        let private_batch_targets = private_batch_circuit.targets();
        let private_batch_data = private_batch_circuit.build_circuit();

        let private_batch_proof_a = prove_private_batch_batch(
            &private_batch_data,
            &private_batch_targets,
            vec![leaf_a0.clone(), leaf_a1.clone()],
        );
        let private_batch_proof_b = prove_private_batch_batch(
            &private_batch_data,
            &private_batch_targets,
            vec![leaf_b0.clone(), leaf_b1.clone()],
        );

        // Sanity: private-batch proofs verify under private-batch circuit data
        private_batch_data
            .verify(private_batch_proof_a.clone())
            .unwrap();
        private_batch_data
            .verify(private_batch_proof_b.clone())
            .unwrap();

        // ---- 3) Build monolithic PublicBatchCircuit and prove ----
        // SECURITY: private_batch_data.verifier_only is baked in as constants at build time
        let public_batch_circuit = PublicBatchCircuit::new(
            CircuitConfig::standard_recursion_config(),
            private_batch_data.common.clone(),
            &private_batch_data.verifier_only,
            N_INNER,
            NUM_LEAVES,
        );
        let public_batch_targets = public_batch_circuit.targets();
        let public_batch_data = public_batch_circuit.build_circuit();

        // 4 felts (8 bytes/felt) for hash-derived accounts
        let aggregator_address: [F; AGGREGATOR_ADDRESS_LEN] = [
            F::from_canonical_u64(0xDEAD),
            F::from_canonical_u64(0xBEEF),
            F::from_canonical_u64(0xCAFE),
            F::from_canonical_u64(0xBABE),
        ];

        let public_batch_proof = prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![private_batch_proof_a.clone(), private_batch_proof_b.clone()],
            aggregator_address,
        )
        .expect("public-batch aggregation failed");

        // Verify proof
        public_batch_data
            .verify(public_batch_proof.clone())
            .expect("public-batch proof verification failed");

        // ---- 4) Verify output PIs match expected layout + forwarded content ----
        let pis = &public_batch_proof.public_inputs;

        // Expected PI length
        let expected_len = pbc::public_batch_pi_len(N_INNER, NUM_LEAVES);
        assert_eq!(pis.len(), expected_len, "unexpected public-batch PI length");

        // Aggregator address (4 felts, 8 bytes/felt)
        assert_eq!(
            pis[pbc::AGGREGATOR_ADDRESS_START].to_canonical_u64(),
            0xDEAD
        );
        assert_eq!(
            pis[pbc::AGGREGATOR_ADDRESS_START + 1].to_canonical_u64(),
            0xBEEF
        );
        assert_eq!(
            pis[pbc::AGGREGATOR_ADDRESS_START + 2].to_canonical_u64(),
            0xCAFE
        );
        assert_eq!(
            pis[pbc::AGGREGATOR_ADDRESS_START + 3].to_canonical_u64(),
            0xBABE
        );

        // Asset ID and volume fee
        assert_eq!(pis[pbc::ASSET_ID_START].to_canonical_u64(), 0); // asset_id = native
        assert_eq!(pis[pbc::VOLUME_FEE_BPS_START].to_canonical_u64(), 10); // volume_fee_bps

        // Block hash
        assert_eq!(pis[pbc::BLOCK_HASH_START].to_canonical_u64(), 0xAA01);
        assert_eq!(pis[pbc::BLOCK_HASH_START + 1].to_canonical_u64(), 0xAA02);
        assert_eq!(pis[pbc::BLOCK_HASH_START + 2].to_canonical_u64(), 0xAA03);
        assert_eq!(pis[pbc::BLOCK_HASH_START + 3].to_canonical_u64(), 0xAA04);

        // Block number
        assert_eq!(pis[pbc::BLOCK_NUMBER_START].to_canonical_u64(), 42);

        // Total exit slots = N_INNER * (2 * NUM_LEAVES)
        assert_eq!(
            pis[pbc::TOTAL_EXIT_SLOTS_START].to_canonical_u64(),
            (N_INNER * 2 * NUM_LEAVES) as u64
        );

        // ---- Forwarding checks (exit slots + nullifiers) ----

        // public-batch exit slots region begins immediately after the header
        let public_batch_exit_start = pbc::PUBLIC_BATCH_HEADER_LEN;
        let private_batch_exit_start = pbc::private_batch_exit_slots_start();
        let private_batch_exit_len =
            pbc::private_batch_exit_slots_count(NUM_LEAVES) * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;

        // For each private-batch proof, ensure its exit slot region is copied verbatim into public-batch PIs.
        for (i, l0p) in [private_batch_proof_a.clone(), private_batch_proof_b.clone()]
            .into_iter()
            .enumerate()
        {
            let src = &l0p.public_inputs
                [private_batch_exit_start..private_batch_exit_start + private_batch_exit_len];
            let dst = &pis[public_batch_exit_start + i * private_batch_exit_len
                ..public_batch_exit_start + (i + 1) * private_batch_exit_len];
            assert_eq!(
                dst, src,
                "public-batch exit slots mismatch for inner proof {i}"
            );
        }

        // Nullifiers:
        let public_batch_null_start = pbc::public_batch_nullifiers_start(N_INNER, NUM_LEAVES);
        let private_batch_null_start = pbc::private_batch_nullifiers_start(NUM_LEAVES);
        let private_batch_null_len = pbc::private_batch_nullifiers_count(NUM_LEAVES) * 4;

        for (i, l0p) in [private_batch_proof_a, private_batch_proof_b]
            .into_iter()
            .enumerate()
        {
            let src = &l0p.public_inputs
                [private_batch_null_start..private_batch_null_start + private_batch_null_len];
            let dst = &pis[public_batch_null_start + i * private_batch_null_len
                ..public_batch_null_start + (i + 1) * private_batch_null_len];
            assert_eq!(
                dst, src,
                "public-batch nullifiers mismatch for inner proof {i}"
            );
        }
    }

    /// A partial public batch padded with an all-dummy private batch:
    /// - proving succeeds (dummy exempt from consistency checks),
    /// - header references come from the real inner proof,
    /// - the dummy inner's exit slots AND nullifiers are zeroed in the output
    ///   (the private batch emits hash-of-preimage nullifiers for dummies, which
    ///   must NOT leak through to the chain).
    #[test]
    fn public_batch_with_dummy_padding() {
        let block_hash: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
        let block_number = 42u32;

        let (leaf_data, leaf_targets) = build_fake_leaf_circuit();

        // Real batch: 2 real leaves
        let real_0 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                100,
                0,
                [1, 2, 3, 4],
                [0, 0, 0, 0],
                [0x10, 0x11, 0x12, 0x13],
                block_hash,
                block_number,
            ),
        );
        let real_1 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                200,
                50,
                [5, 6, 7, 8],
                [9, 10, 11, 12],
                [0x20, 0x21, 0x22, 0x23],
                block_hash,
                block_number,
            ),
        );

        // Dummy batch: 2 dummy leaves (block_hash == 0 sentinel, zero amounts/exits)
        let dummy_leaf_pi = make_leaf_pi(0, 0, [0; 4], [0; 4], [0; 4], [0; 4], 0);
        let dummy_0 = prove_fake_leaf(&leaf_data, &leaf_targets, dummy_leaf_pi);
        let dummy_1 = prove_fake_leaf(&leaf_data, &leaf_targets, dummy_leaf_pi);

        let private_batch_circuit = PrivateBatchCircuit::new(
            CircuitConfig::standard_recursion_config(),
            &leaf_data.common,
            &leaf_data.verifier_only,
            NUM_LEAVES,
        );
        let private_batch_targets = private_batch_circuit.targets();
        let private_batch_data = private_batch_circuit.build_circuit();

        let real_batch = prove_private_batch_batch(
            &private_batch_data,
            &private_batch_targets,
            vec![real_0, real_1],
        );
        let dummy_batch = prove_private_batch_batch(
            &private_batch_data,
            &private_batch_targets,
            vec![dummy_0, dummy_1],
        );

        // Sanity: the all-dummy private batch carries the dummy sentinel (block_hash == 0)
        // but NON-zero nullifiers (dummy replacement hashes) - exactly what the public
        // batch must zero out.
        let dummy_pis = &dummy_batch.public_inputs;
        for j in 0..4 {
            assert_eq!(
                dummy_pis[pbc::PRIVATE_BATCH_BLOCK_HASH_OFFSET + j].to_canonical_u64(),
                0,
                "all-dummy private batch must have block_hash == 0"
            );
        }
        let pb_null_start = pbc::private_batch_nullifiers_start(NUM_LEAVES);
        let pb_null_len = pbc::private_batch_nullifiers_count(NUM_LEAVES) * 4;
        assert!(
            dummy_pis[pb_null_start..pb_null_start + pb_null_len]
                .iter()
                .any(|f| f.to_canonical_u64() != 0),
            "dummy private batch is expected to emit non-zero replacement nullifiers"
        );

        let public_batch_circuit = PublicBatchCircuit::new(
            CircuitConfig::standard_recursion_config(),
            private_batch_data.common.clone(),
            &private_batch_data.verifier_only,
            N_INNER,
            NUM_LEAVES,
        );
        let public_batch_targets = public_batch_circuit.targets();
        let public_batch_data = public_batch_circuit.build_circuit();

        let aggregator_address: [F; AGGREGATOR_ADDRESS_LEN] = [
            F::from_canonical_u64(0xDEAD),
            F::from_canonical_u64(0xBEEF),
            F::from_canonical_u64(0xCAFE),
            F::from_canonical_u64(0xBABE),
        ];

        // Slot 0 = real batch, slot 1 = dummy padding
        let public_batch_proof = prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![real_batch.clone(), dummy_batch],
            aggregator_address,
        )
        .expect("public batch with dummy padding must prove");

        public_batch_data
            .verify(public_batch_proof.clone())
            .expect("padded public-batch proof must verify");

        let pis = &public_batch_proof.public_inputs;

        // Header references come from the real (first non-dummy) inner
        assert_eq!(pis[pbc::ASSET_ID_START].to_canonical_u64(), 0);
        assert_eq!(pis[pbc::VOLUME_FEE_BPS_START].to_canonical_u64(), 10);
        for j in 0..4 {
            assert_eq!(
                pis[pbc::BLOCK_HASH_START + j].to_canonical_u64(),
                block_hash[j]
            );
        }
        assert_eq!(
            pis[pbc::BLOCK_NUMBER_START].to_canonical_u64(),
            block_number as u64
        );

        // Real inner's exit slots forwarded verbatim
        let exit_start = pbc::public_batch_exit_slots_start();
        let seg_exit_len =
            pbc::private_batch_exit_slots_count(NUM_LEAVES) * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
        let src_exit_start = pbc::private_batch_exit_slots_start();
        assert_eq!(
            &pis[exit_start..exit_start + seg_exit_len],
            &real_batch.public_inputs[src_exit_start..src_exit_start + seg_exit_len],
            "real inner's exit slots must be forwarded verbatim"
        );

        // Dummy inner's exit slots are all zero
        assert!(
            pis[exit_start + seg_exit_len..exit_start + 2 * seg_exit_len]
                .iter()
                .all(|f| f.to_canonical_u64() == 0),
            "dummy inner's exit slots must be zeroed"
        );

        // Real inner's nullifiers forwarded verbatim; dummy inner's zeroed
        let null_start = pbc::public_batch_nullifiers_start(N_INNER, NUM_LEAVES);
        let seg_null_len = pbc::private_batch_nullifiers_count(NUM_LEAVES) * 4;
        assert_eq!(
            &pis[null_start..null_start + seg_null_len],
            &real_batch.public_inputs[pb_null_start..pb_null_start + seg_null_len],
            "real inner's nullifiers must be forwarded verbatim"
        );
        assert!(
            pis[null_start + seg_null_len..null_start + 2 * seg_null_len]
                .iter()
                .all(|f| f.to_canonical_u64() == 0),
            "dummy inner's nullifiers must be zeroed"
        );
    }

    /// Negative test: if two private-batch proofs use different block hashes, public-batch proving must fail.
    #[test]
    fn public_batch_mismatched_blocks_fails() {
        let block_a: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
        let block_b: [u64; 4] = [0xBB01, 0xBB02, 0xBB03, 0xBB04];
        let block_number = 42u32;

        let (leaf_data, leaf_targets) = build_fake_leaf_circuit();

        // Batch A uses block_a
        let a0 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                100,
                0,
                [1, 2, 3, 4],
                [0, 0, 0, 0],
                [1, 2, 3, 4],
                block_a,
                block_number,
            ),
        );
        let a1 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                200,
                0,
                [5, 6, 7, 8],
                [0, 0, 0, 0],
                [5, 6, 7, 8],
                block_a,
                block_number,
            ),
        );

        // Batch B uses block_b (still internally consistent)
        let b0 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                300,
                0,
                [9, 10, 11, 12],
                [0, 0, 0, 0],
                [9, 10, 11, 12],
                block_b,
                block_number,
            ),
        );
        let b1 = prove_fake_leaf(
            &leaf_data,
            &leaf_targets,
            make_leaf_pi(
                400,
                0,
                [13, 14, 15, 16],
                [0, 0, 0, 0],
                [13, 14, 15, 16],
                block_b,
                block_number,
            ),
        );

        // Private-batch circuit
        // SECURITY: leaf verifier_only is baked in as constants at build time
        let private_batch_circuit = PrivateBatchCircuit::new(
            CircuitConfig::standard_recursion_config(),
            &leaf_data.common,
            &leaf_data.verifier_only,
            NUM_LEAVES,
        );
        let private_batch_targets = private_batch_circuit.targets();
        let private_batch_data = private_batch_circuit.build_circuit();

        let private_batch_a =
            prove_private_batch_batch(&private_batch_data, &private_batch_targets, vec![a0, a1]);
        let private_batch_b =
            prove_private_batch_batch(&private_batch_data, &private_batch_targets, vec![b0, b1]);

        // Public-batch circuit
        // SECURITY: l0 verifier_only is baked in as constants at build time
        let public_batch_circuit = PublicBatchCircuit::new(
            CircuitConfig::standard_recursion_config(),
            private_batch_data.common.clone(),
            &private_batch_data.verifier_only,
            N_INNER,
            NUM_LEAVES,
        );
        let public_batch_targets = public_batch_circuit.targets();
        let public_batch_data = public_batch_circuit.build_circuit();

        let agg_addr = [
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
        ];

        let res = prove_public_batch(
            &public_batch_data,
            &public_batch_targets,
            vec![private_batch_a, private_batch_b],
            agg_addr,
        );

        assert!(
            res.is_err(),
            "expected public-batch proving to fail for mismatched blocks"
        );
    }
}
