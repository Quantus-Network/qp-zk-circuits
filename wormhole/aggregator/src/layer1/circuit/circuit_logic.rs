//! Layer-1 aggregation circuit (monolithic prebuilt-circuit form).
//!
//! Verifies N layer-0 aggregated proofs directly and emits a layer-1 aggregated proof.

use plonky2::{
    field::types::Field,
    iop::target::Target,
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
    gadgets::bytes_digest_eq,
};

use super::constants::AGGREGATOR_ADDRESS_LEN;

use super::constants as l1c;

/// Runtime targets for the prebuilt layer-1 aggregation circuit.
#[derive(Debug, Clone)]
pub struct Layer1AggregationCircuitTargets {
    /// Verifier target for the layer-0 aggregation circuit.
    pub layer0_verifier_data: VerifierCircuitTarget,
    /// One proof target per layer-0 slot.
    pub layer0_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// Aggregator address (4 felts, 8 bytes/felt) for hash-derived accounts.
    pub aggregator_address: [Target; AGGREGATOR_ADDRESS_LEN],
}

pub struct Layer1AggregationCircuit {
    builder: CircuitBuilder<F, D>,
    targets: Layer1AggregationCircuitTargets,
}

impl Layer1AggregationCircuit {
    /// Build a monolithic layer-1 aggregation circuit that verifies `n_inner` layer-0 aggregated proofs.
    ///
    /// # Arguments
    /// - `config`: circuit config for the layer-1 circuit itself
    /// - `layer0_common`: common data for the layer-0 aggregation circuit
    /// - `n_inner`: number of layer-0 aggregated proofs to aggregate
    /// - `layer0_num_leaves`: number of leaf proofs represented in each layer-0 proof
    pub fn new(
        config: CircuitConfig,
        layer0_common: CommonCircuitData<F, D>,
        n_inner: usize,
        layer0_num_leaves: usize,
    ) -> Self {
        assert!(n_inner > 0, "n_inner must be > 0");
        assert!(layer0_num_leaves > 0, "layer0_num_leaves must be > 0");

        // Expected PI length of each layer-0 aggregated proof, derived from layout.
        let expected_l0_pi_len = l1c::l0_pi_len(layer0_num_leaves);

        // Catch config mismatches early.
        debug_assert_eq!(
            layer0_common.num_public_inputs,
            expected_l0_pi_len,
            "layer0_common.num_public_inputs ({}) != expected layer0 PI len ({}) for layer0_num_leaves={}",
            layer0_common.num_public_inputs,
            expected_l0_pi_len,
            layer0_num_leaves,
        );

        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Allocate verifier target for the layer-0 circuit.
        let layer0_verifier_data =
            builder.add_virtual_verifier_data(layer0_common.fri_params.config.cap_height);

        // Allocate N layer-0 proof targets and verify each.
        let mut layer0_proofs = Vec::with_capacity(n_inner);
        for _ in 0..n_inner {
            let pt = builder.add_virtual_proof_with_pis(&layer0_common);
            builder.verify_proof::<C>(&pt, &layer0_verifier_data, &layer0_common);
            layer0_proofs.push(pt);
        }

        // Aggregator address is witness-filled (NOT a constant).
        // Uses 4 felts (8 bytes/felt) for hash-derived accounts.
        let aggregator_address: [Target; AGGREGATOR_ADDRESS_LEN] = builder
            .add_virtual_targets(AGGREGATOR_ADDRESS_LEN)
            .try_into()
            .unwrap();

        let targets = Layer1AggregationCircuitTargets {
            layer0_verifier_data,
            layer0_proofs,
            aggregator_address,
        };

        // Build wrapper constraints and register public inputs.
        build_layer1_wrapper_constraints(&mut builder, &targets, n_inner, layer0_num_leaves);

        Self { builder, targets }
    }

    pub fn targets(&self) -> Layer1AggregationCircuitTargets {
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
        println!("\n=== Layer-1 Gate Instance Counts ===");
        self.builder.print_gate_counts(0);
        self.builder.build()
    }

    /// Returns the current number of gates in the circuit (before building).
    pub fn num_gates(&self) -> usize {
        self.builder.num_gates()
    }
}

/// Build the layer-1 wrapper constraints and register output public inputs.
///
/// Output layout (layer-1):
/// [aggregator_address(4),
///  asset_id(1),
///  volume_fee_bps(1),
///  block_hash(4),
///  block_number(1),
///  total_exit_slots(1),
///  [sum(1), exit(4)] * total_exit_slots,
///  nullifier(4) * total_nullifiers]
fn build_layer1_wrapper_constraints(
    builder: &mut CircuitBuilder<F, D>,
    targets: &Layer1AggregationCircuitTargets,
    n_inner: usize,
    layer0_num_leaves: usize,
) {
    let one = builder.one();

    let l0_pi_len = l1c::l0_pi_len(layer0_num_leaves);
    let l0_exit_slots_per_proof = l1c::l0_exit_slots_count(layer0_num_leaves);
    let l0_nullifiers_per_proof = l1c::l0_nullifiers_count(layer0_num_leaves);

    // Convenience: references to each child proof's PI slice
    let l0_pi_targets: Vec<&[Target]> = targets
        .layer0_proofs
        .iter()
        .map(|p| p.public_inputs.as_slice())
        .collect();

    debug_assert!(l0_pi_targets.iter().all(|pis| pis.len() == l0_pi_len));

    // -------------------------------------------------------------------------
    // Output PIs
    // -------------------------------------------------------------------------
    let mut output_pis: Vec<Target> = Vec::new();

    // 1) Aggregator address (witness target, 4 felts, 8 bytes/felt)
    output_pis.extend_from_slice(&targets.aggregator_address);

    // 2) Reference values from proof 0
    let asset_ref = l0_pi_targets[0][l1c::L0_ASSET_ID_OFFSET];
    let fee_ref = l0_pi_targets[0][l1c::L0_VOLUME_FEE_BPS_OFFSET];
    output_pis.push(asset_ref);
    output_pis.push(fee_ref);

    let block_ref: [Target; 4] =
        core::array::from_fn(|j| l0_pi_targets[0][l1c::L0_BLOCK_HASH_OFFSET + j]);
    let block_number_ref = l0_pi_targets[0][l1c::L0_BLOCK_NUMBER_OFFSET];

    // 3) Enforce asset/fee consistency and block consistency across all layer-0 proofs
    for pis_i in l0_pi_targets.iter().take(n_inner) {
        // asset_id and volume_fee_bps must match
        builder.connect(pis_i[l1c::L0_ASSET_ID_OFFSET], asset_ref);
        builder.connect(pis_i[l1c::L0_VOLUME_FEE_BPS_OFFSET], fee_ref);

        // block hash must match ref
        let block_i: [Target; 4] = core::array::from_fn(|j| pis_i[l1c::L0_BLOCK_HASH_OFFSET + j]);
        let matches_ref = bytes_digest_eq(builder, block_i, block_ref);
        builder.connect(matches_ref.target, one);
    }

    // Output block reference + number
    output_pis.extend_from_slice(&block_ref);
    output_pis.push(block_number_ref);

    // 4) Total exit slots across all layer-0 proofs
    let total_exit_slots = n_inner * l0_exit_slots_per_proof;
    output_pis.push(builder.constant(F::from_canonical_usize(total_exit_slots)));

    // 5) Forward exit slots from all layer-0 proofs
    let exit_slots_start = l1c::l0_exit_slots_start();
    for pis_i in l0_pi_targets.iter().take(n_inner) {
        for slot_idx in 0..l0_exit_slots_per_proof {
            let slot_base = exit_slots_start + slot_idx * l1c::L0_EXIT_SLOT_LEN;
            // [sum(1), exit_account(4)]
            for j in 0..l1c::L0_EXIT_SLOT_LEN {
                output_pis.push(pis_i[slot_base + j]);
            }
        }
    }

    // 6) Forward nullifiers from all layer-0 proofs
    let nullifiers_start = l1c::l0_nullifiers_start(layer0_num_leaves);
    for pis_i in l0_pi_targets.iter().take(n_inner) {
        for n_idx in 0..l0_nullifiers_per_proof {
            let base = nullifiers_start + n_idx * 4;
            for j in 0..4 {
                output_pis.push(pis_i[base + j]);
            }
        }
    }

    // Register output public inputs (fixed length for fixed n_inner and layer0_num_leaves)
    builder.register_public_inputs(&output_pis);
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::PrimeField64;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::{CircuitConfig, VerifierOnlyCircuitData};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use qp_wormhole_inputs::PUBLIC_INPUTS_FELTS_LEN as LEAF_PI_LEN;

    use super::super::constants::AGGREGATOR_ADDRESS_LEN;
    use crate::layer0::circuit::{
        constants::{INNER_NUM_LEAVES, TOTAL_NUM_LEAVES},
        InnerAggregationCircuit, InnerAggregationCircuitTargets, OuterAggregationCircuit,
        OuterAggregationCircuitTargets,
    };

    const N_INNER: usize = 2; // 2 layer-0 proofs aggregated into one layer-1 proof

    // ---------------- Fake leaf circuit ----------------

    /// Build a fake leaf circuit whose public inputs match the Wormhole leaf PI layout (length=LEAF_PI_LEN).
    /// We use this to generate leaf proofs that the layer-0 circuit can verify/aggregate.
    fn build_fake_leaf_circuit() -> (CircuitData<F, C, D>, [Target; LEAF_PI_LEN]) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pis_vec = builder.add_virtual_targets(LEAF_PI_LEN);
        let pis: [Target; LEAF_PI_LEN] = pis_vec
            .clone()
            .try_into()
            .expect("exactly LEAF_PI_LEN targets");

        // Range checks to mimic real leaf constraints (matches old tests)
        builder.range_check(pis[1], 32); // output_amount_1
        builder.range_check(pis[2], 32); // output_amount_2
        builder.range_check(pis[3], 32); // volume_fee_bps

        builder.register_public_inputs(&pis_vec);

        let data = builder.build::<C>();
        (data, pis)
    }

    fn prove_fake_leaf(
        leaf_data: &CircuitData<F, C, D>,
        leaf_targets: &[Target; LEAF_PI_LEN],
        pis: [F; LEAF_PI_LEN],
    ) -> ProofWithPublicInputs<F, C, D> {
        let mut pw = PartialWitness::new();
        for (t, v) in leaf_targets.iter().zip(pis.iter()) {
            pw.set_target(*t, *v).unwrap();
        }
        leaf_data.prove(pw).unwrap()
    }

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

    // ---------------- Layer-0 proving helpers ----------------

    fn prove_inner_batch(
        inner_data: &CircuitData<F, C, D>,
        inner_targets: &InnerAggregationCircuitTargets,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        assert_eq!(leaf_proofs.len(), INNER_NUM_LEAVES);

        let mut pw = PartialWitness::new();

        // Fill leaf verifier target
        pw.set_verifier_data_target(&inner_targets.leaf_verifier_data, leaf_verifier_only)
            .unwrap();

        // Fill each leaf proof target
        for (pt, proof) in inner_targets.leaf_proofs.iter().zip(leaf_proofs.iter()) {
            pw.set_proof_with_pis_target(pt, proof).unwrap();
        }

        for (i, limbs) in inner_targets.dummy_nullifier_pre_images.iter().enumerate() {
            for (j, t) in limbs.iter().enumerate() {
                let v = F::from_canonical_u64(1000 + (i as u64) * 10 + (j as u64));
                pw.set_target(*t, v).unwrap();
            }
        }

        inner_data.prove(pw).unwrap()
    }

    fn prove_outer_batch(
        outer_data: &CircuitData<F, C, D>,
        outer_targets: &OuterAggregationCircuitTargets,
        inner_verifier_only: &VerifierOnlyCircuitData<C, D>,
        inner_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        assert_eq!(inner_proofs.len(), 2);

        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(&outer_targets.inner_verifier_data, inner_verifier_only)
            .unwrap();
        for (pt, proof) in outer_targets.inner_proofs.iter().zip(inner_proofs.iter()) {
            pw.set_proof_with_pis_target(pt, proof).unwrap();
        }

        outer_data.prove(pw).unwrap()
    }

    fn prove_layer0_batch(
        leaf_data: &CircuitData<F, C, D>,
        leaf_targets: &[Target; LEAF_PI_LEN],
        inner_data: &CircuitData<F, C, D>,
        inner_targets: &InnerAggregationCircuitTargets,
        outer_data: &CircuitData<F, C, D>,
        outer_targets: &OuterAggregationCircuitTargets,
        leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        assert!(leaf_proofs.len() <= TOTAL_NUM_LEAVES);

        let dummy_leaf = prove_fake_leaf(leaf_data, leaf_targets, [F::ZERO; LEAF_PI_LEN]);
        let mut padded = leaf_proofs;
        padded.resize(TOTAL_NUM_LEAVES, dummy_leaf);

        let inner_a = prove_inner_batch(
            inner_data,
            inner_targets,
            &leaf_data.verifier_only,
            padded[..INNER_NUM_LEAVES].to_vec(),
        );
        let inner_b = prove_inner_batch(
            inner_data,
            inner_targets,
            &leaf_data.verifier_only,
            padded[INNER_NUM_LEAVES..].to_vec(),
        );

        prove_outer_batch(
            outer_data,
            outer_targets,
            &inner_data.verifier_only,
            vec![inner_a, inner_b],
        )
    }

    // ---------------- Layer-1 proving helpers ----------------

    /// Prove a layer-1 aggregated proof using Layer1AggregationCircuit.
    fn prove_layer1(
        l1_data: &CircuitData<F, C, D>,
        l1_targets: &Layer1AggregationCircuitTargets,
        layer0_verifier_only: &plonky2::plonk::circuit_data::VerifierOnlyCircuitData<C, D>,
        layer0_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
        aggregator_address: [F; AGGREGATOR_ADDRESS_LEN],
    ) -> Result<ProofWithPublicInputs<F, C, D>, anyhow::Error> {
        assert_eq!(layer0_proofs.len(), N_INNER);

        let mut pw = PartialWitness::new();

        // Fill layer-0 verifier target
        pw.set_verifier_data_target(&l1_targets.layer0_verifier_data, layer0_verifier_only)
            .unwrap();

        // Fill layer-0 proof targets
        for (pt, proof) in l1_targets.layer0_proofs.iter().zip(layer0_proofs.iter()) {
            pw.set_proof_with_pis_target(pt, proof).unwrap();
        }

        // Fill aggregator address (4 felts, 8 bytes/felt)
        for (i, limb) in aggregator_address.iter().enumerate() {
            pw.set_target(l1_targets.aggregator_address[i], *limb)
                .unwrap();
        }

        l1_data
            .prove(pw)
            .map_err(|e| anyhow::anyhow!("layer1 prove failed: {}", e))
    }

    // ---------------- Tests ----------------

    /// End-to-end check that layer-1 forwards shipping layer-0 outputs verbatim.
    #[test]
    fn two_layer_aggregation_pipeline_shipping_layer0() {
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

        // ---- 2) Build shipping layer-0 inner/outer circuits once, prove two batches ----
        let inner_circuit = InnerAggregationCircuit::new(leaf_data.common.clone());
        let inner_targets = inner_circuit.targets();
        let inner_data = inner_circuit.build_circuit();

        let outer_circuit = OuterAggregationCircuit::new(inner_data.common.clone());
        let outer_targets = outer_circuit.targets();
        let outer_data = outer_circuit.build_circuit();

        let l0_proof_a = prove_layer0_batch(
            &leaf_data,
            &leaf_targets,
            &inner_data,
            &inner_targets,
            &outer_data,
            &outer_targets,
            vec![leaf_a0.clone(), leaf_a1.clone()],
        );
        let l0_proof_b = prove_layer0_batch(
            &leaf_data,
            &leaf_targets,
            &inner_data,
            &inner_targets,
            &outer_data,
            &outer_targets,
            vec![leaf_b0.clone(), leaf_b1.clone()],
        );

        // Sanity: layer-0 proofs verify under the shipping outer circuit data
        outer_data.verify(l0_proof_a.clone()).unwrap();
        outer_data.verify(l0_proof_b.clone()).unwrap();

        // ---- 3) Build layer-1 circuit and prove ----
        let l1_circuit = Layer1AggregationCircuit::new(
            CircuitConfig::standard_recursion_config(),
            outer_data.common.clone(),
            N_INNER,
            TOTAL_NUM_LEAVES,
        );
        let l1_targets = l1_circuit.targets();
        let l1_data = l1_circuit.build_circuit();

        // 4 felts (8 bytes/felt) for hash-derived accounts
        let aggregator_address: [F; AGGREGATOR_ADDRESS_LEN] = [
            F::from_canonical_u64(0xDEAD),
            F::from_canonical_u64(0xBEEF),
            F::from_canonical_u64(0xCAFE),
            F::from_canonical_u64(0xBABE),
        ];

        let l1_proof = prove_layer1(
            &l1_data,
            &l1_targets,
            &outer_data.verifier_only,
            vec![l0_proof_a.clone(), l0_proof_b.clone()],
            aggregator_address,
        )
        .expect("layer-1 aggregation failed");

        // Verify proof
        l1_data
            .verify(l1_proof.clone())
            .expect("layer-1 proof verification failed");

        // ---- 4) Verify output PIs match expected layout + forwarded content ----
        let pis = &l1_proof.public_inputs;

        // Expected PI length
        let expected_len = l1c::l1_pi_len(N_INNER, TOTAL_NUM_LEAVES);
        assert_eq!(pis.len(), expected_len, "unexpected layer-1 PI length");

        // Aggregator address (4 felts, 8 bytes/felt)
        assert_eq!(
            pis[l1c::AGGREGATOR_ADDRESS_START].to_canonical_u64(),
            0xDEAD
        );
        assert_eq!(
            pis[l1c::AGGREGATOR_ADDRESS_START + 1].to_canonical_u64(),
            0xBEEF
        );
        assert_eq!(
            pis[l1c::AGGREGATOR_ADDRESS_START + 2].to_canonical_u64(),
            0xCAFE
        );
        assert_eq!(
            pis[l1c::AGGREGATOR_ADDRESS_START + 3].to_canonical_u64(),
            0xBABE
        );

        // Asset ID and volume fee
        assert_eq!(pis[l1c::ASSET_ID_START].to_canonical_u64(), 0); // asset_id = native
        assert_eq!(pis[l1c::VOLUME_FEE_BPS_START].to_canonical_u64(), 10); // volume_fee_bps

        // Block hash
        assert_eq!(pis[l1c::BLOCK_HASH_START].to_canonical_u64(), 0xAA01);
        assert_eq!(pis[l1c::BLOCK_HASH_START + 1].to_canonical_u64(), 0xAA02);
        assert_eq!(pis[l1c::BLOCK_HASH_START + 2].to_canonical_u64(), 0xAA03);
        assert_eq!(pis[l1c::BLOCK_HASH_START + 3].to_canonical_u64(), 0xAA04);

        // Block number
        assert_eq!(pis[l1c::BLOCK_NUMBER_START].to_canonical_u64(), 42);

        // Total exit slots = N_INNER * (2 * TOTAL_NUM_LEAVES)
        assert_eq!(
            pis[l1c::TOTAL_EXIT_SLOTS_START].to_canonical_u64(),
            (N_INNER * 2 * TOTAL_NUM_LEAVES) as u64
        );

        // ---- Forwarding checks (exit slots + nullifiers) ----

        // L1 exit slots region begins immediately after the header
        let l1_exit_start = l1c::L1_HEADER_LEN;
        let l0_exit_start = l1c::l0_exit_slots_start();
        let l0_exit_len = l1c::l0_exit_slots_count(TOTAL_NUM_LEAVES) * l1c::L0_EXIT_SLOT_LEN;

        // For each layer-0 proof, ensure its exit slot region is copied verbatim into layer-1 PIs.
        for (i, l0p) in [l0_proof_a.clone(), l0_proof_b.clone()]
            .into_iter()
            .enumerate()
        {
            let src = &l0p.public_inputs[l0_exit_start..l0_exit_start + l0_exit_len];
            let dst = &pis[l1_exit_start + i * l0_exit_len..l1_exit_start + (i + 1) * l0_exit_len];
            assert_eq!(dst, src, "layer-1 exit slots mismatch for inner proof {i}");
        }

        // Nullifiers:
        let l1_null_start = l1c::l1_nullifiers_start(N_INNER, TOTAL_NUM_LEAVES);
        let l0_null_start = l1c::l0_nullifiers_start(TOTAL_NUM_LEAVES);
        let l0_null_len = l1c::l0_nullifiers_count(TOTAL_NUM_LEAVES) * 4;

        for (i, l0p) in [l0_proof_a, l0_proof_b].into_iter().enumerate() {
            let src = &l0p.public_inputs[l0_null_start..l0_null_start + l0_null_len];
            let dst = &pis[l1_null_start + i * l0_null_len..l1_null_start + (i + 1) * l0_null_len];
            assert_eq!(dst, src, "layer-1 nullifiers mismatch for inner proof {i}");
        }
    }

    /// Negative test: if two layer-0 proofs use different block hashes, layer-1 proving must fail.
    #[test]
    fn layer1_mismatched_blocks_fails() {
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

        let inner_circuit = InnerAggregationCircuit::new(leaf_data.common.clone());
        let inner_targets = inner_circuit.targets();
        let inner_data = inner_circuit.build_circuit();

        let outer_circuit = OuterAggregationCircuit::new(inner_data.common.clone());
        let outer_targets = outer_circuit.targets();
        let outer_data = outer_circuit.build_circuit();

        let l0_a = prove_layer0_batch(
            &leaf_data,
            &leaf_targets,
            &inner_data,
            &inner_targets,
            &outer_data,
            &outer_targets,
            vec![a0, a1],
        );
        let l0_b = prove_layer0_batch(
            &leaf_data,
            &leaf_targets,
            &inner_data,
            &inner_targets,
            &outer_data,
            &outer_targets,
            vec![b0, b1],
        );

        // Layer-1 circuit
        let l1_circuit = Layer1AggregationCircuit::new(
            CircuitConfig::standard_recursion_config(),
            outer_data.common.clone(),
            N_INNER,
            TOTAL_NUM_LEAVES,
        );
        let l1_targets = l1_circuit.targets();
        let l1_data = l1_circuit.build_circuit();

        let agg_addr = [
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
        ];

        let res = prove_layer1(
            &l1_data,
            &l1_targets,
            &outer_data.verifier_only,
            vec![l0_a, l0_b],
            agg_addr,
        );

        assert!(
            res.is_err(),
            "expected layer-1 proving to fail for mismatched blocks"
        );
    }
}
