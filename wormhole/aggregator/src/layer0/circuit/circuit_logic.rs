//! Monolithic prebuilt Layer-0 aggregation circuit.
//!
//! This circuit verifies `N` leaf wormhole proofs directly (without first building a
//! dynamic merge circuit), then applies the wormhole-specific wrapper logic:
//! - enforce block consistency across real proofs
//! - enforce asset_id / volume_fee_bps consistency
//! - dedupe exit accounts and sum output amounts (2 outputs per proof)
//! - replace dummy nullifiers with hashes of externally provided random preimages
//! - emit fixed-format aggregated public inputs
//!
//! The runtime prover fills:
//! - `leaf_verifier_data`
//! - `leaf_proofs[i]`
//! - `dummy_nullifier_pre_images[i]`

use plonky2::{
    field::types::Field,
    hash::poseidon2::Poseidon2Hash,
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
#[derive(Debug, Clone)]
pub struct AggregationCircuitTargets {
    /// Verifier target for the leaf wormhole circuit.
    pub leaf_verifier_data: VerifierCircuitTarget,
    /// One proof target per leaf slot.
    pub leaf_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// One dummy-nullifier preimage target (4 felts) per leaf slot.
    pub dummy_nullifier_pre_images: Vec<[Target; 4]>,
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

        let targets = AggregationCircuitTargets {
            leaf_verifier_data,
            leaf_proofs,
            dummy_nullifier_pre_images,
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

        // Range check final sum to 32 bits (u32::MAX > the max possible sum on our chain)
        builder.range_check(final_sum, 32);

        output_pis.push(final_sum);
        output_pis.extend_from_slice(&final_exit);
    }

    // =========================================================================
    // Nullifiers (replace dummies with hashes of provided random preimages)
    // =========================================================================

    for i in 0..n_leaf {
        let pis_i = leaf_pi_targets[i];
        let real_null_i = limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(pis_i, 0);
        let dummy_null_i =
            hash_dummy_nullifier_pre_image(builder, targets.dummy_nullifier_pre_images[i]);
        let is_dummy_i = is_dummy_flags[i];

        // output = is_dummy ? hash(dummy_nullifier_pre_image[i]) : real_nullifier[i]
        output_pis.extend_from_slice(&[
            builder.select(is_dummy_i, dummy_null_i[0], real_null_i[0]),
            builder.select(is_dummy_i, dummy_null_i[1], real_null_i[1]),
            builder.select(is_dummy_i, dummy_null_i[2], real_null_i[2]),
            builder.select(is_dummy_i, dummy_null_i[3], real_null_i[3]),
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
mod tests {
    use std::collections::BTreeMap;

    use anyhow::Result;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::{
        hash::poseidon2::Poseidon2Hash,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{
                CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
                VerifierOnlyCircuitData,
            },
            config::Hasher,
            proof::ProofWithPublicInputs,
        },
    };
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use zk_circuits_common::circuit::{C, D, F};

    use crate::layer0::{
        circuit::{
            circuit_logic::Layer0AggregationCircuit,
            constants::{
                ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START, EXIT_2_START,
                LEAF_PI_LEN, NULLIFIER_START, OUTPUT_AMOUNT_1_START, OUTPUT_AMOUNT_2_START,
                VOLUME_FEE_BPS_START,
            },
        },
        prover::witness::fill_layer0_aggregation_witness,
    };

    const TEST_ASSET_ID_U64: u64 = 0;
    const TEST_VOLUME_FEE_BPS: u64 = 10; // 0.1% = 10 bps

    // ---------------- Root PI header layout (layer-0 aggregation output) ----------------
    // [ num_exit_slots(1), asset_id(1), volume_fee_bps(1), block_hash(4), block_number(1), ... ]
    const ROOT_NUM_EXIT_SLOTS_IDX: usize = 0;
    const ROOT_ASSET_ID_IDX: usize = 1;
    const ROOT_VOLUME_FEE_BPS_IDX: usize = 2;
    const ROOT_BLOCK_HASH_START: usize = 3;
    const ROOT_BLOCK_NUMBER_IDX: usize = 7;
    const ROOT_HEADER_LEN: usize = 8;

    // ---------------- Circuit helpers ----------------

    /// Dummy leaf circuit with the Wormhole leaf PI layout only.
    ///
    /// This lets us generate "fake" leaf proofs with arbitrary public inputs so we can
    /// stress-test the layer-0 aggregation circuit in isolation.
    fn generate_dummy_wormhole_circuit() -> (CircuitData<F, C, D>, [Target; LEAF_PI_LEN]) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pis_vec = builder.add_virtual_targets(LEAF_PI_LEN);
        let pis: [Target; LEAF_PI_LEN] = pis_vec
            .clone()
            .try_into()
            .expect("expected exactly LEAF_PI_LEN targets");

        // Mimic some lightweight constraints like the real leaf circuit.
        builder.range_check(pis[OUTPUT_AMOUNT_1_START], 32);
        builder.range_check(pis[OUTPUT_AMOUNT_2_START], 32);
        builder.range_check(pis[VOLUME_FEE_BPS_START], 32);

        builder.register_public_inputs(&pis_vec);

        let data = builder.build::<C>();
        (data, pis)
    }

    fn prove_dummy_wormhole(
        pis: [F; LEAF_PI_LEN],
    ) -> (ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>) {
        let (circuit_data, targets) = generate_dummy_wormhole_circuit();
        let mut pw = PartialWitness::new();

        for (t, v) in targets.into_iter().zip(pis.into_iter()) {
            pw.set_target(t, v).unwrap();
        }

        let proof = circuit_data.prove(pw).unwrap();
        (proof, circuit_data)
    }

    /// Build and prove the layer-0 aggregation circuit using the split witness-filler path.
    fn aggregate_proofs_layer0(
        leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: VerifierOnlyCircuitData<C, D>,
        dummy_nullifier_pre_images: Vec<[F; 4]>,
    ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> {
        let n_leaf = leaf_proofs.len();
        assert!(n_leaf > 0, "need at least one leaf proof");
        assert_eq!(
            dummy_nullifier_pre_images.len(),
            n_leaf,
            "dummy_nullifier_pre_images must have one entry per leaf slot"
        );

        let agg_config = CircuitConfig::standard_recursion_zk_config();
        let agg_circuit =
            Layer0AggregationCircuit::new(agg_config.clone(), leaf_common.clone(), n_leaf);
        let targets = agg_circuit.targets();
        let prover_data = agg_circuit.build_prover();

        let mut pw = PartialWitness::new();
        fill_layer0_aggregation_witness(
            &mut pw,
            &targets,
            &leaf_verifier_only,
            &leaf_proofs,
            &dummy_nullifier_pre_images,
        )?;

        let agg_proof = prover_data.prove(pw)?;

        // Build verifier data from the same config/leaf common so we can verify the result.
        let verifier_data =
            Layer0AggregationCircuit::new(agg_config, leaf_common, n_leaf).build_verifier();

        Ok((agg_proof, verifier_data))
    }

    fn deterministic_dummy_nullifier_pre_images(n: usize) -> Vec<[F; 4]> {
        let mut rng = StdRng::from_seed([77u8; 32]);
        (0..n)
            .map(|_| {
                [
                    F::from_canonical_u64(rng.gen::<u32>() as u64),
                    F::from_canonical_u64(rng.gen::<u32>() as u64),
                    F::from_canonical_u64(rng.gen::<u32>() as u64),
                    F::from_canonical_u64(rng.gen::<u32>() as u64),
                ]
            })
            .collect()
    }

    fn hash_dummy_nullifier_pre_image_native(pre_image: [F; 4]) -> [F; 4] {
        let inner_hash = Poseidon2Hash::hash_no_pad(&pre_image).elements;
        Poseidon2Hash::hash_no_pad(&inner_hash).elements
    }

    // ---------------- Packing helpers ----------------

    #[inline]
    fn limbs_u64_to_felts_be(l: [u64; 4]) -> [F; 4] {
        [
            F::from_canonical_u64(l[0]),
            F::from_canonical_u64(l[1]),
            F::from_canonical_u64(l[2]),
            F::from_canonical_u64(l[3]),
        ]
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn make_pi_from_felts(
        asset_id: F,
        output_amount_1: F,
        output_amount_2: F,
        volume_fee_bps: F,
        nullifier: [F; 4],
        exit_1: [F; 4],
        exit_2: [F; 4],
        block_hash: [F; 4],
        block_number: F,
    ) -> [F; LEAF_PI_LEN] {
        let mut out = [F::ZERO; LEAF_PI_LEN];
        out[ASSET_ID_START] = asset_id;
        out[OUTPUT_AMOUNT_1_START] = output_amount_1;
        out[OUTPUT_AMOUNT_2_START] = output_amount_2;
        out[VOLUME_FEE_BPS_START] = volume_fee_bps;
        out[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&nullifier);
        out[EXIT_1_START..EXIT_1_START + 4].copy_from_slice(&exit_1);
        out[EXIT_2_START..EXIT_2_START + 4].copy_from_slice(&exit_2);
        out[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&block_hash);
        out[BLOCK_NUMBER_START] = block_number;
        out
    }

    // ---------------- Hardcoded 64-bit-limb digests ----------------

    const EXIT_ACCOUNTS: [[u64; 4]; 8] = [
        [
            0x1111_0001_0000_0001,
            0x1111_0001_0000_0002,
            0x1111_0001_0000_0003,
            0x1111_0001_0000_0004,
        ],
        [
            0x2222_0001_0000_0001,
            0x2222_0001_0000_0002,
            0x2222_0001_0000_0003,
            0x2222_0001_0000_0004,
        ],
        [
            0x3333_0001_0000_0001,
            0x3333_0001_0000_0002,
            0x3333_0001_0000_0003,
            0x3333_0001_0000_0004,
        ],
        [
            0x4444_0001_0000_0001,
            0x4444_0001_0000_0002,
            0x4444_0001_0000_0003,
            0x4444_0001_0000_0004,
        ],
        [
            0x5555_0001_0000_0001,
            0x5555_0001_0000_0002,
            0x5555_0001_0000_0003,
            0x5555_0001_0000_0004,
        ],
        [
            0x6666_0001_0000_0001,
            0x6666_0001_0000_0002,
            0x6666_0001_0000_0003,
            0x6666_0001_0000_0004,
        ],
        [
            0x7777_0001_0000_0001,
            0x7777_0001_0000_0002,
            0x7777_0001_0000_0003,
            0x7777_0001_0000_0004,
        ],
        [
            0x8888_0001_0000_0001,
            0x8888_0001_0000_0002,
            0x8888_0001_0000_0003,
            0x8888_0001_0000_0004,
        ],
    ];

    const BLOCK_HASHES: [[u64; 4]; 8] = [
        [
            0xAAAA_0001_0000_0001,
            0xAAAA_0001_0000_0002,
            0xAAAA_0001_0000_0003,
            0xAAAA_0001_0000_0004,
        ],
        [
            0xBBBB_0001_0000_0001,
            0xBBBB_0001_0000_0002,
            0xBBBB_0001_0000_0003,
            0xBBBB_0001_0000_0004,
        ],
        [
            0xCCCC_0001_0000_0001,
            0xCCCC_0001_0000_0002,
            0xCCCC_0001_0000_0003,
            0xCCCC_0001_0000_0004,
        ],
        [
            0xDDDD_0001_0000_0001,
            0xDDDD_0001_0000_0002,
            0xDDDD_0001_0000_0003,
            0xDDDD_0001_0000_0004,
        ],
        [
            0xEEEE_0001_0000_0001,
            0xEEEE_0001_0000_0002,
            0xEEEE_0001_0000_0003,
            0xEEEE_0001_0000_0004,
        ],
        [
            0xFFFF_0001_0000_0001,
            0xFFFF_0001_0000_0002,
            0xFFFF_0001_0000_0003,
            0xFFFF_0001_0000_0004,
        ],
        [
            0xABCD_0001_0000_0001,
            0xABCD_0001_0000_0002,
            0xABCD_0001_0000_0003,
            0xABCD_0001_0000_0004,
        ],
        [
            0x1234_0001_0000_0001,
            0x1234_0001_0000_0002,
            0x1234_0001_0000_0003,
            0x1234_0001_0000_0004,
        ],
    ];

    const NULLIFIERS: [[u64; 4]; 8] = [
        [
            0x90A0_0001_0000_0001,
            0x90A0_0001_0000_0002,
            0x90A0_0001_0000_0003,
            0x90A0_0001_0000_0004,
        ],
        [
            0x80B0_0001_0000_0001,
            0x80B0_0001_0000_0002,
            0x80B0_0001_0000_0003,
            0x80B0_0001_0000_0004,
        ],
        [
            0x70C0_0001_0000_0001,
            0x70C0_0001_0000_0002,
            0x70C0_0001_0000_0003,
            0x70C0_0001_0000_0004,
        ],
        [
            0x60D0_0001_0000_0001,
            0x60D0_0001_0000_0002,
            0x60D0_0001_0000_0003,
            0x60D0_0001_0000_0004,
        ],
        [
            0x50E0_0001_0000_0001,
            0x50E0_0001_0000_0002,
            0x50E0_0001_0000_0003,
            0x50E0_0001_0000_0004,
        ],
        [
            0x40F0_0001_0000_0001,
            0x40F0_0001_0000_0002,
            0x40F0_0001_0000_0003,
            0x40F0_0001_0000_0004,
        ],
        [
            0x30A1_0001_0000_0001,
            0x30A1_0001_0000_0002,
            0x30A1_0001_0000_0003,
            0x30A1_0001_0000_0004,
        ],
        [
            0x20B2_0001_0000_0001,
            0x20B2_0001_0000_0002,
            0x20B2_0001_0000_0003,
            0x20B2_0001_0000_0004,
        ],
    ];

    #[test]
    fn recursive_aggregation_tree() {
        let mut rng = StdRng::from_seed([41u8; 32]);

        let output1_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
        let output2_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);

        let output1_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(output1_vals_u32[i] as u64));
        let output2_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(output2_vals_u32[i] as u64));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // All real proofs must be from the same block
        let common_block_hash = block_hashes_felts[0];
        let common_block_number = F::from_canonical_u64(42);

        let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            pis_list.push(make_pi_from_felts(
                asset_id,
                output1_felts[i],
                output2_felts[i],
                volume_fee_bps,
                nullifiers_felts[i],
                exits_felts[i],
                exits_felts[(i + 1) % 8],
                common_block_hash,
                common_block_number,
            ));
        }

        let leaves = pis_list
            .clone()
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();

        let leaf_common = leaves[0].1.common.clone();
        let leaf_verifier_only = leaves[0].1.verifier_only.clone();
        let proofs = leaves
            .into_iter()
            .map(|(proof, _)| proof)
            .collect::<Vec<_>>();

        let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

        let (root_proof, root_verifier) = aggregate_proofs_layer0(
            proofs,
            leaf_common,
            leaf_verifier_only,
            dummy_nullifier_pre_images,
        )
        .unwrap();

        // ---------------------------
        // Reference aggregation OFF-CIRCUIT
        // ---------------------------
        let n_leaf = pis_list.len();
        assert_eq!(n_leaf, 8);

        let mut exit_sums: BTreeMap<[F; 4], F> = BTreeMap::new();
        for (i, pis) in pis_list.iter().enumerate() {
            let exit_1 = [
                pis[EXIT_1_START],
                pis[EXIT_1_START + 1],
                pis[EXIT_1_START + 2],
                pis[EXIT_1_START + 3],
            ];
            let amount_1 = output1_felts[i];
            exit_sums
                .entry(exit_1)
                .and_modify(|s| *s += amount_1)
                .or_insert(amount_1);

            let exit_2 = [
                pis[EXIT_2_START],
                pis[EXIT_2_START + 1],
                pis[EXIT_2_START + 2],
                pis[EXIT_2_START + 3],
            ];
            let amount_2 = output2_felts[i];
            exit_sums
                .entry(exit_2)
                .and_modify(|s| *s += amount_2)
                .or_insert(amount_2);
        }

        let block_hash_ref = common_block_hash;
        let block_num_ref = common_block_number;

        let mut nullifiers_ref: Vec<[F; 4]> = Vec::with_capacity(n_leaf);
        for pis in &pis_list {
            nullifiers_ref.push([
                pis[NULLIFIER_START],
                pis[NULLIFIER_START + 1],
                pis[NULLIFIER_START + 2],
                pis[NULLIFIER_START + 3],
            ]);
        }

        // ---------------------------
        // Parse aggregated PIs
        // ---------------------------
        let pis = &root_proof.public_inputs;
        let root_pi_len = n_leaf * LEAF_PI_LEN;
        assert_eq!(pis.len(), root_pi_len + ROOT_HEADER_LEN);

        let num_exit_slots_circuit = pis[ROOT_NUM_EXIT_SLOTS_IDX].to_canonical_u64() as usize;
        assert_eq!(num_exit_slots_circuit, n_leaf * 2);

        let asset_id_circuit = pis[ROOT_ASSET_ID_IDX];
        assert_eq!(asset_id_circuit, asset_id);

        let volume_fee_bps_circuit = pis[ROOT_VOLUME_FEE_BPS_IDX];
        assert_eq!(volume_fee_bps_circuit, volume_fee_bps);

        let block_hash_circuit: [F; 4] = [
            pis[ROOT_BLOCK_HASH_START],
            pis[ROOT_BLOCK_HASH_START + 1],
            pis[ROOT_BLOCK_HASH_START + 2],
            pis[ROOT_BLOCK_HASH_START + 3],
        ];
        let block_num_circuit = pis[ROOT_BLOCK_NUMBER_IDX];
        assert_eq!(block_hash_circuit, block_hash_ref);
        assert_eq!(block_num_circuit, block_num_ref);

        let mut idx = ROOT_HEADER_LEN;

        // Exit slots region: 2*N slots, each [sum(1), exit(4)]
        let mut exit_sums_from_circuit: BTreeMap<[F; 4], F> = BTreeMap::new();
        for _ in 0..(n_leaf * 2) {
            let sum_circuit = pis[idx];
            idx += 1;

            let exit_key_circuit = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
            idx += 4;

            if sum_circuit != F::ZERO {
                exit_sums_from_circuit
                    .entry(exit_key_circuit)
                    .or_insert(sum_circuit);
            }
        }

        for (exit_key, sum_ref) in &exit_sums {
            let sum_from_circuit = exit_sums_from_circuit.get(exit_key).unwrap();
            assert_eq!(
                *sum_from_circuit, *sum_ref,
                "sum mismatch for exit {:?}",
                exit_key
            );
        }

        // Nullifiers (real-proof-only test => should match leaf nullifiers exactly)
        for (leaf_idx, nullifier_expected) in nullifiers_ref.iter().enumerate() {
            let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
            idx += 4;

            assert_eq!(
                got, *nullifier_expected,
                "nullifier mismatch at leaf {leaf_idx}"
            );
        }

        // Padding zeros
        while idx < pis.len() {
            assert_eq!(pis[idx], F::ZERO, "expected zero padding at index {idx}");
            idx += 1;
        }

        // Verify final proof
        root_verifier.verify(root_proof).unwrap();
    }

    #[test]
    fn recursive_aggregation_tree_different_blocks_fails() {
        let mut rng = StdRng::from_seed([42u8; 32]);

        let output1_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
        let output1_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(output1_vals_u32[i] as u64));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));
        let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            pis_list.push(make_pi_from_felts(
                asset_id,
                output1_felts[i],
                F::ZERO,
                volume_fee_bps,
                nullifiers_felts[i],
                exits_felts[i],
                [F::ZERO; 4],
                block_hashes_felts[i], // different block hash per proof -> should fail
                block_numbers[i],      // different block number per proof -> should fail
            ));
        }

        let leaves = pis_list
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();
        let leaf_common = leaves[0].1.common.clone();
        let leaf_verifier_only = leaves[0].1.verifier_only.clone();
        let proofs = leaves
            .into_iter()
            .map(|(proof, _)| proof)
            .collect::<Vec<_>>();
        let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

        let res = aggregate_proofs_layer0(
            proofs,
            leaf_common,
            leaf_verifier_only,
            dummy_nullifier_pre_images,
        );

        assert!(
            res.is_err(),
            "expected failure because proofs are from different blocks"
        );
    }

    #[test]
    fn recursive_aggregation_tree_mismatched_asset_id_fails() {
        let asset_a = F::from_canonical_u64(7);
        let asset_b = F::from_canonical_u64(9);

        let output_felts: [F; 8] = core::array::from_fn(|_| F::from_canonical_u64(1));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            let asset_id = if i == 3 { asset_b } else { asset_a };
            pis_list.push(make_pi_from_felts(
                asset_id,
                output_felts[i],
                F::ZERO,
                volume_fee_bps,
                nullifiers_felts[i],
                exits_felts[i],
                [F::ZERO; 4],
                block_hashes_felts[i],
                block_numbers[i],
            ));
        }

        let leaves = pis_list
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();
        let leaf_common = leaves[0].1.common.clone();
        let leaf_verifier_only = leaves[0].1.verifier_only.clone();
        let proofs = leaves
            .into_iter()
            .map(|(proof, _)| proof)
            .collect::<Vec<_>>();
        let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

        let res = aggregate_proofs_layer0(
            proofs,
            leaf_common,
            leaf_verifier_only,
            dummy_nullifier_pre_images,
        );

        assert!(res.is_err(), "expected failure due to mismatched asset IDs");
    }

    #[test]
    fn recursive_aggregation_tree_with_dummy_proofs() {
        // 2 real proofs + 6 dummy proofs (block_hash = 0 sentinel)
        let mut rng = StdRng::from_seed([99u8; 32]);

        let output_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
        let output_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(output_vals_u32[i] as u64));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        let num_real_proofs = 2usize;

        // All real proofs share the same block
        let common_block_hash = block_hashes_felts[0];
        let common_block_number = F::from_canonical_u64(42);

        let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);

        // Real proofs
        for i in 0..num_real_proofs {
            pis_list.push(make_pi_from_felts(
                asset_id,
                output_felts[i],
                F::ZERO,
                volume_fee_bps,
                nullifiers_felts[i],
                exits_felts[i],
                [F::ZERO; 4],
                common_block_hash,
                common_block_number,
            ));
        }

        // Dummy proofs: zero block hash + zero outputs + zero exits
        let dummy_exit = [F::ZERO; 4];
        let dummy_block_hash = [F::ZERO; 4];
        for nullifier in nullifiers_felts.iter().skip(num_real_proofs) {
            pis_list.push(make_pi_from_felts(
                asset_id,
                F::ZERO,
                F::ZERO,
                volume_fee_bps,
                *nullifier, // layer-0 replaces dummy nullifiers with hashes of provided preimages
                dummy_exit,
                dummy_exit,
                dummy_block_hash,
                F::ZERO,
            ));
        }

        let leaves = pis_list
            .clone()
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();
        let leaf_common = leaves[0].1.common.clone();
        let leaf_verifier_only = leaves[0].1.verifier_only.clone();
        let proofs = leaves
            .into_iter()
            .map(|(proof, _)| proof)
            .collect::<Vec<_>>();

        let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());

        let (root_proof, root_verifier) = aggregate_proofs_layer0(
            proofs,
            leaf_common,
            leaf_verifier_only,
            dummy_nullifier_pre_images.clone(),
        )
        .unwrap();

        root_verifier.verify(root_proof.clone()).unwrap();

        let pis = &root_proof.public_inputs;

        // Root header should reference the real block
        let block_hash_circuit: [F; 4] = [
            pis[ROOT_BLOCK_HASH_START],
            pis[ROOT_BLOCK_HASH_START + 1],
            pis[ROOT_BLOCK_HASH_START + 2],
            pis[ROOT_BLOCK_HASH_START + 3],
        ];
        assert_eq!(block_hash_circuit, common_block_hash);

        let block_num_circuit = pis[ROOT_BLOCK_NUMBER_IDX];
        assert_eq!(block_num_circuit, common_block_number);

        let nullifier_region_start = ROOT_HEADER_LEN + (pis_list.len() * 2 * 5);
        for (i, nullifier) in nullifiers_felts.iter().enumerate().take(num_real_proofs) {
            let idx = nullifier_region_start + i * 4;
            let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
            assert_eq!(got, *nullifier, "real nullifier mismatch at leaf {i}");
        }

        for (i, pre_image) in dummy_nullifier_pre_images
            .iter()
            .enumerate()
            .take(pis_list.len())
            .skip(num_real_proofs)
        {
            let idx = nullifier_region_start + i * 4;
            let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
            let expected = hash_dummy_nullifier_pre_image_native(*pre_image);
            assert_eq!(got, expected, "dummy nullifier hash mismatch at leaf {i}");
        }

        println!(
            "Successfully aggregated {} real proofs + {} dummy proofs!",
            num_real_proofs,
            8 - num_real_proofs
        );
    }
}
