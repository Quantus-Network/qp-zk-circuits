//! Shipping compact-child inner aggregation circuit for the 2x8 layer-0 topology.
//!
//! This is the first proving stage in the production layer-0 flow:
//! - verify exactly 8 leaf proofs
//! - preserve the compact-child public-input schema
//! - dedupe exit slots with the incremental unique-table path
//! - replace dummy nullifiers with hashed preimages only for dummy leaves

use plonky2::{
    field::types::Field,
    hash::poseidon2::Poseidon2Hash,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
        },
    },
};
use zk_circuits_common::{
    circuit::{C, D, F},
    gadgets::{bytes_digest_eq, limb1_at_offset, limbs4_at_offset},
};

use super::constants::{inner_circuit_config, INNER_NUM_LEAVES, INNER_OUTPUT_PI_LEN};
use crate::layer0::circuit::constants::{
    aggregated_output, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START,
    EXIT_2_START, LEAF_PI_LEN, NULLIFIER_START, OUTPUT_AMOUNT_1_START, OUTPUT_AMOUNT_2_START,
    VOLUME_FEE_BPS_START,
};

/// Runtime targets for the shipping inner aggregation circuit.
#[derive(Debug, Clone)]
pub struct AggregationCircuitTargets {
    /// Verifier target for the leaf wormhole circuit.
    pub leaf_verifier_data: plonky2::plonk::circuit_data::VerifierCircuitTarget,
    /// One proof target per leaf slot.
    pub leaf_proofs: Vec<plonky2::plonk::proof::ProofWithPublicInputsTarget<D>>,
    /// One dummy-nullifier preimage target (4 felts) per leaf slot.
    pub dummy_nullifier_pre_images: Vec<[Target; 4]>,
}

pub type InnerAggregationCircuitTargets = AggregationCircuitTargets;

impl AggregationCircuitTargets {
    /// Serialize the target layout so the prover can recreate sessions without rebuilding the circuit.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        use anyhow::anyhow;
        use plonky2::util::serialization::Write;

        let mut bytes = Vec::new();
        bytes
            .write_target_verifier_circuit(&self.leaf_verifier_data)
            .map_err(|e| anyhow!("failed to serialize leaf verifier target: {}", e))?;
        bytes
            .write_usize(self.leaf_proofs.len())
            .map_err(|e| anyhow!("failed to serialize leaf proof count: {}", e))?;
        for proof in &self.leaf_proofs {
            bytes
                .write_target_proof_with_public_inputs(proof)
                .map_err(|e| anyhow!("failed to serialize leaf proof target: {}", e))?;
        }
        bytes
            .write_usize(self.dummy_nullifier_pre_images.len())
            .map_err(|e| anyhow!("failed to serialize dummy nullifier count: {}", e))?;
        for targets in &self.dummy_nullifier_pre_images {
            bytes
                .write_target_array(targets)
                .map_err(|e| anyhow!("failed to serialize dummy nullifier targets: {}", e))?;
        }
        Ok(bytes)
    }

    /// Deserialize a previously saved target layout.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        use anyhow::anyhow;
        use plonky2::util::serialization::{Buffer, Read, Remaining};

        let mut buffer = Buffer::new(bytes);
        let leaf_verifier_data = buffer
            .read_target_verifier_circuit()
            .map_err(|e| anyhow!("failed to deserialize leaf verifier target: {}", e))?;

        let proof_count = buffer
            .read_usize()
            .map_err(|e| anyhow!("failed to deserialize leaf proof count: {}", e))?;
        let mut leaf_proofs = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            leaf_proofs.push(
                buffer
                    .read_target_proof_with_public_inputs()
                    .map_err(|e| anyhow!("failed to deserialize leaf proof target: {}", e))?,
            );
        }

        let dummy_count = buffer
            .read_usize()
            .map_err(|e| anyhow!("failed to deserialize dummy nullifier count: {}", e))?;
        let mut dummy_nullifier_pre_images = Vec::with_capacity(dummy_count);
        for _ in 0..dummy_count {
            dummy_nullifier_pre_images.push(
                buffer
                    .read_target_array()
                    .map_err(|e| anyhow!("failed to deserialize dummy nullifier targets: {}", e))?,
            );
        }

        if buffer.remaining() != 0 {
            return Err(anyhow!(
                "layer-0 target layout had {} trailing bytes",
                buffer.remaining()
            ));
        }

        Ok(Self {
            leaf_verifier_data,
            leaf_proofs,
            dummy_nullifier_pre_images,
        })
    }
}

#[derive(Debug)]
pub struct InnerAggregationCircuit {
    builder: CircuitBuilder<F, D>,
    targets: InnerAggregationCircuitTargets,
}

impl InnerAggregationCircuit {
    pub fn new(leaf_common: CommonCircuitData<F, D>) -> Self {
        Self::new_with_config(inner_circuit_config(), leaf_common)
    }

    pub fn new_with_config(config: CircuitConfig, leaf_common: CommonCircuitData<F, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_verifier_data =
            builder.add_virtual_verifier_data(leaf_common.fri_params.config.cap_height);

        let mut leaf_proofs = Vec::with_capacity(INNER_NUM_LEAVES);
        for _ in 0..INNER_NUM_LEAVES {
            let pt = builder.add_virtual_proof_with_pis(&leaf_common);
            builder.verify_proof::<C>(&pt, &leaf_verifier_data, &leaf_common);
            leaf_proofs.push(pt);
        }

        let mut dummy_nullifier_pre_images = Vec::with_capacity(INNER_NUM_LEAVES);
        for _ in 0..INNER_NUM_LEAVES {
            dummy_nullifier_pre_images.push([
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
            ]);
        }

        let targets = InnerAggregationCircuitTargets {
            leaf_verifier_data,
            leaf_proofs,
            dummy_nullifier_pre_images,
        };

        build_inner_wrapper_constraints(&mut builder, &targets);

        Self { builder, targets }
    }

    pub fn targets(&self) -> InnerAggregationCircuitTargets {
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

    #[cfg(feature = "profile")]
    pub fn build_circuit_profiled(self) -> CircuitData<F, C, D> {
        self.builder.print_gate_counts(0);
        self.builder.build()
    }

    pub fn num_gates(&self) -> usize {
        self.builder.num_gates()
    }
}

fn build_inner_wrapper_constraints(
    builder: &mut CircuitBuilder<F, D>,
    targets: &InnerAggregationCircuitTargets,
) {
    let one = builder.one();
    let zero = builder.zero();
    let zero_digest = [zero, zero, zero, zero];

    let leaf_pi_targets: Vec<&[Target]> = targets
        .leaf_proofs
        .iter()
        .map(|p| p.public_inputs.as_slice())
        .collect();
    debug_assert!(leaf_pi_targets.iter().all(|pis| pis.len() == LEAF_PI_LEN));

    let num_exit_slots_t = builder.constant(F::from_canonical_usize(INNER_NUM_LEAVES * 2));
    let asset_ref = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(leaf_pi_targets[0], 0);
    let volume_fee_bps_ref =
        limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(leaf_pi_targets[0], 0);
    let block_ref = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(leaf_pi_targets[0], 0);
    let block_number_ref =
        limb1_at_offset::<LEAF_PI_LEN, BLOCK_NUMBER_START>(leaf_pi_targets[0], 0);

    let dummy_sentinel = [zero, zero, zero, zero];
    let mut is_dummy_flags = Vec::with_capacity(INNER_NUM_LEAVES);

    for pis_i in leaf_pi_targets.iter().take(INNER_NUM_LEAVES) {
        let block_i = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(pis_i, 0);
        let is_dummy_i = bytes_digest_eq(builder, block_i, dummy_sentinel);
        is_dummy_flags.push(is_dummy_i);

        let matches_ref = bytes_digest_eq(builder, block_i, block_ref);
        let valid_block_relation = builder.or(is_dummy_i, matches_ref);
        builder.connect(valid_block_relation.target, one);

        let asset_i = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(pis_i, 0);
        let asset_or_ref = builder.select(is_dummy_i, asset_ref, asset_i);
        builder.connect(asset_or_ref, asset_ref);

        let volume_fee_bps_i = limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(pis_i, 0);
        let fee_or_ref = builder.select(is_dummy_i, volume_fee_bps_ref, volume_fee_bps_i);
        builder.connect(fee_or_ref, volume_fee_bps_ref);
    }

    let mut output_pis = vec![
        num_exit_slots_t,
        asset_ref,
        volume_fee_bps_ref,
        block_ref[0],
        block_ref[1],
        block_ref[2],
        block_ref[3],
        block_number_ref,
    ];

    let raw_slot_count = INNER_NUM_LEAVES * 2;
    let mut slot_exits: Vec<[Target; 4]> = Vec::with_capacity(raw_slot_count);
    let mut slot_amounts = Vec::with_capacity(raw_slot_count);
    for slot in 0..raw_slot_count {
        let proof_idx = slot / 2;
        let output_idx = slot % 2;
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

        slot_exits.push(exit);
        slot_amounts.push(amount);
    }

    let (unique_amounts, unique_exits) =
        dedupe_with_incremental_unique_table(builder, &slot_exits, &slot_amounts, zero_digest);
    for slot in 0..raw_slot_count {
        builder.range_check(unique_amounts[slot], 32);
        output_pis.push(unique_amounts[slot]);
        output_pis.extend_from_slice(&unique_exits[slot]);
    }

    for i in 0..INNER_NUM_LEAVES {
        let pis_i = leaf_pi_targets[i];
        let real_null_i = limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(pis_i, 0);
        let dummy_null_i =
            hash_dummy_nullifier_pre_image(builder, targets.dummy_nullifier_pre_images[i]);
        let is_dummy_i = is_dummy_flags[i];
        output_pis.extend_from_slice(&[
            builder.select(is_dummy_i, dummy_null_i[0], real_null_i[0]),
            builder.select(is_dummy_i, dummy_null_i[1], real_null_i[1]),
            builder.select(is_dummy_i, dummy_null_i[2], real_null_i[2]),
            builder.select(is_dummy_i, dummy_null_i[3], real_null_i[3]),
        ]);
    }

    assert_eq!(
        output_pis.len(),
        INNER_OUTPUT_PI_LEN,
        "inner output PI length mismatch"
    );
    debug_assert_eq!(
        output_pis.len(),
        aggregated_output::HEADER_LEN + 16 * 5 + 8 * 4
    );
    builder.register_public_inputs(&output_pis);
}

fn dedupe_with_incremental_unique_table(
    builder: &mut CircuitBuilder<F, D>,
    slot_exits: &[[Target; 4]],
    slot_amounts: &[Target],
    zero_digest: [Target; 4],
) -> (Vec<Target>, Vec<[Target; 4]>) {
    let zero = builder.zero();
    let raw_slot_count = slot_exits.len();
    let mut unique_exits = vec![[zero; 4]; raw_slot_count];
    let mut unique_amounts = vec![zero; raw_slot_count];
    let mut unique_valid = vec![builder._false(); raw_slot_count];

    for slot in 0..raw_slot_count {
        let slot_exit = slot_exits[slot];
        let slot_amount = slot_amounts[slot];
        let slot_is_zero = bytes_digest_eq(builder, slot_exit, zero_digest);
        let mut matched = builder._false();

        for unique_idx in 0..raw_slot_count {
            let active = unique_valid[unique_idx];
            let equal_exit = bytes_digest_eq(builder, slot_exit, unique_exits[unique_idx]);
            let eq = builder.and(active, equal_exit);
            let not_matched = builder.not(matched);
            let take = builder.and(eq, not_matched);
            let routed = builder.select(take, slot_amount, zero);
            unique_amounts[unique_idx] = builder.add(unique_amounts[unique_idx], routed);
            matched = builder.or(matched, eq);
        }

        let not_slot_zero = builder.not(slot_is_zero);
        let not_matched = builder.not(matched);
        let should_insert = builder.and(not_slot_zero, not_matched);
        let mut placing_new = should_insert;
        for unique_idx in 0..raw_slot_count {
            let empty = builder.not(unique_valid[unique_idx]);
            let new_here = builder.and(placing_new, empty);
            unique_valid[unique_idx] = builder.or(unique_valid[unique_idx], new_here);
            unique_exits[unique_idx] = core::array::from_fn(|limb| {
                builder.select(new_here, slot_exit[limb], unique_exits[unique_idx][limb])
            });
            unique_amounts[unique_idx] =
                builder.select(new_here, slot_amount, unique_amounts[unique_idx]);
            let not_empty = builder.not(empty);
            placing_new = builder.and(placing_new, not_empty);
        }
    }

    let mut output_amounts = Vec::with_capacity(raw_slot_count);
    let mut output_exits = Vec::with_capacity(raw_slot_count);
    for unique_idx in 0..raw_slot_count {
        let zero_out = builder.not(unique_valid[unique_idx]);
        output_amounts.push(builder.select(zero_out, zero, unique_amounts[unique_idx]));
        let output_exit: [Target; 4] = core::array::from_fn(|limb| {
            builder.select(zero_out, zero, unique_exits[unique_idx][limb])
        });
        output_exits.push(output_exit);
    }

    (output_amounts, output_exits)
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
