use anyhow::{anyhow, Result};
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
    util::serialization::{Buffer, Read, Remaining, Write},
};
use zk_circuits_common::{
    circuit::{C, D, F},
    gadgets::bytes_digest_eq,
};

use crate::layer0::circuit::constants::aggregated_output;

use super::constants::{
    outer_circuit_config, OUTER_CHILD_EXIT_SLOTS, OUTER_CHILD_EXIT_SLOTS_START,
    OUTER_CHILD_EXIT_SLOT_LEN, OUTER_CHILD_NULLIFIERS, OUTER_CHILD_NULLIFIERS_START,
    OUTER_CHILD_PI_LEN, OUTER_FINAL_EXIT_SLOTS, OUTER_INNER_PROOFS, OUTER_OUTPUT_PI_LEN,
};

#[derive(Debug, Clone)]
pub struct OuterAggregationCircuitTargets {
    pub inner_verifier_data: VerifierCircuitTarget,
    pub inner_proofs: Vec<ProofWithPublicInputsTarget<D>>,
}

impl OuterAggregationCircuitTargets {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes
            .write_target_verifier_circuit(&self.inner_verifier_data)
            .map_err(|e| anyhow!("failed to serialize inner verifier target: {}", e))?;
        bytes
            .write_usize(self.inner_proofs.len())
            .map_err(|e| anyhow!("failed to serialize inner proof count: {}", e))?;
        for proof in &self.inner_proofs {
            bytes
                .write_target_proof_with_public_inputs(proof)
                .map_err(|e| anyhow!("failed to serialize inner proof target: {}", e))?;
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut buffer = Buffer::new(bytes);
        let inner_verifier_data = buffer
            .read_target_verifier_circuit()
            .map_err(|e| anyhow!("failed to deserialize inner verifier target: {}", e))?;
        let proof_count = buffer
            .read_usize()
            .map_err(|e| anyhow!("failed to deserialize inner proof count: {}", e))?;
        let mut inner_proofs = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            inner_proofs.push(
                buffer
                    .read_target_proof_with_public_inputs()
                    .map_err(|e| anyhow!("failed to deserialize inner proof target: {}", e))?,
            );
        }

        if buffer.remaining() != 0 {
            return Err(anyhow!(
                "outer target layout had {} trailing bytes",
                buffer.remaining()
            ));
        }

        Ok(Self {
            inner_verifier_data,
            inner_proofs,
        })
    }
}

pub struct OuterAggregationCircuit {
    builder: CircuitBuilder<F, D>,
    targets: OuterAggregationCircuitTargets,
}

impl OuterAggregationCircuit {
    pub fn new(inner_common: CommonCircuitData<F, D>) -> Self {
        Self::new_with_config(outer_circuit_config(), inner_common)
    }

    pub fn new_with_config(config: CircuitConfig, inner_common: CommonCircuitData<F, D>) -> Self {
        debug_assert_eq!(
            inner_common.num_public_inputs, OUTER_CHILD_PI_LEN,
            "inner common PI length mismatch"
        );

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let inner_verifier_data =
            builder.add_virtual_verifier_data(inner_common.fri_params.config.cap_height);
        let mut inner_proofs = Vec::with_capacity(OUTER_INNER_PROOFS);
        for _ in 0..OUTER_INNER_PROOFS {
            let pt = builder.add_virtual_proof_with_pis(&inner_common);
            builder.verify_proof::<C>(&pt, &inner_verifier_data, &inner_common);
            inner_proofs.push(pt);
        }

        let targets = OuterAggregationCircuitTargets {
            inner_verifier_data,
            inner_proofs,
        };

        build_outer_wrapper_constraints(&mut builder, &targets);

        Self { builder, targets }
    }

    pub fn targets(&self) -> OuterAggregationCircuitTargets {
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

fn build_outer_wrapper_constraints(
    builder: &mut CircuitBuilder<F, D>,
    targets: &OuterAggregationCircuitTargets,
) {
    let zero = builder.zero();
    let inner_pi_targets: Vec<&[Target]> = targets
        .inner_proofs
        .iter()
        .map(|p| p.public_inputs.as_slice())
        .collect();

    debug_assert_eq!(inner_pi_targets.len(), OUTER_INNER_PROOFS);
    debug_assert!(inner_pi_targets
        .iter()
        .all(|pis| pis.len() == OUTER_CHILD_PI_LEN));

    let proof_a = inner_pi_targets[0];
    let proof_b = inner_pi_targets[1];
    let expected_child_slots = builder.constant(F::from_canonical_usize(OUTER_CHILD_EXIT_SLOTS));
    builder.connect(
        proof_a[aggregated_output::NUM_EXIT_SLOTS_OFFSET],
        expected_child_slots,
    );
    builder.connect(
        proof_b[aggregated_output::NUM_EXIT_SLOTS_OFFSET],
        expected_child_slots,
    );

    let asset_ref = proof_a[aggregated_output::ASSET_ID_OFFSET];
    let fee_ref = proof_a[aggregated_output::VOLUME_FEE_BPS_OFFSET];
    let block_ref: [Target; 4] =
        core::array::from_fn(|i| proof_a[aggregated_output::BLOCK_HASH_OFFSET + i]);
    let block_number_ref = proof_a[aggregated_output::BLOCK_NUMBER_OFFSET];

    let asset_b = proof_b[aggregated_output::ASSET_ID_OFFSET];
    let fee_b = proof_b[aggregated_output::VOLUME_FEE_BPS_OFFSET];

    let block_b: [Target; 4] =
        core::array::from_fn(|i| proof_b[aggregated_output::BLOCK_HASH_OFFSET + i]);
    let block_b_is_dummy = bytes_digest_eq(builder, block_b, [zero, zero, zero, zero]);
    let block_b_matches = bytes_digest_eq(builder, block_b, block_ref);
    let valid_block_relation = builder.or(block_b_is_dummy, block_b_matches);
    let one = builder.one();
    builder.connect(valid_block_relation.target, one);
    let asset_b_or_ref = builder.select(block_b_is_dummy, asset_ref, asset_b);
    builder.connect(asset_b_or_ref, asset_ref);
    let fee_b_or_ref = builder.select(block_b_is_dummy, fee_ref, fee_b);
    builder.connect(fee_b_or_ref, fee_ref);

    let mut output_pis = Vec::with_capacity(OUTER_OUTPUT_PI_LEN);
    output_pis.push(builder.constant(F::from_canonical_usize(OUTER_FINAL_EXIT_SLOTS)));
    output_pis.push(asset_ref);
    output_pis.push(fee_ref);
    output_pis.extend_from_slice(&block_ref);
    output_pis.push(block_number_ref);

    let (a_amounts, a_exits, a_is_zero) = read_exit_slots(builder, proof_a);
    let (b_amounts, b_exits, b_is_zero) = read_exit_slots(builder, proof_b);

    let mut cross_eq = vec![vec![builder._false(); OUTER_CHILD_EXIT_SLOTS]; OUTER_CHILD_EXIT_SLOTS];
    for i in 0..OUTER_CHILD_EXIT_SLOTS {
        for (j, b_exit) in b_exits.iter().enumerate().take(OUTER_CHILD_EXIT_SLOTS) {
            cross_eq[i][j] = bytes_digest_eq(builder, a_exits[i], *b_exit);
        }
    }

    for i in 0..OUTER_CHILD_EXIT_SLOTS {
        let mut sum_from_b = zero;
        for (j, b_amount) in b_amounts.iter().enumerate().take(OUTER_CHILD_EXIT_SLOTS) {
            let matched_amount = builder.select(cross_eq[i][j], *b_amount, zero);
            sum_from_b = builder.add(sum_from_b, matched_amount);
        }

        let merged_sum = builder.add(a_amounts[i], sum_from_b);
        let final_sum = builder.select(a_is_zero[i], zero, merged_sum);
        builder.range_check(final_sum, 32);

        output_pis.push(final_sum);
        for exit_limb in a_exits[i].iter().take(4) {
            output_pis.push(builder.select(a_is_zero[i], zero, *exit_limb));
        }
    }

    for j in 0..OUTER_CHILD_EXIT_SLOTS {
        let mut matches_a = builder._false();
        for cross_eq in cross_eq.iter().take(OUTER_CHILD_EXIT_SLOTS) {
            matches_a = builder.or(matches_a, cross_eq[j]);
        }
        let zero_out = builder.or(b_is_zero[j], matches_a);
        let final_sum = builder.select(zero_out, zero, b_amounts[j]);
        builder.range_check(final_sum, 32);

        output_pis.push(final_sum);
        for exit_limb in b_exits[j].iter().take(4) {
            output_pis.push(builder.select(zero_out, zero, *exit_limb));
        }
    }

    for proof in [proof_a, proof_b] {
        for idx in 0..OUTER_CHILD_NULLIFIERS {
            let base = OUTER_CHILD_NULLIFIERS_START + idx * 4;
            output_pis.extend_from_slice(&proof[base..base + 4]);
        }
    }

    while output_pis.len() < OUTER_OUTPUT_PI_LEN {
        output_pis.push(zero);
    }

    builder.register_public_inputs(&output_pis);
}

fn read_exit_slots(
    builder: &mut CircuitBuilder<F, D>,
    pis: &[Target],
) -> (Vec<Target>, Vec<[Target; 4]>, Vec<BoolTarget>) {
    let zero = builder.zero();
    let zero_digest = [zero, zero, zero, zero];
    let mut amounts = Vec::with_capacity(OUTER_CHILD_EXIT_SLOTS);
    let mut exits = Vec::with_capacity(OUTER_CHILD_EXIT_SLOTS);
    let mut is_zero = Vec::with_capacity(OUTER_CHILD_EXIT_SLOTS);
    for slot in 0..OUTER_CHILD_EXIT_SLOTS {
        let base = OUTER_CHILD_EXIT_SLOTS_START + slot * OUTER_CHILD_EXIT_SLOT_LEN;
        let amount = pis[base];
        let exit = core::array::from_fn(|i| pis[base + 1 + i]);
        let slot_is_zero = bytes_digest_eq(builder, exit, zero_digest);
        amounts.push(amount);
        exits.push(exit);
        is_zero.push(slot_is_zero);
    }
    (amounts, exits, is_zero)
}
