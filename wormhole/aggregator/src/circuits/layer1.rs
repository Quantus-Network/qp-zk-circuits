//! Layer-1 aggregation wrapper.
//!
//! Aggregates N layer-0 aggregated proofs into a single proof.
//! This is intended to be run by a third-party aggregator who collects
//! batches of layer-0 proofs and combines them for on-chain submission.
//!
//! The wrapper:
//! - Validates that all layer-0 proofs share the same asset_id and volume_fee_bps
//! - Collects all exit account slots and nullifiers from all layer-0 proofs
//! - Includes the aggregator's address in the output for fee collection
//! - Detects dummies by checking if block_hash == [0,0,0,0] in the layer-0 output header

use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::proof::ProofWithPublicInputs;

use zk_circuits_common::aggregation::{AggregatedProof, AggregationWrapper};
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::gadgets::bytes_digest_eq;

/// Layer-0 aggregated proof header layout.
/// These are the first 8 felts of any layer-0 aggregated proof's public inputs.
const L0_ASSET_ID_OFFSET: usize = 1;
const L0_VOLUME_FEE_BPS_OFFSET: usize = 2;
const L0_BLOCK_HASH_OFFSET: usize = 3; // 4 felts
const L0_BLOCK_NUMBER_OFFSET: usize = 7;
const L0_HEADER_LEN: usize = 8;

/// Each exit slot in layer-0 output is [sum(1), exit_account(4)] = 5 felts.
const EXIT_SLOT_LEN: usize = 5;

/// Layer-1 aggregation wrapper.
///
/// Combines N layer-0 aggregated proofs. The wrapper circuit:
/// - Verifies the merged proof (done by `aggregate_chunk` before this is called)
/// - Enforces all layer-0 proofs have the same asset_id and volume_fee_bps
/// - Enforces all real layer-0 proofs reference the same block
/// - Forwards all exit account slots and nullifiers
/// - Includes the aggregator's address in the output PI for fee collection
///
/// # Public inputs layout (layer-1 output):
/// ```text
/// [aggregator_address(4),
///  asset_id(1),
///  volume_fee_bps(1),
///  block_hash(4),
///  block_number(1),
///  total_exit_slots(1),
///  [sum(1), exit(4)] * total_exit_slots,
///  nullifier(4) * total_nullifiers,
///  padding...]
/// ```
pub struct Layer1Wrapper {
    /// The aggregator's address (4 felts / 32 bytes), included in output for fee collection.
    pub aggregator_address: [F; 4],
    /// Number of leaf proofs per layer-0 batch (needed to parse PI layout).
    pub layer0_num_leaves: usize,
}

impl Layer1Wrapper {
    pub fn new(aggregator_address: [F; 4], layer0_num_leaves: usize) -> Self {
        Self {
            aggregator_address,
            layer0_num_leaves,
        }
    }

    /// Compute the expected PI length of a single layer-0 aggregated proof.
    fn layer0_pi_len(&self) -> usize {
        let n = self.layer0_num_leaves;
        // header(8) + exit_slots(5 * 2*n) + nullifiers(4 * n) + padding
        // Padding is to root_pi_len + 8 where root_pi_len = n * LEAF_PI_LEN
        // LEAF_PI_LEN = 21, so root_pi_len = 21*n
        // Total padded = 21*n + 8
        21 * n + 8
    }

    /// Number of exit slots per layer-0 proof (2 per leaf).
    fn exit_slots_per_l0(&self) -> usize {
        self.layer0_num_leaves * 2
    }

    /// Number of nullifiers per layer-0 proof (1 per leaf).
    fn nullifiers_per_l0(&self) -> usize {
        self.layer0_num_leaves
    }

    /// Offset of exit slot data within a layer-0 proof's PIs.
    fn exit_slots_start(&self) -> usize {
        L0_HEADER_LEN
    }

    /// Offset of nullifier data within a layer-0 proof's PIs.
    fn nullifiers_start(&self) -> usize {
        L0_HEADER_LEN + self.exit_slots_per_l0() * EXIT_SLOT_LEN
    }
}

impl AggregationWrapper for Layer1Wrapper {
    fn is_dummy(&self, proof: &ProofWithPublicInputs<F, C, D>) -> bool {
        // A dummy layer-0 aggregated proof has block_hash == [0,0,0,0] in its header.
        // This propagates from the layer-0 wrapper: if all leaf proofs are dummies,
        // the layer-0 output's block_hash is [0,0,0,0].
        proof.public_inputs[L0_BLOCK_HASH_OFFSET..L0_BLOCK_HASH_OFFSET + 4]
            .iter()
            .all(|f| f.is_zero())
    }

    fn build_wrapper(
        &self,
        merged: AggregatedProof,
        n_inner: usize,
    ) -> anyhow::Result<AggregatedProof> {
        let l0_pi_len = self.layer0_pi_len();

        let root_pi_len = merged.proof.public_inputs.len();
        anyhow::ensure!(
            root_pi_len == n_inner * l0_pi_len,
            "Merged PI length {} != {} layer-0 proofs * {} PI each",
            root_pi_len,
            n_inner,
            l0_pi_len,
        );

        let child_common = &merged.circuit_data.common;
        let child_verifier_only = &merged.circuit_data.verifier_only;

        let mut builder = CircuitBuilder::new(child_common.config.clone());
        let vd_t = builder.add_virtual_verifier_data(child_common.fri_params.config.cap_height);

        let child_pt = builder.add_virtual_proof_with_pis(child_common);
        builder.verify_proof::<C>(&child_pt, &vd_t, child_common);

        let child_pis = &child_pt.public_inputs;

        let zero = builder.zero();
        let one = builder.one();

        // ===== Output PIs =====
        let mut output_pis: Vec<Target> = Vec::new();

        // 1) Aggregator address (4 felts) -- identifies the layer-1 operator for fee collection
        let agg_addr_targets: [Target; 4] =
            core::array::from_fn(|i| builder.constant(self.aggregator_address[i]));
        output_pis.extend_from_slice(&agg_addr_targets);

        // 2) Reference values from first layer-0 proof
        let asset_ref = child_pis[L0_ASSET_ID_OFFSET];
        let volume_fee_ref = child_pis[L0_VOLUME_FEE_BPS_OFFSET];
        output_pis.push(asset_ref);
        output_pis.push(volume_fee_ref);

        // 3) Block hash validation -- same pattern as layer-0 but over layer-0 headers
        let block_ref: [Target; 4] = core::array::from_fn(|j| child_pis[L0_BLOCK_HASH_OFFSET + j]);
        let block_number_ref = child_pis[L0_BLOCK_NUMBER_OFFSET];

        let dummy_sentinel = [zero; 4];

        for i in 0..n_inner {
            let base = i * l0_pi_len;

            // Enforce same asset_id and volume_fee_bps
            let asset_i = child_pis[base + L0_ASSET_ID_OFFSET];
            builder.connect(asset_i, asset_ref);
            let fee_i = child_pis[base + L0_VOLUME_FEE_BPS_OFFSET];
            builder.connect(fee_i, volume_fee_ref);

            // Enforce same block (or dummy)
            let block_i: [Target; 4] =
                core::array::from_fn(|j| child_pis[base + L0_BLOCK_HASH_OFFSET + j]);
            let is_dummy = bytes_digest_eq(&mut builder, block_i, dummy_sentinel);
            let matches_ref = bytes_digest_eq(&mut builder, block_i, block_ref);
            let ok = builder.or(is_dummy, matches_ref);
            builder.connect(ok.target, one);
        }

        output_pis.extend_from_slice(&block_ref);
        output_pis.push(block_number_ref);

        // 4) Total exit slots across all layer-0 proofs
        let total_exit_slots = n_inner * self.exit_slots_per_l0();
        let total_exit_slots_t = builder.constant(F::from_canonical_usize(total_exit_slots));
        output_pis.push(total_exit_slots_t);

        // 5) Forward all exit slots from all layer-0 proofs
        for i in 0..n_inner {
            let base = i * l0_pi_len + self.exit_slots_start();
            for slot in 0..self.exit_slots_per_l0() {
                let slot_base = base + slot * EXIT_SLOT_LEN;
                // [sum(1), exit_account(4)]
                for j in 0..EXIT_SLOT_LEN {
                    output_pis.push(child_pis[slot_base + j]);
                }
            }
        }

        // 6) Forward all nullifiers from all layer-0 proofs
        for i in 0..n_inner {
            let base = i * l0_pi_len + self.nullifiers_start();
            for n_idx in 0..self.nullifiers_per_l0() {
                let null_base = base + n_idx * 4;
                for j in 0..4 {
                    output_pis.push(child_pis[null_base + j]);
                }
            }
        }

        // Register output public inputs
        builder.register_public_inputs(&output_pis);

        // Build and prove
        let circuit_data = builder.build();
        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(&vd_t, child_verifier_only)?;
        pw.set_proof_with_pis_target(&child_pt, &merged.proof)?;

        let proof = circuit_data.prove(pw)?;
        Ok(AggregatedProof {
            proof,
            circuit_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::PrimeField64;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use qp_wormhole_inputs::PUBLIC_INPUTS_FELTS_LEN as LEAF_PI_LEN;
    use zk_circuits_common::aggregation::aggregate_with_wrapper;

    use crate::circuits::tree::aggregate_proofs;

    const NUM_LEAVES: usize = 2; // 2 leaf proofs per layer-0 batch (small for fast tests)

    /// Create a fake leaf circuit and prove it with given PIs.
    fn prove_fake_leaf(pis: [F; LEAF_PI_LEN]) -> AggregatedProof {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets: Vec<Target> = (0..LEAF_PI_LEN)
            .map(|_| builder.add_virtual_target())
            .collect();
        // Range checks to match real leaf circuit constraints
        builder.range_check(targets[1], 32); // output_amount_1
        builder.range_check(targets[2], 32); // output_amount_2
        builder.range_check(targets[3], 32); // volume_fee_bps
        builder.register_public_inputs(&targets);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        for (t, v) in targets.iter().zip(pis.iter()) {
            pw.set_target(*t, *v).unwrap();
        }
        let proof = data.prove(pw).unwrap();
        AggregatedProof {
            proof,
            circuit_data: data,
        }
    }

    /// Build a leaf PI array with the given parameters.
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
        out[1] = F::from_canonical_u32(amount1);
        out[2] = F::from_canonical_u32(amount2);
        out[3] = F::from_canonical_u64(10); // volume_fee_bps
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
        out[20] = F::from_canonical_u32(block_number);
        out
    }

    /// Run a full 2-layer aggregation pipeline:
    /// 1. Create fake leaf proofs
    /// 2. Aggregate them via layer-0 (WormholeAggregationWrapper)
    /// 3. Aggregate the layer-0 proofs via layer-1 (Layer1Wrapper)
    /// 4. Verify the output contains the expected data
    #[test]
    fn two_layer_aggregation_pipeline() {
        let block_hash: [u64; 4] = [0xAA01, 0xAA02, 0xAA03, 0xAA04];
        let block_number = 42u32;

        // -- Layer 0, batch A: 2 leaf proofs --
        let leaf_a0 = prove_fake_leaf(make_leaf_pi(
            100,
            0,
            [1, 2, 3, 4],
            [0, 0, 0, 0],             // exit1, exit2 (unused)
            [0x10, 0x11, 0x12, 0x13], // nullifier
            block_hash,
            block_number,
        ));
        let leaf_a1 = prove_fake_leaf(make_leaf_pi(
            200,
            50,
            [5, 6, 7, 8],
            [9, 10, 11, 12],          // exit1, exit2
            [0x20, 0x21, 0x22, 0x23], // nullifier
            block_hash,
            block_number,
        ));

        // Both leaves must come from the same circuit
        let common_a = leaf_a0.circuit_data.common.clone();
        let verifier_a = leaf_a0.circuit_data.verifier_only.clone();

        let l0_batch_a =
            aggregate_proofs(vec![leaf_a0.proof, leaf_a1.proof], &common_a, &verifier_a)
                .expect("layer-0 batch A aggregation failed");

        // -- Layer 0, batch B: 2 more leaf proofs (same circuit, same block) --
        let leaf_b0 = prove_fake_leaf(make_leaf_pi(
            300,
            0,
            [13, 14, 15, 16],
            [0, 0, 0, 0],
            [0x30, 0x31, 0x32, 0x33],
            block_hash,
            block_number,
        ));
        let leaf_b1 = prove_fake_leaf(make_leaf_pi(
            400,
            100,
            [17, 18, 19, 20],
            [21, 22, 23, 24],
            [0x40, 0x41, 0x42, 0x43],
            block_hash,
            block_number,
        ));

        let l0_batch_b =
            aggregate_proofs(vec![leaf_b0.proof, leaf_b1.proof], &common_a, &verifier_a)
                .expect("layer-0 batch B aggregation failed");

        // -- Layer 1: aggregate the two layer-0 proofs --
        let aggregator_address = [
            F::from_canonical_u64(0xDEAD),
            F::from_canonical_u64(0xBEEF),
            F::from_canonical_u64(0xCAFE),
            F::from_canonical_u64(0xBABE),
        ];

        let l1_wrapper = Layer1Wrapper::new(aggregator_address, NUM_LEAVES);

        // Both layer-0 proofs must come from the same circuit
        let l0_common = l0_batch_a.circuit_data.common.clone();
        let l0_verifier = l0_batch_a.circuit_data.verifier_only.clone();

        let l1_result = aggregate_with_wrapper(
            vec![l0_batch_a.proof, l0_batch_b.proof],
            &l0_common,
            &l0_verifier,
            &l1_wrapper,
        )
        .expect("layer-1 aggregation failed");

        // -- Verify the output --
        let pis = l1_result.proof.public_inputs.clone();

        // Aggregator address
        assert_eq!(pis[0].to_canonical_u64(), 0xDEAD);
        assert_eq!(pis[1].to_canonical_u64(), 0xBEEF);
        assert_eq!(pis[2].to_canonical_u64(), 0xCAFE);
        assert_eq!(pis[3].to_canonical_u64(), 0xBABE);

        // Asset ID and volume fee
        assert_eq!(pis[4].to_canonical_u64(), 0); // asset_id = native
        assert_eq!(pis[5].to_canonical_u64(), 10); // volume_fee_bps

        // Block hash
        assert_eq!(pis[6].to_canonical_u64(), 0xAA01);
        assert_eq!(pis[7].to_canonical_u64(), 0xAA02);
        assert_eq!(pis[8].to_canonical_u64(), 0xAA03);
        assert_eq!(pis[9].to_canonical_u64(), 0xAA04);

        // Block number
        assert_eq!(pis[10].to_canonical_u64(), 42);

        // Total exit slots = 2 batches * 2 leaves * 2 outputs = 8
        assert_eq!(pis[11].to_canonical_u64(), 8);

        // Verify the proof is valid
        l1_result
            .circuit_data
            .verify(l1_result.proof)
            .expect("layer-1 proof verification failed");

        println!("Two-layer aggregation pipeline passed!");
        println!("  Layer-0: 2 batches of {} leaves each", NUM_LEAVES);
        println!("  Layer-1: aggregated 2 layer-0 proofs");
        println!("  Total leaf proofs represented: {}", NUM_LEAVES * 2);
        println!("  Output PI count: {}", pis.len());
    }
}
