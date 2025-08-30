use alloc::{vec, vec::Vec};
use anyhow::bail;
use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    inputs::CircuitInputs,
    storage_proof::leaf::{LeafInputs, LeafTargets},
};
use zk_circuits_common::utils::{digest_bytes_to_felts, injective_bytes_to_felts};
use zk_circuits_common::{
    circuit::{CircuitFragment, D, F},
    utils::INJECTIVE_BYTES_PER_ELEMENT,
};

pub mod leaf;

pub const MAX_PROOF_LEN: usize = 20;
pub const PROOF_NODE_MAX_SIZE_F: usize = 188; // Should match the felt preimage max set on poseidon-resonance crate.
pub const PROOF_NODE_MAX_SIZE_B: usize = 256;
pub const FELTS_PER_AMOUNT: usize = 2;

#[derive(Debug, Clone)]
pub struct StorageProofTargets {
    pub root_hash: HashOutTarget,
    pub proof_len: Target,
    pub proof_data: Vec<Vec<Target>>,
    pub indices: Vec<Target>,
    pub leaf_inputs: LeafTargets,
}

impl StorageProofTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Setup targets. Each 8-bytes are represented as their equivalent field element. We also
        // need to track total proof length to allow for variable length.
        let proof_data: Vec<_> = (0..MAX_PROOF_LEN)
            .map(|_| builder.add_virtual_targets(PROOF_NODE_MAX_SIZE_F))
            .collect();

        let indices: Vec<_> = (0..MAX_PROOF_LEN)
            .map(|_| builder.add_virtual_target())
            .collect();

        Self {
            root_hash: builder.add_virtual_hash_public_input(),
            proof_len: builder.add_virtual_target(),
            proof_data,
            indices,
            leaf_inputs: LeafTargets::new(builder),
        }
    }
}

/// A storgae proof along with an array of indices where the hash child ndoes are placed.
#[derive(Debug, Clone)]
pub struct ProcessedStorageProof {
    pub proof: Vec<Vec<u8>>,
    pub indices: Vec<usize>,
}

impl ProcessedStorageProof {
    pub fn new(proof: Vec<Vec<u8>>, indices: Vec<usize>) -> anyhow::Result<Self> {
        if proof.len() != indices.len() {
            bail!(
                "indices length must be equal to proof length, actual lengths: {}, {}",
                proof.len(),
                indices.len()
            );
        }

        Ok(Self { proof, indices })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct StorageProof {
    pub proof: Vec<Vec<F>>,
    pub indices: Vec<F>,
    pub root_hash: [u8; 32],
    pub leaf_inputs: LeafInputs,
}

impl StorageProof {
    pub fn new(
        processed_proof: &ProcessedStorageProof,
        root_hash: [u8; 32],
        leaf_inputs: LeafInputs,
    ) -> Self {
        let proof: Vec<Vec<F>> = processed_proof
            .proof
            .iter()
            .map(|node| injective_bytes_to_felts(node))
            .collect();
        // print the length of the proof at index 4
        // println!(
        //     "[+] StorageProof: proof length at index 4: {}",
        //     proof.get(4).map_or(0, |node| node.len())
        // );

        let indices = processed_proof
            .indices
            .iter()
            .map(|&i| {
                // Divide by 8 to get the field element index instead of the hex index.
                let i = i / (INJECTIVE_BYTES_PER_ELEMENT * 2);
                F::from_canonical_usize(i)
            })
            .collect();

        StorageProof {
            proof,
            indices,
            root_hash,
            leaf_inputs,
        }
    }
}

impl TryFrom<&CircuitInputs> for StorageProof {
    type Error = anyhow::Error;

    fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
        Ok(Self::new(
            &inputs.private.storage_proof,
            *inputs.public.root_hash,
            LeafInputs::try_from(inputs)?,
        ))
    }
}

impl CircuitFragment for StorageProof {
    type Targets = StorageProofTargets;

    #[allow(unused_variables)]
    fn circuit(
        &Self::Targets {
            root_hash,
            proof_len,
            ref proof_data,
            ref indices,
            ref leaf_inputs,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        use plonky2::hash::poseidon::PoseidonHash;
        use zk_circuits_common::gadgets::is_const_less_than;

        let leaf_targets_32_bit = leaf_inputs.collect_32_bit_targets();
        // Range contrain the first 2 and last 4 elements of the leaf inputs (transfer_count and funding_amount) to be 32 bits.
        for target in leaf_targets_32_bit.iter() {
            builder.range_check(*target, 32);
        }

        // Calculate the leaf inputs hash.
        let leaf_inputs_hash =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(leaf_inputs.collect_to_vec());

        // constant 2^32 for (lo + hi * 2^32) reconstruction
        let two_pow_32 = builder.constant(F::from_canonical_u64(1u64 << 32));

        // The first node should be the root node so we initialize `prev_hash` to the provided `root_hash`.
        let mut prev_hash = root_hash;
        let n_log = (usize::BITS - (MAX_PROOF_LEN - 1).leading_zeros()) as usize;
        for i in 0..MAX_PROOF_LEN {
            let node = &proof_data[i];

            // Check if this is a valid proof node or a dummy one.
            let is_proof_node = is_const_less_than(builder, i, proof_len, n_log);

            // Check if this is a leaf node.
            let i_t = builder.constant(F::from_canonical_usize(i));
            let is_leaf_node = builder.is_equal(i_t, proof_len);

            // Compute the hash of this node and compare it against the previous hash.
            let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node.clone());
            for y in 0..4 {
                let diff = builder.sub(computed_hash.elements[y], prev_hash.elements[y]);
                let result = builder.mul(diff, is_proof_node.target);
                let zero = builder.zero();
                builder.connect(result, zero);
            }

            // Update `prev_hash` to the hash of the child that's stored within this node.
            // We first find the hash using the commited index.
            let mut found_hash = vec![
                builder.zero(),
                builder.zero(),
                builder.zero(),
                builder.zero(),
            ];
            let expected_hash_index = indices[i];
            for (j, felt) in node.iter().enumerate().take(PROOF_NODE_MAX_SIZE_F - 8) {
                // Range constrain each target in the node to be 32 bits.
                builder.range_check(*felt, 32);
                let felt_index = builder.constant(F::from_canonical_usize(j));
                let is_start_of_hash = builder.is_equal(felt_index, expected_hash_index);

                // If this is the start of the hash, set the next 4 felts of `found_hash`.
                // Combine pairs (lo, hi) -> lo + hi * 2^32 (little-endian)
                let mut combine_le_32x2 = |lo: Target, hi: Target| {
                    let hi_shifted = builder.mul(hi, two_pow_32);
                    builder.add(lo, hi_shifted)
                };

                // Reconstruct the 4 hash elements from the next 8 felts (32-bit limbs).
                // Layout (little-endian pairs):
                // h0 = node[j+0] (lo) , node[j+1] (hi)
                // h1 = node[j+2] (lo) , node[j+3] (hi)
                // h2 = node[j+4] (lo) , node[j+5] (hi)
                // h3 = node[j+6] (lo) , node[j+7] (hi)
                let h0 = combine_le_32x2(node[j], node[j + 1]);
                let h1 = combine_le_32x2(node[j + 2], node[j + 3]);
                let h2 = combine_le_32x2(node[j + 4], node[j + 5]);
                let h3 = combine_le_32x2(node[j + 6], node[j + 7]);

                // If this is the start of the hash, set the 4 reconstructed felts into found_hash.
                found_hash[0] = builder.select(is_start_of_hash, h0, found_hash[0]);
                found_hash[1] = builder.select(is_start_of_hash, h1, found_hash[1]);
                found_hash[2] = builder.select(is_start_of_hash, h2, found_hash[2]);
                found_hash[3] = builder.select(is_start_of_hash, h3, found_hash[3]);
            }
            // Range check the last 8 felts of the node to be 32 bits.
            for felt in node.iter().skip(PROOF_NODE_MAX_SIZE_F - 8) {
                builder.range_check(*felt, 32);
            }

            // Lastly, we do an additional check if this is the leaf node - that the hash of its
            // inputs is contained within the node. Note: we only compare the last 3 felts since
            // the stored leaf inputs hash does not always contain the first nibble.
            for y in 1..4 {
                let diff = builder.sub(leaf_inputs_hash.elements[y], prev_hash.elements[y]);
                let result = builder.mul(diff, is_leaf_node.target);
                let zero = builder.zero();
                builder.connect(result, zero);
            }

            prev_hash = HashOutTarget::from_vec(found_hash);
        }
    }

    fn fill_targets(
        &self,
        pw: &mut plonky2::iop::witness::PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        use plonky2::iop::witness::WitnessWrite;
        use zk_circuits_common::utils::felts_to_hashout;

        const EMPTY_PROOF_NODE: [F; PROOF_NODE_MAX_SIZE_F] = [F::ZERO; PROOF_NODE_MAX_SIZE_F];

        pw.set_hash_target(targets.root_hash, bytes_32_to_hashout(self.root_hash))?;
        // bail if proof is too long
        if self.proof.len() > MAX_PROOF_LEN {
            bail!(
                "proof length exceeds maximum allowed length: {} > {}",
                self.proof.len(),
                MAX_PROOF_LEN
            );
        }
        pw.set_target(targets.proof_len, F::from_canonical_usize(self.proof.len()))?;

        for i in 0..MAX_PROOF_LEN {
            match self.proof.get(i) {
                Some(node) => {
                    let mut padded_proof_node = node.clone();

                    if padded_proof_node.len() > PROOF_NODE_MAX_SIZE_F {
                        bail!(
                            "proof node at index {} is too large: {}",
                            i,
                            padded_proof_node.len()
                        );
                    }
                    padded_proof_node.resize(PROOF_NODE_MAX_SIZE_F, F::ZERO);
                    pw.set_target_arr(&targets.proof_data[i], &padded_proof_node)?;
                }
                None => pw.set_target_arr(&targets.proof_data[i], &EMPTY_PROOF_NODE)?,
            }
        }

        for i in 0..MAX_PROOF_LEN {
            let &felt = self.indices.get(i).unwrap_or(&F::ZERO);
            pw.set_target(targets.indices[i], felt)?;
        }

        // Set leaf input targets.
        let funding_account = felts_to_hashout(&self.leaf_inputs.funding_account.0);
        let to_account = felts_to_hashout(&self.leaf_inputs.to_account.0);

        pw.set_target_arr(
            &targets.leaf_inputs.transfer_count,
            &self.leaf_inputs.transfer_count,
        )?;
        pw.set_hash_target(targets.leaf_inputs.funding_account, funding_account)?;
        pw.set_hash_target(targets.leaf_inputs.to_account, to_account)?;
        pw.set_target_arr(
            &targets.leaf_inputs.funding_amount,
            &self.leaf_inputs.funding_amount,
        )?;

        Ok(())
    }
}

fn bytes_32_to_hashout(bytes: [u8; 32]) -> HashOut<F> {
    use zk_circuits_common::utils::BytesDigest;

    let digest = BytesDigest::try_from(bytes).unwrap();
    let elements = digest_bytes_to_felts(digest);
    HashOut { elements }
}
