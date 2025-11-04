use plonky2::{
    field::types::Field,
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use anyhow::bail;
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::gadgets::is_const_less_than;
use zk_circuits_common::utils::{
    felts_to_hashout, Digest, PrivateKey, DIGEST_NUM_FIELD_ELEMENTS, ZERO_DIGEST,
};

/// Maximum depth of the Merkle tree for eligible voters.
/// This allows for up to 2^32 eligible voters.
pub const MAX_MERKLE_DEPTH: usize = 32;

/// Public inputs for the vote circuit.
///
/// These inputs are visible to all parties and are used to verify the vote's validity.
#[derive(Debug, Clone)]
pub struct VotePublicInputs {
    /// The proposal ID this vote is for
    pub proposal_id: Digest,
    /// The merkle root of eligible addresses
    pub merkle_root: Digest,
    /// The vote (0 for no, 1 for yes)
    pub vote: bool,
    /// The nullifier to prevent double voting
    pub nullifier: Digest,
}

/// Private inputs for the vote circuit.
///
/// These inputs are only known to the voter and are used to prove eligibility
/// without revealing the voter's identity.
#[derive(Debug, Clone)]
pub struct VotePrivateInputs {
    /// The private key of the voter
    pub private_key: PrivateKey,
    /// The sibling hashes in the merkle tree path
    pub merkle_siblings: Vec<Digest>,
    /// The path indices (0 for left, 1 for right) for each level of the Merkle tree
    pub path_indices: Vec<bool>,
    /// The actual depth of this specific Merkle proof
    pub actual_merkle_depth: usize,
}

/// Holds all the targets created during circuit construction.
#[derive(Clone, Debug)]
pub struct VoteTargets {
    // Public Input Targets
    pub proposal_id: HashOutTarget,
    pub expected_merkle_root: HashOutTarget,
    pub vote: BoolTarget,
    pub expected_nullifier: HashOutTarget,

    // Private Input Targets
    pub private_key: HashOutTarget,
    pub merkle_siblings: Vec<HashOutTarget>,
    pub path_indices: Vec<BoolTarget>,
    pub actual_merkle_depth: Target,
}

impl VoteTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Public Input Targets
        let proposal_id = builder.add_virtual_hash_public_input();
        let expected_merkle_root = builder.add_virtual_hash_public_input();
        let vote = builder.add_virtual_bool_target_safe(); // Not public by default
        builder.register_public_input(vote.target); // Explicitly make it public
        let expected_nullifier = builder.add_virtual_hash_public_input();

        // Private Input Targets
        let private_key = builder.add_virtual_hash();
        let merkle_siblings: Vec<_> = (0..MAX_MERKLE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let path_indices: Vec<_> = (0..MAX_MERKLE_DEPTH)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();
        let actual_merkle_depth = builder.add_virtual_target();

        Self {
            proposal_id,
            expected_merkle_root,
            vote,
            expected_nullifier,
            private_key,
            merkle_siblings,
            path_indices,
            actual_merkle_depth,
        }
    }
}

/// Data for the vote circuit, used for witness generation.
///
/// This struct holds both public and private inputs needed to generate a proof
/// that a vote is valid and from an eligible voter.
#[derive(Debug, Clone)]
pub struct VoteCircuitData {
    pub public_inputs: VotePublicInputs,
    pub private_inputs: VotePrivateInputs,
}

impl VoteCircuitData {
    pub fn new(public_inputs: VotePublicInputs, private_inputs: VotePrivateInputs) -> Self {
        Self {
            public_inputs,
            private_inputs,
        }
    }
}

impl CircuitFragment for VoteCircuitData {
    type Targets = VoteTargets;

    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>) {
        // --- 1. Merkle Proof Verification ---
        let leaf_hash_targets = builder
            .hash_n_to_hash_no_pad_p2::<plonky2::hash::poseidon2::Poseidon2Hash>(
                targets.private_key.elements.to_vec(),
            );
        let mut current_hash_targets = leaf_hash_targets;

        let n_log = (usize::BITS - (MAX_MERKLE_DEPTH - 1).leading_zeros()) as usize;
        for i in 0..MAX_MERKLE_DEPTH {
            let is_active_level =
                is_const_less_than(builder, i, targets.actual_merkle_depth, n_log);

            let sibling_hash_targets = targets.merkle_siblings[i];
            let path_index_bool_target = targets.path_indices[i];

            let mut combined_elements = Vec::with_capacity(2 * DIGEST_NUM_FIELD_ELEMENTS);
            let mut left_elements = Vec::with_capacity(DIGEST_NUM_FIELD_ELEMENTS);
            let mut right_elements = Vec::with_capacity(DIGEST_NUM_FIELD_ELEMENTS);

            for k in 0..DIGEST_NUM_FIELD_ELEMENTS {
                let left_k = builder.select(
                    path_index_bool_target,
                    sibling_hash_targets.elements[k],
                    current_hash_targets.elements[k],
                );
                left_elements.push(left_k);

                let right_k = builder.select(
                    path_index_bool_target,
                    current_hash_targets.elements[k],
                    sibling_hash_targets.elements[k],
                );
                right_elements.push(right_k);
            }
            combined_elements.extend(&left_elements);
            combined_elements.extend(&right_elements);

            let parent_hash_candidacy = builder
                .hash_n_to_hash_no_pad_p2::<plonky2::hash::poseidon2::Poseidon2Hash>(
                    combined_elements,
                );

            let mut next_hash_elements = Vec::with_capacity(DIGEST_NUM_FIELD_ELEMENTS);
            for k in 0..DIGEST_NUM_FIELD_ELEMENTS {
                let selected_k = builder.select(
                    is_active_level,
                    parent_hash_candidacy.elements[k],
                    current_hash_targets.elements[k],
                );
                next_hash_elements.push(selected_k);
            }
            current_hash_targets = HashOutTarget {
                elements: next_hash_elements.try_into().unwrap(),
            };
        }

        // Final root verification - ensure the computed root matches the expected root
        builder.connect_hashes(current_hash_targets, targets.expected_merkle_root);

        // --- 2. Nullifier Generation & Verification ---
        let mut nullifier_input_elements = Vec::with_capacity(2 * DIGEST_NUM_FIELD_ELEMENTS);
        nullifier_input_elements.extend_from_slice(&leaf_hash_targets.elements);
        nullifier_input_elements.extend_from_slice(&targets.proposal_id.elements);

        let computed_nullifier_targets = builder
            .hash_n_to_hash_no_pad_p2::<plonky2::hash::poseidon2::Poseidon2Hash>(
                nullifier_input_elements,
            );

        // Ensure the computed nullifier matches the expected nullifier
        builder.connect_hashes(computed_nullifier_targets, targets.expected_nullifier);

        // --- 3. Vote Validation ---
        // targets.vote_target is BoolTarget, which implies it is 0 or 1.
        // No explicit constraint needed here as add_virtual_bool_public_input ensures this.
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        // Validate merkle depth
        if self.private_inputs.actual_merkle_depth > MAX_MERKLE_DEPTH {
            bail!(
                "Merkle tree depth {} exceeds maximum allowed depth {}",
                self.private_inputs.actual_merkle_depth,
                MAX_MERKLE_DEPTH
            );
        }

        // Validate merkle proof length
        if self.private_inputs.merkle_siblings.len() != self.private_inputs.path_indices.len() {
            bail!(
                "Merkle proof length mismatch: {} siblings vs {} path indices",
                self.private_inputs.merkle_siblings.len(),
                self.private_inputs.path_indices.len()
            );
        }

        // Set public input witnesses
        pw.set_hash_target(
            targets.proposal_id,
            felts_to_hashout(&self.public_inputs.proposal_id),
        )?;
        pw.set_hash_target(
            targets.expected_merkle_root,
            felts_to_hashout(&self.public_inputs.merkle_root),
        )?;
        pw.set_bool_target(targets.vote, self.public_inputs.vote)?;
        pw.set_hash_target(
            targets.expected_nullifier,
            felts_to_hashout(&self.public_inputs.nullifier),
        )?;

        // Set private input witnesses
        pw.set_hash_target(
            targets.private_key,
            felts_to_hashout(&self.private_inputs.private_key),
        )?;
        pw.set_target(
            targets.actual_merkle_depth,
            F::from_canonical_usize(self.private_inputs.actual_merkle_depth),
        )?;

        for i in 0..MAX_MERKLE_DEPTH {
            if i < self.private_inputs.actual_merkle_depth {
                pw.set_hash_target(
                    targets.merkle_siblings[i],
                    felts_to_hashout(&self.private_inputs.merkle_siblings[i]),
                )?;
                pw.set_bool_target(targets.path_indices[i], self.private_inputs.path_indices[i])?;
            } else {
                pw.set_hash_target(targets.merkle_siblings[i], felts_to_hashout(&ZERO_DIGEST))?;
                pw.set_bool_target(targets.path_indices[i], false)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod voting_tests {
    use super::*;
    use plonky2::{
        field::types::Field,
        hash::poseidon2::Poseidon2Hash,
        iop::witness::PartialWitness,
        plonk::{circuit_data::CircuitConfig, config::Hasher},
    };
    use zk_circuits_common::{
        circuit::C,
        utils::{digest_bytes_to_felts, BytesDigest},
    };

    fn compute_nullifier(private_key: &PrivateKey, proposal_id: &Digest) -> Digest {
        let pk_hash = Poseidon2Hash::hash_no_pad(private_key).elements;
        let mut input = [F::ZERO; 8];
        input[..4].copy_from_slice(&pk_hash);
        input[4..].copy_from_slice(proposal_id);
        Poseidon2Hash::hash_no_pad(&input).elements
    }

    fn create_test_inputs() -> VoteCircuitData {
        let private_keys_for_tree: [BytesDigest; 4] = [
            zk_circuits_common::utils::BytesDigest::try_from([1u8; 32]).unwrap(),
            zk_circuits_common::utils::BytesDigest::try_from([2u8; 32]).unwrap(),
            zk_circuits_common::utils::BytesDigest::try_from([3u8; 32]).unwrap(),
            zk_circuits_common::utils::BytesDigest::try_from([4u8; 32]).unwrap(),
        ];
        let leaves: Vec<Digest> = private_keys_for_tree
            .iter()
            .map(|bytes| Poseidon2Hash::hash_no_pad(&digest_bytes_to_felts(*bytes)).elements)
            .collect();

        // Build the Merkle tree level by level
        let mut current_level = leaves.clone();
        let mut merkle_tree = Vec::new();
        merkle_tree.push(current_level.clone());

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    let mut combined = [F::ZERO; 8];
                    combined[..4].copy_from_slice(&current_level[i]);
                    combined[4..].copy_from_slice(&current_level[i + 1]);
                    next_level.push(Poseidon2Hash::hash_no_pad(&combined).elements);
                } else {
                    next_level.push(current_level[i]);
                }
            }
            merkle_tree.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level[0];
        let voter_private_key: PrivateKey = digest_bytes_to_felts(private_keys_for_tree[0]);
        let merkle_siblings: Vec<Digest> = vec![leaves[1], merkle_tree[1][1]];
        let path_indices: Vec<bool> = vec![false, false];
        let actual_merkle_depth = 2;

        let digest_bytes = BytesDigest::try_from([42u8; 32]).unwrap();
        let proposal_id: Digest = digest_bytes_to_felts(digest_bytes);
        let vote = true;
        let nullifier = compute_nullifier(&voter_private_key, &proposal_id);

        let public_inputs = VotePublicInputs {
            proposal_id,
            merkle_root: root,
            vote,
            nullifier,
        };
        let private_inputs = VotePrivateInputs {
            private_key: voter_private_key,
            merkle_siblings,
            path_indices,
            actual_merkle_depth,
        };

        VoteCircuitData::new(public_inputs, private_inputs)
    }

    #[test]
    fn test_vote_circuit_end_to_end() -> anyhow::Result<()> {
        let vote_circuit_data = create_test_inputs();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets = VoteTargets::new(&mut builder);
        VoteCircuitData::circuit(&targets, &mut builder);
        let mut pw = PartialWitness::new();
        vote_circuit_data.fill_targets(&mut pw, targets.clone())?;

        let circuit_built_data = builder.build::<C>();
        let proof = circuit_built_data.prove(pw)?;
        circuit_built_data.verify(proof)?;
        Ok(())
    }

    #[test]
    fn test_invalid_merkle_depth() {
        let mut inputs = create_test_inputs();
        inputs.private_inputs.actual_merkle_depth = MAX_MERKLE_DEPTH + 1;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = VoteTargets::new(&mut builder);
        let result = inputs.fill_targets(&mut PartialWitness::new(), targets);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum allowed depth"));
    }

    #[test]
    fn test_merkle_proof_length_mismatch() {
        let mut inputs = create_test_inputs();
        inputs.private_inputs.path_indices.push(false); // Add extra path index
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = VoteTargets::new(&mut builder);
        let result = inputs.fill_targets(&mut PartialWitness::new(), targets);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length mismatch"));
    }

    #[test]
    fn test_invalid_merkle_proof() -> anyhow::Result<()> {
        let mut inputs = create_test_inputs();
        // Create an invalid proof by using a different actual_merkle_depth
        inputs.private_inputs.actual_merkle_depth = 1; // Should be 2 for our test tree
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets = VoteTargets::new(&mut builder);
        VoteCircuitData::circuit(&targets, &mut builder);
        let mut pw = PartialWitness::new();
        inputs.fill_targets(&mut pw, targets.clone())?;

        let circuit_built_data = builder.build::<C>();
        let proof_result = circuit_built_data.prove(pw);
        assert!(
            proof_result.is_err(),
            "Proof generation should have failed but it succeeded"
        );
        Ok(())
    }

    #[test]
    fn test_completely_invalid_proof() -> anyhow::Result<()> {
        let mut inputs = create_test_inputs();
        // Use completely random values that should make the proof invalid
        inputs.private_inputs.private_key = [F::from_canonical_u64(12345); 4];
        inputs.private_inputs.merkle_siblings = vec![
            [F::from_canonical_u64(67890); 4],
            [F::from_canonical_u64(11111); 4],
        ];
        inputs.private_inputs.path_indices = vec![true, true]; // Different path
        inputs.private_inputs.actual_merkle_depth = 2;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets = VoteTargets::new(&mut builder);
        VoteCircuitData::circuit(&targets, &mut builder);
        let mut pw = PartialWitness::new();
        inputs.fill_targets(&mut pw, targets.clone())?;

        let circuit_built_data = builder.build::<C>();
        let proof_result = circuit_built_data.prove(pw);

        assert!(
            proof_result.is_err(),
            "Proof generation should have failed but it succeeded"
        );
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_simple_fail() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let one = builder.one();
        let zero = builder.zero();
        builder.connect(one, zero);
        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        data.prove(pw).unwrap();
    }
}
