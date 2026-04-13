use std::fs;
use std::panic;

use hex;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::util::serialization::DefaultGateSerializer;
use qp_wormhole_inputs::PublicCircuitInputs;
use test_helpers::TestInputs;
use wormhole_circuit::inputs::{CircuitInputs, ParsePublicInputs};
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{wormhole_aggregator_circuit_config, C, D, F};
use zk_circuits_common::zk_merkle::{Hash256, ARITY, MAX_DEPTH, SIBLINGS_PER_LEVEL};

#[cfg(test)]
const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

#[test]
fn commit_and_prove() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    prover.commit(&inputs).unwrap().prove().unwrap();
}

#[test]
fn commit_rejects_zk_merkle_proof_exceeding_max_depth() {
    use zk_circuits_common::zk_merkle::SIBLINGS_PER_LEVEL;

    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let mut inputs = CircuitInputs::test_inputs_0();

    // Add siblings beyond the max depth (MAX_DEPTH = 16)
    let extra_siblings = [[0u8; 32]; SIBLINGS_PER_LEVEL];
    while inputs.private.zk_merkle_siblings.len() <= MAX_DEPTH {
        inputs.private.zk_merkle_siblings.push(extra_siblings);
    }

    let err = prover.commit(&inputs).unwrap_err();
    assert!(err.to_string().contains("ZK Merkle proof depth"));
}

#[test]
fn new_from_bytes_rejects_invalid_common_bytes_without_panicking() {
    let result = panic::catch_unwind(|| WormholeProver::new_from_bytes(b"bad-common", b"bad"));
    let err = result.expect("invalid bytes should not panic").unwrap_err();
    assert!(err
        .to_string()
        .contains("failed to deserialize common circuit data from bytes"));
}

#[test]
fn new_from_bytes_rejects_invalid_prover_bytes_without_panicking() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let gate_serializer = DefaultGateSerializer;
    let common_bytes = prover
        .circuit_data
        .common
        .to_bytes(&gate_serializer)
        .unwrap();

    let result =
        panic::catch_unwind(|| WormholeProver::new_from_bytes(b"bad-prover", &common_bytes));
    let err = result.expect("invalid bytes should not panic").unwrap_err();
    assert!(err
        .to_string()
        .contains("failed to deserialize prover-only data from bytes"));
}

#[test]
fn new_from_bytes_rejects_non_wormhole_circuit_data() {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = plonky2::util::serialization::DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let mut builder = CircuitBuilder::<F, D>::new(CIRCUIT_CONFIG);
    let _pi = builder.add_virtual_public_input();
    let data = builder.build::<C>();

    let common_bytes = data.common.to_bytes(&gate_serializer).unwrap();
    let prover_bytes = data
        .prover_only
        .to_bytes(&generator_serializer, &data.common)
        .unwrap();

    let err = WormholeProver::new_from_bytes(&prover_bytes, &common_bytes).unwrap_err();
    assert!(err
        .to_string()
        .contains("does not match the canonical Wormhole circuit"));
}

#[test]
fn proof_can_be_deserialized() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let public_inputs = PublicCircuitInputs::try_from_proof(&proof).unwrap();

    // Build expected values from the canonical test fixtures.
    let expected = inputs.public;
    assert_eq!(public_inputs, expected);
    println!("{:?}", public_inputs);
}

#[test]
fn get_public_inputs() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let public_inputs = proof.public_inputs;
    println!("{:?}", public_inputs);
}

#[test]
#[ignore = "debug"]
fn export_test_proof() {
    const FILE_PATH: &str = "../../dummy_proof.bin";

    let circuit_config = CircuitConfig::standard_recursion_config();

    let prover = WormholeProver::new(circuit_config);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let proof_bytes = proof.to_bytes();
    let _ = fs::write(FILE_PATH, proof_bytes);
}

#[test]
#[ignore = "debug"]
fn export_test_proof_zk() {
    const FILE_PATH: &str = "../../dummy_proof_zk.bin";

    let circuit_config = wormhole_aggregator_circuit_config();

    let prover = WormholeProver::new(circuit_config);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let proof_bytes = proof.to_bytes();
    let _ = fs::write(FILE_PATH, proof_bytes);
}

#[test]
#[ignore = "debug"]
fn export_hex_proof_for_pallet() {
    const FILE_PATH: &str = "proof.hex";

    let circuit_config = CircuitConfig::standard_recursion_config();

    let prover = WormholeProver::new(circuit_config);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let proof_bytes = proof.to_bytes();
    let hex_proof = hex::encode(proof_bytes);
    let _ = fs::write(FILE_PATH, hex_proof);
}

#[test]
#[ignore = "debug"]
fn export_hex_proof_from_bins_for_pallet() {
    const FILE_PATH: &str = "proof_from_bins.hex";

    // Use the pre-generated bin files to ensure compatibility with the verifier
    let prover = WormholeProver::new_from_files(
        std::path::Path::new("../../generated-bins/prover.bin"),
        std::path::Path::new("../../generated-bins/common.bin"),
    )
    .expect("Failed to load prover from bin files");

    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let proof_bytes = proof.to_bytes();
    let proof_size = proof_bytes.len();
    let hex_proof = hex::encode(proof_bytes);
    let _ = fs::write(FILE_PATH, hex_proof);

    println!("Generated proof hex file: {}", FILE_PATH);
    println!("Proof size: {} bytes", proof_size);
}

// ============================================================================
// Random tree tests for ZK Merkle proof verification
// ============================================================================

/// Build a 4-ary Merkle tree from leaf hashes and return the root.
/// Also returns the tree structure for proof generation.
fn build_4ary_tree(leaves: &[Hash256]) -> (Hash256, Vec<Vec<Hash256>>) {
    use zk_circuits_common::zk_merkle::hash_node;

    if leaves.is_empty() {
        return ([0u8; 32], vec![]);
    }

    let mut levels: Vec<Vec<Hash256>> = vec![leaves.to_vec()];

    // Build tree bottom-up
    while levels.last().unwrap().len() > 1 {
        let current_level = levels.last().unwrap();
        let mut next_level = Vec::new();

        // Process in chunks of 4, padding with zeros if needed
        for chunk in current_level.chunks(ARITY) {
            let mut children: [Hash256; ARITY] = [[0u8; 32]; ARITY];
            for (i, child) in chunk.iter().enumerate() {
                children[i] = *child;
            }
            // hash_node sorts children internally before hashing
            next_level.push(hash_node(&children));
        }

        levels.push(next_level);
    }

    let root = levels.last().unwrap()[0];
    (root, levels)
}

/// Generate a Merkle proof for a leaf at the given index.
/// Returns (siblings, positions) where siblings are in sorted order
/// and positions indicate where to insert current hash.
fn generate_proof(
    leaf_index: usize,
    levels: &[Vec<Hash256>],
) -> (Vec<[Hash256; SIBLINGS_PER_LEVEL]>, Vec<u8>) {
    let mut siblings = Vec::new();
    let mut positions = Vec::new();
    let mut current_index = leaf_index;

    // Walk up the tree (skip the root level)
    for level in levels.iter().take(levels.len() - 1) {
        // Which group of 4 does this node belong to?
        let group_start = (current_index / ARITY) * ARITY;
        let position_in_group = current_index % ARITY;

        // Collect the 4 children in this group
        let mut children: [Hash256; ARITY] = [[0u8; 32]; ARITY];
        for (i, child) in children.iter_mut().enumerate() {
            let idx = group_start + i;
            if idx < level.len() {
                *child = level[idx];
            }
        }

        // Sort children to match hash_node behavior
        let current_hash = children[position_in_group];
        children.sort();

        // Find where current_hash ended up after sorting
        let sorted_position = children.iter().position(|h| *h == current_hash).unwrap() as u8;

        // Extract the 3 siblings (excluding current_hash)
        let mut level_siblings: [Hash256; SIBLINGS_PER_LEVEL] = [[0u8; 32]; SIBLINGS_PER_LEVEL];
        let mut sib_idx = 0;
        for (i, child) in children.iter().enumerate() {
            if i as u8 != sorted_position {
                level_siblings[sib_idx] = *child;
                sib_idx += 1;
            }
        }

        siblings.push(level_siblings);
        positions.push(sorted_position);

        // Move to parent index
        current_index /= ARITY;
    }

    (siblings, positions)
}

/// Verify a proof matches the expected root using the same logic as the circuit.
fn verify_proof_native(
    leaf_hash: Hash256,
    siblings: &[[Hash256; SIBLINGS_PER_LEVEL]],
    positions: &[u8],
    expected_root: Hash256,
) -> bool {
    use zk_circuits_common::zk_merkle::{hash_node_presorted, insert_at_position};

    let mut current_hash = leaf_hash;

    for (level_siblings, &position) in siblings.iter().zip(positions.iter()) {
        let sorted_children = insert_at_position(current_hash, level_siblings, position);
        current_hash = hash_node_presorted(&sorted_children);
    }

    current_hash == expected_root
}

#[test]
fn test_random_tree_proof_native_verification() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    // Use a seeded RNG for reproducibility
    let mut rng = StdRng::seed_from_u64(12345);

    // Generate 16 random leaf hashes (creates a depth-2 tree: 16 leaves -> 4 nodes -> 1 root)
    let num_leaves = 16;
    let leaves: Vec<Hash256> = (0..num_leaves)
        .map(|_| {
            let mut hash = [0u8; 32];
            rng.fill(&mut hash);
            hash
        })
        .collect();

    // Build the tree
    let (root, levels) = build_4ary_tree(&leaves);
    println!(
        "Built tree with {} leaves, {} levels",
        num_leaves,
        levels.len()
    );
    println!("Root: {}", hex::encode(root));

    // Test proof for each leaf
    for (leaf_index, &leaf_hash) in leaves.iter().enumerate().take(num_leaves) {
        let (siblings, positions) = generate_proof(leaf_index, &levels);

        // Verify natively
        let valid = verify_proof_native(leaf_hash, &siblings, &positions, root);
        assert!(
            valid,
            "Native verification failed for leaf {} (depth {})",
            leaf_index,
            siblings.len()
        );

        println!(
            "Leaf {}: hash={}, positions={:?}, verified={}",
            leaf_index,
            &hex::encode(leaf_hash)[..16],
            positions,
            valid
        );
    }
}

#[test]
fn test_random_tree_circuit_verification() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use test_helpers::block_header::{
        DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_STATE_ROOTS,
    };
    use test_helpers::compute_zk_leaf_hash;
    use wormhole_circuit::inputs::PrivateCircuitInputs;
    use wormhole_circuit::nullifier::Nullifier;
    use wormhole_circuit::unspendable_account::UnspendableAccount;
    use zk_circuits_common::utils::digest_to_bytes;
    use zk_circuits_common::utils::BytesDigest;

    let mut rng = StdRng::seed_from_u64(42);

    // Generate random secrets and create corresponding leaf hashes
    let num_leaves = 4; // Depth-1 tree for faster testing
    let mut secrets: Vec<[u8; 32]> = Vec::new();
    let mut leaf_hashes: Vec<Hash256> = Vec::new();
    let transfer_count = 1u64;
    let asset_id = 0u32;
    let input_amount = 100u32;

    for _ in 0..num_leaves {
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        secrets.push(secret);

        // Compute the unspendable account from the secret
        let secret_digest = BytesDigest::try_from(secret).unwrap();
        let unspendable_account =
            digest_to_bytes(UnspendableAccount::from_secret(secret_digest).account_id);

        // Compute leaf hash the same way the circuit does
        let leaf_hash =
            compute_zk_leaf_hash(&unspendable_account, transfer_count, asset_id, input_amount);
        leaf_hashes.push(leaf_hash);
    }

    // Build the tree
    let (root, levels) = build_4ary_tree(&leaf_hashes);
    println!(
        "Built tree with {} leaves, root: {}",
        num_leaves,
        hex::encode(root)
    );

    // Pick a random leaf to prove
    let leaf_index = rng.random_range(0..num_leaves);
    let (siblings, positions) = generate_proof(leaf_index, &levels);

    println!(
        "Testing circuit verification for leaf {} with depth {}",
        leaf_index,
        siblings.len()
    );

    // Verify natively first
    assert!(
        verify_proof_native(leaf_hashes[leaf_index], &siblings, &positions, root),
        "Native verification failed"
    );

    // Build circuit inputs
    let secret = secrets[leaf_index];
    let secret_digest = BytesDigest::try_from(secret).unwrap();
    let unspendable_account =
        digest_to_bytes(UnspendableAccount::from_secret(secret_digest).account_id);
    let nullifier = digest_to_bytes(Nullifier::from_preimage(secret_digest, transfer_count).hash);
    let exit_account = BytesDigest::try_from([4u8; 32]).unwrap();

    let inputs = CircuitInputs {
        public: PublicCircuitInputs {
            asset_id,
            // Use dummy mode (block_hash=0, outputs=0) to skip block header validation
            output_amount_1: 0u32,
            output_amount_2: 0u32,
            volume_fee_bps: 10,
            nullifier,
            exit_account_1: exit_account,
            exit_account_2: BytesDigest::default(),
            block_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
            block_number: DEFAULT_BLOCK_NUMBERS[0],
        },
        private: PrivateCircuitInputs {
            secret: secret_digest,
            transfer_count,
            unspendable_account,
            parent_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
            state_root: BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
            extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
            digest: DEFAULT_DIGESTS[0],
            input_amount,
            zk_tree_root: root,
            zk_merkle_siblings: siblings,
            zk_merkle_positions: positions,
        },
    };

    // Run the circuit prover
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let result = prover.commit(&inputs);
    assert!(result.is_ok(), "Commit failed: {:?}", result.err());

    let proof_result = result.unwrap().prove();
    assert!(
        proof_result.is_ok(),
        "Prove failed: {:?}",
        proof_result.err()
    );

    println!("Circuit verification succeeded for random tree proof!");
}

#[test]
fn test_depth_2_tree_circuit_verification() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use test_helpers::block_header::{
        DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_STATE_ROOTS,
    };
    use test_helpers::compute_zk_leaf_hash;
    use wormhole_circuit::inputs::PrivateCircuitInputs;
    use wormhole_circuit::nullifier::Nullifier;
    use wormhole_circuit::unspendable_account::UnspendableAccount;
    use zk_circuits_common::utils::digest_to_bytes;
    use zk_circuits_common::utils::BytesDigest;

    let mut rng = StdRng::seed_from_u64(999);

    // Generate 16 leaves for a depth-2 tree
    let num_leaves = 16;
    let mut secrets: Vec<[u8; 32]> = Vec::new();
    let mut leaf_hashes: Vec<Hash256> = Vec::new();
    let transfer_count = 5u64;
    let asset_id = 0u32;
    let input_amount = 250u32;

    for _ in 0..num_leaves {
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        secrets.push(secret);

        let secret_digest = BytesDigest::try_from(secret).unwrap();
        let unspendable_account =
            digest_to_bytes(UnspendableAccount::from_secret(secret_digest).account_id);
        let leaf_hash =
            compute_zk_leaf_hash(&unspendable_account, transfer_count, asset_id, input_amount);
        leaf_hashes.push(leaf_hash);
    }

    let (root, levels) = build_4ary_tree(&leaf_hashes);
    println!(
        "Built depth-2 tree with {} leaves, {} levels",
        num_leaves,
        levels.len()
    );

    // Test a leaf from each quarter of the tree
    for &leaf_index in &[0, 5, 10, 15] {
        let (siblings, positions) = generate_proof(leaf_index, &levels);

        println!(
            "Testing leaf {} at depth {}, positions: {:?}",
            leaf_index,
            siblings.len(),
            positions
        );

        // Build circuit inputs
        let secret = secrets[leaf_index];
        let secret_digest = BytesDigest::try_from(secret).unwrap();
        let unspendable_account =
            digest_to_bytes(UnspendableAccount::from_secret(secret_digest).account_id);
        let nullifier =
            digest_to_bytes(Nullifier::from_preimage(secret_digest, transfer_count).hash);
        let exit_account = BytesDigest::try_from([4u8; 32]).unwrap();

        let inputs = CircuitInputs {
            public: PublicCircuitInputs {
                asset_id,
                output_amount_1: 0u32,
                output_amount_2: 0u32,
                volume_fee_bps: 10,
                nullifier,
                exit_account_1: exit_account,
                exit_account_2: BytesDigest::default(),
                block_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                block_number: DEFAULT_BLOCK_NUMBERS[0],
            },
            private: PrivateCircuitInputs {
                secret: secret_digest,
                transfer_count,
                unspendable_account,
                parent_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                state_root: BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
                extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
                digest: DEFAULT_DIGESTS[0],
                input_amount,
                zk_tree_root: root,
                zk_merkle_siblings: siblings,
                zk_merkle_positions: positions,
            },
        };

        let prover = WormholeProver::new(CIRCUIT_CONFIG);
        let _proof = prover.commit(&inputs).unwrap().prove().unwrap();
        println!("Leaf {} verified successfully!", leaf_index);
    }

    println!("All depth-2 tree proofs verified!");
}

#[test]
fn test_depth_3_tree_circuit_verification() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use test_helpers::block_header::{
        DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_STATE_ROOTS,
    };
    use test_helpers::compute_zk_leaf_hash;
    use wormhole_circuit::inputs::PrivateCircuitInputs;
    use wormhole_circuit::nullifier::Nullifier;
    use wormhole_circuit::unspendable_account::UnspendableAccount;
    use zk_circuits_common::utils::digest_to_bytes;
    use zk_circuits_common::utils::BytesDigest;

    let mut rng = StdRng::seed_from_u64(7777);

    // Generate 64 leaves for a depth-3 tree (64 = 4^3)
    let num_leaves = 64;
    let mut secrets: Vec<[u8; 32]> = Vec::new();
    let mut leaf_hashes: Vec<Hash256> = Vec::new();
    let transfer_count = 42u64;
    let asset_id = 0u32;
    let input_amount = 500u32;

    for _ in 0..num_leaves {
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        secrets.push(secret);

        let secret_digest = BytesDigest::try_from(secret).unwrap();
        let unspendable_account =
            digest_to_bytes(UnspendableAccount::from_secret(secret_digest).account_id);
        let leaf_hash =
            compute_zk_leaf_hash(&unspendable_account, transfer_count, asset_id, input_amount);
        leaf_hashes.push(leaf_hash);
    }

    let (root, levels) = build_4ary_tree(&leaf_hashes);
    println!(
        "Built depth-3 tree with {} leaves, {} levels",
        num_leaves,
        levels.len()
    );
    println!("Root: {}", hex::encode(root));

    // Test leaves from different parts of the tree
    // Pick indices that cover different branches at each level
    let test_indices = [0, 7, 16, 31, 32, 47, 48, 63];

    for &leaf_index in &test_indices {
        let (siblings, positions) = generate_proof(leaf_index, &levels);

        assert_eq!(
            siblings.len(),
            3,
            "Expected depth 3 for leaf {}",
            leaf_index
        );

        println!(
            "Testing leaf {} at depth {}, positions: {:?}",
            leaf_index,
            siblings.len(),
            positions
        );

        // Verify natively first
        assert!(
            verify_proof_native(leaf_hashes[leaf_index], &siblings, &positions, root),
            "Native verification failed for leaf {}",
            leaf_index
        );

        // Build circuit inputs
        let secret = secrets[leaf_index];
        let secret_digest = BytesDigest::try_from(secret).unwrap();
        let unspendable_account =
            digest_to_bytes(UnspendableAccount::from_secret(secret_digest).account_id);
        let nullifier =
            digest_to_bytes(Nullifier::from_preimage(secret_digest, transfer_count).hash);
        let exit_account = BytesDigest::try_from([4u8; 32]).unwrap();

        let inputs = CircuitInputs {
            public: PublicCircuitInputs {
                asset_id,
                output_amount_1: 0u32,
                output_amount_2: 0u32,
                volume_fee_bps: 10,
                nullifier,
                exit_account_1: exit_account,
                exit_account_2: BytesDigest::default(),
                block_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                block_number: DEFAULT_BLOCK_NUMBERS[0],
            },
            private: PrivateCircuitInputs {
                secret: secret_digest,
                transfer_count,
                unspendable_account,
                parent_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                state_root: BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
                extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
                digest: DEFAULT_DIGESTS[0],
                input_amount,
                zk_tree_root: root,
                zk_merkle_siblings: siblings,
                zk_merkle_positions: positions,
            },
        };

        let prover = WormholeProver::new(CIRCUIT_CONFIG);
        let _proof = prover.commit(&inputs).unwrap().prove().unwrap();
        println!("Leaf {} verified successfully!", leaf_index);
    }

    println!("All depth-3 tree proofs verified!");
}
