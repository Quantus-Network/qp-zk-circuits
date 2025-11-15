//! Utility functions for the wormhole example.
use subxt::backend::legacy::rpc_methods::Bytes;
use wormhole_circuit::storage_proof::ProcessedStorageProof;

/// Hash a node preimage exactly as the blockchain does.
/// Uses qp_poseidon_core's hash_padded_bytes which pads to 189 felts.
fn hash_node_with_poseidon_padded(node_bytes: &[u8]) -> [u8; 32] {
    use qp_poseidon_core::{hash_padded_bytes, FIELD_ELEMENT_PREIMAGE_PADDING_LEN};
    hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(node_bytes)
}

/// DEBUG: Test the hashing logic with known test data
#[allow(dead_code)]
fn test_hash_verification() {
    let proof_node_0_hex = "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000545576a55a3f69e109b776d252064d3c9bf2fd3a0cd0447c8d82ec12b0343f3a20000000000000000f3ed746dd90e0e2a0d3f8faf0b8a41d5fafd9edcbc88630e389f2db76dd44b7200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000e6f538f42cbc6e72d6a302a648da34c475bcfa104e7cb80625fcf3219bd12172200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb2000000000000000d549afac7285d8e774c1ae9fc95e7348bf41355780363b8fae5f9419d102ac862000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000003687179c5ce1cb12b50e50d421bcbdceb82ec583de7585fb7898e167108168b5";
    let expected_root_hash = "24d6a3e3877cf86a5e17a32e3f269b70963fbaf4b050e04911cf11afa3b48350";

    let proof_node_0_bytes = hex::decode(proof_node_0_hex).unwrap();

    // Test: Hash with qp_poseidon_core's hash_padded_bytes (blockchain's hash function)
    let computed_hash = hash_node_with_poseidon_padded(&proof_node_0_bytes);
    let computed_hash_hex = hex::encode(computed_hash);

    println!("\n=== HASH VERIFICATION TEST ===");
    println!("Expected root hash:  {}", expected_root_hash);
    println!("Computed hash:       {}", computed_hash_hex);
    println!("Match: {}", computed_hash_hex == expected_root_hash);
    println!("=============================\n");
}

/// Prepares the storage proof for circuit consumption by ordering nodes from root to leaf.
///
/// The RPC returns an UNORDERED list of proof node preimages. We need to:
/// 1. Find which node, when hashed with Poseidon2, equals the state_root
/// 2. Build the path from root to leaf by finding parent-child relationships
pub fn prepare_proof_for_circuit(
    proof: Vec<Bytes>,
    state_root: String,
) -> anyhow::Result<ProcessedStorageProof> {
    // DEBUG: Test hashing with known data
    test_hash_verification();

    println!("Total proof nodes: {}", proof.len());
    println!("State root: {}", state_root);

    // Create a map of hash -> (index, node_bytes, node_hex)
    // Hash each trie node with the blockchain's hash function (hash_padded_bytes)
    let mut node_map: std::collections::HashMap<String, (usize, Vec<u8>, String)> =
        std::collections::HashMap::new();
    for (idx, node) in proof.iter().enumerate() {
        let hash = hash_node_with_poseidon_padded(&node.0);
        let hash_hex = hex::encode(&hash);
        let node_hex = hex::encode(&node.0);
        println!("Node {}: hash = {}", idx, &hash_hex);
        node_map.insert(hash_hex.clone(), (idx, node.0.clone(), node_hex));
    }

    // Find which node hashes to the state root
    let state_root_hex = state_root.trim_start_matches("0x").to_string();
    println!(
        "\nSearching for node that hashes to state root: {}",
        state_root_hex
    );

    // Check if any node's hash equals the state root
    let root_hash = if node_map.contains_key(&state_root_hex) {
        println!("✓ Found node that hashes to state root!");
        state_root_hex.clone()
    } else {
        anyhow::bail!(
            "No node hashes to state root!\nState root: {}\nNode hashes: {:?}",
            state_root_hex,
            node_map.keys().collect::<Vec<_>>()
        );
    };

    let root_entry = node_map
        .get(&root_hash)
        .ok_or_else(|| anyhow::anyhow!("Failed to get root entry from map"))?;

    let mut ordered_nodes = vec![root_entry.1.clone()];
    let mut current_node_hex = root_entry.2.clone();

    println!(
        "Root node index: {}, first 200 chars: {}",
        root_entry.0,
        &current_node_hex[..200.min(current_node_hex.len())]
    );
    println!("\nDEBUG: Full root node:");
    println!("{}", current_node_hex);
    println!("\nDEBUG: Searching for child hashes in root node:");
    for (hash, (idx, _, _)) in &node_map {
        if current_node_hex.contains(hash) {
            println!("  ✓ Node {} hash FOUND in root", idx);
        }
    }

    // Build the path from root to leaf by finding which child hash appears in current node
    // NOTE: In ZK-trie, child hashes are stored with an 8-byte length prefix:
    // [8-byte length (0x20 = 32 in little-endian)] + [32-byte hash]
    const HASH_LENGTH_PREFIX: &str = "2000000000000000"; // 32 as little-endian u64

    loop {
        println!(
            "\nCurrent node (first 200 chars): {}",
            &current_node_hex[..200.min(current_node_hex.len())]
        );

        // Try to find which node's hash appears in the current node
        // Child hashes are prefixed with their length (32 bytes = 0x2000000000000000 in little-endian)
        let mut found_child = None;
        for (child_hash, (idx, child_bytes, _)) in &node_map {
            let hash_with_prefix = format!("{}{}", HASH_LENGTH_PREFIX, child_hash);
            if current_node_hex.contains(&hash_with_prefix) {
                // Make sure we haven't already added this node
                if !ordered_nodes.iter().any(|n| n == child_bytes) {
                    found_child = Some((child_hash.clone(), child_bytes.clone()));
                    println!(
                        "Found child node {} in current node (with length prefix)",
                        idx
                    );
                    break;
                }
            }
        }

        if let Some((_, child_bytes)) = found_child {
            ordered_nodes.push(child_bytes.clone());
            current_node_hex = hex::encode(ordered_nodes.last().unwrap());
        } else {
            // No more children found - we've reached the end of the proof path
            println!("No more child nodes found - reached end of proof path");
            break;
        }
    }

    println!(
        "Ordered {} nodes from root to leaf parent",
        ordered_nodes.len()
    );

    // Now compute the indices - where child hashes appear within parent nodes
    const INJECTIVE_BYTES_LIMB: usize = 4;
    let mut indices = Vec::<usize>::new();

    // Compute indices only for parent-child relationships (not for the last node)
    for i in 0..ordered_nodes.len() - 1 {
        let current_hex = hex::encode(&ordered_nodes[i]);
        let next_node = &ordered_nodes[i + 1];
        let next_hash = hex::encode(hash_node_with_poseidon_padded(next_node));

        if let Some(hex_idx) = current_hex.find(&next_hash) {
            let felt_idx = hex_idx / (INJECTIVE_BYTES_LIMB * 2);
            indices.push(felt_idx);
        } else {
            anyhow::bail!("Could not find child hash in ordered node {}", i);
        }
    }

    // For the last node, use index 0 as placeholder (circuit will verify the actual storage key)
    indices.push(0);
    println!("Last node: using index 0 (storage key verification done by circuit)");

    println!("Indices: {:?}", indices);

    ProcessedStorageProof::new(ordered_nodes, indices)
}
