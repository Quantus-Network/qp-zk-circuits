//! Utility functions for the wormhole example.
use subxt::backend::legacy::rpc_methods::Bytes;
use wormhole_circuit::storage_proof::ProcessedStorageProof;

/// Hash a node preimage exactly as the blockchain does.
/// Uses qp_poseidon_core's hash_padded_bytes which pads to 189 felts.
fn hash_node_with_poseidon_padded(node_bytes: &[u8]) -> [u8; 32] {
    use qp_poseidon_core::{hash_padded_bytes, FIELD_ELEMENT_PREIMAGE_PADDING_LEN};
    hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(node_bytes)
}

// Function to check that the 24 byte suffix of the leaf hash is the last [-32, -8] bytes of the
// leaf node
pub fn check_leaf(leaf_hash: &[u8; 32], leaf_node: Vec<u8>) -> (bool, usize) {
    let hash_suffix = &leaf_hash[8..32];
    let mut last_idx = 0usize;
    let mut found = false;

    for i in 0..=leaf_node.len().saturating_sub(hash_suffix.len()) {
        if &leaf_node[i..i + hash_suffix.len()] == hash_suffix {
            last_idx = i;
            found = true;
            break;
        }
    }

    println!(
        "Checking leaf hash suffix: {:?} in leaf_node at index: {:?}",
        hex::encode(hash_suffix),
        last_idx
    );
    println!("leaf_node: {:?}", hex::encode(leaf_node.clone()));

    (found, (last_idx * 2).saturating_sub(16))
}

/// Prepares the storage proof for circuit consumption by ordering nodes from root to leaf.
///
/// The RPC returns an UNORDERED list of proof node preimages. We need to:
/// 1. Find which node, when hashed with Poseidon2, equals the state_root
/// 2. Build the path from root to leaf by finding parent-child relationships
pub fn prepare_proof_for_circuit(
    proof: Vec<Bytes>,
    state_root: String,
    leaf_hash: [u8; 32],
) -> anyhow::Result<ProcessedStorageProof> {
    println!("Total proof nodes: {}", proof.len());
    println!("State root: {}", state_root);

    // Create a map of hash -> (index, node_bytes, node_hex)
    // Hash each trie node with the blockchain's hash function (hash_padded_bytes)
    let mut node_map: std::collections::HashMap<String, (usize, Vec<u8>, String)> =
        std::collections::HashMap::new();
    for (idx, node) in proof.iter().enumerate() {
        let hash = hash_node_with_poseidon_padded(&node.0);
        let hash_hex = hex::encode(hash);
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
    let mut indices = Vec::<usize>::new();

    // Compute indices only for parent-child relationships (not for the last node)
    for i in 0..ordered_nodes.len() - 1 {
        let current_hex = hex::encode(&ordered_nodes[i]);
        let next_node = &ordered_nodes[i + 1];
        let next_hash = hex::encode(hash_node_with_poseidon_padded(next_node));

        if let Some(hex_idx) = current_hex.find(&next_hash) {
            let felt_idx = hex_idx;
            indices.push(felt_idx);
        } else {
            anyhow::bail!("Could not find child hash in ordered node {}", i);
        }
    }

    let (found, last_idx) = check_leaf(&leaf_hash, ordered_nodes.last().unwrap().clone());
    if !found {
        anyhow::bail!("Leaf hash suffix not found in leaf node!");
    }
    println!(
        "✓ Leaf hash suffix found in leaf node at byte index {}",
        last_idx
    );

    // Set the last index to the found leaf index
    indices.push(last_idx);
    println!(
        "Last node: using index {} (storage key verification done by circuit)",
        last_idx
    );

    println!("Indices: {:?}", indices);

    // Debug: Print detailed info about what we're passing to the circuit
    println!("\n=== STORAGE PROOF DEBUG ===");
    println!("Total proof nodes: {}", ordered_nodes.len());
    for (i, node) in ordered_nodes.iter().enumerate() {
        println!("  Node {}: {} bytes", i, node.len());
    }
    println!("Total indices: {}", indices.len());
    println!(
        "Indices match nodes-1? {}",
        indices.len() == ordered_nodes.len()
    );

    if indices.len() != ordered_nodes.len() {
        println!(
            "WARNING: indices.len() = {}, ordered_nodes.len() = {}",
            indices.len(),
            ordered_nodes.len()
        );
        println!("This will cause circuit failures!");
    }
    println!("========================\n");

    ProcessedStorageProof::new(ordered_nodes, indices)
}
