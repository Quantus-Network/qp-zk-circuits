//! Storage proof utilities for processing blockchain storage proofs.
//!
//! This module provides utilities for:
//! - Converting unordered RPC proof nodes into circuit-ready ordered proofs
//! - Verifying leaf node placement in storage proofs
//! - Computing indices for parent-child relationships in trie structures

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::bail;

/// A storage proof along with an array of indices where the hash child nodes are placed.
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

/// Hash a node preimage exactly as the blockchain does.
/// Uses qp_poseidon_core's hash_padded_bytes which pads to 189 felts.
pub fn hash_node_with_poseidon_padded(node_bytes: &[u8]) -> [u8; 32] {
    use qp_poseidon_core::{hash_padded_bytes, FIELD_ELEMENT_PREIMAGE_PADDING_LEN};
    hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(node_bytes)
}

/// Check that the 24 byte suffix of the leaf hash is in the leaf node.
///
/// Returns a tuple of (found: bool, byte_index: usize) where byte_index is
/// the hex character index (multiplied by 2 and adjusted by -16).
pub fn check_leaf(leaf_hash: &[u8; 32], leaf_node: &[u8]) -> (bool, usize) {
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

    (found, (last_idx * 2).saturating_sub(16))
}

/// Prepares the storage proof for circuit consumption by ordering nodes from root to leaf.
///
/// The RPC returns an UNORDERED list of proof node preimages. We need to:
/// 1. Find which node, when hashed with Poseidon2, equals the state_root
/// 2. Build the path from root to leaf by finding parent-child relationships
/// 3. Compute indices where child hashes appear in parent nodes
/// 4. Verify the leaf hash suffix appears in the leaf node
///
/// # Arguments
/// * `proof` - Unordered list of proof node bytes
/// * `state_root` - The state root hash (with or without 0x prefix)
/// * `leaf_hash` - The hash of the leaf data
///
/// # Returns
/// A `ProcessedStorageProof` with ordered nodes and corresponding indices
pub fn prepare_proof_for_circuit<T: AsRef<[u8]>>(
    proof: Vec<T>,
    state_root: String,
    leaf_hash: [u8; 32],
) -> anyhow::Result<ProcessedStorageProof> {
    // Create a map of hash -> (index, node_bytes, node_hex)
    // Hash each trie node with the blockchain's hash function (hash_padded_bytes)
    let mut node_map: alloc::collections::BTreeMap<String, (usize, Vec<u8>, String)> =
        alloc::collections::BTreeMap::new();

    for (idx, node) in proof.iter().enumerate() {
        let node_bytes = node.as_ref();
        let hash = hash_node_with_poseidon_padded(node_bytes);
        let hash_hex = hex::encode(hash);
        let node_hex = hex::encode(node_bytes);
        node_map.insert(hash_hex.clone(), (idx, node_bytes.to_vec(), node_hex));
    }

    // Find which node hashes to the state root
    let state_root_hex = state_root.trim_start_matches("0x").to_string();

    // Check if any node's hash equals the state root
    let root_hash = if node_map.contains_key(&state_root_hex) {
        state_root_hex.clone()
    } else {
        bail!("No node hashes to state root!");
    };

    let root_entry = node_map
        .get(&root_hash)
        .ok_or_else(|| anyhow::anyhow!("Failed to get root entry from map"))?;

    let mut ordered_nodes = vec![root_entry.1.clone()];
    let mut current_node_hex = root_entry.2.clone();

    // Build the path from root to leaf by finding which child hash appears in current node
    // NOTE: In ZK-trie, child hashes are stored with an 8-byte length prefix:
    // [8-byte length (0x20 = 32 in little-endian)] + [32-byte hash]
    const HASH_LENGTH_PREFIX: &str = "2000000000000000"; // 32 as little-endian u64

    loop {
        // Try to find which node's hash appears in the current node
        // Child hashes are prefixed with their length (32 bytes = 0x2000000000000000 in little-endian)
        let mut found_child = None;
        for (child_hash, (_, child_bytes, _)) in &node_map {
            let hash_with_prefix = format!("{}{}", HASH_LENGTH_PREFIX, child_hash);
            if current_node_hex.contains(&hash_with_prefix) {
                // Make sure we haven't already added this node
                if !ordered_nodes.iter().any(|n| n == child_bytes) {
                    found_child = Some(child_bytes.clone());
                    break;
                }
            }
        }

        if let Some(child_bytes) = found_child {
            ordered_nodes.push(child_bytes.clone());
            current_node_hex = hex::encode(ordered_nodes.last().unwrap());
        } else {
            // No more children found - we've reached the end of the proof path
            break;
        }
    }

    // Now compute the indices - where child hashes appear within parent nodes
    let mut indices = Vec::<usize>::new();

    // Compute indices only for parent-child relationships (not for the last node)
    for i in 0..ordered_nodes.len() - 1 {
        let current_hex = hex::encode(&ordered_nodes[i]);
        let next_node = &ordered_nodes[i + 1];
        let next_hash = hex::encode(hash_node_with_poseidon_padded(next_node));

        if let Some(hex_idx) = current_hex.find(&next_hash) {
            indices.push(hex_idx);
        } else {
            bail!("Could not find child hash in ordered node {}", i);
        }
    }

    let (found, last_idx) = check_leaf(&leaf_hash, ordered_nodes.last().unwrap());
    if !found {
        bail!("Leaf hash suffix not found in leaf node!");
    }

    // Set the last index to the found leaf index
    indices.push(last_idx);

    if indices.len() != ordered_nodes.len() {
        bail!(
            "Indices length mismatch: indices.len() = {}, ordered_nodes.len() = {}",
            indices.len(),
            ordered_nodes.len()
        );
    }

    ProcessedStorageProof::new(ordered_nodes, indices)
}
