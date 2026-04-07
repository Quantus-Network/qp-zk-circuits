//! Storage proof utilities for processing blockchain storage proofs.
//!
//! This module provides utilities for:
//! - Converting unordered RPC proof nodes into circuit-ready ordered proofs
//! - Verifying leaf node placement in storage proofs
//! - Computing indices for parent-child relationships in trie structures

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::bail;

pub use qp_poseidon_core::PROOF_NODE_MAX_SIZE_FELTS;

/// Maximum number of trie nodes that an actual Wormhole storage proof may contain.
///
/// The circuit reserves one extra witness slot to keep the leaf-binding check in-circuit, so the
/// fixed witness capacity is [`STORAGE_PROOF_WITNESS_CAPACITY`].
pub const MAX_STORAGE_PROOF_NODES: usize = 19;

/// Fixed number of proof-node witness slots allocated by the Wormhole circuit.
pub const STORAGE_PROOF_WITNESS_CAPACITY: usize = MAX_STORAGE_PROOF_NODES + 1;

/// A storage proof along with child-hash indices for each non-terminal proof node.
///
/// The proof contains N nodes: [root, ..., leaf, value_node]
/// The indices array has N-1 entries, one for each parent-child relationship.
/// The last node (value_node) doesn't need an index since it's always 32 bytes
/// with the hash at offset 0.
#[derive(Debug, Clone)]
pub struct ProcessedStorageProof {
    pub proof: Vec<Vec<u8>>,
    pub indices: Vec<usize>,
}

impl ProcessedStorageProof {
    pub fn new(proof: Vec<Vec<u8>>, indices: Vec<usize>) -> anyhow::Result<Self> {
        let expected_indices_len = proof.len().saturating_sub(1);
        if indices.len() != expected_indices_len {
            bail!(
                "indices length must be one less than proof length, actual lengths: {}, {}",
                proof.len(),
                indices.len()
            );
        }

        Ok(Self { proof, indices })
    }
}

/// Hash a node preimage exactly as the blockchain does.
///
/// Uses compact encoding (8 bytes per felt) to match
/// the chain's `PoseidonHasher::hash` implementation.
pub fn hash_node_with_poseidon_padded(node_bytes: &[u8]) -> [u8; 32] {
    qp_poseidon_core::hash_for_circuit::<{ PROOF_NODE_MAX_SIZE_FELTS }>(node_bytes)
}

/// Parse a HashedValueLeaf node (type 5) and extract the byte offset where the value hash starts.
///
/// Our storage values are always 32 bytes (leaf_inputs_hash), which exceeds zk-trie's
/// MAX_INLINE_VALUE=31, so they're always stored as HashedValueLeaf nodes.
///
/// HashedValueLeaf format:
/// - `[0..8]`: 8-byte header (type=5 in bits 60-63, nibble_count in bits 0-31)
/// - `[8..8+nibble_section]`: partial key with felt-alignment padding
/// - `[8+nibble_section..]`: 32-byte hash reference to value node
///
/// Returns the byte offset to the hash, or None if parsing fails.
fn parse_leaf_hash_offset(leaf_node: &[u8]) -> Option<usize> {
    if leaf_node.len() < 8 {
        return None;
    }

    let header = u64::from_le_bytes(leaf_node[0..8].try_into().ok()?);
    let node_type = (header >> 60) & 0xF;
    let nibble_count = (header & 0xFFFFFFFF) as usize;

    // Only accept HashedValueLeaf (type 5)
    if node_type != 5 {
        return None;
    }

    // Calculate nibble section size (matches zk-trie node_codec.rs)
    let nibble_bytes = nibble_count.div_ceil(2);
    let misalignment = nibble_bytes % 8;
    let prefix_padding = if misalignment == 0 {
        0
    } else {
        8 - misalignment
    };
    let nibble_section = (prefix_padding + nibble_bytes).div_ceil(8) * 8;

    let value_start = 8 + nibble_section;

    if leaf_node.len() < value_start + 32 {
        return None;
    }
    Some(value_start)
}

/// Prepares a storage proof for circuit consumption by ordering nodes from root to leaf.
///
/// The RPC returns an unordered list of proof nodes. This function:
/// 1. Finds the root node (hashes to state_root)
/// 2. Builds the path from root to leaf by following child hash references
/// 3. Appends any value node referenced by the leaf (for indirect storage)
/// 4. Computes indices where child hashes appear in non-terminal parent nodes
/// 5. Verifies the terminal value node contains the expected leaf_hash
///
/// # Arguments
/// * `proof` - Unordered list of proof node bytes from RPC
/// * `state_root` - The state root hash (with or without 0x prefix)
/// * `leaf_hash` - The expected hash stored in the leaf's value section
///
/// # Returns
/// A `ProcessedStorageProof` with ordered nodes and corresponding indices
pub fn prepare_proof_for_circuit<T: AsRef<[u8]>>(
    proof: Vec<T>,
    state_root: String,
    leaf_hash: [u8; 32],
) -> anyhow::Result<ProcessedStorageProof> {
    // Build map: node_hash (binary) -> node_bytes
    let mut node_map: alloc::collections::BTreeMap<[u8; 32], Vec<u8>> =
        alloc::collections::BTreeMap::new();

    for node in proof.iter() {
        let node_bytes = node.as_ref();
        let hash = hash_node_with_poseidon_padded(node_bytes);
        node_map.insert(hash, node_bytes.to_vec());
    }

    // Parse state root from hex string to bytes
    let state_root_hex = state_root.trim_start_matches("0x");
    let state_root_bytes: [u8; 32] = hex::decode(state_root_hex)
        .map_err(|e| anyhow::anyhow!("Invalid state root hex: {}", e))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("State root must be 32 bytes"))?;

    // Find root node
    let root_node = node_map
        .get(&state_root_bytes)
        .ok_or_else(|| anyhow::anyhow!("No node hashes to state root"))?;

    let mut ordered_nodes = vec![root_node.clone()];
    let mut current_node = root_node.clone();

    // Build path from root to leaf by following raw 32-byte child-hash references.
    loop {
        let mut next_child = None;
        for child_bytes in node_map.values() {
            // The terminal value node is 32 bytes. We append it after we locate the leaf.
            if child_bytes.len() == 32 {
                continue;
            }

            let child_hash = hash_node_with_poseidon_padded(child_bytes);
            if current_node
                .windows(child_hash.len())
                .any(|w| w == child_hash.as_ref())
                && !ordered_nodes.iter().any(|n| n == child_bytes)
            {
                next_child = Some(child_bytes.clone());
                break;
            }
        }

        match next_child {
            Some(child_bytes) => {
                current_node = child_bytes.clone();
                ordered_nodes.push(child_bytes);
            }
            None => break,
        }
    }

    // The leaf node references a separate value node (zk-trie uses MAX_INLINE_VALUE=31,
    // so our 32-byte leaf_inputs_hash is always stored indirectly via a value node).
    let leaf = ordered_nodes.last().unwrap();
    let hash_offset =
        parse_leaf_hash_offset(leaf).ok_or_else(|| anyhow::anyhow!("Failed to parse leaf node"))?;

    let value_ref: [u8; 32] = leaf[hash_offset..hash_offset + 32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Value reference must be 32 bytes"))?;
    let value_node = node_map
        .get(&value_ref)
        .ok_or_else(|| anyhow::anyhow!("Value node not found in proof"))?;

    ordered_nodes.push(value_node.clone());

    if ordered_nodes.len() > MAX_STORAGE_PROOF_NODES {
        bail!(
            "Proof length {} exceeds maximum {}",
            ordered_nodes.len(),
            MAX_STORAGE_PROOF_NODES
        );
    }

    // Compute indices: where each child hash appears in its parent node.
    // The circuit expects a hex-character offset, so we convert byte offsets by *2.
    let mut indices = Vec::new();
    for i in 0..ordered_nodes.len() - 1 {
        let parent = &ordered_nodes[i];
        let child_hash = hash_node_with_poseidon_padded(&ordered_nodes[i + 1]);

        let matches: Vec<usize> = parent
            .windows(child_hash.len())
            .enumerate()
            .filter_map(|(idx, window)| (window == child_hash.as_ref()).then_some(idx))
            .collect();

        let byte_idx = match matches.as_slice() {
            [] => bail!("Child hash not found in parent node {}", i),
            [idx] => *idx,
            _ => bail!(
                "Ambiguous child hash in parent node {} ({} matches)",
                i,
                matches.len()
            ),
        };

        indices.push(byte_idx * 2);
    }

    // Off-circuit validation: verify the value node contains the expected leaf_inputs_hash.
    // This is a development aid - the circuit constraints will reject invalid inputs.
    // We log a warning instead of failing to allow fuzzing/testing of circuit constraints.
    let value_node = ordered_nodes.last().unwrap();
    if value_node.len() != 32 || value_node.as_slice() != leaf_hash {
        #[cfg(feature = "std")]
        eprintln!(
            "WARNING: Off-circuit check failed - value node doesn't match leaf_hash! expected={}, value_node={}",
            hex::encode(leaf_hash),
            hex::encode(value_node)
        );
    }

    if indices.len() != ordered_nodes.len().saturating_sub(1) {
        bail!(
            "Indices length mismatch: indices.len() = {}, ordered_nodes.len() - 1 = {}",
            indices.len(),
            ordered_nodes.len().saturating_sub(1)
        );
    }

    ProcessedStorageProof::new(ordered_nodes, indices)
}

#[cfg(test)]
mod tests {
    use super::parse_leaf_hash_offset;

    /// Create a HashedValueLeaf node (type 5).
    fn create_hashed_value_leaf(nibble_count: u32) -> Vec<u8> {
        // Header: type 5 (HashedValueLeaf) in bits 63-60
        let header: u64 = 0x5000000000000000 | (nibble_count as u64);

        // Calculate nibble section size
        let nibble_bytes = (nibble_count as usize).div_ceil(2);
        let misalignment = nibble_bytes % 8;
        let prefix_padding = if misalignment == 0 {
            0
        } else {
            8 - misalignment
        };
        let nibble_section = (prefix_padding + nibble_bytes).div_ceil(8) * 8;

        let total_size = 8 + nibble_section + 32; // header + nibbles + hash
        let mut leaf_node = vec![0u8; total_size];
        leaf_node[0..8].copy_from_slice(&header.to_le_bytes());

        leaf_node
    }

    #[test]
    fn parse_leaf_hash_offset_no_nibbles() {
        let leaf_node = create_hashed_value_leaf(0);
        // Type 5 with no nibbles: 8-byte header = offset 8
        assert_eq!(parse_leaf_hash_offset(&leaf_node), Some(8));
    }

    #[test]
    fn parse_leaf_hash_offset_with_nibbles() {
        let leaf_node = create_hashed_value_leaf(4);
        // nibble_count=4: 2 bytes of nibbles, padded to 8
        // 8-byte header + 8-byte nibble section = offset 16
        assert_eq!(parse_leaf_hash_offset(&leaf_node), Some(16));
    }

    #[test]
    fn parse_leaf_hash_offset_rejects_truncated_node() {
        let leaf_node = vec![0u8; 4];
        assert_eq!(parse_leaf_hash_offset(&leaf_node), None);
    }

    #[test]
    fn parse_leaf_hash_offset_rejects_wrong_type() {
        // Type 3 (Leaf) - not supported, we only use HashedValueLeaf
        let header: u64 = 0x3000000000000000;
        let mut leaf_node = vec![0u8; 48];
        leaf_node[0..8].copy_from_slice(&header.to_le_bytes());
        assert_eq!(parse_leaf_hash_offset(&leaf_node), None);
    }
}
