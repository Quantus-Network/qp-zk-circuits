//! Handles processing of Substrate storage proofs for the wormhole circuit.

use std::collections::{BTreeSet, HashMap};

use anyhow::anyhow;
use sp_core::hasher::Hasher;
use sp_trie::{NibbleSlice, NodeCodec, NodePlan, TrieLayout};
use wormhole_circuit::storage_proof::ProcessedStorageProof;

/// Finds the byte offset of a child hash within a parent node's raw data.
fn find_child_offset(node_data: &[u8], child_data: &[u8]) -> anyhow::Result<usize> {
    node_data
        .windows(child_data.len())
        .position(|window| window == child_data)
        .ok_or_else(|| anyhow!("Could not find child data in parent node"))
}

/// Processes the raw proof from an RPC call into an ordered list of nodes and their
/// corresponding child hash indices, as required by the circuit.
///
/// This function is generic over the `Hasher` used by the trie.
pub fn process_storage_proof<H: Hasher<Out = sp_core::H256>>(
    state_root: sp_core::H256,
    storage_key: &[u8],
    proof_nodes: BTreeSet<Vec<u8>>,
) -> anyhow::Result<ProcessedStorageProof> {
    // Define a codec for the specific hasher provided.
    type ZkTrieNodeCodec<H> = NodeCodec<TrieLayout<H>>;

    let mut proof = Vec::new();
    let mut indices = Vec::new();

    // 1. Create a map from `hash(node)` -> `node` for efficient lookups.
    let node_map: HashMap<sp_core::H256, Vec<u8>> = proof_nodes
        .into_iter()
        .map(|node_data| (H::hash(&node_data), node_data))
        .collect();

    // 2. Begin traversal from the state root, using the storage key as the path.
    let mut current_hash = state_root;
    let mut key_nibbles = NibbleSlice::new(storage_key);

    loop {
        let current_node_data = node_map
            .get(&current_hash)
            .ok_or_else(|| anyhow!("Node not found in proof: {}", current_hash))?;

        proof.push(current_node_data.clone());

        // Decode the node using the generic codec.
        let node_plan = ZkTrieNodeCodec::<H>::decode_plan(current_node_data)?;

        let child_data: Option<&[u8]> = match node_plan {
            NodePlan::Leaf { partial, .. } => {
                let partial_nibbles = NibbleSlice::new_offset(partial.as_slice(), partial.offset());
                if partial_nibbles != key_nibbles {
                    return Err(anyhow!(
                        "Invalid leaf node key. Remaining key: {:?}, Leaf key: {:?}",
                        key_nibbles,
                        partial_nibbles
                    ));
                }
                None
            }
            NodePlan::Extension { partial, child } => {
                let partial_nibbles = NibbleSlice::new_offset(partial.as_slice(), partial.offset());
                if !key_nibbles.starts_with(&partial_nibbles) {
                    return Err(anyhow!("Invalid extension node key"));
                }
                key_nibbles.advance(partial_nibbles.len());
                Some(child)
            }
            NodePlan::Branch { children, .. } => {
                let nibble = key_nibbles
                    .at(0)
                    .ok_or_else(|| anyhow!("Key is too short, ran out of nibbles"))?;
                key_nibbles.advance(1);

                children[nibble as usize]
                    .as_ref()
                    .map(|child_ref| *child_ref)
                    .ok_or_else(|| anyhow!("Branch node does not have a child for the key nibble"))?
            }
            NodePlan::Empty => return Err(anyhow!("Reached an empty node during traversal")),
            _ => return Err(anyhow!("Unexpected node plan during traversal")),
        };

        match child_data {
            Some(data) => {
                // Per ZK-Trie, child references are always 32-byte hashes.
                if data.len() != 32 {
                    return Err(anyhow!(
                        "Invalid child reference in ZK-Trie node; expected 32-byte hash, got {} bytes",
                        data.len()
                    ));
                }
                let index = find_child_offset(current_node_data, data)?;
                indices.push(index);
                current_hash.copy_from_slice(data);
            }
            None => {
                // This was the leaf node.
                indices.push(0);
                break;
            }
        }
    }

    ProcessedStorageProof::new(proof, indices)
}
