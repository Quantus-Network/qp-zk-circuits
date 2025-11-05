//! Utility functions for the wormhole example.
use anyhow::{anyhow, bail};
use hex;
use qp_poseidon::PoseidonHasher;
use sp_core::{Hasher, H256};
use std::collections::{HashMap, HashSet};
use subxt::backend::legacy::rpc_methods::Bytes;
use wormhole_circuit::storage_proof::ProcessedStorageProof;

/// Prepares the storage proof for circuit consumption by finding the proof's root,
/// verifying it against the state root, and ordering the nodes from root to leaf.
pub fn prepare_proof_for_circuit(
    proof: Vec<Bytes>,
    last_idx: usize,
) -> anyhow::Result<(ProcessedStorageProof, H256)> {
    if proof.is_empty() {
        return Err(anyhow!("Proof cannot be empty."));
    }

    //Create a lookup from hash to node data, and collect all node hashes.
    let mut node_map = HashMap::new();
    let mut all_hashes = HashSet::new();
    for node_data in proof.iter() {
        let hash = <PoseidonHasher as Hasher>::hash(&node_data.0);
        node_map.insert(hash, &node_data.0);
        all_hashes.insert(hash);
    }

    // Find all hashes that are children of other nodes by searching for their
    // raw byte representation inside other nodes.
    let mut child_hashes = HashSet::new();
    for node_data in node_map.values() {
        for &hash in &all_hashes {
            if node_data
                .windows(32)
                .any(|window| window == hash.as_bytes())
            {
                child_hashes.insert(hash);
            }
        }
    }

    //The root of the proof is the hash that is in `all_hashes` but not in `child_hashes`.
    let proof_root_hashes: Vec<_> = all_hashes.difference(&child_hashes).collect();

    if proof_root_hashes.len() != 1 {
        bail!(
            "Expected to find exactly one root node in the proof, but found {}. Proof might be malformed or contain multiple disjoint paths.",
            proof_root_hashes.len()
        );
    }
    let proof_root_hash = *proof_root_hashes[0];

    // 4. Now that we have the root, order the proof from top down.
    let mut ordered_proof_nodes = Vec::<Vec<u8>>::new();
    let mut indices = Vec::<usize>::new();
    let mut current_hash = proof_root_hash;
    let mut used_hashes = HashMap::<H256, bool>::new();

    while let Some(current_node_data) = node_map.get(&current_hash) {
        ordered_proof_nodes.push(current_node_data.to_vec());
        used_hashes.insert(current_hash, true);

        let mut found_next_hash = None;

        for (&hash_to_find, _) in node_map.iter() {
            if used_hashes.contains_key(&hash_to_find) {
                continue; // Skip nodes already in the path.
            }

            if let Some(index) = current_node_data
                .windows(32)
                .position(|window| window == hash_to_find.as_bytes())
            {
                found_next_hash = Some((hash_to_find, index));
                break;
            }
        }

        if let Some((next_hash, index)) = found_next_hash {
            current_hash = next_hash;
            indices.push(index * 2); // Convert byte index to hex index for circuit
        } else {
            break; // End of path
        }
    }
    indices.push(last_idx);

    let processed_proof = ProcessedStorageProof::new(ordered_proof_nodes, indices)?;

    Ok((processed_proof, proof_root_hash))
}
