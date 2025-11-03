//! Utility functions for the wormhole example.
use anyhow::anyhow;
use hex;
use sp_core::{Hasher, H256};
use subxt::backend::legacy::rpc_methods::Bytes;
use wormhole_circuit::storage_proof::ProcessedStorageProof;

use qp_poseidon::PoseidonHasher;

/// Prepares the storage proof for circuit consumption.
/// This function attempts to order the proof nodes based on finding child hashes
/// within parent nodes using a string search.
pub fn prepare_proof_for_circuit(
    proof: Vec<Bytes>,
    state_root: H256,
    last_idx: usize,
) -> anyhow::Result<ProcessedStorageProof> {
    let mut hashes = vec![];
    let mut bytes_hex = vec![];
    let mut storage_proof_hex = vec![];

    for node_data in proof.iter() {
        let hash = <PoseidonHasher as Hasher>::hash(&node_data.0);
        if hash == state_root {
            storage_proof_hex.push(hex::encode(&node_data.0));
        } else {
            hashes.push(hash);
            bytes_hex.push(hex::encode(&node_data.0));
        }
    }

    if storage_proof_hex.is_empty() {
        return Err(anyhow!("State root node not found in proof set"));
    }

    let mut indices = Vec::<usize>::new();

    while !hashes.is_empty() {
        let mut found_in_iteration = false;
        for i in (0..hashes.len()).rev() {
            let hash = hashes[i];
            let hash_hex = hex::encode(hash.as_bytes());

            if let Some(last_node_hex) = storage_proof_hex.last() {
                if let Some(index) = last_node_hex.find(&hash_hex) {
                    // NOTE: This provides the byte index within a hex string.
                    // This is likely not the correct index format for the circuit.
                    indices.push(index);
                    storage_proof_hex.push(bytes_hex[i].clone());
                    hashes.remove(i);
                    bytes_hex.remove(i);
                    found_in_iteration = true;
                    break; // Found a match, restart the inner loop
                }
            }
        }
        if !found_in_iteration && !hashes.is_empty() {
            return Err(anyhow!("Could not order storage proof, path is broken."));
        }
    }

    indices.push(last_idx);

    let final_storage_proof: Vec<Vec<u8>> = storage_proof_hex
        .into_iter()
        .map(hex::decode)
        .collect::<Result<_, _>>()?;

    ProcessedStorageProof::new(final_storage_proof, indices)
}
