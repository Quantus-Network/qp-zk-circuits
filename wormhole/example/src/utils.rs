//! Utility functions for the wormhole example.
use qp_poseidon::PoseidonHasher;
use sp_core::Hasher;
use subxt::backend::legacy::rpc_methods::Bytes;
use wormhole_circuit::storage_proof::ProcessedStorageProof;

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

/// Prepares the storage proof for circuit consumption by finding the proof's root,
/// verifying it against the state root, and ordering the nodes from root to leaf.
pub fn prepare_proof_for_circuit(
    proof: Vec<Bytes>,
    state_root: String,
    last_idx: usize,
) -> anyhow::Result<ProcessedStorageProof> {
    let mut hashes = Vec::<String>::new();
    let mut bytes = Vec::<String>::new();
    let mut parts = Vec::<(String, String)>::new();
    let mut storage_proof = Vec::<String>::new();
    for node_data in proof.iter() {
        let hash = hex::encode(<PoseidonHasher as Hasher>::hash(node_data));
        let node_bytes = hex::encode(&node_data.0);
        if hash == state_root {
            storage_proof.push(node_bytes);
        } else {
            // don't put the hash in if it is the root
            hashes.push(hash);
            bytes.push(node_bytes.clone());
        }
    }

    println!(
        "Finished constructing bytes and hashes vectors {:?} {:?}",
        bytes, hashes
    );

    let mut ordered_hashes = Vec::<String>::new();
    let mut indices = Vec::<usize>::new();

    while !hashes.is_empty() {
        for i in (1..hashes.len()).rev() {
            let hash = hashes[i].clone();
            if let Some(last) = storage_proof.last() {
                if let Some(index) = last.find(&hash) {
                    let (left, right) = last.split_at(index);
                    indices.push(index);
                    parts.push((left.to_string(), right.to_string()));
                    storage_proof.push(bytes[i].clone());
                    ordered_hashes.push(hash.clone());
                    hashes.remove(i);
                    bytes.remove(i);
                }
            }
        }
    }
    indices.push(last_idx);

    // iterate through the storage proof, printing the size of each.
    for (i, node) in storage_proof.iter().enumerate() {
        println!("Storage proof node {}: {} bytes", i, (node.len() / 16));
    }

    println!(
        "Storage proof generated: {:?} {:?} {:?} {:?}",
        &storage_proof, parts, ordered_hashes, indices
    );

    for (i, _) in storage_proof.iter().enumerate() {
        if i == parts.len() {
            break;
        }
        let part = parts[i].clone();
        let hash = ordered_hashes[i].clone();
        if part.1[..64] != hash {
            panic!("storage proof index incorrect {:?} != {:?}", part.1, hash);
        } else {
            println!("storage proof index correct: {:?}", part.0.len());
        }
    }

    ProcessedStorageProof::new(
        storage_proof
            .iter()
            .map(|a| hex::decode(a).unwrap())
            .collect(),
        indices,
    )
}
