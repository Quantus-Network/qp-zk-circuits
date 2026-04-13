//! 4-ary Poseidon Merkle tree proof types and utilities.
//!
//! This module provides:
//! - Proof data structures for the 4-ary ZK Merkle tree
//! - Utility functions for proof verification outside circuits
//! - Constants for circuit constraints
//!
//! ## Tree Structure
//!
//! The ZK tree uses a 4-ary structure where each internal node has 4 children.
//! Children are **sorted** before hashing, which eliminates the need for path
//! indices in proofs. The verifier simply combines the current hash with the
//! 3 siblings, sorts all 4, and hashes to get the parent.
//!
//! ```text
//!                     [Root]                    Level N
//!                    /  |  \  \
//!              [N0] [N1] [N2] [N3]              Level N-1
//!             /|||\  ...
//!          [L0-L3]  ...                         Level 0 (leaves)
//! ```
//!
//! ## Hashing
//!
//! - **Leaves**: Injective Poseidon (4 bytes/felt) for collision resistance
//! - **Internal nodes**: Non-injective Poseidon (8 bytes/felt) on sorted children

use alloc::vec::Vec;

use crate::circuit::F;
use crate::serialization;

/// Type alias for 32-byte hash.
pub type Hash256 = [u8; 32];

/// Arity of the Merkle tree (4-ary).
pub const ARITY: usize = 4;

/// Maximum tree depth supported by circuits.
/// A tree of depth 16 can hold 4^16 = ~4.3 billion leaves.
pub const MAX_DEPTH: usize = 16;

/// Number of siblings per level (ARITY - 1 = 3).
pub const SIBLINGS_PER_LEVEL: usize = ARITY - 1;

/// Number of field elements per hash (32 bytes / 8 bytes per felt = 4 felts).
pub const HASH_NUM_FELTS: usize = serialization::POSEIDON2_OUTPUT;

/// Total bytes in a child set for internal node hashing (4 * 32 = 128 bytes).
pub const CHILDREN_BYTES: usize = ARITY * 32;

/// Number of felts for children in internal node hashing (128 / 8 = 16 felts).
pub const CHILDREN_NUM_FELTS: usize = CHILDREN_BYTES / 8;

/// Type alias for 4-felt digest (Poseidon2 output).
pub type Digest = [F; HASH_NUM_FELTS];

/// A 4-ary Merkle proof.
///
/// Contains siblings at each level from leaf to root. The siblings are provided
/// in **sorted order** (excluding the current node), and a position index indicates
/// where the current hash should be inserted to reconstruct the sorted 4-tuple
/// that was hashed to produce the parent.
///
/// This design avoids in-circuit sorting: the prover provides the sorted siblings
/// and the position, and the circuit just inserts and hashes.
#[derive(Debug, Clone)]
pub struct ZkMerkleProof {
    /// Leaf index in the tree (informational, not needed for verification).
    pub leaf_index: u64,

    /// Sibling hashes at each level, from leaf level up to root.
    /// Each level has 3 siblings in **sorted order** (the other children of the parent).
    /// The `positions` array indicates where the current hash fits in the sorted order.
    pub siblings: Vec<[Hash256; SIBLINGS_PER_LEVEL]>,

    /// Position index (0-3) at each level indicating where the current hash
    /// should be inserted among the sorted siblings to reconstruct the full
    /// sorted 4-tuple. For example, position=1 means the sorted order is
    /// [sib0, current, sib1, sib2].
    pub positions: Vec<u8>,

    /// The leaf hash at the bottom of the proof.
    pub leaf_hash: Hash256,

    /// Expected root hash.
    pub root: Hash256,
}

impl ZkMerkleProof {
    /// Create a new proof.
    pub fn new(
        leaf_index: u64,
        siblings: Vec<[Hash256; SIBLINGS_PER_LEVEL]>,
        positions: Vec<u8>,
        leaf_hash: Hash256,
        root: Hash256,
    ) -> Self {
        Self {
            leaf_index,
            siblings,
            positions,
            leaf_hash,
            root,
        }
    }

    /// Get the depth (number of levels) of this proof.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Verify the proof against the expected root.
    ///
    /// Returns `true` if the proof is valid.
    pub fn verify(&self) -> bool {
        if self.siblings.len() != self.positions.len() {
            return false;
        }

        let mut current_hash = self.leaf_hash;

        for (level_siblings, &position) in self.siblings.iter().zip(self.positions.iter()) {
            if position > 3 {
                return false;
            }

            // Combine current hash with 3 siblings to get all 4 children
            let children: [Hash256; ARITY] = [
                current_hash,
                level_siblings[0],
                level_siblings[1],
                level_siblings[2],
            ];

            // Compute parent hash (hash_node sorts internally)
            current_hash = hash_node(&children);
        }

        current_hash == self.root
    }

    /// Verify the proof using pre-sorted siblings and position hints.
    ///
    /// This is the verification method that matches the circuit logic:
    /// siblings are already sorted, and the position indicates where
    /// to insert the current hash.
    pub fn verify_with_positions(&self) -> bool {
        if self.siblings.len() != self.positions.len() {
            return false;
        }

        let mut current_hash = self.leaf_hash;

        for (level_siblings, &position) in self.siblings.iter().zip(self.positions.iter()) {
            if position > 3 {
                return false;
            }

            // Insert current_hash at the given position among sorted siblings
            let sorted_children = insert_at_position(current_hash, level_siblings, position);

            // Hash the sorted children directly (no sorting needed)
            current_hash = hash_node_presorted(&sorted_children);
        }

        current_hash == self.root
    }

    /// Create a proof from raw siblings, computing positions automatically.
    ///
    /// This takes unsorted siblings and computes the correct sorted order
    /// and position hints for circuit verification.
    pub fn from_unsorted(
        leaf_index: u64,
        unsorted_siblings: Vec<[Hash256; SIBLINGS_PER_LEVEL]>,
        leaf_hash: Hash256,
        root: Hash256,
    ) -> Self {
        let mut current_hash = leaf_hash;
        let mut sorted_siblings = Vec::with_capacity(unsorted_siblings.len());
        let mut positions = Vec::with_capacity(unsorted_siblings.len());

        for level_siblings in &unsorted_siblings {
            // Combine current hash with siblings
            let mut all_four = [
                current_hash,
                level_siblings[0],
                level_siblings[1],
                level_siblings[2],
            ];

            // Sort to get the order used by hash_node
            all_four.sort();

            // Find position of current_hash in sorted order
            let pos = all_four.iter().position(|h| *h == current_hash).unwrap() as u8;
            positions.push(pos);

            // Extract the 3 siblings in sorted order (excluding current_hash)
            let sorted_sibs: [Hash256; SIBLINGS_PER_LEVEL] = {
                let mut sibs = [[0u8; 32]; 3];
                let mut sib_idx = 0;
                for (i, h) in all_four.iter().enumerate() {
                    if i as u8 != pos {
                        sibs[sib_idx] = *h;
                        sib_idx += 1;
                    }
                }
                sibs
            };
            sorted_siblings.push(sorted_sibs);

            // Compute parent hash for next level
            current_hash = hash_node_presorted(&all_four);
        }

        Self {
            leaf_index,
            siblings: sorted_siblings,
            positions,
            leaf_hash,
            root,
        }
    }
}

/// Insert a hash at a given position (0-3) among 3 sorted siblings.
///
/// Returns the 4 hashes in order: siblings before position, then current, then siblings after.
pub fn insert_at_position(
    current: Hash256,
    sorted_siblings: &[Hash256; SIBLINGS_PER_LEVEL],
    position: u8,
) -> [Hash256; ARITY] {
    match position {
        0 => [
            current,
            sorted_siblings[0],
            sorted_siblings[1],
            sorted_siblings[2],
        ],
        1 => [
            sorted_siblings[0],
            current,
            sorted_siblings[1],
            sorted_siblings[2],
        ],
        2 => [
            sorted_siblings[0],
            sorted_siblings[1],
            current,
            sorted_siblings[2],
        ],
        3 => [
            sorted_siblings[0],
            sorted_siblings[1],
            sorted_siblings[2],
            current,
        ],
        _ => panic!("position must be 0-3"),
    }
}

/// Hash 4 child hashes that are already in sorted order.
///
/// Unlike `hash_node`, this does NOT sort - it assumes the input is already sorted.
/// This is used by the circuit verification path.
pub fn hash_node_presorted(sorted_children: &[Hash256; ARITY]) -> Hash256 {
    // Concatenate all 4 child hashes (128 bytes total)
    let mut data = Vec::with_capacity(CHILDREN_BYTES);
    for child in sorted_children {
        data.extend_from_slice(child);
    }

    // Convert to felts using compact encoding (8 bytes/felt)
    let felts = qp_poseidon_core::serialization::bytes_to_felts_compact(&data);

    // Hash the felts
    qp_poseidon_core::hash_to_bytes(&felts)
}

/// Hash 4 child hashes into a parent node hash.
///
/// Children are sorted before hashing to eliminate the need for path indices.
/// Uses non-injective Poseidon (8 bytes/felt) - safe because internal nodes
/// only contain fixed-size hash outputs.
pub fn hash_node(children: &[Hash256; ARITY]) -> Hash256 {
    // Sort children to make hash order-independent
    let mut sorted = *children;
    sorted.sort();

    // Concatenate all 4 child hashes (128 bytes total)
    let mut data = Vec::with_capacity(CHILDREN_BYTES);
    for child in &sorted {
        data.extend_from_slice(child);
    }

    // Convert to felts using compact encoding (8 bytes/felt)
    // 128 bytes -> 16 felts
    let felts = qp_poseidon_core::serialization::bytes_to_felts_compact(&data);

    // Hash the felts
    qp_poseidon_core::hash_to_bytes(&felts)
}

/// Empty hash value (all zeros).
pub fn empty_hash() -> Hash256 {
    [0u8; 32]
}

/// Convert a 32-byte hash to 4 field elements (digest format, 8 bytes/felt).
pub fn hash_to_felts(hash: &Hash256) -> Digest {
    serialization::bytes_to_digest(hash)
}

/// Convert 4 field elements back to a 32-byte hash.
pub fn felts_to_hash(felts: &Digest) -> Hash256 {
    serialization::digest_to_bytes(felts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_hash() {
        assert_eq!(empty_hash(), [0u8; 32]);
    }

    #[test]
    fn test_hash_node_is_deterministic() {
        let children = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let hash1 = hash_node(&children);
        let hash2 = hash_node(&children);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_node_is_order_independent() {
        // Because children are sorted, different input orders should give same hash
        let children1 = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let children2 = [[4u8; 32], [2u8; 32], [1u8; 32], [3u8; 32]];
        assert_eq!(hash_node(&children1), hash_node(&children2));
    }

    #[test]
    fn test_hash_node_presorted_matches_hash_node() {
        // hash_node_presorted on sorted input should match hash_node
        let mut children = [[4u8; 32], [2u8; 32], [1u8; 32], [3u8; 32]];
        children.sort();

        let from_presorted = hash_node_presorted(&children);
        let from_hash_node = hash_node(&children);
        assert_eq!(from_presorted, from_hash_node);
    }

    #[test]
    fn test_hash_felts_roundtrip() {
        let original = [0xab; 32];
        let felts = hash_to_felts(&original);
        let recovered = felts_to_hash(&felts);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_insert_at_position() {
        let current = [0xcc; 32];
        let siblings = [[0x11; 32], [0x22; 32], [0x33; 32]];

        assert_eq!(
            insert_at_position(current, &siblings, 0),
            [current, siblings[0], siblings[1], siblings[2]]
        );
        assert_eq!(
            insert_at_position(current, &siblings, 1),
            [siblings[0], current, siblings[1], siblings[2]]
        );
        assert_eq!(
            insert_at_position(current, &siblings, 2),
            [siblings[0], siblings[1], current, siblings[2]]
        );
        assert_eq!(
            insert_at_position(current, &siblings, 3),
            [siblings[0], siblings[1], siblings[2], current]
        );
    }

    #[test]
    fn test_simple_proof_verification() {
        // Single leaf tree (depth 0 means just the leaf is the root)
        let leaf_hash = [0x42; 32];
        let proof = ZkMerkleProof {
            leaf_index: 0,
            siblings: vec![],
            positions: vec![],
            leaf_hash,
            root: leaf_hash,
        };
        assert!(proof.verify());
        assert!(proof.verify_with_positions());
    }

    #[test]
    fn test_depth_1_proof_verification() {
        // Tree with depth 1: root is hash of 4 leaves
        let leaf0 = [0x00; 32];
        let leaf1 = [0x11; 32];
        let leaf2 = [0x22; 32];
        let leaf3 = [0x33; 32];

        // Compute expected root
        let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);

        // Create proof for leaf0 using from_unsorted
        let proof = ZkMerkleProof::from_unsorted(0, vec![[leaf1, leaf2, leaf3]], leaf0, root);

        assert!(proof.verify());
        assert!(proof.verify_with_positions());

        // Create proof for leaf2 using from_unsorted
        let proof2 = ZkMerkleProof::from_unsorted(2, vec![[leaf0, leaf1, leaf3]], leaf2, root);

        assert!(proof2.verify());
        assert!(proof2.verify_with_positions());
    }

    #[test]
    fn test_from_unsorted_computes_correct_positions() {
        let leaf0 = [0x00; 32];
        let leaf1 = [0x11; 32];
        let leaf2 = [0x22; 32];
        let leaf3 = [0x33; 32];

        let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);

        // leaf0 is smallest, so position should be 0
        let proof0 = ZkMerkleProof::from_unsorted(0, vec![[leaf1, leaf2, leaf3]], leaf0, root);
        assert_eq!(proof0.positions[0], 0);

        // leaf3 is largest, so position should be 3
        let proof3 = ZkMerkleProof::from_unsorted(3, vec![[leaf0, leaf1, leaf2]], leaf3, root);
        assert_eq!(proof3.positions[0], 3);
    }

    #[test]
    fn test_invalid_proof_fails() {
        let leaf0 = [0x00; 32];
        let leaf1 = [0x11; 32];
        let leaf2 = [0x22; 32];
        let leaf3 = [0x33; 32];

        let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);

        // Wrong leaf hash should fail
        let bad_proof = ZkMerkleProof::from_unsorted(
            0,
            vec![[leaf1, leaf2, leaf3]],
            [0xff; 32], // wrong!
            root,
        );

        assert!(!bad_proof.verify());
    }
}
