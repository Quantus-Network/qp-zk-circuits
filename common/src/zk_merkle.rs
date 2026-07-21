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

/// Goldilocks field modulus `p = 2^64 - 2^32 + 1`.
///
/// A 32-byte hash is decoded into four little-endian `u64` limbs before
/// hashing; each limb must be `< p` for the 8-bytes-per-felt decode to be
/// injective (see [`is_canonical_hash`]).
const GOLDILOCKS_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

/// Returns `true` if every 8-byte little-endian limb of `hash` is a canonical
/// Goldilocks field element (strictly `< p`).
///
/// Internal-node hashing packs each limb into a field element via a mod-`p`
/// reduction, so two distinct byte strings whose limbs differ by a multiple of
/// `p` hash identically. Byte-level Merkle verification must therefore reject
/// noncanonical hashes up front; otherwise a proof for a noncanonical byte
/// alias of a genuine child would verify against the same root, and the API
/// would validate membership of a field-equivalence class rather than of the
/// exact 32-byte hash it presents.
pub fn is_canonical_hash(hash: &Hash256) -> bool {
    hash.chunks_exact(8).all(|chunk| {
        let limb = u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes"));
        limb < GOLDILOCKS_MODULUS
    })
}

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

    /// Verify the proof against the expected root, including position hints.
    ///
    /// Returns `true` if the proof is valid.
    ///
    /// This validates the FULL object invariant, identically to
    /// [`Self::verify_with_positions`]: the current hash is inserted at each
    /// level's position hint and the tuple is hashed without re-sorting, so a
    /// proof that passes here is guaranteed usable by the circuit path. (An
    /// earlier version hashed through the order-independent [`hash_node`],
    /// which sorts children internally — that checked membership but silently
    /// ignored the position hints, letting proofs with bogus positions pass
    /// this verifier and only fail later inside witness proving.)
    ///
    /// Note: Proofs with depth exceeding `MAX_DEPTH` are rejected early to prevent
    /// resource exhaustion from oversized proofs.
    pub fn verify(&self) -> bool {
        self.verify_with_positions()
    }

    /// Verify the proof using pre-sorted siblings and position hints.
    ///
    /// This is the verification method that matches the circuit logic:
    /// siblings are already sorted, and the position indicates where
    /// to insert the current hash.
    ///
    /// Note: Proofs with depth exceeding `MAX_DEPTH` are rejected early to prevent
    /// resource exhaustion from oversized proofs.
    pub fn verify_with_positions(&self) -> bool {
        // Reject proofs exceeding max supported depth to prevent DoS
        if self.siblings.len() > MAX_DEPTH {
            return false;
        }
        if self.siblings.len() != self.positions.len() {
            return false;
        }

        // Reject noncanonical hash bytes before hashing. The compact node hash
        // reduces each 8-byte limb mod p, so a noncanonical byte alias of a
        // genuine child would derive the same parent; requiring canonical limbs
        // makes this verifier prove membership of the exact 32-byte hashes it
        // presents (see `is_canonical_hash`).
        if !is_canonical_hash(&self.leaf_hash) {
            return false;
        }
        if !self.siblings.iter().flatten().all(is_canonical_hash) {
            return false;
        }

        let mut current_hash = self.leaf_hash;

        for (level_siblings, &position) in self.siblings.iter().zip(self.positions.iter()) {
            // Insert current_hash at the given position among sorted siblings;
            // an out-of-range position byte makes the proof invalid.
            let Ok(sorted_children) = insert_at_position(current_hash, level_siblings, position)
            else {
                return false;
            };

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
///
/// # Errors
///
/// Returns an error when `position > 3`. This is a public API that may receive
/// attacker-controlled position bytes (e.g. from deserialized proofs), so an
/// out-of-range value must produce a normal invalid-input error, not a panic.
pub fn insert_at_position(
    current: Hash256,
    sorted_siblings: &[Hash256; SIBLINGS_PER_LEVEL],
    position: u8,
) -> Result<[Hash256; ARITY], &'static str> {
    match position {
        0 => Ok([
            current,
            sorted_siblings[0],
            sorted_siblings[1],
            sorted_siblings[2],
        ]),
        1 => Ok([
            sorted_siblings[0],
            current,
            sorted_siblings[1],
            sorted_siblings[2],
        ]),
        2 => Ok([
            sorted_siblings[0],
            sorted_siblings[1],
            current,
            sorted_siblings[2],
        ]),
        3 => Ok([
            sorted_siblings[0],
            sorted_siblings[1],
            sorted_siblings[2],
            current,
        ]),
        _ => Err("insert_at_position: position must be 0-3"),
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

    // Compact encoding (8 bytes/felt); lossy path for fixed-size hash payloads.
    serialization::hash_bytes_compact(&data)
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

    // Compact encoding (8 bytes/felt); 128 bytes -> 16 felts.
    serialization::hash_bytes_compact(&data)
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
            insert_at_position(current, &siblings, 0).unwrap(),
            [current, siblings[0], siblings[1], siblings[2]]
        );
        assert_eq!(
            insert_at_position(current, &siblings, 1).unwrap(),
            [siblings[0], current, siblings[1], siblings[2]]
        );
        assert_eq!(
            insert_at_position(current, &siblings, 2).unwrap(),
            [siblings[0], siblings[1], current, siblings[2]]
        );
        assert_eq!(
            insert_at_position(current, &siblings, 3).unwrap(),
            [siblings[0], siblings[1], siblings[2], current]
        );
    }

    /// Out-of-range position bytes (possible in attacker-supplied proofs) must
    /// yield an error, not a panic.
    #[test]
    fn test_insert_at_position_rejects_out_of_range() {
        let current = [0xcc; 32];
        let siblings = [[0x11; 32], [0x22; 32], [0x33; 32]];
        for bad in [4u8, 5, u8::MAX] {
            assert!(insert_at_position(current, &siblings, bad).is_err());
        }
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

    /// Regression (audit): `verify()` used to hash through the
    /// order-independent `hash_node`, so a proof with valid membership but a
    /// bogus position hint passed `verify()` while being unusable by the
    /// position-sensitive circuit path. Both verifiers must reject it.
    #[test]
    fn test_wrong_position_hint_fails_default_verify() {
        let leaf0 = [0x00; 32];
        let leaf1 = [0x11; 32];
        let leaf2 = [0x22; 32];
        let leaf3 = [0x33; 32];
        let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);

        let mut proof = ZkMerkleProof::from_unsorted(0, vec![[leaf1, leaf2, leaf3]], leaf0, root);
        assert!(proof.verify(), "sanity: correct positions must verify");

        // Corrupt the position hint; membership data is untouched.
        proof.positions[0] = 2;
        assert!(!proof.verify());
        assert!(!proof.verify_with_positions());

        // Out-of-range hint is likewise an invalid proof, not a panic.
        proof.positions[0] = 7;
        assert!(!proof.verify());
    }

    /// Goldilocks field modulus `p = 2^64 - 2^32 + 1`.
    const GOLDILOCKS: u64 = 0xFFFF_FFFF_0000_0001;

    /// Build a 32-byte hash from four little-endian `u64` limbs.
    fn hash_from_limbs(limbs: [u64; 4]) -> Hash256 {
        let mut bytes = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    /// Read the four little-endian `u64` limbs of a 32-byte hash.
    fn limbs_from_hash(hash: &Hash256) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(hash[i * 8..i * 8 + 8].try_into().unwrap());
        }
        limbs
    }

    /// Return a distinct byte string that decodes to the same field digest as
    /// `hash` by adding `p` to its first limb, or `None` if that limb is too
    /// large for the `+p` alias to fit in a `u64`.
    fn noncanonical_alias(hash: &Hash256) -> Option<Hash256> {
        let mut limbs = limbs_from_hash(hash);
        limbs[0] = limbs[0].checked_add(GOLDILOCKS)?;
        let alias = hash_from_limbs(limbs);
        (alias != *hash).then_some(alias)
    }

    /// Audit: the internal-node hash packs each 8-byte limb into a Goldilocks
    /// felt via a mod-`p` reduction, so a caller can replace a canonical child
    /// digest with a distinct noncanonical byte alias (limb `+ p`) and derive
    /// the same parent/root. The byte-level verifier must reject noncanonical
    /// leaf bytes so it proves membership of the exact 32-byte hash, not of a
    /// field-equivalence class.
    #[test]
    fn verify_rejects_noncanonical_leaf_alias() {
        let leaf0 = hash_from_limbs([0, 0, 0, 0]);
        let leaf1 = hash_from_limbs([1, 0, 0, 0]);
        let leaf2 = hash_from_limbs([2, 0, 0, 0]);
        let leaf3 = hash_from_limbs([3, 0, 0, 0]);
        let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);

        let mut proof = ZkMerkleProof::from_unsorted(0, vec![[leaf1, leaf2, leaf3]], leaf0, root);
        assert!(proof.verify(), "sanity: canonical proof must verify");

        // Alias of leaf0: limb 0 replaced by `p`, which reduces to 0 mod p.
        let alias = noncanonical_alias(&leaf0).expect("leaf0 limb 0 admits a +p alias");
        assert_ne!(alias, leaf0, "alias must be a distinct byte string");
        proof.leaf_hash = alias;

        assert!(
            !proof.verify(),
            "noncanonical leaf alias must be rejected, not accepted via field aliasing"
        );
        assert!(!proof.verify_with_positions());
    }

    /// Same aliasing attack, but on a sibling hash rather than the leaf.
    #[test]
    fn verify_rejects_noncanonical_sibling_alias() {
        let leaf0 = hash_from_limbs([0, 0, 0, 0]);
        let leaf1 = hash_from_limbs([1, 0, 0, 0]);
        let leaf2 = hash_from_limbs([2, 0, 0, 0]);
        let leaf3 = hash_from_limbs([3, 0, 0, 0]);
        let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);

        let mut proof = ZkMerkleProof::from_unsorted(0, vec![[leaf1, leaf2, leaf3]], leaf0, root);
        assert!(proof.verify(), "sanity: canonical proof must verify");

        // Replace the first sibling with its noncanonical alias.
        let original = proof.siblings[0][0];
        let alias = noncanonical_alias(&original).expect("sibling limb 0 admits a +p alias");
        assert_ne!(alias, original);
        proof.siblings[0][0] = alias;

        assert!(
            !proof.verify(),
            "noncanonical sibling alias must be rejected"
        );
        assert!(!proof.verify_with_positions());
    }

    #[test]
    fn test_oversized_proof_rejected() {
        // Create a proof with depth exceeding MAX_DEPTH
        let leaf_hash = [0x42; 32];
        let oversized_siblings: Vec<[Hash256; SIBLINGS_PER_LEVEL]> =
            (0..MAX_DEPTH + 1).map(|_| [[0u8; 32]; 3]).collect();
        let oversized_positions: Vec<u8> = vec![0; MAX_DEPTH + 1];

        let proof = ZkMerkleProof {
            leaf_index: 0,
            siblings: oversized_siblings,
            positions: oversized_positions,
            leaf_hash,
            root: [0xff; 32], // doesn't matter, should reject before hashing
        };

        // Both verify methods should reject oversized proofs
        assert!(!proof.verify());
        assert!(!proof.verify_with_positions());
    }

    #[test]
    fn test_max_depth_proof_accepted() {
        // Build a valid proof at exactly MAX_DEPTH to ensure the boundary is correct.
        // If a future change tightens the bound to >= MAX_DEPTH, this test will fail.

        // Start with a leaf and build up the tree level by level
        let leaf_hash = [0x42; 32];
        let mut current_hash = leaf_hash;
        let mut siblings_list = Vec::with_capacity(MAX_DEPTH);
        let mut positions_list = Vec::with_capacity(MAX_DEPTH);

        for level in 0..MAX_DEPTH {
            // Create 3 siblings that are distinct from current_hash
            // Use level to make each level unique
            let sib0 = {
                let mut h = [0u8; 32];
                h[0] = (level * 3) as u8;
                h[1] = 0x01;
                h
            };
            let sib1 = {
                let mut h = [0u8; 32];
                h[0] = (level * 3 + 1) as u8;
                h[1] = 0x02;
                h
            };
            let sib2 = {
                let mut h = [0u8; 32];
                h[0] = (level * 3 + 2) as u8;
                h[1] = 0x03;
                h
            };

            // Combine and sort to find position
            let mut all_four = [current_hash, sib0, sib1, sib2];
            all_four.sort();
            let pos = all_four.iter().position(|h| *h == current_hash).unwrap() as u8;

            // Extract sorted siblings (excluding current_hash)
            let mut sorted_sibs = [[0u8; 32]; 3];
            let mut sib_idx = 0;
            for (i, h) in all_four.iter().enumerate() {
                if i as u8 != pos {
                    sorted_sibs[sib_idx] = *h;
                    sib_idx += 1;
                }
            }

            siblings_list.push(sorted_sibs);
            positions_list.push(pos);

            // Compute parent hash for next level
            current_hash = hash_node_presorted(&all_four);
        }

        let root = current_hash;

        let proof = ZkMerkleProof {
            leaf_index: 0,
            siblings: siblings_list,
            positions: positions_list,
            leaf_hash,
            root,
        };

        // This must be true - a valid proof at exactly MAX_DEPTH should be accepted
        assert!(proof.verify_with_positions());
    }
}
