//! 4-ary Poseidon Merkle proof verification for the ZK trie.
//!
//! This module implements circuit logic for verifying Merkle proofs from the
//! 4-ary sorted Poseidon tree used by pallet-zk-trie.
//!
//! ## Key differences from MPT storage proofs:
//!
//! 1. **Fixed structure**: Each internal node has exactly 4 children (vs variable MPT nodes)
//! 2. **Sorted children**: Children are sorted before hashing, eliminating path indices
//! 3. **Simpler leaf**: Only `(to, transfer_count, asset_id, amount)` - no `from` field
//! 4. **Two hash modes**: Leaves use injective (4 bytes/felt), nodes use compact (8 bytes/felt)
//!
//! ## Verification algorithm:
//!
//! 1. Compute leaf hash using injective Poseidon
//! 2. For each level from leaf to root:
//!    - Combine current hash with 3 siblings
//!    - Sort all 4 hashes
//!    - Hash with compact Poseidon to get parent
//! 3. Compare final hash with expected root

use alloc::vec::Vec;
use core::array;
use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::inputs::CircuitInputs;
use crate::substrate_account::AccountTargets;
use zk_circuits_common::{
    circuit::{CircuitFragment, D, F},
    gadgets::{enforce_target_less_than_const, is_const_less_than},
    zk_merkle::{Hash256, HASH_NUM_FELTS, MAX_DEPTH, SIBLINGS_PER_LEVEL},
};

// Re-export for convenience
pub use zk_circuits_common::zk_merkle::ZkMerkleProof;

/// Number of field elements in the ZK trie leaf preimage:
/// - 4 (to_account, 8 bytes/felt for compact encoding)
/// - 2 (transfer_count as u64, two 32-bit limbs)
/// - 1 (asset_id as u32)
/// - 1 (amount as quantized u32)
/// Total: 8
///
/// Note: This is different from the old MPT leaf which included `from`.
/// The ZK trie leaf is: (to, transfer_count, asset_id, amount)
pub const NUM_LEAF_FELTS: usize = HASH_NUM_FELTS + 2 + 1 + 1;

// ============================================================================
// Circuit Targets
// ============================================================================

/// Targets for the ZK Merkle proof leaf data.
#[derive(Debug, Clone)]
pub struct ZkLeafTargets {
    /// Recipient account (4 felts, 8 bytes/felt)
    pub to_account: AccountTargets,
    /// Transfer count (2 felts for u64)
    pub transfer_count: [Target; 2],
    /// Asset ID (1 felt)
    pub asset_id: Target,
    /// Amount stored in the leaf (quantized, private input)
    pub input_amount: Target,
    /// Output amount 1 after fee (public input)
    pub output_amount_1: Target,
    /// Output amount 2 after fee (public input, for change)
    pub output_amount_2: Target,
    /// Volume fee in basis points (public input)
    pub volume_fee_bps: Target,
}

impl ZkLeafTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Public inputs (registered first for consistent ordering)
        let asset_id = builder.add_virtual_public_input();
        let output_amount_1 = builder.add_virtual_public_input();
        let output_amount_2 = builder.add_virtual_public_input();
        let volume_fee_bps = builder.add_virtual_public_input();

        // Private inputs
        let to_account = AccountTargets::new(builder);
        let transfer_count = array::from_fn(|_| builder.add_virtual_target());
        let input_amount = builder.add_virtual_target();

        Self {
            to_account,
            transfer_count,
            asset_id,
            input_amount,
            output_amount_1,
            output_amount_2,
            volume_fee_bps,
        }
    }

    /// Collect targets for leaf hash computation.
    /// Order matches chain: (to, transfer_count, asset_id, amount)
    pub fn collect_for_hash(&self) -> Vec<Target> {
        self.to_account
            .elements
            .iter()
            .copied()
            .chain(self.transfer_count.iter().copied())
            .chain(core::iter::once(self.asset_id))
            .chain(core::iter::once(self.input_amount))
            .collect()
    }

    /// Collect 32-bit targets for range checking.
    pub fn collect_32_bit_targets(&self) -> Vec<Target> {
        self.transfer_count
            .iter()
            .copied()
            .chain(core::iter::once(self.asset_id))
            .chain(core::iter::once(self.input_amount))
            .chain(core::iter::once(self.output_amount_1))
            .chain(core::iter::once(self.output_amount_2))
            .chain(core::iter::once(self.volume_fee_bps))
            .collect()
    }
}

/// Targets for the ZK Merkle proof verification.
#[derive(Debug, Clone)]
pub struct ZkMerkleProofTargets {
    /// Expected root hash (4 felts)
    pub root_hash: HashOutTarget,
    /// Proof depth (number of levels)
    pub depth: Target,
    /// Sibling hashes at each level (3 siblings per level, each 4 felts)
    /// Siblings are provided in **sorted order** (excluding current hash).
    /// Padded to MAX_DEPTH levels.
    pub siblings: Vec<[HashOutTarget; SIBLINGS_PER_LEVEL]>,
    /// Position hints (0-3) for each level indicating where current hash
    /// should be inserted among the sorted siblings.
    /// Padded to MAX_DEPTH levels.
    pub positions: Vec<Target>,
    /// Leaf data targets
    pub leaf: ZkLeafTargets,
    /// Flag for dummy proof detection
    pub is_not_dummy: BoolTarget,
}

impl ZkMerkleProofTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Leaf targets (includes public inputs)
        let leaf = ZkLeafTargets::new(builder);

        // Proof structure targets
        let root_hash = builder.add_virtual_hash();
        let depth = builder.add_virtual_target();
        let is_not_dummy = builder.add_virtual_bool_target_safe();

        // Siblings for each level (padded to MAX_DEPTH)
        let siblings: Vec<[HashOutTarget; SIBLINGS_PER_LEVEL]> = (0..MAX_DEPTH)
            .map(|_| array::from_fn(|_| builder.add_virtual_hash()))
            .collect();

        // Position hints for each level (padded to MAX_DEPTH)
        let positions: Vec<Target> = (0..MAX_DEPTH)
            .map(|_| builder.add_virtual_target())
            .collect();

        Self {
            root_hash,
            depth,
            siblings,
            positions,
            leaf,
            is_not_dummy,
        }
    }
}

// ============================================================================
// Runtime Data
// ============================================================================

/// Leaf data for the ZK Merkle proof.
#[derive(Debug, Clone)]
pub struct ZkLeafData {
    /// Recipient account (32 bytes)
    pub to_account: [F; HASH_NUM_FELTS],
    /// Transfer count (2 felts for u64)
    pub transfer_count: [F; 2],
    /// Asset ID
    pub asset_id: F,
    /// Input amount (quantized)
    pub input_amount: F,
    /// Output amount 1
    pub output_amount_1: F,
    /// Output amount 2
    pub output_amount_2: F,
    /// Volume fee in bps
    pub volume_fee_bps: F,
}

impl ZkLeafData {
    pub fn new(
        to_account: [u8; 32],
        transfer_count: u64,
        asset_id: u32,
        input_amount: u32,
        output_amount_1: u32,
        output_amount_2: u32,
        volume_fee_bps: u32,
    ) -> Self {
        use zk_circuits_common::serialization::bytes_to_digest;
        use zk_circuits_common::utils::u64_to_felts;

        Self {
            to_account: bytes_to_digest(&to_account),
            transfer_count: u64_to_felts(transfer_count),
            asset_id: F::from_canonical_u32(asset_id),
            input_amount: F::from_canonical_u32(input_amount),
            output_amount_1: F::from_canonical_u32(output_amount_1),
            output_amount_2: F::from_canonical_u32(output_amount_2),
            volume_fee_bps: F::from_canonical_u32(volume_fee_bps),
        }
    }

    /// Collect felts for leaf hash computation.
    pub fn collect_for_hash(&self) -> Vec<F> {
        self.to_account
            .iter()
            .copied()
            .chain(self.transfer_count.iter().copied())
            .chain(core::iter::once(self.asset_id))
            .chain(core::iter::once(self.input_amount))
            .collect()
    }
}

/// Runtime data for ZK Merkle proof verification.
#[derive(Debug, Clone)]
pub struct ZkMerkleProofData {
    /// Root hash (32 bytes as 4 felts)
    pub root_hash: [F; HASH_NUM_FELTS],
    /// Proof depth
    pub depth: usize,
    /// Sibling hashes at each level (in sorted order, excluding current hash)
    pub siblings: Vec<[[F; HASH_NUM_FELTS]; SIBLINGS_PER_LEVEL]>,
    /// Position hints (0-3) for each level
    pub positions: Vec<u8>,
    /// Leaf data
    pub leaf: ZkLeafData,
    /// Whether this is a real proof (not dummy)
    pub is_not_dummy: bool,
}

impl ZkMerkleProofData {
    /// Create proof data from raw components with pre-computed positions.
    pub fn new(
        root_hash: [u8; 32],
        siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]>,
        positions: Vec<u8>,
        leaf: ZkLeafData,
        is_not_dummy: bool,
    ) -> Self {
        use zk_circuits_common::serialization::bytes_to_digest;

        let root_hash = bytes_to_digest(&root_hash);
        let depth = siblings.len();
        let siblings: Vec<[[F; HASH_NUM_FELTS]; SIBLINGS_PER_LEVEL]> = siblings
            .into_iter()
            .map(|level| {
                [
                    bytes_to_digest(&level[0]),
                    bytes_to_digest(&level[1]),
                    bytes_to_digest(&level[2]),
                ]
            })
            .collect();

        Self {
            root_hash,
            depth,
            siblings,
            positions,
            leaf,
            is_not_dummy,
        }
    }

    /// Create proof data from unsorted siblings, computing positions automatically.
    pub fn from_unsorted(
        root_hash: [u8; 32],
        unsorted_siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]>,
        leaf_hash: [u8; 32],
        leaf: ZkLeafData,
        is_not_dummy: bool,
    ) -> Self {
        use zk_circuits_common::serialization::bytes_to_digest;
        use zk_circuits_common::zk_merkle::hash_node_presorted;

        let mut current_hash = leaf_hash;
        let mut sorted_siblings_bytes = Vec::with_capacity(unsorted_siblings.len());
        let mut positions = Vec::with_capacity(unsorted_siblings.len());

        for level_siblings in &unsorted_siblings {
            // Combine current hash with siblings
            let mut all_four: [Hash256; 4] = [
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
            sorted_siblings_bytes.push(sorted_sibs);

            // Compute parent hash for next level
            current_hash = hash_node_presorted(&all_four);
        }

        // Convert to felts
        let root_hash = bytes_to_digest(&root_hash);
        let siblings: Vec<[[F; HASH_NUM_FELTS]; SIBLINGS_PER_LEVEL]> = sorted_siblings_bytes
            .into_iter()
            .map(|level| {
                [
                    bytes_to_digest(&level[0]),
                    bytes_to_digest(&level[1]),
                    bytes_to_digest(&level[2]),
                ]
            })
            .collect();

        Self {
            root_hash,
            depth: siblings.len(),
            siblings,
            positions,
            leaf,
            is_not_dummy,
        }
    }
}

impl TryFrom<&CircuitInputs> for ZkMerkleProofData {
    type Error = anyhow::Error;

    fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
        // Detect dummy proofs (block_hash == 0 and outputs == 0)
        let is_not_dummy = !(inputs.public.block_hash.as_ref() == [0u8; 32]
            && inputs.public.output_amount_1 == 0
            && inputs.public.output_amount_2 == 0);

        let leaf = ZkLeafData::new(
            *inputs.private.unspendable_account,
            inputs.private.transfer_count,
            inputs.public.asset_id,
            inputs.private.input_amount,
            inputs.public.output_amount_1,
            inputs.public.output_amount_2,
            inputs.public.volume_fee_bps,
        );

        Ok(Self::new(
            inputs.private.zk_trie_root,
            inputs.private.zk_merkle_siblings.clone(),
            inputs.private.zk_merkle_positions.clone(),
            leaf,
            is_not_dummy,
        ))
    }
}

// ============================================================================
// Circuit Implementation
// ============================================================================

impl CircuitFragment for ZkMerkleProofData {
    type Targets = ZkMerkleProofTargets;

    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>) {
        use plonky2::hash::poseidon2::Poseidon2Hash;

        let zero = builder.zero();

        // Range check 32-bit targets
        for target in targets.leaf.collect_32_bit_targets() {
            builder.range_check(target, 32);
        }

        // Fee constraint: (output_1 + output_2) * 10000 <= input * (10000 - fee_bps)
        let ten_thousand = builder.constant(F::from_canonical_u32(10000));
        let total_output = builder.add(targets.leaf.output_amount_1, targets.leaf.output_amount_2);
        let lhs = builder.mul(total_output, ten_thousand);
        let fee_complement = builder.sub(ten_thousand, targets.leaf.volume_fee_bps);
        builder.range_check(fee_complement, 14); // fee_bps <= 10000
        let rhs = builder.mul(targets.leaf.input_amount, fee_complement);
        let diff = builder.sub(rhs, lhs);
        builder.range_check(diff, 48); // ensures lhs <= rhs

        // Compute leaf hash using injective Poseidon (matches chain's hash_leaf)
        // The chain uses qp_poseidon_core::hash_bytes which is injective (4 bytes/felt)
        let leaf_felts = targets.leaf.collect_for_hash();
        let leaf_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(leaf_felts);

        // Enforce depth <= MAX_DEPTH (proof can have at most MAX_DEPTH levels)
        let n_log = (usize::BITS - MAX_DEPTH.leading_zeros()) as usize;
        enforce_target_less_than_const(builder, targets.depth, MAX_DEPTH + 1, n_log);

        // Merkle proof verification: walk from leaf to root
        // The prover provides sorted siblings and a position hint at each level.
        // We insert current_hash at the indicated position and hash.
        let mut current_hash = leaf_hash;

        for level in 0..MAX_DEPTH {
            // is_active_level = (level < depth)
            let is_active_level = is_const_less_than(builder, level, targets.depth, n_log);

            // Get siblings and position for this level
            let siblings = &targets.siblings[level];
            let position = targets.positions[level];

            // Range check position to be 0-3 (2 bits)
            builder.range_check(position, 2);

            // Insert current_hash at the position indicated by the hint.
            // Position 0: [current, sib0, sib1, sib2]
            // Position 1: [sib0, current, sib1, sib2]
            // Position 2: [sib0, sib1, current, sib2]
            // Position 3: [sib0, sib1, sib2, current]
            //
            // We use select based on position to build each slot:
            let one = builder.one();
            let two = builder.constant(F::from_canonical_usize(2));
            let three = builder.constant(F::from_canonical_usize(3));

            let pos_is_0 = builder.is_equal(position, zero);
            let pos_is_1 = builder.is_equal(position, one);
            let pos_is_2 = builder.is_equal(position, two);
            let pos_is_3 = builder.is_equal(position, three);

            // Build the 4 children in sorted order based on position
            // child[i] = current if position == i, else siblings shifted appropriately
            let children: [HashOutTarget; 4] = array::from_fn(|slot| {
                // For each slot, determine which hash goes there
                // slot 0: current if pos==0, else sib0
                // slot 1: current if pos==1, else (sib0 if pos==0, else sib1)
                // slot 2: current if pos==2, else (sib1 if pos<=1, else sib2)
                // slot 3: current if pos==3, else sib2
                //
                // Simpler formulation:
                // - If position == slot: use current_hash
                // - Else: use siblings[slot - (1 if slot > position else 0)]
                //
                // We can compute this with selects:
                HashOutTarget {
                    elements: array::from_fn(|e| {
                        match slot {
                            0 => {
                                // slot 0: current if pos==0, else sib0
                                builder.select(
                                    pos_is_0,
                                    current_hash.elements[e],
                                    siblings[0].elements[e],
                                )
                            }
                            1 => {
                                // slot 1: current if pos==1, else (sib0 if pos==0, else sib1)
                                let not_current = builder.select(
                                    pos_is_0,
                                    siblings[0].elements[e],
                                    siblings[1].elements[e],
                                );
                                builder.select(pos_is_1, current_hash.elements[e], not_current)
                            }
                            2 => {
                                // slot 2: current if pos==2, else (sib1 if pos<=1, else sib2)
                                let pos_le_1 = builder.or(pos_is_0, pos_is_1);
                                let not_current = builder.select(
                                    pos_le_1,
                                    siblings[1].elements[e],
                                    siblings[2].elements[e],
                                );
                                builder.select(pos_is_2, current_hash.elements[e], not_current)
                            }
                            3 => {
                                // slot 3: current if pos==3, else sib2
                                builder.select(
                                    pos_is_3,
                                    current_hash.elements[e],
                                    siblings[2].elements[e],
                                )
                            }
                            _ => unreachable!(),
                        }
                    }),
                }
            });

            // Concatenate all 4 children hashes and compute parent hash
            // The chain uses compact encoding (8 bytes/felt) for internal nodes
            let mut parent_preimage = Vec::with_capacity(16); // 4 hashes * 4 felts each
            for child in &children {
                parent_preimage.extend_from_slice(&child.elements);
            }
            let parent_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(parent_preimage);

            // Update current_hash: use parent_hash if active level, else keep current
            current_hash = HashOutTarget {
                elements: array::from_fn(|i| {
                    builder.select(
                        is_active_level,
                        parent_hash.elements[i],
                        current_hash.elements[i],
                    )
                }),
            };
        }

        // Verify final hash equals expected root (only for non-dummy proofs)
        for i in 0..HASH_NUM_FELTS {
            let diff = builder.sub(current_hash.elements[i], targets.root_hash.elements[i]);
            let result = builder.mul(diff, targets.is_not_dummy.target);
            builder.connect(result, zero);
        }
    }

    fn fill_targets(
        &self,
        pw: &mut plonky2::iop::witness::PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        use anyhow::bail;
        use plonky2::iop::witness::WitnessWrite;

        // Validate depth
        if self.depth > MAX_DEPTH {
            bail!(
                "ZK Merkle proof depth {} exceeds maximum {}",
                self.depth,
                MAX_DEPTH
            );
        }

        // Validate positions length matches siblings
        if self.positions.len() != self.siblings.len() {
            bail!(
                "ZK Merkle proof positions length {} doesn't match siblings length {}",
                self.positions.len(),
                self.siblings.len()
            );
        }

        // Set root hash
        pw.set_hash_target(
            targets.root_hash,
            HashOut {
                elements: self.root_hash,
            },
        )?;

        // Set depth
        pw.set_target(targets.depth, F::from_canonical_usize(self.depth))?;

        // NOTE: is_not_dummy is computed in connect_shared_targets and connected
        // to the zk_merkle_proof target, so we don't set it here.
        // Setting it would cause a "partition set twice" error.

        // Set siblings and positions (pad with zeros for unused levels)
        let zero_hash = [F::ZERO; HASH_NUM_FELTS];
        for level in 0..MAX_DEPTH {
            let level_siblings = self.siblings.get(level);
            for sib_idx in 0..SIBLINGS_PER_LEVEL {
                let hash = level_siblings.map(|s| s[sib_idx]).unwrap_or(zero_hash);
                pw.set_hash_target(targets.siblings[level][sib_idx], HashOut { elements: hash })?;
            }

            // Set position hint (default to 0 for unused levels)
            let position = self.positions.get(level).copied().unwrap_or(0);
            if position > 3 {
                bail!(
                    "ZK Merkle proof position {} at level {} is invalid (must be 0-3)",
                    position,
                    level
                );
            }
            pw.set_target(targets.positions[level], F::from_canonical_u8(position))?;
        }

        // Set leaf targets
        pw.set_target_arr(&targets.leaf.to_account.elements, &self.leaf.to_account)?;
        pw.set_target_arr(&targets.leaf.transfer_count, &self.leaf.transfer_count)?;
        pw.set_target(targets.leaf.asset_id, self.leaf.asset_id)?;
        pw.set_target(targets.leaf.input_amount, self.leaf.input_amount)?;
        pw.set_target(targets.leaf.output_amount_1, self.leaf.output_amount_1)?;
        pw.set_target(targets.leaf.output_amount_2, self.leaf.output_amount_2)?;
        pw.set_target(targets.leaf.volume_fee_bps, self.leaf.volume_fee_bps)?;

        Ok(())
    }
}
