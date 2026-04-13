//! Constants and layout helpers for the layer-1 aggregation circuit.

use crate::layer0::circuit::constants::aggregated_output;

// -----------------------------------------------------------------------------
// Layer-0 aggregated proof PI layout (input to layer-1)
// -----------------------------------------------------------------------------
//
// Layer-0 output layout (per proof):
// [ num_exit_slots(1),
//   asset_id(1),
//   volume_fee_bps(1),
//   block_hash(4),
//   block_number(1),
//   [sum(1), exit(8)] * (2 * layer0_num_leaves),
//   nullifier(4) * layer0_num_leaves,
//   padding ... ]
//
// Total length = layer0_num_leaves * LEAF_PI_LEN + 8
// -----------------------------------------------------------------------------

// Re-export layer-0 aggregated output constants for use in layer-1 circuit.
// These describe the layout of each layer-0 proof's public inputs.
pub use aggregated_output::{
    ASSET_ID_OFFSET as L0_ASSET_ID_OFFSET, BLOCK_HASH_OFFSET as L0_BLOCK_HASH_OFFSET,
    BLOCK_NUMBER_OFFSET as L0_BLOCK_NUMBER_OFFSET, EXIT_SLOT_LEN as L0_EXIT_SLOT_LEN,
    HEADER_LEN as L0_HEADER_LEN, NUM_EXIT_SLOTS_OFFSET as L0_NUM_EXIT_SLOTS_OFFSET,
    VOLUME_FEE_BPS_OFFSET as L0_VOLUME_FEE_BPS_OFFSET,
};

#[inline]
pub const fn l0_exit_slots_count(layer0_num_leaves: usize) -> usize {
    aggregated_output::exit_slots_count(layer0_num_leaves)
}

#[inline]
pub const fn l0_nullifiers_count(layer0_num_leaves: usize) -> usize {
    aggregated_output::nullifiers_count(layer0_num_leaves)
}

#[inline]
pub const fn l0_exit_slots_start() -> usize {
    L0_HEADER_LEN
}

#[inline]
pub const fn l0_nullifiers_start(layer0_num_leaves: usize) -> usize {
    L0_HEADER_LEN + l0_exit_slots_count(layer0_num_leaves) * L0_EXIT_SLOT_LEN
}

#[inline]
pub const fn l0_pi_len(layer0_num_leaves: usize) -> usize {
    aggregated_output::pi_len(layer0_num_leaves)
}

// -----------------------------------------------------------------------------
// Layer-1 aggregated proof PI layout (output of layer-1 circuit)
// -----------------------------------------------------------------------------
//
// [ aggregator_address(4),  <-- 4 felts (8 bytes/felt) for hash-derived accounts
//   asset_id(1),
//   volume_fee_bps(1),
//   block_hash(4),
//   block_number(1),
//   total_exit_slots(1),
//   [sum(1), exit(4)] * (n_inner * 2 * layer0_num_leaves),
//   nullifier(4) * (n_inner * layer0_num_leaves)
// ]
// -----------------------------------------------------------------------------

pub const AGGREGATOR_ADDRESS_LEN: usize = 4; // 4 felts (8 bytes/felt) for hash-derived accounts
pub const AGGREGATOR_ADDRESS_START: usize = 0;
pub const ASSET_ID_START: usize = AGGREGATOR_ADDRESS_START + AGGREGATOR_ADDRESS_LEN; // 4
pub const VOLUME_FEE_BPS_START: usize = ASSET_ID_START + 1; // 5
pub const BLOCK_HASH_START: usize = VOLUME_FEE_BPS_START + 1; // 6, 4 felts
pub const BLOCK_NUMBER_START: usize = BLOCK_HASH_START + 4; // 10
pub const TOTAL_EXIT_SLOTS_START: usize = BLOCK_NUMBER_START + 1; // 11

pub const L1_HEADER_LEN: usize = TOTAL_EXIT_SLOTS_START + 1; // 12 = 4 + 1 + 1 + 4 + 1 + 1

#[inline]
pub const fn l1_total_exit_slots(n_inner: usize, layer0_num_leaves: usize) -> usize {
    n_inner * l0_exit_slots_count(layer0_num_leaves)
}

#[inline]
pub const fn l1_total_nullifiers(n_inner: usize, layer0_num_leaves: usize) -> usize {
    n_inner * l0_nullifiers_count(layer0_num_leaves)
}

#[inline]
pub const fn l1_exit_slots_start() -> usize {
    L1_HEADER_LEN
}

#[inline]
pub const fn l1_nullifiers_start(n_inner: usize, layer0_num_leaves: usize) -> usize {
    L1_HEADER_LEN + l1_total_exit_slots(n_inner, layer0_num_leaves) * L0_EXIT_SLOT_LEN
}

#[inline]
pub const fn l1_pi_len(n_inner: usize, layer0_num_leaves: usize) -> usize {
    L1_HEADER_LEN
        + l1_total_exit_slots(n_inner, layer0_num_leaves) * L0_EXIT_SLOT_LEN
        + l1_total_nullifiers(n_inner, layer0_num_leaves) * 4
}
