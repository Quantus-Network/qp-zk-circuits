//! Constants and layout helpers for the layer-1 aggregation circuit.

use crate::layer0::circuit::constants::LEAF_PI_LEN as L0_LEAF_PI_LEN;

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
//   [sum(1), exit(4)] * (2 * layer0_num_leaves),
//   nullifier(4) * layer0_num_leaves,
//   padding ... ]
//
// Total length = layer0_num_leaves * LEAF_PI_LEN + 8
// -----------------------------------------------------------------------------

pub const L0_NUM_EXIT_SLOTS_OFFSET: usize = 0;
pub const L0_ASSET_ID_OFFSET: usize = 1;
pub const L0_VOLUME_FEE_BPS_OFFSET: usize = 2;
pub const L0_BLOCK_HASH_OFFSET: usize = 3;
pub const L0_BLOCK_NUMBER_OFFSET: usize = 7;

pub const L0_HEADER_LEN: usize = 8;
pub const L0_EXIT_SLOT_LEN: usize = 5; // [sum(1), exit(4)]

#[inline]
pub const fn l0_exit_slots_count(layer0_num_leaves: usize) -> usize {
    layer0_num_leaves * 2
}

#[inline]
pub const fn l0_nullifiers_count(layer0_num_leaves: usize) -> usize {
    layer0_num_leaves
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
    // Layer-0 output uses fixed length = n_leaf * leaf_pi_len + header
    layer0_num_leaves * L0_LEAF_PI_LEN + L0_HEADER_LEN
}

#[inline]
pub const fn l0_num_leaves_from_pi_len(pi_len: usize) -> usize {
    // Inverse of l0_pi_len: given total PI length, extract layer0_num_leaves
    (pi_len - L0_HEADER_LEN) / L0_LEAF_PI_LEN
}

// -----------------------------------------------------------------------------
// Layer-1 aggregated proof PI layout (output of layer-1 circuit)
// -----------------------------------------------------------------------------
//
// [ aggregator_address(4),
//   asset_id(1),
//   volume_fee_bps(1),
//   block_hash(4),
//   block_number(1),
//   total_exit_slots(1),
//   [sum(1), exit(4)] * (n_inner * 2 * layer0_num_leaves),
//   nullifier(4) * (n_inner * layer0_num_leaves)
// ]
// -----------------------------------------------------------------------------

pub const AGGREGATOR_ADDRESS_START: usize = 0; // 4 felts
pub const ASSET_ID_START: usize = 4;
pub const VOLUME_FEE_BPS_START: usize = 5;
pub const BLOCK_HASH_START: usize = 6; // 4 felts
pub const BLOCK_NUMBER_START: usize = 10;
pub const TOTAL_EXIT_SLOTS_START: usize = 11;

pub const L1_HEADER_LEN: usize = 12; // 4 + 1 + 1 + 4 + 1 + 1

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
