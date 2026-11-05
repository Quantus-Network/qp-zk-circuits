//! Constants and layout helpers for the public-batch aggregation circuit.

use qp_wormhole_inputs::PrivateBatchShape;

use crate::private_batch::circuit::constants::aggregated_output;

// -----------------------------------------------------------------------------
// Private-batch aggregated proof PI layout (input to public-batch)
// -----------------------------------------------------------------------------
//
// Private-batch output layout (per proof), for `shape = (N leaves, M exit slots)`:
// [ num_exit_slots(1),
//   asset_id(1),
//   volume_fee_bps(1),
//   block_hash(4),
//   block_number(1),
//   [amount(1), exit_account(4)] * M,
//   nullifier(4) * N ]
//
// Total length = 8 + 5M + 4N
// -----------------------------------------------------------------------------

// Re-export private-batch aggregated output constants for use in public-batch circuit.
// These describe the layout of each private-batch proof's public inputs.
pub use aggregated_output::{
    ASSET_ID_OFFSET as PRIVATE_BATCH_ASSET_ID_OFFSET,
    BLOCK_HASH_OFFSET as PRIVATE_BATCH_BLOCK_HASH_OFFSET,
    BLOCK_NUMBER_OFFSET as PRIVATE_BATCH_BLOCK_NUMBER_OFFSET,
    EXIT_SLOT_LEN as PRIVATE_BATCH_EXIT_SLOT_LEN, HEADER_LEN as PRIVATE_BATCH_HEADER_LEN,
    NUM_EXIT_SLOTS_OFFSET as PRIVATE_BATCH_NUM_EXIT_SLOTS_OFFSET,
    VOLUME_FEE_BPS_OFFSET as PRIVATE_BATCH_VOLUME_FEE_BPS_OFFSET,
};

#[inline]
pub const fn private_batch_exit_slots_count(shape: PrivateBatchShape) -> usize {
    aggregated_output::exit_slots_count(shape)
}

#[inline]
pub const fn private_batch_nullifiers_count(shape: PrivateBatchShape) -> usize {
    aggregated_output::nullifiers_count(shape)
}

#[inline]
pub const fn private_batch_exit_slots_start() -> usize {
    aggregated_output::exit_slots_start()
}

#[inline]
pub const fn private_batch_nullifiers_start(shape: PrivateBatchShape) -> usize {
    aggregated_output::nullifiers_start(shape)
}

#[inline]
pub const fn private_batch_pi_len(shape: PrivateBatchShape) -> usize {
    aggregated_output::pi_len(shape)
}

// -----------------------------------------------------------------------------
// Public-batch aggregated proof PI layout (output of public-batch circuit)
// -----------------------------------------------------------------------------
//
// [ aggregator_address(4),  <-- 4 felts (8 bytes/felt) for hash-derived accounts
//   asset_id(1),
//   volume_fee_bps(1),
//   block_hash(4),
//   block_number(1),
//   total_exit_slots(1),
//   [amount(1), exit_account(4)] * (n_inner * M),
//   nullifier(4) * (n_inner * N)
// ]
// -----------------------------------------------------------------------------

pub const AGGREGATOR_ADDRESS_LEN: usize = 4; // 4 felts (8 bytes/felt) for hash-derived accounts
pub const AGGREGATOR_ADDRESS_START: usize = 0;
pub const ASSET_ID_START: usize = AGGREGATOR_ADDRESS_START + AGGREGATOR_ADDRESS_LEN; // 4
pub const VOLUME_FEE_BPS_START: usize = ASSET_ID_START + 1; // 5
pub const BLOCK_HASH_START: usize = VOLUME_FEE_BPS_START + 1; // 6, 4 felts
pub const BLOCK_NUMBER_START: usize = BLOCK_HASH_START + 4; // 10
pub const TOTAL_EXIT_SLOTS_START: usize = BLOCK_NUMBER_START + 1; // 11

pub const PUBLIC_BATCH_HEADER_LEN: usize = TOTAL_EXIT_SLOTS_START + 1; // 12 = 4 + 1 + 1 + 4 + 1 + 1

#[inline]
pub const fn public_batch_total_exit_slots(n_inner: usize, shape: PrivateBatchShape) -> usize {
    n_inner * private_batch_exit_slots_count(shape)
}

#[inline]
pub const fn public_batch_total_nullifiers(n_inner: usize, shape: PrivateBatchShape) -> usize {
    n_inner * private_batch_nullifiers_count(shape)
}

#[inline]
pub const fn public_batch_exit_slots_start() -> usize {
    PUBLIC_BATCH_HEADER_LEN
}

#[inline]
pub const fn public_batch_nullifiers_start(n_inner: usize, shape: PrivateBatchShape) -> usize {
    PUBLIC_BATCH_HEADER_LEN
        + public_batch_total_exit_slots(n_inner, shape) * PRIVATE_BATCH_EXIT_SLOT_LEN
}

#[inline]
pub const fn public_batch_pi_len(n_inner: usize, shape: PrivateBatchShape) -> usize {
    PUBLIC_BATCH_HEADER_LEN
        + public_batch_total_exit_slots(n_inner, shape) * PRIVATE_BATCH_EXIT_SLOT_LEN
        + public_batch_total_nullifiers(n_inner, shape) * 4
}
