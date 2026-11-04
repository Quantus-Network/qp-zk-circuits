//! Private-batch aggregation constants and public-input layout helpers.

/// Public inputs per leaf proof (Bitcoin-style 2-output layout)
///
/// Layout:
/// - asset_id(1)
/// - output_amount_1(1)
/// - output_amount_2(1)
/// - volume_fee_bps(1)
/// - nullifier(4)
/// - exit_account_1(4) - 4 felts (8 bytes/felt) for hash-derived accounts
/// - exit_account_2(4) - 4 felts (8 bytes/felt) for hash-derived accounts
/// - block_hash(4)
/// - block_number(1)
/// - input_amount(1) - intermediate only, not forwarded by aggregation
///
/// Total = 22 felts
pub const LEAF_PI_LEN: usize = 22;

pub const ASSET_ID_START: usize = 0; // 1 felt
pub const OUTPUT_AMOUNT_1_START: usize = 1; // 1 felt
pub const OUTPUT_AMOUNT_2_START: usize = 2; // 1 felt
pub const VOLUME_FEE_BPS_START: usize = 3; // 1 felt
pub const NULLIFIER_START: usize = 4; // 4 felts
pub const EXIT_1_START: usize = 8; // 4 felts
pub const EXIT_2_START: usize = 12; // 4 felts
pub const BLOCK_HASH_START: usize = 16; // 4 felts
pub const BLOCK_NUMBER_START: usize = 20; // 1 felt
pub const INPUT_AMOUNT_START: usize = 21; // 1 felt

/// Private-batch aggregated proof output layout.
///
/// ```text
/// [num_exit_slots(1), asset_id(1), volume_fee_bps(1),
///  block_hash(4), block_number(1),
///  [amount(1), exit_account(4)] * M,
///  nullifier(4) * N]
/// ```
///
/// where `M = shape.num_exit_slots` and `N = shape.num_leaf_proofs`.
///
/// The shape-parameterized helpers use UNCHECKED arithmetic and assume the
/// shape was already bounded with
/// [`PrivateBatchShape::validate`](qp_wormhole_inputs::PrivateBatchShape::validate),
/// per the repo-wide invariant that every externally supplied batch dimension
/// is validated at its API boundary before any allocation or arithmetic.
pub mod aggregated_output {
    pub use qp_wormhole_inputs::private_batch_pi::{
        exit_slots_start, nullifiers_start, pi_len, EXIT_SLOT_LEN, HEADER_LEN, NULLIFIER_LEN,
    };
    use qp_wormhole_inputs::{private_batch_pi, PrivateBatchShape};

    /// Offset of `num_exit_slots` in the output PIs.
    pub const NUM_EXIT_SLOTS_OFFSET: usize = private_batch_pi::NUM_EXIT_SLOTS_INDEX;
    /// Offset of `asset_id` in the output PIs.
    pub const ASSET_ID_OFFSET: usize = private_batch_pi::ASSET_ID_INDEX;
    /// Offset of `volume_fee_bps` in the output PIs.
    pub const VOLUME_FEE_BPS_OFFSET: usize = private_batch_pi::VOLUME_FEE_BPS_INDEX;
    /// Offset of `block_hash` (4 felts) in the output PIs.
    pub const BLOCK_HASH_OFFSET: usize = private_batch_pi::BLOCK_HASH_START_INDEX;
    /// Offset of `block_number` in the output PIs.
    pub const BLOCK_NUMBER_OFFSET: usize = private_batch_pi::BLOCK_NUMBER_INDEX;

    /// Number of exit slots in the output.
    pub const fn exit_slots_count(shape: PrivateBatchShape) -> usize {
        shape.num_exit_slots
    }

    /// Number of nullifiers in the output (one per leaf proof).
    pub const fn nullifiers_count(shape: PrivateBatchShape) -> usize {
        shape.num_leaf_proofs
    }
}
