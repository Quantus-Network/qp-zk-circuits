//! Layer-0 aggregation constants and public-input layout helpers.

use plonky2::plonk::circuit_data::CircuitConfig;
use zk_circuits_common::circuit::wormhole_aggregator_circuit_config;

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
///
/// Total = 21 felts
pub const LEAF_PI_LEN: usize = 21;

pub const ASSET_ID_START: usize = 0; // 1 felt
pub const OUTPUT_AMOUNT_1_START: usize = 1; // 1 felt
pub const OUTPUT_AMOUNT_2_START: usize = 2; // 1 felt
pub const VOLUME_FEE_BPS_START: usize = 3; // 1 felt
pub const NULLIFIER_START: usize = 4; // 4 felts
pub const EXIT_1_START: usize = 8; // 4 felts
pub const EXIT_2_START: usize = 12; // 4 felts
pub const BLOCK_HASH_START: usize = 16; // 4 felts
pub const BLOCK_NUMBER_START: usize = 20; // 1 felt

/// Layer-0 aggregated proof output layout constants.
///
/// Output layout:
/// ```text
/// [num_exit_slots(1), asset_id(1), volume_fee_bps(1),
///  block_hash(4), block_number(1),
///  [sum(1), exit_account(4)] * (2*N),
///  nullifier(4) * N,
///  padding...]
/// ```
pub mod aggregated_output {
    use super::LEAF_PI_LEN;

    /// Offset of `num_exit_slots` in the output PIs.
    pub const NUM_EXIT_SLOTS_OFFSET: usize = 0;
    /// Offset of `asset_id` in the output PIs.
    pub const ASSET_ID_OFFSET: usize = 1;
    /// Offset of `volume_fee_bps` in the output PIs.
    pub const VOLUME_FEE_BPS_OFFSET: usize = 2;
    /// Offset of `block_hash` (4 felts) in the output PIs.
    pub const BLOCK_HASH_OFFSET: usize = 3;
    /// Offset of `block_number` in the output PIs.
    pub const BLOCK_NUMBER_OFFSET: usize = 7;

    /// Length of fixed header before exit-slot data.
    pub const HEADER_LEN: usize = 8;

    /// Each exit slot is [sum(1), exit_account(4)] = 5 felts.
    pub const EXIT_SLOT_LEN: usize = 5;

    /// Number of exit slots for N leaves (2 outputs per leaf).
    pub const fn exit_slots_count(num_leaves: usize) -> usize {
        num_leaves * 2
    }

    /// Number of nullifiers for N leaves (one per leaf proof).
    pub const fn nullifiers_count(num_leaves: usize) -> usize {
        num_leaves
    }

    /// Offset where exit-slot region starts.
    pub const fn exit_slots_start() -> usize {
        HEADER_LEN
    }

    /// Offset where nullifier region starts.
    pub const fn nullifiers_start(num_leaves: usize) -> usize {
        HEADER_LEN + exit_slots_count(num_leaves) * EXIT_SLOT_LEN
    }

    /// Total public-input length for the layer-0 aggregation circuit.
    ///
    /// We intentionally pad to `N * LEAF_PI_LEN + 8` to match the legacy wrapper sizing:
    /// - merged root PI length = `N * LEAF_PI_LEN`
    /// - wrapper output length = `merged_root_len + 8`
    pub const fn pi_len(num_leaves: usize) -> usize {
        LEAF_PI_LEN * num_leaves + 8
    }
}

/// Fixed inner batch size for the shipping 2x8 layer-0 path.
pub const INNER_NUM_LEAVES: usize = 8;

/// Final production leaf capacity.
pub const TOTAL_NUM_LEAVES: usize = INNER_NUM_LEAVES * 2;

/// Inner artifact filenames.
pub const INNER_COMMON_FILENAME: &str = "inner_common.bin";
pub const INNER_VERIFIER_FILENAME: &str = "inner_verifier.bin";
pub const INNER_PROVER_FILENAME: &str = "inner_prover.bin";
pub const INNER_TARGETS_FILENAME: &str = "inner_targets.bin";

/// Outer artifact filenames.
pub const OUTER_COMMON_FILENAME: &str = "outer_common.bin";
pub const OUTER_VERIFIER_FILENAME: &str = "outer_verifier.bin";
pub const OUTER_PROVER_FILENAME: &str = "outer_prover.bin";
pub const OUTER_TARGETS_FILENAME: &str = "outer_targets.bin";

/// Shared compact-child PI accounting for the shipping 2x8 topology.
pub const INNER_EXIT_SLOTS: usize = aggregated_output::exit_slots_count(INNER_NUM_LEAVES);
pub const INNER_OUTPUT_PI_LEN: usize = aggregated_output::HEADER_LEN
    + INNER_EXIT_SLOTS * aggregated_output::EXIT_SLOT_LEN
    + INNER_NUM_LEAVES * 4;

pub const OUTER_INNER_PROOFS: usize = 2;
pub const OUTER_CHILD_NUM_LEAVES: usize = INNER_NUM_LEAVES;
pub const OUTER_CHILD_EXIT_SLOTS: usize =
    aggregated_output::exit_slots_count(OUTER_CHILD_NUM_LEAVES);
pub const OUTER_CHILD_NULLIFIERS: usize =
    aggregated_output::nullifiers_count(OUTER_CHILD_NUM_LEAVES);
pub const OUTER_CHILD_HEADER_LEN: usize = aggregated_output::HEADER_LEN;
pub const OUTER_CHILD_EXIT_SLOT_LEN: usize = aggregated_output::EXIT_SLOT_LEN;
pub const OUTER_CHILD_EXIT_SLOTS_START: usize = OUTER_CHILD_HEADER_LEN;
pub const OUTER_CHILD_NULLIFIERS_START: usize =
    OUTER_CHILD_EXIT_SLOTS_START + OUTER_CHILD_EXIT_SLOTS * OUTER_CHILD_EXIT_SLOT_LEN;
pub const OUTER_CHILD_PI_LEN: usize = OUTER_CHILD_NULLIFIERS_START + OUTER_CHILD_NULLIFIERS * 4;
pub const OUTER_OUTPUT_PI_LEN: usize = aggregated_output::pi_len(TOTAL_NUM_LEAVES);
pub const OUTER_FINAL_EXIT_SLOTS: usize = aggregated_output::exit_slots_count(TOTAL_NUM_LEAVES);

pub fn inner_circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config()
}

pub fn outer_circuit_config() -> CircuitConfig {
    wormhole_aggregator_circuit_config()
}
