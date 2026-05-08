//! Public input types for Wormhole circuit proofs.
//!
//! This crate provides the data structures needed to parse and represent
//! public inputs from Wormhole ZK proofs. It is designed to be lightweight
//! and have minimal dependencies, making it suitable for use in both
//! prover and verifier contexts.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::fmt;
use alloc::format;
use alloc::vec::Vec;
use anyhow::{bail, Context};
use core::ops::Deref;

/// Number of bytes in a digest (32 bytes = 256 bits)
pub const DIGEST_BYTES_LEN: usize = 32;

/// Goldilocks field order (2^64 - 2^32 + 1)
/// Used to validate that bytes can be represented as field elements
const GOLDILOCKS_ORDER: u64 = 0xFFFFFFFF00000001;

/// The total size of the public inputs field element vector.
/// Layout: asset_id(1) + output_amount_1(1) + output_amount_2(1) + volume_fee_bps(1) +
///         nullifier(4) + exit_account_1(4) + exit_account_2(4) + block_hash(4) + block_number(1)
/// = 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + 1 = 21
///
/// Note: exit accounts use 4 felts (8 bytes/felt) for hash-derived accounts.
/// parent_hash is a private input to the leaf circuit (used to compute block_hash)
/// but is not exposed as a public input since block_hash already commits to it.
pub const PUBLIC_INPUTS_FELTS_LEN: usize = 21;

/// Current public-input layout version for layer-0 aggregated proofs.
pub const L0_AGGREGATED_PUBLIC_INPUT_LAYOUT_VERSION: u32 = 1;

/// Current public-input layout version for layer-1 aggregated proofs.
pub const L1_AGGREGATED_PUBLIC_INPUT_LAYOUT_VERSION: u32 = 1;

// Index constants for parsing public inputs
pub const ASSET_ID_INDEX: usize = 0;
pub const OUTPUT_AMOUNT_1_INDEX: usize = 1;
pub const OUTPUT_AMOUNT_2_INDEX: usize = 2;
pub const VOLUME_FEE_BPS_INDEX: usize = 3;
pub const NULLIFIER_START_INDEX: usize = 4;
pub const NULLIFIER_END_INDEX: usize = 8;
pub const EXIT_ACCOUNT_1_START_INDEX: usize = 8;
pub const EXIT_ACCOUNT_1_END_INDEX: usize = 12;
pub const EXIT_ACCOUNT_2_START_INDEX: usize = 12;
pub const EXIT_ACCOUNT_2_END_INDEX: usize = 16;
pub const BLOCK_HASH_START_INDEX: usize = 16;
pub const BLOCK_HASH_END_INDEX: usize = 20;
pub const BLOCK_NUMBER_INDEX: usize = 20;

// Layer-1 aggregated public input layout.
//
// [aggregator_address(4),
//  asset_id(1),
//  volume_fee_bps(1),
//  block_hash(4),
//  block_number(1),
//  total_exit_slots(1),
//  [sum(1), exit_account(4)] * total_exit_slots,
//  nullifier(4) * (total_exit_slots / 2)]
pub const L1_AGGREGATOR_ADDRESS_LEN: usize = 4;
pub const L1_AGGREGATOR_ADDRESS_START_INDEX: usize = 0;
pub const L1_AGGREGATOR_ADDRESS_END_INDEX: usize =
    L1_AGGREGATOR_ADDRESS_START_INDEX + L1_AGGREGATOR_ADDRESS_LEN;
pub const L1_ASSET_ID_INDEX: usize = L1_AGGREGATOR_ADDRESS_END_INDEX;
pub const L1_VOLUME_FEE_BPS_INDEX: usize = L1_ASSET_ID_INDEX + 1;
pub const L1_BLOCK_HASH_START_INDEX: usize = L1_VOLUME_FEE_BPS_INDEX + 1;
pub const L1_BLOCK_HASH_END_INDEX: usize = L1_BLOCK_HASH_START_INDEX + 4;
pub const L1_BLOCK_NUMBER_INDEX: usize = L1_BLOCK_HASH_END_INDEX;
pub const L1_TOTAL_EXIT_SLOTS_INDEX: usize = L1_BLOCK_NUMBER_INDEX + 1;
pub const L1_HEADER_FELTS_LEN: usize = L1_TOTAL_EXIT_SLOTS_INDEX + 1;
pub const L1_EXIT_SLOT_FELTS_LEN: usize = 5;
pub const L1_NULLIFIER_FELTS_LEN: usize = 4;

/// A 32-byte digest that can be converted to/from field elements.
#[derive(Hash, Default, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct BytesDigest([u8; DIGEST_BYTES_LEN]);

impl BytesDigest {
    /// Create a BytesDigest without validation.
    ///
    /// Use this for the 4-bytes-per-felt encoding where each chunk is a u32
    /// and doesn't need to fit in an 8-byte field element constraint.
    pub const fn new_unchecked(bytes: [u8; DIGEST_BYTES_LEN]) -> Self {
        BytesDigest(bytes)
    }
}

impl fmt::Debug for BytesDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BytesDigest(0x")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

/// Errors that can occur when working with digests
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    /// A chunk of bytes exceeds the field order
    ChunkOutOfFieldRange { chunk_index: usize, value: u64 },
    /// The input has an invalid length
    InvalidLength { expected: usize, got: usize },
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestError::ChunkOutOfFieldRange { chunk_index, value } => {
                write!(
                    f,
                    "Chunk out of field range at index {}: {}",
                    chunk_index, value
                )
            }
            DigestError::InvalidLength { expected, got } => {
                write!(f, "Invalid length: expected {}, got {}", expected, got)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DigestError {}

impl TryFrom<&[u8]> for BytesDigest {
    type Error = DigestError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; DIGEST_BYTES_LEN] =
            value.try_into().map_err(|_| DigestError::InvalidLength {
                expected: DIGEST_BYTES_LEN,
                got: value.len(),
            })?;
        BytesDigest::try_from(bytes)
    }
}

impl TryFrom<[u8; DIGEST_BYTES_LEN]> for BytesDigest {
    type Error = DigestError;

    fn try_from(value: [u8; DIGEST_BYTES_LEN]) -> Result<Self, Self::Error> {
        // Validate that each 8-byte chunk fits in the Goldilocks field
        for (i, chunk) in value.chunks(8).enumerate() {
            let v =
                u64::from_le_bytes(chunk.try_into().map_err(|_| DigestError::InvalidLength {
                    expected: 8,
                    got: chunk.len(),
                })?);
            if v >= GOLDILOCKS_ORDER {
                return Err(DigestError::ChunkOutOfFieldRange {
                    chunk_index: i,
                    value: v,
                });
            }
        }
        Ok(BytesDigest(value))
    }
}

impl Deref for BytesDigest {
    type Target = [u8; DIGEST_BYTES_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for BytesDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// All of the public inputs required for a single wormhole proof.
/// Supports two outputs (spend + change) from a single input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCircuitInputs {
    /// The asset ID (0 for native token).
    pub asset_id: u32,
    /// Amount to be received by the first exit account (spend).
    /// This value is quantized with 0.01 units of precision.
    ///
    /// **DEV NOTE**: The output amount unit on chain is still u128 with 12 decimals so we will need to
    /// scale by 10^10 when constructing the output amount during on-chain verification.
    pub output_amount_1: u32,
    /// Amount to be received by the second exit account (change).
    /// Set to 0 if only one output is needed.
    pub output_amount_2: u32,
    /// Volume fee rate in basis points (1 basis point = 0.01%).
    /// This is verified on-chain to match the runtime configuration.
    pub volume_fee_bps: u32,
    /// The nullifier (prevents double-spending).
    pub nullifier: BytesDigest,
    /// The address of the first exit account (spend destination).
    pub exit_account_1: BytesDigest,
    /// The address of the second exit account (change destination).
    /// Set to all zeros if only one output is needed.
    pub exit_account_2: BytesDigest,
    /// The hash of the block header.
    pub block_hash: BytesDigest,
    /// The block number, parsed from the block header.
    pub block_number: u32,
}

/// Exit account data in aggregated proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputsByAccount {
    /// Output amounts of duplicate exit accounts summed.
    pub summed_output_amount: u32,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
}

/// Block data (block_hash, block_number) in aggregated proofs.
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct BlockData {
    /// The hash of the block header.
    pub block_hash: BytesDigest,
    /// The block number, parsed from the block header.
    pub block_number: u32,
}

/// Aggregated public inputs from multiple wormhole proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedPublicCircuitInputs {
    /// Number of unique exit-account groups reported by the wrapper circuit.
    /// This is informational only; semantic validation remains the circuit's responsibility.
    pub num_unique_exits: u32,
    /// The asset ID of the set (0 for native token).
    pub asset_id: u32,
    /// Volume fee rate in basis points (1 basis point = 0.01%).
    /// All aggregated proofs must have the same fee rate.
    pub volume_fee_bps: u32,
    /// The block data (block_hash, block_number) for all aggregated proofs.
    /// All proofs in the aggregation must reference the same block for their storage proofs.
    /// Note: The underlying transfers can occur in different blocks; this constraint only
    /// applies to the block used to generate the storage proof (i.e., when the proof is created).
    pub block_data: BlockData,
    /// The set of exit accounts and their summed output amounts.
    pub account_data: Vec<PublicInputsByAccount>,
    /// The nullifiers of each individual transfer proof.
    pub nullifiers: Vec<BytesDigest>,
}

/// Layer-1 aggregated public inputs from multiple layer-0 aggregated proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer1AggregatedPublicCircuitInputs {
    /// Aggregation reward address committed by the delegated layer-1 proof.
    pub aggregator_address: BytesDigest,
    /// The asset ID of the set (0 for native token).
    pub asset_id: u32,
    /// Volume fee rate in basis points (1 basis point = 0.01%).
    pub volume_fee_bps: u32,
    /// The block data (block_hash, block_number) shared by all child layer-0 proofs.
    pub block_data: BlockData,
    /// Number of exit slots forwarded by the layer-1 circuit.
    pub total_exit_slots: u32,
    /// Forwarded exit account data from all child layer-0 proofs.
    pub account_data: Vec<PublicInputsByAccount>,
    /// Forwarded nullifiers from all child layer-0 proofs.
    pub nullifiers: Vec<BytesDigest>,
    /// Reserved for the future constrained bundle-root public input.
    pub bundle_root: Option<BytesDigest>,
    /// Reserved for an explicit circuit identifier public input.
    pub circuit_id: Option<BytesDigest>,
    /// Reserved for an explicit in-circuit layout version public input.
    pub layout_version: Option<u32>,
}

/// Helper to convert 4 u64 values (hash output) to a BytesDigest.
/// Each felt contributes 8 bytes (its full u64 representation).
/// Used for hash outputs which are native field elements.
fn hash_u64s_to_bytes_digest(vals: &[u64]) -> anyhow::Result<BytesDigest> {
    if vals.len() != 4 {
        bail!(
            "Expected 4 field elements for hash digest, got {}",
            vals.len()
        );
    }
    let mut bytes = [0u8; DIGEST_BYTES_LEN];
    for (i, &val) in vals.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
    BytesDigest::try_from(bytes).map_err(|e| anyhow::anyhow!("{}", e))
}

impl PublicCircuitInputs {
    /// Parse public inputs from a slice of u64 values (canonical representation of field elements).
    pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
        if pis.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain {} field elements, got {}",
                PUBLIC_INPUTS_FELTS_LEN,
                pis.len()
            );
        }

        let asset_id: u32 = pis[ASSET_ID_INDEX]
            .try_into()
            .context("failed to convert asset_id to u32")?;
        let output_amount_1: u32 = pis[OUTPUT_AMOUNT_1_INDEX]
            .try_into()
            .context("failed to convert output_amount_1 to u32")?;
        let output_amount_2: u32 = pis[OUTPUT_AMOUNT_2_INDEX]
            .try_into()
            .context("failed to convert output_amount_2 to u32")?;
        let volume_fee_bps: u32 = pis[VOLUME_FEE_BPS_INDEX]
            .try_into()
            .context("failed to convert volume_fee_bps to u32")?;

        let nullifier = hash_u64s_to_bytes_digest(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
            .context("failed to parse nullifier")?;
        let exit_account_1 =
            hash_u64s_to_bytes_digest(&pis[EXIT_ACCOUNT_1_START_INDEX..EXIT_ACCOUNT_1_END_INDEX])
                .context("failed to parse exit_account_1")?;
        let exit_account_2 =
            hash_u64s_to_bytes_digest(&pis[EXIT_ACCOUNT_2_START_INDEX..EXIT_ACCOUNT_2_END_INDEX])
                .context("failed to parse exit_account_2")?;
        let block_hash =
            hash_u64s_to_bytes_digest(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
                .context("failed to parse block_hash")?;

        let block_number: u32 = pis[BLOCK_NUMBER_INDEX]
            .try_into()
            .context("failed to convert block_number to u32")?;

        Ok(PublicCircuitInputs {
            asset_id,
            output_amount_1,
            output_amount_2,
            volume_fee_bps,
            nullifier,
            exit_account_1,
            exit_account_2,
            block_hash,
            block_number,
        })
    }
}

impl AggregatedPublicCircuitInputs {
    /// Parse aggregated public inputs from a slice of u64 values.
    pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
        // Layout in the FINAL (deduped) wrapper proof PIs:
        // [num_unique_exits, asset_id, volume_fee_bps, block_data(5),
        //  [output_sum(1), exit_account(4)] * 2*N,  <-- 2 outputs per leaf
        //  nullifiers(4) * N, padding...]
        //
        // IMPORTANT: With 2 outputs per leaf, we have 2*N exit slots.
        // The parser validates shape/layout only. Circuit-level semantic constraints such as
        // same-block and same-asset consistency remain enforced by the proving circuit.

        if pis.len() < 8 {
            bail!(
                "AggregatedPI: too few elements, need at least 8 for header, got {}",
                pis.len()
            );
        }

        let payload_len = pis.len() - 8;
        if !payload_len.is_multiple_of(PUBLIC_INPUTS_FELTS_LEN) {
            bail!(
                "AggregatedPI: malformed length {} - expected 8 + N*{} felts for the padded aggregated layout",
                pis.len(),
                PUBLIC_INPUTS_FELTS_LEN
            );
        }

        let num_unique_exits: u32 = pis[0]
            .try_into()
            .context("AggregatedPI: num_unique_exits at index 0 exceeds u32 range")?;

        let asset_id: u32 = pis[1]
            .try_into()
            .context("AggregatedPI: asset_id at index 1 exceeds u32 range")?;
        let volume_fee_bps: u32 = pis[2]
            .try_into()
            .context("AggregatedPI: volume_fee_bps at index 2 exceeds u32 range")?;

        // Number of leaf proofs (N) is derived from the padded total PI length.
        let n_leaf = payload_len / PUBLIC_INPUTS_FELTS_LEN;

        if n_leaf == 0 {
            bail!(
                "AggregatedPI: n_leaf is 0 (pis.len()={}, PUBLIC_INPUTS_FELTS_LEN={})",
                pis.len(),
                PUBLIC_INPUTS_FELTS_LEN
            );
        }

        let block_hash = hash_u64s_to_bytes_digest(&pis[3..7])
            .context("AggregatedPI: parsing block_hash from indices 3..7")?;
        let block_number: u32 = pis[7]
            .try_into()
            .context("AggregatedPI: parsing block_number from index 7")?;

        let block_data = BlockData {
            block_hash,
            block_number,
        };

        let mut cursor = 8usize;

        // Read 2*N exit account slots (two outputs per leaf proof)
        let num_exit_slots = n_leaf * 2;
        let mut account_data = Vec::with_capacity(num_exit_slots);
        for i in 0..num_exit_slots {
            if cursor >= pis.len() {
                bail!(
                    "AggregatedPI: cursor {} out of bounds (pis.len={}) while reading account {}",
                    cursor,
                    pis.len(),
                    i
                );
            }
            let summed_output_amount: u32 = pis[cursor].try_into().with_context(|| {
                format!(
                    "AggregatedPI: summed_output_amount at cursor {} exceeds u32 range",
                    cursor
                )
            })?;
            cursor += 1;

            if cursor + 4 > pis.len() {
                bail!(
                    "AggregatedPI: not enough elements for exit_account {} (need cursor+4={}, have {})",
                    i,
                    cursor + 4,
                    pis.len()
                );
            }
            let exit_account =
                hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                    format!(
                        "AggregatedPI: parsing exit_account[{}] at cursor {}",
                        i, cursor
                    )
                })?;
            cursor += 4;

            account_data.push(PublicInputsByAccount {
                summed_output_amount,
                exit_account,
            });
        }

        // Read N nullifiers (one per leaf proof)
        let mut nullifiers = Vec::with_capacity(n_leaf);
        for i in 0..n_leaf {
            if cursor + 4 > pis.len() {
                bail!(
                    "AggregatedPI: not enough elements for nullifier {} (need cursor+4={}, have {})",
                    i,
                    cursor + 4,
                    pis.len()
                );
            }
            let n = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                format!(
                    "AggregatedPI: parsing nullifier[{}] at cursor {}",
                    i, cursor
                )
            })?;
            cursor += 4;

            nullifiers.push(n);
        }

        // Verify we consumed expected number of felts
        // 8 metadata + 2*N*5 exit slots (1 sum + 4 account) + N*4 nullifiers
        let expected_felts = 8 + num_exit_slots * 5 + n_leaf * 4;
        if cursor != expected_felts {
            bail!(
                "AggregatedPI: cursor mismatch - consumed {} felts, expected {} (n_leaf={}, num_exit_slots={})",
                cursor,
                expected_felts,
                n_leaf,
                num_exit_slots
            );
        }

        Ok(AggregatedPublicCircuitInputs {
            num_unique_exits,
            asset_id,
            volume_fee_bps,
            block_data,
            account_data,
            nullifiers,
        })
    }
}

impl Layer1AggregatedPublicCircuitInputs {
    /// Parse layer-1 aggregated public inputs from a slice of u64 values.
    pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
        if pis.len() < L1_HEADER_FELTS_LEN {
            bail!(
                "Layer1AggregatedPI: too few elements, need at least {} for header, got {}",
                L1_HEADER_FELTS_LEN,
                pis.len()
            );
        }

        let aggregator_address = hash_u64s_to_bytes_digest(
            &pis[L1_AGGREGATOR_ADDRESS_START_INDEX..L1_AGGREGATOR_ADDRESS_END_INDEX],
        )
        .context("Layer1AggregatedPI: parsing aggregator_address")?;

        let asset_id: u32 = pis[L1_ASSET_ID_INDEX]
            .try_into()
            .context("Layer1AggregatedPI: asset_id exceeds u32 range")?;
        let volume_fee_bps: u32 = pis[L1_VOLUME_FEE_BPS_INDEX]
            .try_into()
            .context("Layer1AggregatedPI: volume_fee_bps exceeds u32 range")?;
        let block_hash =
            hash_u64s_to_bytes_digest(&pis[L1_BLOCK_HASH_START_INDEX..L1_BLOCK_HASH_END_INDEX])
                .context("Layer1AggregatedPI: parsing block_hash")?;
        let block_number: u32 = pis[L1_BLOCK_NUMBER_INDEX]
            .try_into()
            .context("Layer1AggregatedPI: block_number exceeds u32 range")?;
        let total_exit_slots: u32 = pis[L1_TOTAL_EXIT_SLOTS_INDEX]
            .try_into()
            .context("Layer1AggregatedPI: total_exit_slots exceeds u32 range")?;

        let total_exit_slots_usize: usize = total_exit_slots
            .try_into()
            .context("Layer1AggregatedPI: total_exit_slots exceeds usize range")?;
        let Some(exit_slots_felts) = total_exit_slots_usize.checked_mul(L1_EXIT_SLOT_FELTS_LEN)
        else {
            bail!(
                "Layer1AggregatedPI: total_exit_slots {} overflows exit-slot felt length",
                total_exit_slots
            );
        };

        let mut cursor = L1_HEADER_FELTS_LEN;
        let Some(exit_slots_end) = cursor.checked_add(exit_slots_felts) else {
            bail!(
                "Layer1AggregatedPI: exit slots end overflows (cursor={}, slots={})",
                cursor,
                total_exit_slots
            );
        };
        if exit_slots_end > pis.len() {
            bail!(
                "Layer1AggregatedPI: not enough elements for {} exit slots (need {}, got {})",
                total_exit_slots,
                exit_slots_end,
                pis.len()
            );
        }

        let mut account_data = Vec::with_capacity(total_exit_slots_usize);
        for i in 0..total_exit_slots_usize {
            let summed_output_amount: u32 = pis[cursor].try_into().with_context(|| {
                format!(
                    "Layer1AggregatedPI: summed_output_amount at cursor {} exceeds u32 range",
                    cursor
                )
            })?;
            cursor += 1;

            let exit_account =
                hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                    format!(
                        "Layer1AggregatedPI: parsing exit_account[{}] at cursor {}",
                        i, cursor
                    )
                })?;
            cursor += 4;

            account_data.push(PublicInputsByAccount {
                summed_output_amount,
                exit_account,
            });
        }

        let remaining = pis.len() - cursor;
        if !remaining.is_multiple_of(L1_NULLIFIER_FELTS_LEN) {
            bail!(
                "Layer1AggregatedPI: malformed nullifier length {} - expected a multiple of {} felts",
                remaining,
                L1_NULLIFIER_FELTS_LEN
            );
        }

        let nullifier_count = remaining / L1_NULLIFIER_FELTS_LEN;
        if !total_exit_slots_usize.is_multiple_of(2) {
            bail!(
                "Layer1AggregatedPI: total_exit_slots {} is not even; expected two exit slots per nullifier",
                total_exit_slots
            );
        }
        if nullifier_count * 2 != total_exit_slots_usize {
            bail!(
                "Layer1AggregatedPI: inconsistent shape - total_exit_slots={} implies {} nullifiers, got {}",
                total_exit_slots,
                total_exit_slots_usize / 2,
                nullifier_count
            );
        }

        let mut nullifiers = Vec::with_capacity(nullifier_count);
        for i in 0..nullifier_count {
            let nullifier =
                hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                    format!(
                        "Layer1AggregatedPI: parsing nullifier[{}] at cursor {}",
                        i, cursor
                    )
                })?;
            cursor += 4;
            nullifiers.push(nullifier);
        }

        if cursor != pis.len() {
            bail!(
                "Layer1AggregatedPI: cursor mismatch - consumed {} felts, input length {}",
                cursor,
                pis.len()
            );
        }

        Ok(Layer1AggregatedPublicCircuitInputs {
            aggregator_address,
            asset_id,
            volume_fee_bps,
            block_data: BlockData {
                block_hash,
                block_number,
            },
            total_exit_slots,
            account_data,
            nullifiers,
            bundle_root: None,
            circuit_id: None,
            layout_version: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        hash_u64s_to_bytes_digest, AggregatedPublicCircuitInputs,
        Layer1AggregatedPublicCircuitInputs, L1_AGGREGATOR_ADDRESS_START_INDEX, L1_ASSET_ID_INDEX,
        L1_BLOCK_HASH_START_INDEX, L1_BLOCK_NUMBER_INDEX, L1_HEADER_FELTS_LEN,
        L1_TOTAL_EXIT_SLOTS_INDEX, L1_VOLUME_FEE_BPS_INDEX, PUBLIC_INPUTS_FELTS_LEN,
    };

    #[test]
    fn aggregated_public_inputs_reject_malformed_padded_length() {
        let err = AggregatedPublicCircuitInputs::try_from_u64_slice(&[0u64; 9]).unwrap_err();
        assert!(err.to_string().contains(&format!(
            "malformed length 9 - expected 8 + N*{} felts",
            PUBLIC_INPUTS_FELTS_LEN
        )));
    }

    #[test]
    fn aggregated_public_inputs_parse_num_unique_exits() {
        let mut pis = vec![0u64; 8 + PUBLIC_INPUTS_FELTS_LEN];
        pis[0] = 1; // num_unique_exits
        pis[7] = 42; // block_number

        let parsed = AggregatedPublicCircuitInputs::try_from_u64_slice(&pis).unwrap();
        assert_eq!(parsed.num_unique_exits, 1);
        assert_eq!(parsed.block_data.block_number, 42);
        assert_eq!(parsed.account_data.len(), 2);
        assert_eq!(parsed.nullifiers.len(), 1);
    }

    fn valid_layer1_pis(total_exit_slots: usize) -> Vec<u64> {
        assert!(total_exit_slots.is_multiple_of(2));

        let mut pis = vec![0u64; L1_HEADER_FELTS_LEN];
        pis[L1_AGGREGATOR_ADDRESS_START_INDEX] = 0x1111;
        pis[L1_AGGREGATOR_ADDRESS_START_INDEX + 1] = 0x2222;
        pis[L1_AGGREGATOR_ADDRESS_START_INDEX + 2] = 0x3333;
        pis[L1_AGGREGATOR_ADDRESS_START_INDEX + 3] = 0x4444;
        pis[L1_ASSET_ID_INDEX] = 0;
        pis[L1_VOLUME_FEE_BPS_INDEX] = 25;
        pis[L1_BLOCK_HASH_START_INDEX] = 0xAA01;
        pis[L1_BLOCK_HASH_START_INDEX + 1] = 0xAA02;
        pis[L1_BLOCK_HASH_START_INDEX + 2] = 0xAA03;
        pis[L1_BLOCK_HASH_START_INDEX + 3] = 0xAA04;
        pis[L1_BLOCK_NUMBER_INDEX] = 42;
        pis[L1_TOTAL_EXIT_SLOTS_INDEX] = total_exit_slots as u64;

        for slot in 0..total_exit_slots {
            pis.push((slot as u64) + 100);
            pis.extend_from_slice(&[
                0xE000 + slot as u64,
                0xE100 + slot as u64,
                0xE200 + slot as u64,
                0xE300 + slot as u64,
            ]);
        }

        for nullifier in 0..(total_exit_slots / 2) {
            pis.extend_from_slice(&[
                0xA000 + nullifier as u64,
                0xA100 + nullifier as u64,
                0xA200 + nullifier as u64,
                0xA300 + nullifier as u64,
            ]);
        }

        pis
    }

    #[test]
    fn layer1_public_inputs_parse_valid_minimal_vector() {
        let pis = valid_layer1_pis(2);

        let parsed = Layer1AggregatedPublicCircuitInputs::try_from_u64_slice(&pis).unwrap();

        assert_eq!(
            parsed.aggregator_address,
            hash_u64s_to_bytes_digest(&[0x1111, 0x2222, 0x3333, 0x4444]).unwrap()
        );
        assert_eq!(parsed.asset_id, 0);
        assert_eq!(parsed.volume_fee_bps, 25);
        assert_eq!(parsed.block_data.block_number, 42);
        assert_eq!(parsed.total_exit_slots, 2);
        assert_eq!(parsed.account_data.len(), 2);
        assert_eq!(parsed.nullifiers.len(), 1);
        assert_eq!(parsed.bundle_root, None);
        assert_eq!(parsed.circuit_id, None);
        assert_eq!(parsed.layout_version, None);
    }

    #[test]
    fn layer1_public_inputs_reject_too_short_vector() {
        let err = Layer1AggregatedPublicCircuitInputs::try_from_u64_slice(&[0u64; 11]).unwrap_err();
        assert!(err.to_string().contains("too few elements"));
    }

    #[test]
    fn layer1_public_inputs_reject_malformed_nullifier_length() {
        let mut pis = valid_layer1_pis(2);
        pis.push(1);

        let err = Layer1AggregatedPublicCircuitInputs::try_from_u64_slice(&pis).unwrap_err();
        assert!(err.to_string().contains("malformed nullifier length"));
    }

    #[test]
    fn layer1_public_inputs_parse_expected_positions() {
        let pis = valid_layer1_pis(4);

        let parsed = Layer1AggregatedPublicCircuitInputs::try_from_u64_slice(&pis).unwrap();

        assert_eq!(
            parsed.aggregator_address,
            hash_u64s_to_bytes_digest(&[0x1111, 0x2222, 0x3333, 0x4444]).unwrap()
        );
        assert_eq!(
            parsed.block_data.block_hash,
            hash_u64s_to_bytes_digest(&[0xAA01, 0xAA02, 0xAA03, 0xAA04]).unwrap()
        );
        assert_eq!(parsed.block_data.block_number, 42);
    }

    #[test]
    fn layer1_public_inputs_nullifier_count_matches_expected_shape() {
        let pis = valid_layer1_pis(4);

        let parsed = Layer1AggregatedPublicCircuitInputs::try_from_u64_slice(&pis).unwrap();

        assert_eq!(parsed.total_exit_slots, 4);
        assert_eq!(parsed.account_data.len(), 4);
        assert_eq!(parsed.nullifiers.len(), 2);
    }

    #[test]
    fn layer1_public_inputs_reject_cursor_shape_mismatch() {
        let mut pis = valid_layer1_pis(2);
        pis.extend_from_slice(&[0xB000, 0xB100, 0xB200, 0xB300]);

        let err = Layer1AggregatedPublicCircuitInputs::try_from_u64_slice(&pis).unwrap_err();
        assert!(err.to_string().contains("inconsistent shape"));
    }
}
