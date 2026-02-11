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
pub const PUBLIC_INPUTS_FELTS_LEN: usize = 20;

// Index constants for parsing public inputs
pub const ASSET_ID_INDEX: usize = 0;
pub const OUTPUT_AMOUNT_INDEX: usize = 1;
pub const VOLUME_FEE_BPS_INDEX: usize = 2;
pub const NULLIFIER_START_INDEX: usize = 3;
pub const NULLIFIER_END_INDEX: usize = 7;
pub const EXIT_ACCOUNT_START_INDEX: usize = 7;
pub const EXIT_ACCOUNT_END_INDEX: usize = 11;
pub const BLOCK_HASH_START_INDEX: usize = 11;
pub const BLOCK_HASH_END_INDEX: usize = 15;
pub const PARENT_HASH_START_INDEX: usize = 15;
pub const PARENT_HASH_END_INDEX: usize = 19;
pub const BLOCK_NUMBER_INDEX: usize = 19;

/// A 32-byte digest that can be converted to/from field elements.
#[derive(Hash, Default, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct BytesDigest([u8; DIGEST_BYTES_LEN]);

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCircuitInputs {
    /// The asset ID (0 for native token).
    pub asset_id: u32,
    /// Amount to be received by the exit account after fee deduction.
    /// This value is quantized with 0.01 units of precision.
    pub output_amount: u32,
    /// Volume fee rate in basis points (1 basis point = 0.01%).
    pub volume_fee_bps: u32,
    /// The nullifier (prevents double-spending).
    pub nullifier: BytesDigest,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
    /// The hash of the block header.
    pub block_hash: BytesDigest,
    /// The parent hash of the block.
    pub parent_hash: BytesDigest,
    /// The block number.
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

/// Block data in aggregated proofs.
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct BlockData {
    /// The hash of the block header.
    pub block_hash: BytesDigest,
    /// The block number.
    pub block_number: u32,
}

/// Aggregated public inputs from multiple wormhole proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedPublicCircuitInputs {
    /// The asset ID (0 for native token).
    pub asset_id: u32,
    /// Volume fee rate in basis points.
    pub volume_fee_bps: u32,
    /// The block data for the last block in the aggregation.
    pub block_data: BlockData,
    /// Exit accounts and their summed output amounts.
    pub account_data: Vec<PublicInputsByAccount>,
    /// Nullifiers from all aggregated proofs.
    pub nullifiers: Vec<BytesDigest>,
}

/// Helper to convert 4 u64 values (field elements as canonical u64) to a BytesDigest
fn u64s_to_bytes_digest(vals: &[u64]) -> anyhow::Result<BytesDigest> {
    if vals.len() != 4 {
        bail!("Expected 4 field elements for digest, got {}", vals.len());
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
        let output_amount: u32 = pis[OUTPUT_AMOUNT_INDEX]
            .try_into()
            .context("failed to convert output_amount to u32")?;
        let volume_fee_bps: u32 = pis[VOLUME_FEE_BPS_INDEX]
            .try_into()
            .context("failed to convert volume_fee_bps to u32")?;

        let nullifier = u64s_to_bytes_digest(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
            .context("failed to parse nullifier")?;
        let exit_account =
            u64s_to_bytes_digest(&pis[EXIT_ACCOUNT_START_INDEX..EXIT_ACCOUNT_END_INDEX])
                .context("failed to parse exit_account")?;
        let block_hash = u64s_to_bytes_digest(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
            .context("failed to parse block_hash")?;
        let parent_hash =
            u64s_to_bytes_digest(&pis[PARENT_HASH_START_INDEX..PARENT_HASH_END_INDEX])
                .context("failed to parse parent_hash")?;

        let block_number: u32 = pis[BLOCK_NUMBER_INDEX]
            .try_into()
            .context("failed to convert block_number to u32")?;

        Ok(PublicCircuitInputs {
            asset_id,
            output_amount,
            volume_fee_bps,
            nullifier,
            exit_account,
            block_hash,
            parent_hash,
            block_number,
        })
    }
}

impl AggregatedPublicCircuitInputs {
    /// Parse aggregated public inputs from a slice of u64 values.
    pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
        // Layout in the FINAL (deduped) wrapper proof PIs:
        // [num_unique_exits, asset_id, volume_fee_bps, block_data(5), [output_sum(1), exit_account(4)] * N, nullifiers(4) * N, padding...]
        //
        // IMPORTANT: The output has N "slots" (one per leaf proof position), NOT account_count slots.
        // The num_unique_exits is informational only - the actual slot count is always N.

        if pis.len() < 8 {
            bail!(
                "AggregatedPI: too few elements, need at least 8 for header, got {}",
                pis.len()
            );
        }

        let asset_id = pis[1] as u32;
        let volume_fee_bps = pis[2] as u32;

        // Number of leaf proofs (N) is derived from the total PI length.
        let n_leaf = pis.len() / PUBLIC_INPUTS_FELTS_LEN;

        if n_leaf == 0 {
            bail!(
                "AggregatedPI: n_leaf is 0 (pis.len()={}, PUBLIC_INPUTS_FELTS_LEN={})",
                pis.len(),
                PUBLIC_INPUTS_FELTS_LEN
            );
        }

        let block_hash = u64s_to_bytes_digest(&pis[3..7])
            .context("AggregatedPI: parsing block_hash from indices 3..7")?;
        let block_number: u32 = pis[7]
            .try_into()
            .context("AggregatedPI: parsing block_number from index 7")?;

        let block_data = BlockData {
            block_hash,
            block_number,
        };

        let mut cursor = 8usize;

        // Read N exit account slots (one per leaf proof position)
        let mut account_data = Vec::with_capacity(n_leaf);
        for i in 0..n_leaf {
            if cursor >= pis.len() {
                bail!(
                    "AggregatedPI: cursor {} out of bounds (pis.len={}) while reading account {}",
                    cursor,
                    pis.len(),
                    i
                );
            }
            let summed_output_amount = pis[cursor] as u32;
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
                u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
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
            let n = u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                format!(
                    "AggregatedPI: parsing nullifier[{}] at cursor {}",
                    i, cursor
                )
            })?;
            cursor += 4;

            nullifiers.push(n);
        }

        // Verify we consumed expected number of felts
        let expected_felts = 8 + n_leaf * 5 + n_leaf * 4;
        if cursor != expected_felts {
            bail!(
                "AggregatedPI: cursor mismatch - consumed {} felts, expected {} (n_leaf={}, formula: 8 + {} * 5 + {} * 4)",
                cursor,
                expected_felts,
                n_leaf,
                n_leaf,
                n_leaf
            );
        }

        Ok(AggregatedPublicCircuitInputs {
            asset_id,
            volume_fee_bps,
            block_data,
            account_data,
            nullifiers,
        })
    }
}
