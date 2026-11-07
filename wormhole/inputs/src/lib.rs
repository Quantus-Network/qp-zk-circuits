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
use anyhow::{anyhow, bail, Context};
use core::ops::Deref;

/// Number of bytes in a digest (32 bytes = 256 bits)
pub const DIGEST_BYTES_LEN: usize = 32;

/// Goldilocks field order (2^64 - 2^32 + 1)
/// Used to validate that bytes can be represented as field elements
const GOLDILOCKS_ORDER: u64 = 0xFFFFFFFF00000001;

/// The total size of the leaf public inputs field element vector.
/// Layout: asset_id(1) + nullifier(4) + block_hash(4) + block_number(1) + input_amount(1)
/// = 1 + 4 + 4 + 1 + 1 = 11
///
/// A leaf proof is a proof of burn: it authenticates that `input_amount` of
/// `asset_id` was deposited to an unspendable account in the block `block_hash`
/// and binds the spend to `nullifier`. Where the value goes (exit accounts,
/// amounts, fee) is decided by the private batch that consumes the leaf.
///
/// parent_hash is a private input to the leaf circuit (used to compute block_hash)
/// but is not exposed as a public input since block_hash already commits to it.
///
/// `input_amount` is exposed only by the intermediate leaf proof so the private
/// batch can enforce value conservation over the whole segment. Private- and
/// public-batch proofs do not forward it.
pub const PUBLIC_INPUTS_FELTS_LEN: usize = 11;

/// Minimum acceptable security level (bits) for the canonical leaf circuit config.
/// Guards against a qp-plonky2 upgrade silently weakening the config below
/// this floor.
pub const MIN_LEAF_SECURITY_BITS: usize = 128;

/// FRI and wire parameters of the canonical leaf circuit config.
///
/// Shared by the circuit side (`zk_circuits_common::circuit::wormhole_leaf_circuit_config`)
/// and the `no_std` verifier, which cannot depend on the circuit crates. The
/// leaf is a 2^8-degree circuit, so a large blowup is nearly free for the
/// prover while every query it saves removes ~110 gates from each recursive
/// verification in the private batch. `16 * 7 + 16 = 128` conjectured bits.
pub mod leaf_config {
    pub const NUM_WIRES: usize = 135;
    pub const NUM_ROUTED_WIRES: usize = 60;
    pub const SECURITY_BITS: usize = 128;
    pub const FRI_RATE_BITS: usize = 7;
    pub const FRI_CAP_HEIGHT: usize = 4;
    pub const FRI_PROOF_OF_WORK_BITS: u32 = 16;
    pub const FRI_NUM_QUERY_ROUNDS: usize = 16;
}

/// Maximum number of leaf proofs and of exit slots in a private batch. The formal
/// spec (`formal/WormholeSpec/Aggregation.lean`) proves the fee arithmetic cannot
/// wrap the field and fits the 52-bit range check for at most 64 of each, so
/// raising this requires widening that range check and the Lean bounds with it.
/// Every externally supplied or length-derived private-batch dimension must be
/// validated against it before any allocation, arithmetic, or circuit construction.
pub const MAX_PROOF_COUNT: usize = 64;

/// Maximum number of private-batch proofs aggregated into one public batch. The
/// public batch has no field-arithmetic bound of its own (it forwards inner public
/// inputs), so this only caps circuit-construction, proving, and public-input
/// parsing work: 256 inner proofs is a 2^21-row circuit. Validate every externally
/// supplied arity against it before any allocation or arithmetic.
pub const MAX_PUBLIC_BATCH_ARITY: usize = 256;

/// The deployed batch dimensions. Shared by the circuit-builder defaults, the
/// profiler, the benches, and the degree-pinning tests in the aggregator crate.
pub mod production {
    use super::PrivateBatchShape;

    /// Leaf proofs per private batch. Ten fits the private batch in 2^15 rows with
    /// ~250 gates to spare; eleven does not.
    pub const NUM_LEAF_PROOFS: usize = 10;
    /// Exit slots per private batch. Slots cost ~1 gate each in the private batch
    /// and ~1 gate per inner proof in the public batch, but 40 bytes of public
    /// input each on chain whether used or not.
    pub const NUM_EXIT_SLOTS: usize = 32;
    /// Private-batch proofs per public batch. 109 is the most that fit in 2^19
    /// rows: each inner proof costs ~4,740 gates of recursive verification plus
    /// 25 Poseidon gates hashing its 200 forwarded public inputs.
    pub const PUBLIC_BATCH_ARITY: usize = 109;

    pub const PRIVATE_BATCH_SHAPE: PrivateBatchShape =
        PrivateBatchShape::new(NUM_LEAF_PROOFS, NUM_EXIT_SLOTS);
}

fn validate_count(count: usize, max: usize, label: &str) -> anyhow::Result<()> {
    if count == 0 {
        bail!("{} must be > 0", label);
    }
    if count > max {
        bail!("{} ({}) exceeds maximum allowed ({})", label, count, max);
    }
    Ok(())
}

/// Validate that a private-batch dimension (leaf proofs or exit slots) is in the
/// canonical `1..=MAX_PROOF_COUNT` range.
///
/// Centralizes the bound so every build/parse entry point applies the same cap
/// before doing work that scales with the count.
pub fn validate_proof_count(count: usize, label: &str) -> anyhow::Result<()> {
    validate_count(count, MAX_PROOF_COUNT, label)
}

/// Validate that a public-batch arity is in the canonical `1..=MAX_PUBLIC_BATCH_ARITY`
/// range.
pub fn validate_public_batch_arity(count: usize, label: &str) -> anyhow::Result<()> {
    validate_count(count, MAX_PUBLIC_BATCH_ARITY, label)
}

/// Circuit-build-time shape of a private batch: how many leaf proofs it
/// verifies and how many exit (output) slots it exposes. The two are
/// independent: a batch may split one burn across many outputs or pool many
/// burns into one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrivateBatchShape {
    pub num_leaf_proofs: usize,
    pub num_exit_slots: usize,
}

impl PrivateBatchShape {
    pub const fn new(num_leaf_proofs: usize, num_exit_slots: usize) -> Self {
        Self {
            num_leaf_proofs,
            num_exit_slots,
        }
    }

    /// Validate both dimensions against the canonical `1..=MAX_PROOF_COUNT` range.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_proof_count(self.num_leaf_proofs, "num_leaf_proofs")?;
        validate_proof_count(self.num_exit_slots, "num_exit_slots")
    }
}

/// One requested payout of a private batch: `amount` (quantized, 0.01 units)
/// to `exit_account`. Unused slots are `(zero account, 0)`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalOutput {
    pub exit_account: BytesDigest,
    pub amount: u32,
}

/// Private-batch PI layout.
///
/// ```text
/// [num_exit_slots(1), asset_id(1), volume_fee_bps(1), block_hash(4), block_number(1),
///  [amount(1), exit_account(4)] * num_exit_slots,
///  nullifier(4) * num_leaf_proofs]
/// ```
pub mod private_batch_pi {
    use super::PrivateBatchShape;

    pub const NUM_EXIT_SLOTS_INDEX: usize = 0;
    pub const ASSET_ID_INDEX: usize = 1;
    pub const VOLUME_FEE_BPS_INDEX: usize = 2;
    pub const BLOCK_HASH_START_INDEX: usize = 3;
    pub const BLOCK_NUMBER_INDEX: usize = 7;
    pub const HEADER_LEN: usize = 8;
    /// Each exit slot is `[amount(1), exit_account(4)]`.
    pub const EXIT_SLOT_LEN: usize = 5;
    pub const NULLIFIER_LEN: usize = 4;

    #[inline]
    pub const fn exit_slots_start() -> usize {
        HEADER_LEN
    }

    #[inline]
    pub const fn nullifiers_start(shape: PrivateBatchShape) -> usize {
        HEADER_LEN + shape.num_exit_slots * EXIT_SLOT_LEN
    }

    /// Total PI length. Unchecked arithmetic: callers must have validated
    /// `shape` ([`PrivateBatchShape::validate`]) first.
    #[inline]
    pub const fn pi_len(shape: PrivateBatchShape) -> usize {
        nullifiers_start(shape) + shape.num_leaf_proofs * NULLIFIER_LEN
    }
}

// Index constants for parsing leaf public inputs
pub const ASSET_ID_INDEX: usize = 0;
pub const NULLIFIER_START_INDEX: usize = 1;
pub const NULLIFIER_END_INDEX: usize = 5;
pub const BLOCK_HASH_START_INDEX: usize = 5;
pub const BLOCK_HASH_END_INDEX: usize = 9;
pub const BLOCK_NUMBER_INDEX: usize = 9;
pub const INPUT_AMOUNT_INDEX: usize = 10;

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

/// All of the public inputs of a single wormhole leaf proof (a proof of burn).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicCircuitInputs {
    /// The asset ID (0 for native token).
    pub asset_id: u32,
    /// The nullifier: `H(H(salt || secret || transfer_count))`.
    ///
    /// The circuit only proves this value is *well-formed* (bound to the deposit
    /// being spent). Double-spend prevention — rejecting an already-settled
    /// nullifier — is enforced on-chain by the wormhole pallet, which maintains
    /// the persistent set of settled nullifiers. No circuit or aggregator layer
    /// checks uniqueness; see "Nullifiers and Double-Spend Prevention" in
    /// `wormhole/README.md`.
    pub nullifier: BytesDigest,
    /// The hash of the block header. All zeros marks a dummy (padding) proof.
    pub block_hash: BytesDigest,
    /// The block number, parsed from the block header.
    pub block_number: u32,
    /// Amount authenticated by the spent ZK-tree leaf, in quantized units
    /// (0.01 units of precision).
    ///
    /// This is an intermediate leaf-proof public input consumed by the local
    /// private-batch wrapper. Aggregate proofs do not reveal it.
    pub input_amount: u32,
}

impl fmt::Debug for PublicCircuitInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicCircuitInputs")
            .field("asset_id", &self.asset_id)
            .field("nullifier", &self.nullifier)
            .field("block_hash", &self.block_hash)
            .field("block_number", &self.block_number)
            .field("input_amount", &"[REDACTED]")
            .finish()
    }
}

/// Exit account data in aggregated proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputsByAccount {
    /// Amount paid to `exit_account` by this slot. Slots are forwarded
    /// verbatim; several slots may name the same account.
    pub output_amount: u32,
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
pub struct PrivateBatchPublicInputs {
    /// Number of exit slots in the batch: the structural constant
    /// `PrivateBatchShape::num_exit_slots` that the aggregation circuit writes
    /// at index 0, always equal to `account_data.len()`. Unused slots are
    /// `(zero account, 0)`; the parser derives the leaf count from this felt
    /// and the total length.
    pub num_exit_slots: u32,
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

/// Public inputs from a public-batch aggregation proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBatchPublicInputs {
    /// Aggregator address (4 felts, hash-derived account).
    pub aggregator_address: BytesDigest,
    /// The asset ID of the set (0 for native token).
    pub asset_id: u32,
    /// Volume fee rate in basis points.
    pub volume_fee_bps: u32,
    /// Block data shared by all non-dummy inner private batches.
    pub block_data: BlockData,
    /// Total exit slots across all inner proofs (structural constant).
    pub total_exit_slots: u32,
    /// Flattened exit slots from all inner private batches, in order.
    pub account_data: Vec<PublicInputsByAccount>,
    /// Flattened nullifiers from all inner private batches, in order.
    pub nullifiers: Vec<BytesDigest>,
}

/// Public-batch PI layout constants (mirrors `public_batch/circuit/constants.rs`).
pub mod public_batch_pi {
    use super::PrivateBatchShape;

    pub const AGGREGATOR_ADDRESS_LEN: usize = 4;
    pub const HEADER_LEN: usize = 12; // 4 + 1 + 1 + 4 + 1 + 1
    pub const EXIT_SLOT_LEN: usize = 5; // sum(1) + exit_account(4)

    #[inline]
    pub const fn exit_slots_per_inner(shape: PrivateBatchShape) -> usize {
        shape.num_exit_slots
    }

    #[inline]
    pub const fn nullifiers_per_inner(shape: PrivateBatchShape) -> usize {
        shape.num_leaf_proofs
    }

    #[inline]
    pub const fn pi_len(num_private_batch_proofs: usize, shape: PrivateBatchShape) -> usize {
        HEADER_LEN
            + num_private_batch_proofs * exit_slots_per_inner(shape) * EXIT_SLOT_LEN
            + num_private_batch_proofs * nullifiers_per_inner(shape) * 4
    }

    /// Checked variant of [`pi_len`]: returns `None` on overflow instead of wrapping.
    ///
    /// Use this (plus [`PrivateBatchShape::validate`]) when the dimensions come
    /// from untrusted input; [`pi_len`] is unchecked and may wrap for huge counts.
    #[inline]
    pub const fn try_pi_len(
        num_private_batch_proofs: usize,
        shape: PrivateBatchShape,
    ) -> Option<usize> {
        let slots = exit_slots_per_inner(shape);
        let nulls = nullifiers_per_inner(shape);
        let exit_felts = match num_private_batch_proofs.checked_mul(slots) {
            Some(v) => match v.checked_mul(EXIT_SLOT_LEN) {
                Some(e) => e,
                None => return None,
            },
            None => return None,
        };
        let null_felts = match num_private_batch_proofs.checked_mul(nulls) {
            Some(v) => match v.checked_mul(4) {
                Some(n) => n,
                None => return None,
            },
            None => return None,
        };
        match HEADER_LEN.checked_add(exit_felts) {
            Some(v) => match v.checked_add(null_felts) {
                Some(total) => Some(total),
                None => None,
            },
            None => None,
        }
    }
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

        let nullifier = hash_u64s_to_bytes_digest(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
            .context("failed to parse nullifier")?;
        let block_hash =
            hash_u64s_to_bytes_digest(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
                .context("failed to parse block_hash")?;

        let block_number: u32 = pis[BLOCK_NUMBER_INDEX]
            .try_into()
            .context("failed to convert block_number to u32")?;
        let input_amount: u32 = pis[INPUT_AMOUNT_INDEX]
            .try_into()
            .context("failed to convert input_amount to u32")?;

        Ok(PublicCircuitInputs {
            asset_id,
            nullifier,
            block_hash,
            block_number,
            input_amount,
        })
    }
}

/// Recover the [`PrivateBatchShape`] a private-batch public-input vector was
/// produced for: the exit-slot count is the header felt at index 0, and the
/// leaf count is what remains of the length after the header and exit slots.
/// Both are validated against `MAX_PROOF_COUNT` before any other work.
pub fn private_batch_shape_from_pis(pis: &[u64]) -> anyhow::Result<PrivateBatchShape> {
    use private_batch_pi::{EXIT_SLOT_LEN, HEADER_LEN, NULLIFIER_LEN, NUM_EXIT_SLOTS_INDEX};

    if pis.len() < HEADER_LEN {
        bail!(
            "AggregatedPI: too few elements, need at least {} for header, got {}",
            HEADER_LEN,
            pis.len()
        );
    }
    let num_exit_slots = usize::try_from(pis[NUM_EXIT_SLOTS_INDEX])
        .context("AggregatedPI: num_exit_slots at index 0 exceeds usize range")?;
    validate_proof_count(num_exit_slots, "AggregatedPI: num_exit_slots")?;

    let nullifier_felts = pis
        .len()
        .checked_sub(HEADER_LEN + num_exit_slots * EXIT_SLOT_LEN)
        .filter(|len| len.is_multiple_of(NULLIFIER_LEN))
        .ok_or_else(|| {
            anyhow!(
                "AggregatedPI: malformed length {} - expected {} + {}*{} + N*{} felts",
                pis.len(),
                HEADER_LEN,
                num_exit_slots,
                EXIT_SLOT_LEN,
                NULLIFIER_LEN
            )
        })?;
    let num_leaf_proofs = nullifier_felts / NULLIFIER_LEN;
    validate_proof_count(num_leaf_proofs, "AggregatedPI: n_leaf")?;

    Ok(PrivateBatchShape::new(num_leaf_proofs, num_exit_slots))
}

impl PrivateBatchPublicInputs {
    /// Parse aggregated public inputs from a slice of u64 values.
    pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
        // Layout: see [`private_batch_pi`]. The parser validates shape/layout
        // only. Circuit-level semantic constraints such as same-block and
        // same-asset consistency remain enforced by the proving circuit.
        let shape = private_batch_shape_from_pis(pis)?;
        let total_slots = shape.num_exit_slots;
        let n_leaf = shape.num_leaf_proofs;

        let num_exit_slots = total_slots as u32;
        let asset_id: u32 = pis[private_batch_pi::ASSET_ID_INDEX]
            .try_into()
            .context("AggregatedPI: asset_id at index 1 exceeds u32 range")?;
        let volume_fee_bps: u32 = pis[private_batch_pi::VOLUME_FEE_BPS_INDEX]
            .try_into()
            .context("AggregatedPI: volume_fee_bps at index 2 exceeds u32 range")?;

        let block_hash = hash_u64s_to_bytes_digest(
            &pis[private_batch_pi::BLOCK_HASH_START_INDEX
                ..private_batch_pi::BLOCK_HASH_START_INDEX + 4],
        )
        .context("AggregatedPI: parsing block_hash from indices 3..7")?;
        let block_number: u32 = pis[private_batch_pi::BLOCK_NUMBER_INDEX]
            .try_into()
            .context("AggregatedPI: parsing block_number from index 7")?;

        let block_data = BlockData {
            block_hash,
            block_number,
        };

        let mut cursor = private_batch_pi::exit_slots_start();

        let mut account_data = Vec::with_capacity(total_slots);
        for i in 0..total_slots {
            if cursor >= pis.len() {
                bail!(
                    "AggregatedPI: cursor {} out of bounds (pis.len={}) while reading account {}",
                    cursor,
                    pis.len(),
                    i
                );
            }
            let output_amount: u32 = pis[cursor].try_into().with_context(|| {
                format!(
                    "AggregatedPI: output_amount at cursor {} exceeds u32 range",
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
                output_amount,
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

        let expected_felts = private_batch_pi::pi_len(shape);
        if cursor != expected_felts {
            bail!(
                "AggregatedPI: cursor mismatch - consumed {} felts, expected {} (n_leaf={}, num_exit_slots={})",
                cursor,
                expected_felts,
                n_leaf,
                num_exit_slots
            );
        }

        Ok(PrivateBatchPublicInputs {
            num_exit_slots,
            asset_id,
            volume_fee_bps,
            block_data,
            account_data,
            nullifiers,
        })
    }
}

impl PublicBatchPublicInputs {
    /// Parse public-batch public inputs from a slice of u64 values.
    ///
    /// `num_private_batch_proofs` and `shape` must match the circuit
    /// parameters used to generate the proof (embedded in the on-chain verifier).
    pub fn try_from_u64_slice(
        pis: &[u64],
        num_private_batch_proofs: usize,
        shape: PrivateBatchShape,
    ) -> anyhow::Result<Self> {
        use public_batch_pi::{
            exit_slots_per_inner, nullifiers_per_inner, try_pi_len, AGGREGATOR_ADDRESS_LEN,
            HEADER_LEN,
        };

        validate_public_batch_arity(num_private_batch_proofs, "num_private_batch_proofs")?;
        shape.validate()?;

        let expected_len = try_pi_len(num_private_batch_proofs, shape).ok_or_else(|| {
            anyhow!(
                "PublicBatchPI: layout length overflow (n_inner={}, shape={:?})",
                num_private_batch_proofs,
                shape
            )
        })?;
        if pis.len() != expected_len {
            bail!(
                "PublicBatchPI: expected {} felts (n_inner={}, shape={:?}), got {}",
                expected_len,
                num_private_batch_proofs,
                shape,
                pis.len()
            );
        }

        let slots_per_inner = exit_slots_per_inner(shape);
        let nulls_per_inner = nullifiers_per_inner(shape);
        let total_exit_slots_expected = u32::try_from(
            num_private_batch_proofs
                .checked_mul(slots_per_inner)
                .ok_or_else(|| anyhow!("PublicBatchPI: exit slot count overflow"))?,
        )
        .context("PublicBatchPI: total_exit_slots exceeds u32")?;

        let aggregator_address = hash_u64s_to_bytes_digest(&pis[0..AGGREGATOR_ADDRESS_LEN])
            .context("PublicBatchPI: parsing aggregator_address")?;

        let asset_id: u32 = pis[4]
            .try_into()
            .context("PublicBatchPI: asset_id exceeds u32 range")?;
        let volume_fee_bps: u32 = pis[5]
            .try_into()
            .context("PublicBatchPI: volume_fee_bps exceeds u32 range")?;

        let block_hash =
            hash_u64s_to_bytes_digest(&pis[6..10]).context("PublicBatchPI: parsing block_hash")?;
        let block_number: u32 = pis[10]
            .try_into()
            .context("PublicBatchPI: block_number exceeds u32 range")?;

        let total_exit_slots: u32 = pis[11]
            .try_into()
            .context("PublicBatchPI: total_exit_slots exceeds u32 range")?;
        if total_exit_slots != total_exit_slots_expected {
            bail!(
                "PublicBatchPI: total_exit_slots {} != expected {}",
                total_exit_slots,
                total_exit_slots_expected
            );
        }

        let block_data = BlockData {
            block_hash,
            block_number,
        };

        let mut cursor = HEADER_LEN;
        let total_slots = num_private_batch_proofs
            .checked_mul(slots_per_inner)
            .ok_or_else(|| anyhow!("PublicBatchPI: exit slot count overflow"))?;
        let mut account_data = Vec::with_capacity(total_slots);
        for i in 0..total_slots {
            let output_amount: u32 = pis[cursor]
                .try_into()
                .with_context(|| format!("PublicBatchPI: exit slot {} sum exceeds u32", i))?;
            cursor += 1;

            let exit_account = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                .with_context(|| format!("PublicBatchPI: parsing exit slot {} account", i))?;
            cursor += 4;

            account_data.push(PublicInputsByAccount {
                output_amount,
                exit_account,
            });
        }

        let total_nullifiers = num_private_batch_proofs
            .checked_mul(nulls_per_inner)
            .ok_or_else(|| anyhow!("PublicBatchPI: nullifier count overflow"))?;
        let mut nullifiers = Vec::with_capacity(total_nullifiers);
        for i in 0..total_nullifiers {
            let n = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                .with_context(|| format!("PublicBatchPI: parsing nullifier {}", i))?;
            cursor += 4;
            nullifiers.push(n);
        }

        if cursor != expected_len {
            bail!(
                "PublicBatchPI: cursor mismatch - consumed {} felts, expected {}",
                cursor,
                expected_len
            );
        }

        Ok(PublicBatchPublicInputs {
            aggregator_address,
            asset_id,
            volume_fee_bps,
            block_data,
            total_exit_slots,
            account_data,
            nullifiers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{private_batch_pi, public_batch_pi};
    use super::{
        private_batch_shape_from_pis, production, validate_proof_count,
        validate_public_batch_arity, PrivateBatchPublicInputs, PrivateBatchShape,
        PublicBatchPublicInputs, PublicCircuitInputs, INPUT_AMOUNT_INDEX, MAX_PROOF_COUNT,
        MAX_PUBLIC_BATCH_ARITY, PUBLIC_INPUTS_FELTS_LEN,
    };

    #[test]
    fn leaf_public_inputs_parse_appended_input_amount() {
        let mut pis = [0u64; PUBLIC_INPUTS_FELTS_LEN];
        pis[INPUT_AMOUNT_INDEX] = 42;
        let parsed = PublicCircuitInputs::try_from_u64_slice(&pis).unwrap();
        assert_eq!(parsed.input_amount, 42);
        assert!(!format!("{parsed:?}").contains("42"));
    }

    fn private_batch_pis(shape: PrivateBatchShape) -> Vec<u64> {
        let mut pis = vec![0u64; private_batch_pi::pi_len(shape)];
        pis[private_batch_pi::NUM_EXIT_SLOTS_INDEX] = shape.num_exit_slots as u64;
        pis
    }

    #[test]
    fn aggregated_public_inputs_reject_malformed_length() {
        let shape = PrivateBatchShape::new(1, 3);
        let mut pis = private_batch_pis(shape);
        pis.push(0);
        let err = PrivateBatchPublicInputs::try_from_u64_slice(&pis).unwrap_err();
        assert!(err.to_string().contains("malformed length"), "got: {err}");

        let err = PrivateBatchPublicInputs::try_from_u64_slice(&[0u64; 7]).unwrap_err();
        assert!(err.to_string().contains("too few elements"), "got: {err}");
    }

    #[test]
    fn aggregated_public_inputs_parse_header_and_shape() {
        let shape = PrivateBatchShape::new(3, 5);
        let mut pis = private_batch_pis(shape);
        pis[private_batch_pi::BLOCK_NUMBER_INDEX] = 42;

        assert_eq!(private_batch_shape_from_pis(&pis).unwrap(), shape);
        let parsed = PrivateBatchPublicInputs::try_from_u64_slice(&pis).unwrap();
        assert_eq!(parsed.num_exit_slots, 5);
        assert_eq!(parsed.account_data.len(), 5);
        assert_eq!(parsed.nullifiers.len(), 3);
        assert_eq!(parsed.block_data.block_number, 42);
    }

    /// A zero exit-slot count or one that leaves no room for a whole number
    /// of nullifiers cannot come from the circuit.
    #[test]
    fn aggregated_public_inputs_reject_inconsistent_slot_count() {
        let shape = PrivateBatchShape::new(2, 4);
        let mut pis = private_batch_pis(shape);
        pis[private_batch_pi::NUM_EXIT_SLOTS_INDEX] = 0;
        let err = PrivateBatchPublicInputs::try_from_u64_slice(&pis).unwrap_err();
        assert!(err.to_string().contains("must be > 0"), "got: {err}");

        pis[private_batch_pi::NUM_EXIT_SLOTS_INDEX] = 3;
        let err = PrivateBatchPublicInputs::try_from_u64_slice(&pis).unwrap_err();
        assert!(err.to_string().contains("malformed length"), "got: {err}");
    }

    #[test]
    fn aggregated_public_inputs_reject_oversized_counts() {
        // Dimensions above MAX_PROOF_COUNT must be rejected rather than
        // driving unbounded allocation (#97052, #97070).
        let shape = PrivateBatchShape::new(MAX_PROOF_COUNT + 1, 1);
        let err =
            PrivateBatchPublicInputs::try_from_u64_slice(&private_batch_pis(shape)).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");

        let mut pis = vec![0u64; private_batch_pi::HEADER_LEN];
        pis[private_batch_pi::NUM_EXIT_SLOTS_INDEX] = u64::MAX;
        let err = PrivateBatchPublicInputs::try_from_u64_slice(&pis).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "got: {err}");
    }

    #[test]
    fn public_batch_parser_rejects_oversized_counts() {
        // Counts whose product would wrap the layout arithmetic must be rejected by
        // the MAX_PUBLIC_BATCH_ARITY cap instead of panicking or wrapping to an empty batch.
        let header = vec![0u64; public_batch_pi::HEADER_LEN];
        let shape = PrivateBatchShape::new(1, 2);
        for bad in [1usize << 63, MAX_PUBLIC_BATCH_ARITY + 1] {
            let err = PublicBatchPublicInputs::try_from_u64_slice(&header, bad, shape)
                .expect_err("oversized inner count must be rejected");
            assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
        }
        let err = PublicBatchPublicInputs::try_from_u64_slice(&header, 0, shape)
            .expect_err("zero inner count must be rejected");
        assert!(err.to_string().contains("must be > 0"), "got: {err}");
    }

    #[test]
    fn public_batch_parser_accepts_production_arity() {
        let shape = production::PRIVATE_BATCH_SHAPE;
        let n_inner = production::PUBLIC_BATCH_ARITY;
        assert!(
            n_inner > MAX_PROOF_COUNT,
            "arity must not be bound by the private-batch cap"
        );
        let mut pis = vec![0u64; public_batch_pi::pi_len(n_inner, shape)];
        pis[11] = (n_inner * shape.num_exit_slots) as u64;
        let parsed = PublicBatchPublicInputs::try_from_u64_slice(&pis, n_inner, shape).unwrap();
        assert_eq!(parsed.account_data.len(), n_inner * shape.num_exit_slots);
        assert_eq!(parsed.nullifiers.len(), n_inner * shape.num_leaf_proofs);
    }

    #[test]
    fn public_batch_parser_round_trips_shape() {
        let shape = PrivateBatchShape::new(2, 3);
        let n_inner = 2;
        let mut pis = vec![0u64; public_batch_pi::pi_len(n_inner, shape)];
        pis[11] = (n_inner * shape.num_exit_slots) as u64;
        let parsed = PublicBatchPublicInputs::try_from_u64_slice(&pis, n_inner, shape).unwrap();
        assert_eq!(parsed.account_data.len(), 6);
        assert_eq!(parsed.nullifiers.len(), 4);
    }

    #[test]
    fn validate_proof_count_enforces_canonical_range() {
        assert!(validate_proof_count(0, "x").is_err());
        assert!(validate_proof_count(MAX_PROOF_COUNT + 1, "x").is_err());
        assert!(validate_proof_count(1, "x").is_ok());
        assert!(validate_public_batch_arity(0, "x").is_err());
        assert!(validate_public_batch_arity(MAX_PUBLIC_BATCH_ARITY + 1, "x").is_err());
        assert!(validate_public_batch_arity(MAX_PROOF_COUNT + 1, "x").is_ok());
        assert!(validate_public_batch_arity(production::PUBLIC_BATCH_ARITY, "x").is_ok());
        assert!(validate_proof_count(MAX_PROOF_COUNT, "x").is_ok());
    }
}
