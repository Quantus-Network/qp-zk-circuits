use crate::circuit::F;
use crate::serialization;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::anyhow;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

// Re-export BytesDigest and related types from wormhole_inputs (single source of truth)
pub use qp_wormhole_inputs::{BytesDigest, DigestError, DIGEST_BYTES_LEN};

// Re-export serialization constants
pub use crate::serialization::{DIGEST_NUM_FELTS, FELTS_PER_U128, FELTS_PER_U64, POSEIDON2_OUTPUT};

pub const BYTES_PER_FELT: usize = 4;

/// Number of field elements for Poseidon2 hash output (the Digest type uses 4 felts).
pub const DIGEST_NUM_FIELD_ELEMENTS: usize = POSEIDON2_OUTPUT;

pub const ZERO_DIGEST: Digest = [F::ZERO; DIGEST_NUM_FIELD_ELEMENTS];
pub const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

/// Poseidon2 hash output: 4 field elements (each holding 8 bytes).
pub type Digest = [F; DIGEST_NUM_FIELD_ELEMENTS];
pub type PrivateKey = [F; 4];

/// Account ID: 8 field elements (4 bytes per felt for 32 bytes total).
/// Used for substrate accounts where collision resistance is critical.
pub type AccountId = [F; DIGEST_NUM_FELTS];
pub const ZERO_ACCOUNT_ID: AccountId = [F::ZERO; DIGEST_NUM_FELTS];

// ============================================================================
// Conversion functions - delegating to local serialization module
// ============================================================================

pub fn u128_to_felts(num: u128) -> [F; FELTS_PER_U128] {
    serialization::u128_to_felts(num)
}

pub fn felts_to_u128(felts: [F; FELTS_PER_U128]) -> Result<u128, String> {
    serialization::try_felts_to_u128(felts)
}

pub fn u64_to_felts(num: u64) -> [F; FELTS_PER_U64] {
    serialization::u64_to_felts(num)
}

pub fn felts_to_u64(felts: [F; FELTS_PER_U64]) -> Result<u64, String> {
    serialization::try_felts_to_u64(felts)
}

/// Encodes a string into field elements.
pub fn string_to_felts(input: &str) -> Vec<F> {
    serialization::string_to_felts(input)
}

/// Converts bytes to field elements (4 bytes/felt + terminator).
pub fn bytes_to_felts(input: &[u8]) -> Vec<F> {
    serialization::bytes_to_felts(input)
}

/// Converts field elements back to bytes.
pub fn felts_to_bytes(input: &[F]) -> Result<Vec<u8>, String> {
    serialization::felts_to_bytes(input).map_err(|e| e.to_string())
}

/// Convert BytesDigest to 8 field elements (4 bytes/felt).
/// Use for secrets/preimages where collision resistance matters.
pub fn digest_to_felts(input: BytesDigest) -> [F; DIGEST_NUM_FELTS] {
    serialization::digest_to_felts(&input)
}

/// Convert 8 field elements to BytesDigest (inverse of `digest_to_felts`).
pub fn felts_to_digest(input: [F; DIGEST_NUM_FELTS]) -> BytesDigest {
    let bytes: [u8; DIGEST_BYTES_LEN] = serialization::felts_to_digest(&input);
    BytesDigest::try_from(bytes).expect("field elements are always in valid range")
}

/// Convert BytesDigest to 4 field elements (digest format, 8 bytes/felt).
/// Use for hash outputs where the value came from Poseidon2 squeeze.
pub fn bytes_to_digest(input: BytesDigest) -> Digest {
    serialization::bytes_to_digest(&input)
}

/// Convert 4 field elements (digest) to BytesDigest.
pub fn digest_to_bytes(input: Digest) -> BytesDigest {
    let bytes: [u8; DIGEST_BYTES_LEN] = serialization::digest_to_bytes(&input);
    BytesDigest::try_from(bytes).expect("field elements are always in valid range")
}

/// Try to convert a slice of field elements to BytesDigest (assumes digest format).
pub fn try_felts_slice_to_bytes_digest(value: &[F]) -> anyhow::Result<BytesDigest> {
    let digest: Digest = value.try_into().map_err(|_| {
        anyhow!(
            "failed to deserialize bytes digest from field elements. Expected length {}, got {}",
            DIGEST_NUM_FIELD_ELEMENTS,
            value.len()
        )
    })?;
    Ok(digest_to_bytes(digest))
}

pub fn felts_to_hashout(felts: &[F; 4]) -> HashOut<F> {
    HashOut { elements: *felts }
}
