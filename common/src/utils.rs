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
pub use crate::serialization::{
    DIGEST_BYTES_PER_ELEMENT, FELTS_PER_U128, FELTS_PER_U64, POSEIDON2_OUTPUT,
};

pub const INJECTIVE_BYTES_LIMB: usize = 4;
pub const NON_INJECTIVE_BYTES_LIMB: usize = 8;
pub const DIGEST_NUM_FIELD_ELEMENTS: usize = POSEIDON2_OUTPUT;

pub const ZERO_DIGEST: Digest = [F::ZERO; DIGEST_NUM_FIELD_ELEMENTS];
pub const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

pub type Digest = [F; DIGEST_NUM_FIELD_ELEMENTS];
pub type PrivateKey = [F; 4];

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

/// Encodes a string into field elements using injective encoding.
pub fn injective_string_to_felt(input: &str) -> Vec<F> {
    serialization::injective_string_to_felts(input)
}

/// Converts a given slice into its field element representation (injective encoding).
/// Uses 4 bytes per felt with a terminator marker for collision resistance.
pub fn injective_bytes_to_felts(input: &[u8]) -> Vec<F> {
    serialization::injective_bytes_to_felts(input)
}

/// Converts a given slice into its field element representation (non-injective encoding).
/// Uses 8 bytes per felt without a terminator - more compact but not collision-resistant
/// for variable-length inputs. Safe for self-describing structures like trie nodes.
pub fn non_injective_bytes_to_felts(input: &[u8]) -> Vec<F> {
    serialization::non_injective_bytes_to_felts(input)
}

/// Converts a given field element slice into its byte representation.
/// Only works for injective felt encodings (outputs of `injective_bytes_to_felts`).
pub fn injective_felts_to_bytes(input: &[F]) -> Result<Vec<u8>, String> {
    serialization::try_injective_felts_to_bytes(input).map_err(|e| e.to_string())
}

/// Convert BytesDigest to field elements
pub fn digest_bytes_to_felts(input: BytesDigest) -> Digest {
    serialization::unsafe_digest_bytes_to_felts(&input)
}

/// Try to convert a slice of field elements to BytesDigest
pub fn try_felts_slice_to_bytes_digest(value: &[F]) -> anyhow::Result<BytesDigest> {
    let digest: Digest = value.try_into().map_err(|_| {
        anyhow!(
            "failed to deserialize bytes digest from field elements. Expected length 4, got {}",
            value.len()
        )
    })?;
    Ok(digest_felts_to_bytes(digest))
}

/// Convert field elements to BytesDigest
pub fn digest_felts_to_bytes(input: Digest) -> BytesDigest {
    let bytes: [u8; DIGEST_BYTES_LEN] = serialization::digest_felts_to_bytes(&input);
    // Field elements are always in valid range, so this won't fail
    BytesDigest::try_from(bytes).expect("field elements are always in valid range")
}

pub fn felts_to_hashout(felts: &[F; 4]) -> HashOut<F> {
    HashOut { elements: *felts }
}
