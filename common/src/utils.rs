use crate::circuit::F;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::anyhow;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

// Re-export BytesDigest and related types from wormhole_inputs (single source of truth)
pub use qp_wormhole_inputs::{BytesDigest, DigestError, DIGEST_BYTES_LEN};

pub const INJECTIVE_BYTES_LIMB: usize = 4;
pub const DIGEST_BYTES_PER_ELEMENT: usize = 8;
pub const FELTS_PER_U128: usize = 4;
pub const FELTS_PER_U64: usize = 2;
pub const DIGEST_NUM_FIELD_ELEMENTS: usize = 4;

pub const ZERO_DIGEST: Digest = [F::ZERO; DIGEST_NUM_FIELD_ELEMENTS];
pub const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

pub type Digest = [F; DIGEST_NUM_FIELD_ELEMENTS];
pub type PrivateKey = [F; 4];

// ============================================================================
// Conversion functions
// ============================================================================

pub fn u128_to_felts(num: u128) -> [F; FELTS_PER_U128] {
    qp_poseidon_core::serialization::u128_to_felts::<F>(num)
}

pub fn felts_to_u128(felts: [F; FELTS_PER_U128]) -> Result<u128, String> {
    qp_poseidon_core::serialization::try_felts_to_u128::<F>(felts)
}

pub fn u64_to_felts(num: u64) -> [F; FELTS_PER_U64] {
    qp_poseidon_core::serialization::u64_to_felts::<F>(num)
}

pub fn felts_to_u64(felts: [F; FELTS_PER_U64]) -> Result<u64, String> {
    qp_poseidon_core::serialization::try_felts_to_u64::<F>(felts)
}

// Encodes an 8-byte string into two field elements.
// We break into 32 bit limbs to ensure injective field element mapping.
pub fn injective_string_to_felt(input: &str) -> Vec<F> {
    qp_poseidon_core::serialization::injective_string_to_felts::<F>(input)
}

/// Converts a given slice into its field element representation.
pub fn injective_bytes_to_felts(input: &[u8]) -> Vec<F> {
    qp_poseidon_core::serialization::injective_bytes_to_felts::<F>(input)
}

/// Converts a given field element slice into its byte representation.
/// Only works for injective felt encodings (outputs of `injective_bytes_to_felts`).
pub fn injective_felts_to_bytes(input: &[F]) -> Result<Vec<u8>, String> {
    qp_poseidon_core::serialization::try_injective_felts_to_bytes::<F>(input)
        .map_err(|e| e.to_string())
}

/// Convert BytesDigest to field elements
pub fn digest_bytes_to_felts(input: BytesDigest) -> Digest {
    qp_poseidon_core::serialization::unsafe_digest_bytes_to_felts::<F>(&input)
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
    let bytes: [u8; DIGEST_BYTES_LEN] =
        qp_poseidon_core::serialization::digest_felts_to_bytes::<F>(&input);
    // Field elements are always in valid range, so this won't fail
    BytesDigest::try_from(bytes).expect("field elements are always in valid range")
}

pub fn felts_to_hashout(felts: &[F; 4]) -> HashOut<F> {
    HashOut { elements: *felts }
}
