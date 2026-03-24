//! Field element serialization utilities for Plonky2's Goldilocks field.
//!
//! This module provides thin wrappers around qp-poseidon-core's u64-based
//! serialization functions, converting to/from Plonky2's GoldilocksField type.
//!
//! ## API Overview
//!
//! - `bytes_to_felts` / `felts_to_bytes` - Variable-length byte arrays (4 bytes/felt + terminator)
//! - `digest_to_felts` / `felts_to_digest` - Fixed 32-byte digests → 8 felts (4 bytes/felt)
//! - `bytes_to_digest` / `digest_to_bytes` - Digest values (4 felts ↔ 32 bytes, 8 bytes/felt)

use alloc::{string::String, vec::Vec};
use plonky2::field::types::{Field, PrimeField64};

// Re-export constants from qp-poseidon-core
pub use qp_poseidon_constants::POSEIDON2_OUTPUT;
pub use qp_poseidon_core::serialization::{
    AMOUNT_QUANTIZATION_FACTOR, BYTES_PER_FELT, DIGEST_NUM_FELTS, FELTS_PER_U128, FELTS_PER_U64,
};

use crate::circuit::F;

const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

// ============================================================================
// Internal helpers for Plonky2 GoldilocksField conversion
// ============================================================================

#[inline]
fn from_u64(x: u64) -> F {
    F::from_noncanonical_u64(x)
}

#[inline]
fn to_u64(f: F) -> u64 {
    f.to_canonical_u64()
}

#[inline]
fn as_32_bit_limb(v: u64, index: usize) -> Result<u64, String> {
    if v <= BIT_32_LIMB_MASK {
        Ok(v)
    } else {
        Err(alloc::format!(
            "Felt at index {} with value {} exceeds 32-bit limb size",
            index,
            v
        ))
    }
}

// ============================================================================
// Integer conversions (u64, u128)
// ============================================================================

pub fn u128_to_felts(num: u128) -> [F; FELTS_PER_U128] {
    let mut result = [from_u64(0); FELTS_PER_U128];
    for (i, value) in result.iter_mut().enumerate() {
        let shift = 96 - 32 * i;
        *value = from_u64(((num >> shift) & BIT_32_LIMB_MASK as u128) as u64);
    }
    result
}

pub fn u128_to_quantized_felt(num: u128) -> F {
    let quantized = num / AMOUNT_QUANTIZATION_FACTOR;
    assert!(
        quantized <= BIT_32_LIMB_MASK as u128,
        "Quantized value {} exceeds 32-bit limb size",
        quantized
    );
    from_u64(quantized as u64)
}

pub fn u64_to_felts(num: u64) -> [F; FELTS_PER_U64] {
    [
        from_u64((num >> 32) & BIT_32_LIMB_MASK),
        from_u64(num & BIT_32_LIMB_MASK),
    ]
}

pub fn try_felts_to_u128(felts: [F; FELTS_PER_U128]) -> Result<u128, String> {
    let mut out = 0u128;
    for (i, felt) in felts.into_iter().enumerate() {
        let limb = as_32_bit_limb(to_u64(felt), i)?;
        out |= (limb as u128) << (96 - 32 * i);
    }
    Ok(out)
}

pub fn try_felt_to_quantized_u128(felt: F) -> Result<u128, String> {
    let v = as_32_bit_limb(to_u64(felt), 0)? as u128;
    Ok(v * AMOUNT_QUANTIZATION_FACTOR)
}

pub fn try_felts_to_u64(felts: [F; FELTS_PER_U64]) -> Result<u64, String> {
    let mut out = 0u64;
    for (i, felt) in felts.into_iter().enumerate() {
        let limb = as_32_bit_limb(to_u64(felt), i)?;
        out |= limb << (32 - 32 * i);
    }
    Ok(out)
}

// ============================================================================
// Variable-length bytes <-> felts (4 bytes/felt + terminator)
// Uses qp-poseidon-core's u64-based implementation
// ============================================================================

/// Convert variable-length bytes to field elements.
///
/// Uses 4 bytes per field element with a terminator marker (0x01) appended,
/// ensuring different-length inputs always produce different field element sequences.
pub fn bytes_to_felts(input: &[u8]) -> Vec<F> {
    qp_poseidon_core::serialization::bytes_to_u64s(input)
        .into_iter()
        .map(from_u64)
        .collect()
}

/// Convert field elements back to variable-length bytes.
///
/// Inverse of `bytes_to_felts`. Returns an error if the input doesn't have
/// a valid terminator marker.
pub fn felts_to_bytes(input: &[F]) -> Result<Vec<u8>, &'static str> {
    let u64s: Vec<u64> = input.iter().map(|f| to_u64(*f)).collect();
    qp_poseidon_core::serialization::u64s_to_bytes(&u64s)
}

/// Convert a string to field elements.
pub fn string_to_felts(input: &str) -> Vec<F> {
    bytes_to_felts(input.as_bytes())
}

// ============================================================================
// Fixed 32-byte digest <-> 8 felts (4 bytes/felt)
// Uses qp-poseidon-core's u64-based implementation
// ============================================================================

/// Convert a 32-byte digest to 8 field elements (4 bytes per felt).
///
/// Use this for hashes, secrets, account IDs, and other fixed 32-byte values.
pub fn digest_to_felts(input: &[u8; 32]) -> [F; DIGEST_NUM_FELTS] {
    let u64s = qp_poseidon_core::serialization::digest_to_u64s(input);
    core::array::from_fn(|i| from_u64(u64s[i]))
}

/// Convert 8 field elements back to a 32-byte digest.
///
/// Inverse of `digest_to_felts`.
pub fn felts_to_digest(input: &[F; DIGEST_NUM_FELTS]) -> [u8; 32] {
    let u64s: [u64; DIGEST_NUM_FELTS] = core::array::from_fn(|i| to_u64(input[i]));
    qp_poseidon_core::serialization::u64s_to_digest(&u64s)
}

// ============================================================================
// Digest serialization (4 felts <-> 32 bytes, 8 bytes/felt)
// ============================================================================

/// Convert a digest (4 field elements) to 32 bytes.
///
/// Each field element contributes 8 bytes (its full u64 representation).
/// Use this to serialize hash outputs for storage or comparison.
pub fn digest_to_bytes(input: &[F; POSEIDON2_OUTPUT]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, f) in input.iter().enumerate() {
        let start = i * 8;
        bytes[start..start + 8].copy_from_slice(&to_u64(*f).to_le_bytes());
    }
    bytes
}

/// Convert 32 bytes to a digest (4 field elements).
///
/// Each 8-byte chunk becomes one field element.
/// Use this to deserialize hash outputs from storage.
pub fn bytes_to_digest(input: &[u8; 32]) -> [F; POSEIDON2_OUTPUT] {
    core::array::from_fn(|i| {
        let start = i * 8;
        let bytes: [u8; 8] = input[start..start + 8].try_into().unwrap();
        from_u64(u64::from_le_bytes(bytes))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_u64_round_trip() {
        let test_values = vec![0u64, 1u64, 0xFFFFFFFFu64, 0x1234567890ABCDEFu64, u64::MAX];

        for &original in &test_values {
            let felts = u64_to_felts(original);
            let reconstructed = try_felts_to_u64(felts).unwrap();
            assert_eq!(original, reconstructed);
        }
    }

    #[test]
    fn test_u128_round_trip() {
        let test_values = vec![
            0u128,
            1u128,
            0xFFFFFFFFu128,
            0x123456789ABCDEF0123456789ABCDEFu128,
            u128::MAX,
        ];

        for &original in &test_values {
            let felts = u128_to_felts(original);
            let reconstructed = try_felts_to_u128(felts).unwrap();
            assert_eq!(original, reconstructed);
        }
    }

    #[test]
    fn test_bytes_round_trip() {
        let test_cases = vec![
            vec![],
            vec![0u8],
            vec![1u8, 2u8, 3u8],
            vec![255u8; 32],
            b"hello world".to_vec(),
        ];

        for original in test_cases {
            let felts = bytes_to_felts(&original);
            let reconstructed = felts_to_bytes(&felts).unwrap();
            assert_eq!(original, reconstructed);
        }
    }

    #[test]
    fn test_digest_round_trip() {
        let original = [42u8; 32];
        let felts = digest_to_felts(&original);
        let reconstructed = felts_to_digest(&felts);
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_digest_uses_8_felts() {
        let original = [42u8; 32];
        let felts = digest_to_felts(&original);
        assert_eq!(felts.len(), DIGEST_NUM_FELTS);
    }

    #[test]
    fn test_digest_4felts_round_trip() {
        let original = [42u8; 32];
        let felts = bytes_to_digest(&original);
        let reconstructed = digest_to_bytes(&felts);
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_digest_4felts_uses_4_felts() {
        let original = [42u8; 32];
        let felts = bytes_to_digest(&original);
        assert_eq!(felts.len(), POSEIDON2_OUTPUT);
    }
}
