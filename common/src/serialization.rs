//! Field element serialization utilities for Plonky2's Goldilocks field.
//!
//! This module provides thin wrappers around the core u64-based serialization
//! functions from `qp_poseidon_core`, converting to/from Plonky2's `GoldilocksField`.

use alloc::{string::String, vec::Vec};
use plonky2::field::types::{Field, PrimeField64};
pub use qp_poseidon_constants::POSEIDON2_OUTPUT;
use qp_poseidon_core::serialization::{
    digest_u64s_to_bytes, injective_bytes_to_u64s, safe_digest_bytes_to_u64s,
    safe_digest_u64s_to_bytes, try_injective_u64s_to_bytes, unsafe_digest_bytes_to_u64s,
};

use crate::circuit::F;

pub const DIGEST_BYTES_PER_ELEMENT: usize = 8;
pub const FELTS_PER_U128: usize = 4;
pub const FELTS_PER_U64: usize = 2;
pub const AMOUNT_QUANTIZATION_FACTOR: u128 = 10_000_000_000u128; // 10^10
pub const SAFE_DIGEST_NUM_FELTS: usize = 8;

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
fn as_32_bit_limb(felt: F, index: usize) -> Result<u64, String> {
    let v = to_u64(felt);
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
// Plonky2 GoldilocksField wrapper functions
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
        let limb = as_32_bit_limb(felt, i)?;
        out |= (limb as u128) << (96 - 32 * i);
    }
    Ok(out)
}

pub fn try_felt_to_quantized_u128(felt: F) -> Result<u128, String> {
    let v = as_32_bit_limb(felt, 0)? as u128;
    Ok(v * AMOUNT_QUANTIZATION_FACTOR)
}

pub fn try_felts_to_u64(felts: [F; FELTS_PER_U64]) -> Result<u64, String> {
    let mut out = 0u64;
    for (i, felt) in felts.into_iter().enumerate() {
        let limb = as_32_bit_limb(felt, i)?;
        out |= limb << (32 - 32 * i);
    }
    Ok(out)
}

/// Injective encoding: 4 bytes -> 1 felt, with terminator marker for collision resistance.
pub fn injective_bytes_to_felts(input: &[u8]) -> Vec<F> {
    injective_bytes_to_u64s(input)
        .into_iter()
        .map(from_u64)
        .collect()
}

/// Non-injective encoding: 8 bytes -> 1 felt, zero-padded.
/// 2 inputs that differ by the order of the Goldilocks field will hash to the same output.
/// Use with care.
pub fn non_injective_bytes_to_felts(input: &[u8]) -> Vec<F> {
    const BYTES_PER_ELEMENT: usize = 8;

    let num_elements = input.len().div_ceil(BYTES_PER_ELEMENT);
    let mut out = Vec::<F>::with_capacity(num_elements);

    let full_chunks = input.len() / BYTES_PER_ELEMENT;
    for i in 0..full_chunks {
        let start = i * BYTES_PER_ELEMENT;
        let bytes: [u8; 8] = input[start..start + BYTES_PER_ELEMENT].try_into().unwrap();
        out.push(from_u64(u64::from_le_bytes(bytes)));
    }

    let remaining = input.len() % BYTES_PER_ELEMENT;
    if remaining > 0 {
        let mut bytes = [0u8; BYTES_PER_ELEMENT];
        bytes[..remaining].copy_from_slice(&input[full_chunks * BYTES_PER_ELEMENT..]);
        out.push(from_u64(u64::from_le_bytes(bytes)));
    }

    out
}

/// Convert 32-byte digest to 4 field elements. Assumes bytes fit within field order.
pub fn unsafe_digest_bytes_to_felts(input: &[u8; 32]) -> [F; POSEIDON2_OUTPUT] {
    let u64s = unsafe_digest_bytes_to_u64s(input);
    [
        from_u64(u64s[0]),
        from_u64(u64s[1]),
        from_u64(u64s[2]),
        from_u64(u64s[3]),
    ]
}

/// Convert 32-byte digest to 8 field elements using safe 4-bytes-per-felt encoding.
///
/// Unlike `unsafe_digest_bytes_to_felts` (8 bytes/felt), this uses 4 bytes per felt,
/// ensuring all values fit within u32 range with no modular reduction risk.
/// Unlike `injective_bytes_to_felts`, this has no terminator since the length is fixed.
pub fn safe_digest_bytes_to_felts(input: &[u8; 32]) -> [F; SAFE_DIGEST_NUM_FELTS] {
    let u64s = safe_digest_bytes_to_u64s(input);
    core::array::from_fn(|i| from_u64(u64s[i]))
}

/// Convert 4 field elements to 32-byte digest (inverse of `unsafe_digest_bytes_to_felts`).
pub fn digest_felts_to_bytes(input: &[F; POSEIDON2_OUTPUT]) -> [u8; 32] {
    let u64s = [
        to_u64(input[0]),
        to_u64(input[1]),
        to_u64(input[2]),
        to_u64(input[3]),
    ];
    digest_u64s_to_bytes(&u64s)
}

/// Convert 8 field elements to 32-byte digest (inverse of `safe_digest_bytes_to_felts`).
pub fn safe_digest_felts_to_bytes(input: &[F; SAFE_DIGEST_NUM_FELTS]) -> [u8; 32] {
    let u64s: [u64; SAFE_DIGEST_NUM_FELTS] = core::array::from_fn(|i| to_u64(input[i]));
    safe_digest_u64s_to_bytes(&u64s)
}

/// Inverse of `injective_bytes_to_felts`.
pub fn try_injective_felts_to_bytes(input: &[F]) -> Result<Vec<u8>, &'static str> {
    let u64s: Vec<u64> = input.iter().map(|f| to_u64(*f)).collect();
    try_injective_u64s_to_bytes(&u64s)
}

/// Convert a string to field elements using injective encoding.
pub fn injective_string_to_felts(input: &str) -> Vec<F> {
    injective_bytes_to_felts(input.as_bytes())
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
    fn test_injective_bytes_round_trip() {
        let test_cases = vec![
            vec![],
            vec![0u8],
            vec![1u8, 2u8, 3u8],
            vec![255u8; 32],
            b"hello world".to_vec(),
        ];

        for original in test_cases {
            let felts = injective_bytes_to_felts(&original);
            let reconstructed = try_injective_felts_to_bytes(&felts).unwrap();
            assert_eq!(original, reconstructed);
        }
    }

    #[test]
    fn test_digest_round_trip() {
        let original = [42u8; 32];
        let felts = unsafe_digest_bytes_to_felts(&original);
        let reconstructed = digest_felts_to_bytes(&felts);
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_safe_digest_round_trip() {
        let original = [42u8; 32];
        let felts = safe_digest_bytes_to_felts(&original);
        let reconstructed = safe_digest_felts_to_bytes(&felts);
        assert_eq!(original, reconstructed);
    }
}
