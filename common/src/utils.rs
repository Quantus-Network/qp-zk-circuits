use crate::circuit::F;
use alloc::vec::Vec;
use anyhow::anyhow;
use core::ops::Deref;
use plonky2::field::types::{Field, Field64, PrimeField64};
use plonky2::hash::hash_types::HashOut;

pub const INJECTIVE_BYTES_PER_ELEMENT: usize = 4;
pub const DIGEST_BYTES_PER_ELEMENT: usize = 8;
pub const FELTS_PER_U128: usize = 4;
pub const FELTS_PER_U64: usize = 2;
pub const DIGEST_NUM_FIELD_ELEMENTS: usize = 4;

pub const ZERO_DIGEST: Digest = [F::ZERO; DIGEST_NUM_FIELD_ELEMENTS];
pub const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

pub type Digest = [F; DIGEST_NUM_FIELD_ELEMENTS];
pub type PrivateKey = [F; 4];

#[derive(Hash, Default, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct BytesDigest([u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    ChunkOutOfFieldRange { chunk_index: usize, value: u64 },
    InvalidLength { expected: usize, got: usize },
}

impl TryFrom<&[u8]> for BytesDigest {
    type Error = DigestError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.try_into().map_err(|_| DigestError::InvalidLength {
            expected: 32,
            got: value.len(),
        })?;
        BytesDigest::try_from(bytes)
    }
}

impl TryFrom<[u8; 32]> for BytesDigest {
    type Error = DigestError;
    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        for (i, chunk) in value.chunks(8).enumerate() {
            let v = u64::from_le_bytes(chunk.try_into().unwrap());
            if v >= F::ORDER {
                return Err(DigestError::ChunkOutOfFieldRange {
                    chunk_index: i,
                    value: v,
                });
            }
        }
        Ok(BytesDigest(value))
    }
}

impl From<Digest> for BytesDigest {
    fn from(value: Digest) -> Self {
        let bytes = digest_felts_to_bytes(value);
        Self(*bytes)
    }
}

impl TryFrom<&[F]> for BytesDigest {
    type Error = anyhow::Error;

    fn try_from(value: &[F]) -> Result<Self, Self::Error> {
        let digest: Digest = value.try_into().map_err(|_| {
            anyhow!(
                "failed to deserialize bytes digest from field elements. Expected length 4, got {}",
                value.len()
            )
        })?;
        let bytes = digest_felts_to_bytes(digest);
        Ok(Self(*bytes))
    }
}

impl Deref for BytesDigest {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeltWidthError {
    pub index: usize, // which limb failed
    pub value: u64,   // canonical u64 value of the offending felt
}

#[inline]
fn as_32_bit_limb(felt: F, index: usize) -> Result<u64, FeltWidthError> {
    // Prefer canonical value when checking width.
    let v = felt.to_canonical_u64();
    if v <= BIT_32_LIMB_MASK {
        Ok(v)
    } else {
        Err(FeltWidthError { index, value: v })
    }
}

pub fn u128_to_felts(num: u128) -> [F; FELTS_PER_U128] {
    // We are breaking up the u128 into four 32 bit limbs, which is always canonical since F::ORDER > u32::MAX.
    (0..FELTS_PER_U128)
        .map(|i| {
            let shift = 96 - 32 * i;
            let limb = ((num >> shift) & BIT_32_LIMB_MASK as u128) as u64;
            F::from_canonical_u64(limb)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn felts_to_u128(felts: [F; FELTS_PER_U128]) -> Result<u128, FeltWidthError> {
    let mut out = 0u128;
    for (i, felt) in felts.into_iter().enumerate() {
        let limb = as_32_bit_limb(felt, i)?; // validate < 2^32
        out |= (limb as u128) << (96 - 32 * i);
    }
    Ok(out)
}

pub fn u64_to_felts(num: u64) -> [F; FELTS_PER_U64] {
    [
        F::from_noncanonical_u64((num >> 32) & BIT_32_LIMB_MASK),
        F::from_noncanonical_u64(num & BIT_32_LIMB_MASK),
    ]
}

pub fn felts_to_u64(felts: [F; FELTS_PER_U64]) -> Result<u64, FeltWidthError> {
    let mut out = 0u64;
    for (i, felt) in felts.into_iter().enumerate() {
        let limb = as_32_bit_limb(felt, i)?; // validate < 2^32
                                             // i = 0 -> shift 32, i = 1 -> shift 0
        out |= limb << (32 - 32 * i);
    }
    Ok(out)
}

// Encodes an 8-byte string into two field elements.
// We break into 32 bit limbs to ensure injective field element mapping.
pub fn injective_string_to_felt(input: &str) -> [F; 2] {
    let bytes = input.as_bytes();
    assert!(bytes.len() == 8, "String must be exactly 8 bytes long");

    let mut padded = [0u8; 8];
    padded[..bytes.len()].copy_from_slice(bytes);

    let first = u32::from_le_bytes(padded[0..4].try_into().unwrap());
    let second = u32::from_le_bytes(padded[4..8].try_into().unwrap());

    [
        F::from_noncanonical_u64(first as u64),
        F::from_noncanonical_u64(second as u64),
    ]
}

/// Converts a given slice into its field element representation.
pub fn injective_bytes_to_felts(input: &[u8]) -> Vec<F> {
    let mut field_elements: Vec<F> = Vec::new();
    for chunk in input.chunks(INJECTIVE_BYTES_PER_ELEMENT) {
        let mut bytes = [0u8; INJECTIVE_BYTES_PER_ELEMENT];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element.
        let value = u32::from_le_bytes(bytes);
        let field_element = F::from_noncanonical_u64(value as u64);
        field_elements.push(field_element);
    }

    field_elements
}

/// Converts a given field element slice into its byte representation.
pub fn injective_felts_to_bytes(input: &[F]) -> Result<Vec<u8>, FeltWidthError> {
    let mut bytes: Vec<u8> = Vec::new();

    for (i, field_element) in input.iter().enumerate() {
        let value = as_32_bit_limb(*field_element, i)?;
        let value_bytes = &value.to_le_bytes()[..INJECTIVE_BYTES_PER_ELEMENT];
        bytes.extend_from_slice(value_bytes);
    }

    Ok(bytes)
}

pub fn digest_bytes_to_felts(input: BytesDigest) -> Digest {
    let mut field_elements = [F::ZERO; DIGEST_NUM_FIELD_ELEMENTS];
    for (i, chunk) in input.chunks(DIGEST_BYTES_PER_ELEMENT).enumerate() {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element.
        let value = u64::from_le_bytes(bytes);
        let field_element = F::from_noncanonical_u64(value);
        field_elements[i] = field_element;
    }

    field_elements
}

pub fn digest_felts_to_bytes(input: Digest) -> BytesDigest {
    let mut bytes: BytesDigest = BytesDigest([0u8; 32]);

    for (i, field_element) in input.iter().enumerate() {
        let value = field_element.to_noncanonical_u64();
        let value_bytes = value.to_le_bytes();
        let start_index = i * DIGEST_BYTES_PER_ELEMENT;
        let end_index = start_index + DIGEST_BYTES_PER_ELEMENT;
        bytes.0[start_index..end_index].copy_from_slice(&value_bytes);
    }

    BytesDigest(*bytes)
}

pub fn felts_to_hashout(felts: &[F; 4]) -> HashOut<F> {
    HashOut { elements: *felts }
}
