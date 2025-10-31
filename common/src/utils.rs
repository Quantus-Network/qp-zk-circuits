use crate::circuit::F;
use alloc::vec::Vec;
use anyhow::anyhow;
use core::ops::Deref;
use plonky2::field::types::{Field, Field64};
use plonky2::hash::hash_types::HashOut;

pub const INJECTIVE_BYTES_LIMB: usize = 4;
pub const DIGEST_BYTES_PER_ELEMENT: usize = 8;
pub const DIGEST_BYTES_LEN: usize = DIGEST_NUM_FIELD_ELEMENTS * DIGEST_BYTES_PER_ELEMENT;
pub const FELTS_PER_U128: usize = 4;
pub const FELTS_PER_U64: usize = 2;
pub const DIGEST_NUM_FIELD_ELEMENTS: usize = 4;

pub const ZERO_DIGEST: Digest = [F::ZERO; DIGEST_NUM_FIELD_ELEMENTS];
pub const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

pub type Digest = [F; DIGEST_NUM_FIELD_ELEMENTS];
pub type PrivateKey = [F; 4];

#[derive(Hash, Default, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct BytesDigest([u8; DIGEST_BYTES_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    ChunkOutOfFieldRange { chunk_index: usize, value: u64 },
    InvalidLength { expected: usize, got: usize },
}

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
    type Target = [u8; DIGEST_BYTES_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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

pub fn digest_bytes_to_felts(input: BytesDigest) -> Digest {
    qp_poseidon_core::serialization::unsafe_digest_bytes_to_felts::<F>(&input.0)
}

pub fn digest_felts_to_bytes(input: Digest) -> BytesDigest {
    qp_poseidon_core::serialization::digest_felts_to_bytes::<F>(&input)
        .try_into()
        .unwrap()
}

pub fn felts_to_hashout(felts: &[F; 4]) -> HashOut<F> {
    HashOut { elements: *felts }
}
