use alloc::vec::Vec;
use core::array;
use plonky2::{
    field::types::Field, hash::poseidon2::hash_no_pad_bytes, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use zk_circuits_common::{
    circuit::{D, F},
    utils::{bytes_to_digest, bytes_to_felts, BytesDigest, Digest, POSEIDON2_OUTPUT},
};

use crate::inputs::CircuitInputs;

pub const DIGEST_LOGS_SIZE: usize = 110;

/// 110 bytes, rounded to 28 felts with injective encoding (4 bytes/felt + terminator)
const DIGEST_LOGS_FELTS: usize = 28;

#[derive(Debug, Clone)]
pub struct HeaderTargets {
    /// parent_hash uses 4 felts (8 bytes/felt) for hash outputs
    pub parent_hash: [Target; POSEIDON2_OUTPUT],
    pub block_number: Target,
    /// state_root uses 4 felts (8 bytes/felt) for hash outputs
    pub state_root: [Target; POSEIDON2_OUTPUT],
    /// extrinsics_root uses 4 felts (8 bytes/felt) for hash outputs
    pub extrinsics_root: [Target; POSEIDON2_OUTPUT],
    /// zk_trie_root uses 4 felts (8 bytes/felt) for hash outputs
    /// Placed before digest to ensure fixed offset regardless of digest content
    pub zk_trie_root: [Target; POSEIDON2_OUTPUT],
    pub digest: [Target; DIGEST_LOGS_FELTS],
}

impl HeaderTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            // parent_hash is a private input -- it contributes to block_hash computation
            // but does not need to be exposed as a public input since block_hash already
            // commits to it (block_hash = H(parent_hash || block_number || ...)).
            // Uses 4 felts (8 bytes/felt) for hash outputs.
            parent_hash: builder
                .add_virtual_targets(POSEIDON2_OUTPUT)
                .try_into()
                .unwrap(),
            block_number: builder.add_virtual_public_input(),
            state_root: builder
                .add_virtual_targets(POSEIDON2_OUTPUT)
                .try_into()
                .unwrap(),
            extrinsics_root: builder
                .add_virtual_targets(POSEIDON2_OUTPUT)
                .try_into()
                .unwrap(),
            // zk_trie_root is private - verified against zk_merkle_proof.root_hash
            zk_trie_root: builder
                .add_virtual_targets(POSEIDON2_OUTPUT)
                .try_into()
                .unwrap(),
            digest: array::from_fn(|_| builder.add_virtual_target()),
        }
    }

    /// Collect header fields for block hash computation.
    /// Order matches chain: parent_hash, block_number, state_root, extrinsics_root, zk_trie_root, digest
    pub fn collect_to_vec(&self) -> Vec<Target> {
        self.parent_hash
            .iter()
            .chain(core::iter::once(&self.block_number))
            .chain(self.state_root.iter())
            .chain(self.extrinsics_root.iter())
            .chain(self.zk_trie_root.iter())
            .chain(self.digest.iter())
            .cloned()
            .collect()
    }
}

#[derive(Debug)]
pub struct HeaderInputs {
    /// parent_hash uses 4 felts (8 bytes/felt) for hash outputs
    pub parent_hash: Digest,
    pub block_number: F,
    /// state_root uses 4 felts (8 bytes/felt) for hash outputs
    pub state_root: Digest,
    /// extrinsics_root uses 4 felts (8 bytes/felt) for hash outputs
    pub extrinsics_root: Digest,
    /// zk_trie_root uses 4 felts (8 bytes/felt) for hash outputs
    pub zk_trie_root: Digest,
    pub digest: [F; DIGEST_LOGS_FELTS],
}

impl HeaderInputs {
    pub fn new(
        parent_hash: BytesDigest,
        block_number: u32,
        state_root: BytesDigest,
        extrinsics_root: BytesDigest,
        zk_trie_root: BytesDigest,
        digest: &[u8; DIGEST_LOGS_SIZE],
    ) -> anyhow::Result<Self> {
        Ok(Self {
            // Use 8 bytes/felt encoding for hash outputs
            parent_hash: bytes_to_digest(parent_hash),
            block_number: F::from_noncanonical_u64(block_number as u64),
            state_root: bytes_to_digest(state_root),
            extrinsics_root: bytes_to_digest(extrinsics_root),
            zk_trie_root: bytes_to_digest(zk_trie_root),
            digest: bytes_to_felts(digest).try_into().unwrap(),
        })
    }
    pub fn block_hash(&self) -> BytesDigest {
        let mut pre_image = Vec::new();
        pre_image.extend_from_slice(&self.parent_hash);
        pre_image.push(self.block_number);
        pre_image.extend_from_slice(&self.state_root);
        pre_image.extend_from_slice(&self.extrinsics_root);
        pre_image.extend_from_slice(&self.zk_trie_root);
        pre_image.extend_from_slice(&self.digest);
        hash_no_pad_bytes(&pre_image).try_into().unwrap()
    }
}

impl TryFrom<&CircuitInputs> for HeaderInputs {
    type Error = anyhow::Error;

    fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
        Self::new(
            inputs.private.parent_hash,
            inputs.public.block_number,
            inputs.private.state_root,
            inputs.private.extrinsics_root,
            inputs.private.zk_trie_root.try_into()?,
            &inputs.private.digest,
        )
    }
}
