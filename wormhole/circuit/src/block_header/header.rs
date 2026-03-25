use alloc::vec::Vec;
use core::array;
use plonky2::{
    field::types::Field, hash::poseidon2::hash_no_pad_bytes, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use zk_circuits_common::{
    circuit::{D, F},
    utils::{bytes_to_felts, digest_to_felts, AccountId, BytesDigest, DIGEST_NUM_FELTS},
};

use crate::inputs::CircuitInputs;

pub const DIGEST_LOGS_SIZE: usize = 110;

/// 110 bytes, rounded to 28 felts with injective encoding (4 bytes/felt + terminator)
const DIGEST_LOGS_FELTS: usize = 28;

#[derive(Debug, Clone)]
pub struct HeaderTargets {
    /// parent_hash uses 8 felts (4 bytes/felt) for collision-resistant encoding
    pub parent_hash: [Target; DIGEST_NUM_FELTS],
    pub block_number: Target,
    /// state_root uses 8 felts (4 bytes/felt) for collision-resistant encoding
    pub state_root: [Target; DIGEST_NUM_FELTS],
    /// extrinsics_root uses 8 felts (4 bytes/felt) for collision-resistant encoding
    pub extrinsics_root: [Target; DIGEST_NUM_FELTS],
    pub digest: [Target; DIGEST_LOGS_FELTS],
}

impl HeaderTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            // parent_hash is a private input -- it contributes to block_hash computation
            // but does not need to be exposed as a public input since block_hash already
            // commits to it (block_hash = H(parent_hash || block_number || ...)).
            // Uses 8 felts (4 bytes/felt) for collision-resistant encoding.
            parent_hash: builder
                .add_virtual_targets(DIGEST_NUM_FELTS)
                .try_into()
                .unwrap(),
            block_number: builder.add_virtual_public_input(),
            state_root: builder
                .add_virtual_targets(DIGEST_NUM_FELTS)
                .try_into()
                .unwrap(),
            extrinsics_root: builder
                .add_virtual_targets(DIGEST_NUM_FELTS)
                .try_into()
                .unwrap(),
            digest: array::from_fn(|_| builder.add_virtual_target()),
        }
    }
    pub fn collect_to_vec(&self) -> Vec<Target> {
        self.parent_hash
            .iter()
            .chain(core::iter::once(&self.block_number))
            .chain(self.state_root.iter())
            .chain(self.extrinsics_root.iter())
            .chain(self.digest.iter())
            .cloned()
            .collect()
    }
}

#[derive(Debug)]
pub struct HeaderInputs {
    /// parent_hash uses 8 felts (4 bytes/felt) for collision-resistant encoding
    pub parent_hash: AccountId,
    pub block_number: F,
    /// state_root uses 8 felts (4 bytes/felt) for collision-resistant encoding
    pub state_root: AccountId,
    /// extrinsics_root uses 8 felts (4 bytes/felt) for collision-resistant encoding
    pub extrinsics_root: AccountId,
    pub digest: [F; DIGEST_LOGS_FELTS],
}

impl HeaderInputs {
    pub fn new(
        parent_hash: BytesDigest,
        block_number: u32,
        state_root: BytesDigest,
        extrinsics_root: BytesDigest,
        digest: &[u8; DIGEST_LOGS_SIZE],
    ) -> anyhow::Result<Self> {
        Ok(Self {
            // Use 4 bytes/felt encoding for collision-resistant block header hashing
            parent_hash: digest_to_felts(parent_hash),
            block_number: F::from_noncanonical_u64(block_number as u64),
            state_root: digest_to_felts(state_root),
            extrinsics_root: digest_to_felts(extrinsics_root),
            digest: bytes_to_felts(digest).try_into().unwrap(),
        })
    }
    pub fn block_hash(&self) -> BytesDigest {
        let mut pre_image = Vec::new();
        pre_image.extend_from_slice(&self.parent_hash);
        pre_image.push(self.block_number);
        pre_image.extend_from_slice(&self.state_root);
        pre_image.extend_from_slice(&self.extrinsics_root);
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
            &inputs.private.digest,
        )
    }
}
