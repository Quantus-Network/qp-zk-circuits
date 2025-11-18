use alloc::vec::Vec;
use core::array;
use plonky2::{
    field::types::Field, hash::hash_types::HashOutTarget, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use zk_circuits_common::{
    circuit::{D, F},
    utils::{digest_bytes_to_felts, injective_bytes_to_felts, BytesDigest, Digest},
};

use crate::inputs::CircuitInputs;

pub const DIGEST_LOGS_SIZE: usize = 110;

/// 110 bytes, rounded to 23 felts ~= 112 bytes with 4 byte limbs per felt
const DIGEST_LOGS_FELTS: usize = 28;

#[derive(Debug, Clone)]
pub struct HeaderTargets {
    pub parent_hash: HashOutTarget,
    pub block_number: Target,
    pub state_root: HashOutTarget,
    pub extrinsics_root: HashOutTarget,
    pub digest: [Target; DIGEST_LOGS_FELTS],
}

impl HeaderTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            parent_hash: builder.add_virtual_hash_public_input(),
            block_number: builder.add_virtual_public_input(),
            state_root: builder.add_virtual_hash(),
            extrinsics_root: builder.add_virtual_hash(),
            digest: array::from_fn(|_| builder.add_virtual_target()),
        }
    }
    pub fn collect_to_vec(&self) -> Vec<Target> {
        self.parent_hash
            .elements
            .iter()
            .chain(core::iter::once(&self.block_number))
            .chain(self.state_root.elements.iter())
            .chain(self.extrinsics_root.elements.iter())
            .chain(self.digest.iter())
            .cloned()
            .collect()
    }
}

#[derive(Debug)]
pub struct HeaderInputs {
    pub parent_hash: Digest,
    pub block_number: F,
    pub state_root: Digest,
    pub extrinsics_root: Digest,
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
            parent_hash: digest_bytes_to_felts(parent_hash),
            block_number: F::from_noncanonical_u64(block_number as u64),
            state_root: digest_bytes_to_felts(state_root),
            extrinsics_root: digest_bytes_to_felts(extrinsics_root),
            digest: injective_bytes_to_felts(digest).try_into().unwrap(),
        })
    }
}

impl TryFrom<&CircuitInputs> for HeaderInputs {
    type Error = anyhow::Error;

    fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
        Self::new(
            inputs.public.parent_hash,
            inputs.public.block_number,
            inputs.private.state_root,
            inputs.private.extrinsics_root,
            &inputs.private.digest,
        )
    }
}
