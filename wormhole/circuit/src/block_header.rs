use alloc::vec::Vec;
use core::array;

use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use zk_circuits_common::{
    circuit::{CircuitFragment, D, F},
    utils::{digest_bytes_to_felts, u64_to_felts, BytesDigest, Digest, FELTS_PER_U64},
};

use crate::inputs::BlockHeaderInputs;

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub block_hash: Digest,
    pub parent_hash: Digest,
    pub block_number: [F; FELTS_PER_U64],
    pub state_root: Digest,
    pub extrinsics_root: Digest,
}

impl From<&BlockHeaderInputs> for BlockHeader {
    fn from(inputs: &BlockHeaderInputs) -> Self {
        Self {
            block_hash: digest_bytes_to_felts(inputs.block_hash),
            parent_hash: digest_bytes_to_felts(inputs.parent_hash),
            block_number: u64_to_felts(inputs.block_number),
            state_root: digest_bytes_to_felts(inputs.state_root),
            extrinsics_root: digest_bytes_to_felts(inputs.extrinsics_root),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockHeaderTargets {
    /// The hash of the block header. This is a public input.
    pub block_hash: HashOutTarget,
    /// The hash of the parent block header.
    pub parent_hash: HashOutTarget,
    /// The block number.
    pub block_number: [Target; FELTS_PER_U64],
    /// The root of the state trie.
    pub state_root: HashOutTarget,
    /// The root of the extrinsics trie.
    pub extrinsics_root: HashOutTarget,
}

impl BlockHeaderTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            block_hash: builder.add_virtual_hash_public_input(),
            parent_hash: builder.add_virtual_hash(),
            block_number: array::from_fn(|_| builder.add_virtual_target()),
            state_root: builder.add_virtual_hash(),
            extrinsics_root: builder.add_virtual_hash(),
        }
    }
}

impl CircuitFragment for BlockHeader {
    type Targets = BlockHeaderTargets;

    fn circuit(
        &Self::Targets {
            block_hash,
            parent_hash,
            block_number,
            state_root,
            extrinsics_root,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&parent_hash.elements);
        preimage.extend_from_slice(block_number);
        preimage.extend_from_slice(&state_root.elements);
        preimage.extend_from_slice(&extrinsics_root.elements);

        // TODO: find a way to include digest logs with a fixed size
        // For now, we can assume the length and types

        let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);
        builder.connect_hashes(*block_hash, computed_hash);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.block_hash, self.block_hash.into())?;
        pw.set_hash_target(targets.parent_hash, self.parent_hash.into())?;
        pw.set_target_arr(&targets.block_number, &self.block_number)?;
        pw.set_hash_target(targets.state_root, self.state_root.into())?;
        pw.set_hash_target(targets.extrinsics_root, self.extrinsics_root.into())?;
        Ok(())
    }
}
