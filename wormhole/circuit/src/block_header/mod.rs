use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use zk_circuits_common::{
    circuit::{CircuitFragment, D, F},
    utils::{digest_bytes_to_felts, BytesDigest, Digest},
};

use crate::block_header::header::{HeaderInputs, HeaderTargets};
use crate::inputs::CircuitInputs;

pub mod header;

#[derive(Debug)]
pub struct BlockHeader {
    pub block_hash: Digest,
    pub header: HeaderInputs,
}

impl BlockHeader {
    pub fn new(block_hash: BytesDigest, header: HeaderInputs) -> anyhow::Result<Self> {
        Ok(Self {
            block_hash: digest_bytes_to_felts(block_hash),
            header,
        })
    }
}

impl TryFrom<&CircuitInputs> for BlockHeader {
    type Error = anyhow::Error;

    fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
        Self::new(inputs.public.block_hash, HeaderInputs::try_from(inputs)?)
    }
}

#[derive(Debug, Clone)]
pub struct BlockHeaderTargets {
    /// The hash of the block header. This is a public input.
    pub block_hash: HashOutTarget,
    /// The block header targets
    pub header: HeaderTargets,
}

impl BlockHeaderTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            block_hash: builder.add_virtual_hash_public_input(),
            header: HeaderTargets::new(builder),
        }
    }
}

impl CircuitFragment for BlockHeader {
    type Targets = BlockHeaderTargets;

    /// Builds the block header validation circuit.
    ///
    /// NOTE: This function only does range checking on block_number.
    /// The block_hash == computed_hash constraint is added by `add_block_hash_validation()`
    /// or conditionally in `connect_shared_targets` (for dummy proof support).
    fn circuit(
        Self::Targets {
            block_hash: _,
            header,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Range constrain the block_number target to be 32 bits to verify injective encoding
        builder.range_check(header.block_number, 32);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.block_hash, self.block_hash.into())?;
        pw.set_hash_target(targets.header.parent_hash, self.header.parent_hash.into())?;
        pw.set_target(targets.header.block_number, self.header.block_number)?;
        pw.set_hash_target(targets.header.state_root, self.header.state_root.into())?;
        pw.set_hash_target(
            targets.header.extrinsics_root,
            self.header.extrinsics_root.into(),
        )?;
        pw.set_target_arr(&targets.header.digest, &self.header.digest)?;
        Ok(())
    }
}

/// Adds unconditional block hash validation: block_hash == hash(header contents).
/// Use this for isolated testing of BlockHeader. The full WormholeCircuit uses
/// a conditional version in connect_shared_targets() to support dummy proofs.
pub fn add_block_hash_validation(targets: &BlockHeaderTargets, builder: &mut CircuitBuilder<F, D>) {
    use plonky2::hash::poseidon2::Poseidon2Hash;

    let pre_image = targets.header.collect_to_vec();
    let computed_block_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(pre_image);
    builder.connect_hashes(targets.block_hash, computed_block_hash);
}
