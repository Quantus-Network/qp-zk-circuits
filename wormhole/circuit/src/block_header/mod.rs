use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon2::Poseidon2Hash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use zk_circuits_common::{
    circuit::{CircuitFragment, D, F},
    utils::{bytes_to_digest, BytesDigest, Digest},
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
            block_hash: bytes_to_digest(block_hash),
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

impl BlockHeader {
    /// Computes `hash(header contents)` in-circuit.
    fn computed_block_hash(
        targets: &BlockHeaderTargets,
        builder: &mut CircuitBuilder<F, D>,
    ) -> plonky2::hash::hash_types::HashOutTarget {
        let pre_image = targets.header.collect_to_vec();
        builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(pre_image)
    }

    /// Builds the block header circuit WITHOUT binding `block_hash` to the header
    /// contents (only the `block_number` range check is added).
    ///
    /// This is an escape hatch for the full Wormhole circuit, which must make the
    /// hash binding *conditional* to support dummy proofs and therefore pairs this
    /// with [`Self::conditional_block_hash_binding`]. Every other caller should use
    /// [`CircuitFragment::circuit`], which enforces the binding unconditionally.
    /// Using this function without also adding a hash binding produces an
    /// under-constrained circuit where the public `block_hash` is unrelated to the
    /// private header preimage.
    pub fn circuit_without_hash_binding(
        targets: &BlockHeaderTargets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Range constrain the block_number target to be 32 bits to verify injective encoding
        builder.range_check(targets.header.block_number, 32);
    }

    /// Enforces `block_hash == hash(header contents)` whenever `is_not_dummy` is 1,
    /// i.e. `(block_hash[i] - computed[i]) * is_not_dummy == 0` for each limb.
    ///
    /// `is_not_dummy` MUST itself be constrained by the caller (the full Wormhole
    /// circuit derives it in-circuit from `block_hash == 0 AND outputs == 0`);
    /// otherwise a malicious prover can simply witness it to 0 and skip the check.
    pub fn conditional_block_hash_binding(
        targets: &BlockHeaderTargets,
        builder: &mut CircuitBuilder<F, D>,
        is_not_dummy: Target,
    ) {
        let computed_block_hash = Self::computed_block_hash(targets, builder);
        let zero = builder.zero();
        for i in 0..4 {
            let diff = builder.sub(
                targets.block_hash.elements[i],
                computed_block_hash.elements[i],
            );
            let result = builder.mul(diff, is_not_dummy);
            builder.connect(result, zero);
        }
    }
}

impl CircuitFragment for BlockHeader {
    type Targets = BlockHeaderTargets;

    /// Builds the block header validation circuit, unconditionally enforcing
    /// `block_hash == hash(header contents)` in addition to range-checking
    /// `block_number`.
    ///
    /// This is the safe-by-default entry point: any circuit composed from this
    /// fragment inherits the hash binding that gives the public `block_hash`
    /// input its meaning. The full Wormhole circuit is the one exception; it
    /// uses [`BlockHeader::circuit_without_hash_binding`] together with
    /// [`BlockHeader::conditional_block_hash_binding`] so dummy proofs
    /// (block_hash == 0) can skip the binding.
    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>) {
        Self::circuit_without_hash_binding(targets, builder);
        let computed_block_hash = Self::computed_block_hash(targets, builder);
        builder.connect_hashes(targets.block_hash, computed_block_hash);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.block_hash, self.block_hash.into())?;
        // parent_hash, state_root, extrinsics_root, zk_tree_root use 4 felts (8 bytes/felt)
        pw.set_target_arr(&targets.header.parent_hash, &self.header.parent_hash)?;
        pw.set_target(targets.header.block_number, self.header.block_number)?;
        pw.set_target_arr(&targets.header.state_root, &self.header.state_root)?;
        pw.set_target_arr(
            &targets.header.extrinsics_root,
            &self.header.extrinsics_root,
        )?;
        pw.set_target_arr(&targets.header.zk_tree_root, &self.header.zk_tree_root)?;
        pw.set_target_arr(&targets.header.digest, &self.header.digest)?;
        Ok(())
    }
}