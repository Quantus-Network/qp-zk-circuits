use core::array;

use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOutTarget, poseidon2::Poseidon2Hash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use zk_circuits_common::{
    circuit::{CircuitFragment, D, F},
    gadgets::digest4_from_le32x8,
    utils::{digest_bytes_to_felts, injective_bytes_to_felts, BytesDigest, Digest},
};

use crate::inputs::{CircuitInputs, BLOCK_HEADER_SIZE};

pub const DIGEST_LOGS_SIZE: usize = 110;

/// 210 bytes, rounded to 53 felts ~= 212 bytes with 4 byte limbs per felt
const BLOCK_HEADER_FELTS: usize = 53;

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub block_header: [F; BLOCK_HEADER_FELTS],
    pub block_hash: Digest,
    pub parent_hash: Digest,
    pub block_number: F, // Remember to range constaint this to u32
    pub state_root: Digest,
}

impl BlockHeader {
    pub fn new(
        block_header: &[u8; BLOCK_HEADER_SIZE],
        parent_hash: BytesDigest,
        block_number: u32,
        state_root: BytesDigest,
        block_hash: BytesDigest,
    ) -> anyhow::Result<Self> {
        const BLOCK_NUMBER_BYTE_OFFSET: usize = 32;
        const STATE_ROOT_OFFSET: usize = BLOCK_NUMBER_BYTE_OFFSET + 4;
        debug_assert!(
            parent_hash == block_header[..BLOCK_NUMBER_BYTE_OFFSET].try_into().unwrap(),
            "Parent hash not found in expected offset of block header"
        );
        debug_assert!(
            block_number
                == u32::from_le_bytes(
                    block_header[BLOCK_NUMBER_BYTE_OFFSET..(BLOCK_NUMBER_BYTE_OFFSET + 4)]
                        .try_into()
                        .unwrap()
                ),
            "Block number not found in expected offset of block header with LE bytes encoding"
        );
        debug_assert!(
            state_root
                == block_header[STATE_ROOT_OFFSET..(STATE_ROOT_OFFSET + 32)]
                    .try_into()
                    .unwrap(),
            "State root not found in expected offset of block header"
        );
        let block_header = injective_bytes_to_felts(block_header)
            .try_into()
            .expect("block header size not correct; qed");
        Ok(Self {
            block_header,
            block_hash: digest_bytes_to_felts(block_hash),
            parent_hash: digest_bytes_to_felts(parent_hash),
            block_number: F::from_noncanonical_u64(block_number as u64),
            state_root: digest_bytes_to_felts(state_root),
        })
    }
}

impl TryFrom<&CircuitInputs> for BlockHeader {
    type Error = anyhow::Error;

    fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
        Self::new(
            &inputs.private.block_header,
            inputs.public.parent_hash,
            inputs.public.block_number,
            inputs.private.state_root,
            inputs.public.block_hash,
        )
    }
}

const BLOCK_NUMBER_OFFSET: usize = 8;
const STATE_ROOT_OFFSET: usize = 9;

#[derive(Debug, Clone)]
pub struct BlockHeaderTargets {
    /// The felt encoded block header bytes preimage
    pub block_header: [Target; BLOCK_HEADER_FELTS],
    /// The hash of the block header. This is a public input.
    pub block_hash: HashOutTarget,
    /// The hash of the parent block header.
    pub parent_hash: HashOutTarget,
    /// The block number.
    pub block_number: Target,
    /// The root of the state trie.
    pub state_root: HashOutTarget,
}

impl BlockHeaderTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            block_header: array::from_fn(|_| builder.add_virtual_target()),
            block_hash: builder.add_virtual_hash_public_input(),
            parent_hash: builder.add_virtual_hash_public_input(),
            block_number: builder.add_virtual_public_input(),
            state_root: builder.add_virtual_hash(),
        }
    }
}

impl CircuitFragment for BlockHeader {
    type Targets = BlockHeaderTargets;

    fn circuit(
        &Self::Targets {
            block_header,
            block_hash,
            parent_hash,
            block_number,
            state_root,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Range constrain the block_header targets to be 32 bits to verify injective encoding
        for target in block_header {
            builder.range_check(target, 32);
        }
        // Constrain the block number to equal where the block number is stored in the block header
        builder.connect(block_header[BLOCK_NUMBER_OFFSET], block_number);
        // constant 2^32 for (lo + hi * 2^32) reconstruction
        let two_pow_32 = builder.constant(F::from_canonical_u64(1u64 << 32));
        // Constrain the parent hash and state root to equal where these hashes are expected to be stored in the block header
        let limbs_parent_hash: [Target; 8] =
            block_header[..BLOCK_NUMBER_OFFSET].try_into().unwrap();
        let limbs_state_root: [Target; 8] = block_header
            [STATE_ROOT_OFFSET..(STATE_ROOT_OFFSET + 8)]
            .try_into()
            .unwrap();
        let extracted_parent_hash = HashOutTarget::from(digest4_from_le32x8::<F, D>(
            builder,
            limbs_parent_hash,
            Some(two_pow_32),
        ));
        let extracted_state_root = HashOutTarget::from(digest4_from_le32x8(
            builder,
            limbs_state_root,
            Some(two_pow_32),
        ));
        builder.connect_hashes(extracted_parent_hash, parent_hash);
        builder.connect_hashes(extracted_state_root, state_root);
        let computed_hash =
            builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(block_header.to_vec());
        builder.connect_hashes(block_hash, computed_hash);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_target_arr(&targets.block_header, &self.block_header)?;
        pw.set_hash_target(targets.block_hash, self.block_hash.into())?;
        pw.set_hash_target(targets.parent_hash, self.parent_hash.into())?;
        pw.set_target(targets.block_number, self.block_number)?;
        pw.set_hash_target(targets.state_root, self.state_root.into())?;
        Ok(())
    }
}
