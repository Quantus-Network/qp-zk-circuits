use alloc::vec::Vec;
use core::array;
use plonky2::field::types::Field;
use plonky2::hash::poseidon2::hash_no_pad_bytes;
use plonky2::{
    hash::hash_types::HashOutTarget, iop::target::Target, plonk::circuit_builder::CircuitBuilder,
};

use crate::inputs::CircuitInputs;
use crate::substrate_account::SubstrateAccount;
use zk_circuits_common::circuit::{D, F};
use zk_circuits_common::codec::ByteCodec;
use zk_circuits_common::utils::{u64_to_felts, BytesDigest, FELTS_PER_U64};

pub const NUM_LEAF_INPUT_FELTS: usize = 12;

#[derive(Debug, Clone)]
pub struct LeafTargets {
    pub asset_id: Target,
    pub transfer_count: [Target; FELTS_PER_U64],
    pub funding_account: HashOutTarget,
    pub to_account: HashOutTarget,
    /// The input amount from storage (private). This is what's stored in the merkle trie.
    pub input_amount: Target,
    /// The output amount after fee deduction (public). This is what the user receives.
    pub output_amount: Target,
    /// Volume fee rate in basis points (public). Verified on-chain to match runtime config.
    pub volume_fee_bps: Target,
}

impl LeafTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Register asset_id as a public input (should be first if this is called before other targets)
        let asset_id = builder.add_virtual_public_input();
        // output_amount and volume_fee_bps are public inputs
        let output_amount = builder.add_virtual_public_input();
        let volume_fee_bps = builder.add_virtual_public_input();
        // Private inputs
        let transfer_count = array::from_fn(|_| builder.add_virtual_target());
        let funding_account = builder.add_virtual_hash();
        let to_account = builder.add_virtual_hash();
        let input_amount = builder.add_virtual_target(); // Private - not a public input

        Self {
            asset_id,
            transfer_count,
            funding_account,
            to_account,
            input_amount,
            output_amount,
            volume_fee_bps,
        }
    }

    /// Collect targets for the leaf hash (uses input_amount, which is what's stored in the trie)
    pub fn collect_to_vec(&self) -> Vec<Target> {
        core::iter::once(self.asset_id)
            .chain(self.transfer_count.iter().copied())
            .chain(self.funding_account.elements.iter().copied())
            .chain(self.to_account.elements.iter().copied())
            .chain(core::iter::once(self.input_amount))
            .collect()
    }

    /// Collect 32-bit targets for range checking
    pub fn collect_32_bit_targets(&self) -> Vec<Target> {
        core::iter::once(self.asset_id)
            .chain(self.transfer_count.iter().copied())
            .chain(core::iter::once(self.input_amount))
            .chain(core::iter::once(self.output_amount))
            .chain(core::iter::once(self.volume_fee_bps))
            .collect()
    }
}

#[derive(Debug)]
pub struct LeafInputs {
    pub asset_id: F,
    pub transfer_count: [F; FELTS_PER_U64],
    pub funding_account: SubstrateAccount,
    pub to_account: SubstrateAccount,
    /// The input amount from storage (private)
    pub input_amount: F,
    /// The output amount after fee deduction (public)
    pub output_amount: F,
    /// Volume fee rate in basis points (public)
    pub volume_fee_bps: F,
}

impl LeafInputs {
    pub fn new(
        asset_id: u32,
        transfer_count: u64,
        funding_account: BytesDigest,
        to_account: BytesDigest,
        input_amount: u32,
        output_amount: u32,
        volume_fee_bps: u32,
    ) -> anyhow::Result<Self> {
        let asset_id = F::from_canonical_u32(asset_id);
        let transfer_count = u64_to_felts(transfer_count);
        let input_amount = F::from_canonical_u32(input_amount);
        let output_amount = F::from_canonical_u32(output_amount);
        let volume_fee_bps = F::from_canonical_u32(volume_fee_bps);
        let funding_account = SubstrateAccount::from_bytes(funding_account.as_slice())?;
        let to_account = SubstrateAccount::from_bytes(to_account.as_slice())?;
        Ok(Self {
            asset_id,
            transfer_count,
            funding_account,
            to_account,
            input_amount,
            output_amount,
            volume_fee_bps,
        })
    }

    /// Compute the leaf hash using input_amount (what's stored in the trie)
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut leaf_elements = Vec::new();
        leaf_elements.push(self.asset_id);
        leaf_elements.extend_from_slice(&self.transfer_count);
        leaf_elements.extend_from_slice(&self.funding_account.0);
        leaf_elements.extend_from_slice(&self.to_account.0);
        leaf_elements.push(self.input_amount);

        hash_no_pad_bytes(&leaf_elements)
    }
}

impl TryFrom<&CircuitInputs> for LeafInputs {
    type Error = anyhow::Error;

    fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
        Self::new(
            inputs.public.asset_id,
            inputs.private.transfer_count,
            inputs.private.funding_account,
            inputs.private.unspendable_account,
            inputs.private.input_amount,
            inputs.public.output_amount,
            inputs.public.volume_fee_bps,
        )
    }
}
