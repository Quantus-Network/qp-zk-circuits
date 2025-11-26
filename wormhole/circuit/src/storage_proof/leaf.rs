use alloc::vec::Vec;
use core::array;
use plonky2::hash::poseidon2::hash_no_pad_bytes;
use plonky2::{
    hash::hash_types::HashOutTarget, iop::target::Target, plonk::circuit_builder::CircuitBuilder,
};

use crate::inputs::CircuitInputs;
use crate::substrate_account::SubstrateAccount;
use zk_circuits_common::circuit::{D, F};
use zk_circuits_common::codec::ByteCodec;
use zk_circuits_common::utils::{
    u128_to_felts, u64_to_felts, BytesDigest, FELTS_PER_U128, FELTS_PER_U64,
};

pub const NUM_LEAF_INPUT_FELTS: usize = 11;

#[derive(Debug, Clone)]
pub struct LeafTargets {
    pub transfer_count: [Target; FELTS_PER_U64],
    pub funding_account: HashOutTarget,
    pub to_account: HashOutTarget,
    pub funding_amount: [Target; FELTS_PER_U128],
}

impl LeafTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        let transfer_count = array::from_fn(|_| builder.add_virtual_target());
        let funding_account = builder.add_virtual_hash();
        let to_account = builder.add_virtual_hash();
        let funding_amount = array::from_fn(|_| builder.add_virtual_public_input());

        Self {
            transfer_count,
            funding_account,
            to_account,
            funding_amount,
        }
    }

    pub fn collect_to_vec(&self) -> Vec<Target> {
        self.transfer_count
            .iter()
            .chain(self.funding_account.elements.iter())
            .chain(self.to_account.elements.iter())
            .chain(self.funding_amount.iter())
            .cloned()
            .collect()
    }
    pub fn collect_32_bit_targets(&self) -> Vec<Target> {
        self.transfer_count
            .iter()
            .chain(self.funding_amount.iter())
            .cloned()
            .collect()
    }
}

#[derive(Debug)]
pub struct LeafInputs {
    pub transfer_count: [F; FELTS_PER_U64],
    pub funding_account: SubstrateAccount,
    pub to_account: SubstrateAccount,
    pub funding_amount: [F; FELTS_PER_U128],
}

impl LeafInputs {
    pub fn new(
        transfer_count: u64,
        funding_account: BytesDigest,
        to_account: BytesDigest,
        funding_amount: u128,
    ) -> anyhow::Result<Self> {
        let transfer_count = u64_to_felts(transfer_count);
        let funding_amount = u128_to_felts(funding_amount);
        let funding_account = SubstrateAccount::from_bytes(funding_account.as_slice())?;
        let to_account = SubstrateAccount::from_bytes(to_account.as_slice())?;
        Ok(Self {
            transfer_count,
            funding_account,
            to_account,
            funding_amount,
        })
    }

    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut leaf_elements = Vec::new();
        leaf_elements.extend_from_slice(&self.transfer_count);
        leaf_elements.extend_from_slice(&self.funding_account.0);
        leaf_elements.extend_from_slice(&self.to_account.0);
        leaf_elements.extend_from_slice(&self.funding_amount);

        hash_no_pad_bytes(&leaf_elements)
    }
}

impl TryFrom<&CircuitInputs> for LeafInputs {
    type Error = anyhow::Error;

    fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
        Self::new(
            inputs.private.transfer_count,
            inputs.private.funding_account,
            inputs.private.unspendable_account,
            inputs.public.funding_amount,
        )
    }
}
