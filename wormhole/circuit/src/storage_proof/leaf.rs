#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::array;
use plonky2::{
	field::types::Field, hash::hash_types::HashOutTarget, iop::target::Target,
	plonk::circuit_builder::CircuitBuilder,
};
#[cfg(feature = "std")]
use std::array;

use crate::{
	codec::ByteCodec,
	inputs::{BytesDigest, CircuitInputs},
	substrate_account::SubstrateAccount,
};
use zk_circuits_common::{
	circuit::{D, F},
	utils::{u128_to_felts, FELTS_PER_U128},
};

pub const NUM_LEAF_INPUT_FELTS: usize = 11;

#[derive(Debug, Clone)]
pub struct LeafTargets {
	pub transfer_count: Target,
	pub funding_account: HashOutTarget,
	pub to_account: HashOutTarget,
	pub funding_amount: [Target; FELTS_PER_U128],
}

impl LeafTargets {
	pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
		let transfer_count = builder.add_virtual_target();
		let funding_account = builder.add_virtual_hash();
		let to_account = builder.add_virtual_hash();
		let funding_amount = array::from_fn(|_| builder.add_virtual_public_input());

		Self { transfer_count, funding_account, to_account, funding_amount }
	}

	pub fn collect_to_vec(&self) -> Vec<Target> {
		core::iter::once(self.transfer_count)
			.chain(self.funding_account.elements)
			.chain(self.to_account.elements)
			.chain(self.funding_amount)
			.collect()
	}
}

#[derive(Debug)]
pub struct LeafInputs {
	pub transfer_count: F,
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
		let transfer_count = F::from_noncanonical_u64(transfer_count);
		let funding_amount = u128_to_felts(funding_amount);
		let funding_account = SubstrateAccount::from_bytes(funding_account.as_slice())?;
		let to_account = SubstrateAccount::from_bytes(to_account.as_slice())?;
		Ok(Self { transfer_count, funding_account, to_account, funding_amount })
	}
}

impl TryFrom<&CircuitInputs> for LeafInputs {
	type Error = anyhow::Error;

	fn try_from(inputs: &CircuitInputs) -> Result<Self, Self::Error> {
		Self::new(
			inputs.private.transfer_count,
			inputs.private.funding_account,
			inputs.public.exit_account,
			inputs.public.funding_amount,
		)
	}
}
