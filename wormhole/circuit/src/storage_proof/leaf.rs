use alloc::vec::Vec;
use core::array;
use plonky2::field::types::Field;
use plonky2::hash::poseidon2::hash_no_pad_bytes;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::inputs::CircuitInputs;
use crate::substrate_account::AccountTargets;
use zk_circuits_common::circuit::{D, F};
use zk_circuits_common::utils::{
    bytes_to_digest, u64_to_felts, BytesDigest, Digest, FELTS_PER_U64, POSEIDON2_OUTPUT,
};

/// Number of field elements in the leaf preimage:
/// - 1 (asset_id)
/// - 2 (transfer_count as u64)
/// - 4 (funding_account, 8 bytes/felt)
/// - 4 (to_account, 8 bytes/felt)
/// - 1 (input_amount)
///   Total: 12
///
/// Note: Both accounts use 4 felts (8 bytes/felt) to match on-chain poseidon hashing.
/// Collision resistance is provided by the storage proof verification.
pub const NUM_LEAF_INPUT_FELTS: usize = 1 + FELTS_PER_U64 + POSEIDON2_OUTPUT + POSEIDON2_OUTPUT + 1;

#[derive(Debug, Clone)]
pub struct LeafTargets {
    pub asset_id: Target,
    pub transfer_count: [Target; FELTS_PER_U64],
    /// Funding account encoded as 4 felts (8 bytes/felt)
    pub funding_account: AccountTargets,
    /// To account (unspendable) encoded as 4 felts (8 bytes/felt)
    pub to_account: AccountTargets,
    /// The input amount from storage (private). This is what's stored in the merkle trie.
    pub input_amount: Target,
    /// The first output amount after fee deduction (public). Spend destination.
    pub output_amount_1: Target,
    /// The second output amount after fee deduction (public). Change destination.
    pub output_amount_2: Target,
    /// Volume fee rate in basis points (public). Verified on-chain to match runtime config.
    pub volume_fee_bps: Target,
}

impl LeafTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Register asset_id as a public input (should be first if this is called before other targets)
        let asset_id = builder.add_virtual_public_input();
        // output_amount_1, output_amount_2, and volume_fee_bps are public inputs
        let output_amount_1 = builder.add_virtual_public_input();
        let output_amount_2 = builder.add_virtual_public_input();
        let volume_fee_bps = builder.add_virtual_public_input();
        // Private inputs
        let transfer_count = array::from_fn(|_| builder.add_virtual_target());
        let funding_account = AccountTargets::new(builder);
        let to_account = AccountTargets::new(builder);
        let input_amount = builder.add_virtual_target(); // Private - not a public input

        Self {
            asset_id,
            transfer_count,
            funding_account,
            to_account,
            input_amount,
            output_amount_1,
            output_amount_2,
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
            .chain(core::iter::once(self.output_amount_1))
            .chain(core::iter::once(self.output_amount_2))
            .chain(core::iter::once(self.volume_fee_bps))
            .collect()
    }
}

#[derive(Debug)]
pub struct LeafInputs {
    pub asset_id: F,
    pub transfer_count: [F; FELTS_PER_U64],
    /// Funding account encoded as 4 felts (8 bytes/felt)
    pub funding_account: Digest,
    /// To account (unspendable) encoded as 4 felts (8 bytes/felt)
    pub to_account: Digest,
    /// The input amount from storage (private)
    pub input_amount: F,
    /// The first output amount after fee deduction (public). Spend destination.
    pub output_amount_1: F,
    /// The second output amount after fee deduction (public). Change destination.
    pub output_amount_2: F,
    /// Volume fee rate in basis points (public)
    pub volume_fee_bps: F,
}

impl LeafInputs {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: u32,
        transfer_count: u64,
        funding_account: BytesDigest,
        to_account: BytesDigest,
        input_amount: u32,
        output_amount_1: u32,
        output_amount_2: u32,
        volume_fee_bps: u32,
    ) -> anyhow::Result<Self> {
        let asset_id = F::from_canonical_u32(asset_id);
        let transfer_count = u64_to_felts(transfer_count);
        let input_amount = F::from_canonical_u32(input_amount);
        let output_amount_1 = F::from_canonical_u32(output_amount_1);
        let output_amount_2 = F::from_canonical_u32(output_amount_2);
        let volume_fee_bps = F::from_canonical_u32(volume_fee_bps);
        // Use 4 felts (8 bytes/felt) to match on-chain poseidon encoding
        let funding_account = bytes_to_digest(funding_account);
        let to_account = bytes_to_digest(to_account);
        Ok(Self {
            asset_id,
            transfer_count,
            funding_account,
            to_account,
            input_amount,
            output_amount_1,
            output_amount_2,
            volume_fee_bps,
        })
    }

    /// Compute the leaf hash using input_amount (what's stored in the trie)
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut leaf_elements = Vec::new();
        leaf_elements.push(self.asset_id);
        leaf_elements.extend_from_slice(&self.transfer_count);
        leaf_elements.extend_from_slice(&self.funding_account);
        leaf_elements.extend_from_slice(&self.to_account);
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
            inputs.public.output_amount_1,
            inputs.public.output_amount_2,
            inputs.public.volume_fee_bps,
        )
    }
}
