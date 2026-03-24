use alloc::vec::Vec;
use core::ops::Deref;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use zk_circuits_common::circuit::CircuitFragment;
use zk_circuits_common::circuit::{D, F};
use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
use zk_circuits_common::utils::{
    digest_to_felts, felts_to_digest, AccountId, BytesDigest, DIGEST_NUM_FELTS,
};

/// A substrate account represented as 8 field elements (4 bytes per felt).
/// This encoding ensures collision resistance for account addresses.
#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct SubstrateAccount(pub AccountId);

impl SubstrateAccount {
    pub fn new(address: &[u8]) -> anyhow::Result<Self> {
        Self::from_bytes(address)
    }
}

impl ByteCodec for SubstrateAccount {
    fn to_bytes(&self) -> Vec<u8> {
        felts_to_digest(self.0).to_vec()
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        // For 4-bytes-per-felt encoding, we don't need the 8-byte chunk validation
        // that BytesDigest::try_from performs. Each u32 chunk is valid in Goldilocks.
        let bytes: [u8; 32] = slice.try_into().map_err(|_| {
            anyhow::anyhow!(
                "SubstrateAccount requires exactly 32 bytes, got {}",
                slice.len()
            )
        })?;
        let address = digest_to_felts(BytesDigest::new_unchecked(bytes));
        Ok(SubstrateAccount(address))
    }
}

impl FieldElementCodec for SubstrateAccount {
    fn to_field_elements(&self) -> Vec<F> {
        self.0.to_vec()
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != DIGEST_NUM_FELTS {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for SubstrateAccount, got: {}",
                DIGEST_NUM_FELTS,
                elements.len()
            ));
        }
        let account_id: AccountId = elements
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert slice to AccountId"))?;
        Ok(Self(account_id))
    }
}

impl Deref for SubstrateAccount {
    type Target = AccountId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<BytesDigest> for SubstrateAccount {
    fn from(value: BytesDigest) -> Self {
        let felts = digest_to_felts(value);
        SubstrateAccount(felts)
    }
}

/// Targets for a substrate account (8 field elements).
#[derive(Debug, Clone, Copy)]
pub struct AccountTargets {
    pub elements: [Target; DIGEST_NUM_FELTS],
}

impl AccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            elements: core::array::from_fn(|_| builder.add_virtual_target()),
        }
    }

    pub fn new_public(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            elements: core::array::from_fn(|_| builder.add_virtual_public_input()),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        self.elements.to_vec()
    }
}

/// Targets for a single exit account (used for public outputs)
#[derive(Debug, Clone, Copy)]
pub struct ExitAccountTargets {
    pub address: AccountTargets,
}

impl ExitAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            address: AccountTargets::new_public(builder),
        }
    }
}

/// Targets for two exit accounts (spend + change) in Bitcoin-style outputs
#[derive(Debug, Clone, Copy)]
pub struct DualExitAccountTargets {
    /// First exit account (spend destination)
    pub exit_account_1: ExitAccountTargets,
    /// Second exit account (change destination)
    pub exit_account_2: ExitAccountTargets,
}

impl DualExitAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            exit_account_1: ExitAccountTargets::new(builder),
            exit_account_2: ExitAccountTargets::new(builder),
        }
    }
}

/// Exit account data for two outputs (spend + change)
#[derive(Debug, Clone)]
pub struct DualExitAccount {
    pub exit_account_1: SubstrateAccount,
    pub exit_account_2: SubstrateAccount,
}

impl CircuitFragment for DualExitAccount {
    type Targets = DualExitAccountTargets;

    /// Builds a dummy circuit to include both exit accounts as public inputs.
    fn circuit(_targets: &Self::Targets, _builder: &mut CircuitBuilder<F, D>) {
        // No constraints needed - exit accounts are just public inputs
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_target_arr(
            &targets.exit_account_1.address.elements,
            &self.exit_account_1.0,
        )?;
        pw.set_target_arr(
            &targets.exit_account_2.address.elements,
            &self.exit_account_2.0,
        )
    }
}

impl CircuitFragment for SubstrateAccount {
    type Targets = ExitAccountTargets;

    /// Builds a dummy circuit to include the exit account as a public input.
    fn circuit(Self::Targets { address: _ }: &Self::Targets, _builder: &mut CircuitBuilder<F, D>) {}

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_target_arr(&targets.address.elements, &self.0)
    }
}
