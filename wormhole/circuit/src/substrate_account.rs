use alloc::vec::Vec;
use core::ops::Deref;
use plonky2::iop::witness::PartialWitness;
use plonky2::{
    hash::hash_types::HashOutTarget, iop::witness::WitnessWrite,
    plonk::circuit_builder::CircuitBuilder,
};
use zk_circuits_common::circuit::CircuitFragment;
use zk_circuits_common::circuit::{D, F};
use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
use zk_circuits_common::utils::{
    digest_bytes_to_felts, digest_felts_to_bytes, BytesDigest, Digest,
};

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct SubstrateAccount(pub Digest);

impl SubstrateAccount {
    pub fn new(address: &[u8]) -> anyhow::Result<Self> {
        Self::from_bytes(address)
    }
}

impl ByteCodec for SubstrateAccount {
    fn to_bytes(&self) -> Vec<u8> {
        digest_felts_to_bytes(self.0).to_vec()
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let bytes = BytesDigest::try_from(slice).unwrap();
        let address = digest_bytes_to_felts(bytes);
        Ok(SubstrateAccount(address))
    }
}

impl FieldElementCodec for SubstrateAccount {
    fn to_field_elements(&self) -> Vec<F> {
        self.0.to_vec()
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 field elements for SubstrateAccount, got: {}",
                elements.len()
            ));
        }
        let account_id: [F; 4] = elements
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert slice to [GoldilocksField; 4]"))?;
        Ok(Self(account_id))
    }
}

impl Deref for SubstrateAccount {
    type Target = Digest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<BytesDigest> for SubstrateAccount {
    fn from(value: BytesDigest) -> Self {
        let felts = digest_bytes_to_felts(value);
        SubstrateAccount(felts)
    }
}

/// Targets for a single exit account (used internally)
#[derive(Debug, Clone, Copy)]
pub struct ExitAccountTargets {
    pub address: HashOutTarget,
}

impl ExitAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            address: builder.add_virtual_hash_public_input(),
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
        pw.set_hash_target(targets.exit_account_1.address, self.exit_account_1.0.into())?;
        pw.set_hash_target(targets.exit_account_2.address, self.exit_account_2.0.into())
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
        pw.set_hash_target(targets.address, self.0.into())
    }
}
