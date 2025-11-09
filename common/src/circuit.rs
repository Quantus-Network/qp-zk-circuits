use alloc::{string::String, vec::Vec};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use serde::Deserialize;

// Plonky2 setup parameters.
pub const D: usize = 2; // D=2 provides 100-bits of security
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField; // Goldilocks field

#[derive(Debug, Deserialize)]
pub struct TransferProofJson {
    pub transfer_count: u64,
    pub state_root: String,         // hex (no 0x)
    pub storage_proof: Vec<String>, // hex-encoded nodes
    pub indices: Vec<usize>,
}

pub trait CircuitFragment {
    /// The targets that the circuit operates on. These are constrained in the circuit definition
    /// and filled with [`Self::fill_targets`].
    type Targets;

    /// Builds a circuit with the operating wires being provided by [`Self::Targets`].
    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>);

    /// Fills the targets in the partial witness with the provided inputs.
    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()>;
}
