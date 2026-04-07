use alloc::{string::String, vec::Vec};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
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

/// Circuit config for leaf wormhole proofs (non-ZK).
///
/// Since the chain only verifies aggregated proofs (not individual leaf proofs), there's no
/// privacy benefit from using ZK on the leaves. Disabling ZK gives faster proving and smaller
/// proofs without compromising security - the aggregator that verifies these proofs runs in a
/// trusted environment anyway.
pub fn wormhole_leaf_circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config() // zero_knowledge: false
}

/// Circuit config for aggregation circuits (ZK enabled).
///
/// The aggregated proofs are verified on-chain, so they must use ZK to prevent leaking
/// witness information to the public.
pub fn wormhole_circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_zk_config() // zero_knowledge: true
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
