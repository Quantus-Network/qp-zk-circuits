use plonky2::plonk::{
    circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, proof::ProofWithPublicInputs,
};
use zk_circuits_common::circuit::{C, D, F};

/// Convenience function for initializing a test circuit environment.
pub fn setup_test_builder_and_witness(
    zk: bool,
) -> (
    CircuitBuilder<F, D>,
    plonky2::iop::witness::PartialWitness<F>,
) {
    let config = if zk {
        CircuitConfig::standard_recursion_zk_config()
    } else {
        CircuitConfig::standard_recursion_config()
    };
    let builder = CircuitBuilder::<F, D>::new(config);
    let pw = plonky2::iop::witness::PartialWitness::new();

    (builder, pw)
}

/// Convenience function for building and verifying a test function. The circuit is assumed to
/// have been setup prior to calling this function.
pub fn build_and_prove_test(
    builder: CircuitBuilder<F, D>,
    pw: plonky2::iop::witness::PartialWitness<F>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let data = builder.build::<C>();
    data.prove(pw)
}
