use ownership_circuit::circuit::circuit_logic::OwnershipCircuit;
use ownership_circuit::PUBLIC_INPUTS_FELTS_LEN;
use plonky2::plonk::circuit_data::CircuitConfig;
use zk_circuits_common::circuit::ownership_circuit_config;

#[test]
fn circuit_builds_and_exposes_eight_public_inputs() {
    let circuit = OwnershipCircuit::new(CircuitConfig::standard_recursion_config()).unwrap();
    assert!(circuit.num_gates() > 0);
    let verifier = circuit.build_verifier();
    assert_eq!(verifier.common.num_public_inputs, PUBLIC_INPUTS_FELTS_LEN);
}

#[test]
fn rejected_config_does_not_build() {
    let mut config = ownership_circuit_config();
    config.num_wires = 1;
    assert!(OwnershipCircuit::new(config).is_err());
}
