use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::{EXIT_ACCOUNT_1_END_INDEX, EXIT_ACCOUNT_1_START_INDEX};
use test_helpers::TestInputs;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;
use zk_circuits_common::codec::FieldElementCodec;

#[cfg(test)]
const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

/// Helper to build a verifier from the circuit for testing.
/// In production, verifiers load pre-built circuit data from files.
fn build_test_verifier() -> plonky2::plonk::circuit_data::VerifierCircuitData<
    zk_circuits_common::circuit::F,
    zk_circuits_common::circuit::C,
    { zk_circuits_common::circuit::D },
> {
    WormholeCircuit::new(CIRCUIT_CONFIG).build_verifier()
}

fn build_verifier_bytes(config: CircuitConfig) -> (Vec<u8>, Vec<u8>) {
    let verifier_data = WormholeCircuit::new(config).build_verifier();
    let common_bytes = verifier_data
        .common
        .to_bytes(&plonky2::util::serialization::DefaultGateSerializer)
        .unwrap();
    let verifier_bytes = verifier_data.verifier_only.to_bytes().unwrap();
    (verifier_bytes, common_bytes)
}

#[test]
fn verify_simple_proof() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let commitment = prover.commit(&inputs).unwrap();
    let proof = commitment.prove().unwrap();

    let verifier_data = build_test_verifier();
    verifier_data.verify(proof).unwrap();
}

#[test]
fn borrowed_verify_keeps_proof_available() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let (verifier_bytes, common_bytes) = build_verifier_bytes(CIRCUIT_CONFIG);
    let verifier = WormholeVerifier::new_from_bytes(&verifier_bytes, &common_bytes).unwrap();
    let verifier_proof = wormhole_verifier::ProofWithPublicInputs::from_bytes(
        proof.to_bytes(),
        &verifier.circuit_data.common,
    )
    .unwrap();
    verifier.verify_ref(&verifier_proof).unwrap();

    assert_eq!(proof.public_inputs.len(), 21);
}

#[test]
fn cannot_verify_with_modified_exit_account() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let mut proof = prover.commit(&inputs).unwrap().prove().unwrap();

    println!("proof before: {:?}", proof.public_inputs);
    let exit_account = SubstrateAccount::from_field_elements(
        &proof.public_inputs[EXIT_ACCOUNT_1_START_INDEX..EXIT_ACCOUNT_1_END_INDEX],
    );
    println!("exit_account: {:?}", exit_account);
    let modified_exit_account = SubstrateAccount::new(&[8u8; 32]).unwrap();
    proof.public_inputs[EXIT_ACCOUNT_1_START_INDEX..EXIT_ACCOUNT_1_END_INDEX]
        .copy_from_slice(&modified_exit_account.to_field_elements());
    println!("proof after: {:?}", proof.public_inputs);

    let verifier_data = build_test_verifier();
    let result = verifier_data.verify(proof);
    assert!(
        result.is_err(),
        "Expected proof to fail with modified exit_account"
    );
}

#[test]
fn cannot_verify_with_any_public_input_modification() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let verifier_data = build_test_verifier();

    for ix in 0..proof.public_inputs.len() {
        let mut p = proof.clone();
        for jx in 0..8 {
            p.public_inputs[ix].0 ^= 255 << (8 * jx);
            let result = verifier_data.verify(p.clone());
            assert!(
                result.is_err(),
                "Expected proof to fail with modified inputs"
            );
        }
    }
}

#[ignore]
#[test]
fn cannot_verify_with_modified_proof() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();
    let verifier_data = build_test_verifier();

    let proof_bytes = proof.to_bytes();
    for ix in 0..proof_bytes.len() {
        let mut b = proof_bytes.clone();
        b[ix] ^= 255;
        let result1 = ProofWithPublicInputs::from_bytes(b, &verifier_data.common);
        match result1 {
            Ok(p) => {
                let result2 = verifier_data.verify(p.clone());
                assert!(result2.is_err(), "Expected modified proof to fail");
            }
            Err(_) => {
                continue;
            }
        }
    }
}
