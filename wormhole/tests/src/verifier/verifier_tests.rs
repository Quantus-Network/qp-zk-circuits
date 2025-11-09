use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use test_helpers::TestInputs;
use wormhole_circuit::codec::FieldElementCodec;
use wormhole_circuit::inputs::{CircuitInputs, EXIT_ACCOUNT_END_INDEX, EXIT_ACCOUNT_START_INDEX};
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;

#[cfg(test)]
const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

#[test]
fn verify_simple_proof() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let commitment = prover.commit(&inputs).unwrap();
    let proof = commitment.prove().unwrap();

    let verifier = WormholeVerifier::new(CIRCUIT_CONFIG, None);
    verifier.verify(proof).unwrap();
}

#[test]
fn cannot_verify_with_modified_exit_account() {
    let prover = WormholeProver::new(CIRCUIT_CONFIG);
    let inputs = CircuitInputs::test_inputs_0();
    let mut proof = prover.commit(&inputs).unwrap().prove().unwrap();

    println!("proof before: {:?}", proof.public_inputs);
    let exit_account = SubstrateAccount::from_field_elements(
        &proof.public_inputs[EXIT_ACCOUNT_START_INDEX..EXIT_ACCOUNT_END_INDEX],
    );
    println!("exit_account: {:?}", exit_account);
    let modified_exit_account = SubstrateAccount::new(&[8u8; 32]).unwrap();
    proof.public_inputs[EXIT_ACCOUNT_START_INDEX..EXIT_ACCOUNT_END_INDEX]
        .copy_from_slice(&modified_exit_account.to_field_elements());
    println!("proof after: {:?}", proof.public_inputs);

    let verifier = WormholeVerifier::new(CIRCUIT_CONFIG, None);
    let result = verifier.verify(proof);
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
    let verifier = WormholeVerifier::new(CIRCUIT_CONFIG, None);

    for ix in 0..proof.public_inputs.len() {
        let mut p = proof.clone();
        for jx in 0..8 {
            p.public_inputs[ix].0 ^= 255 << (8 * jx);
            let result = verifier.verify(p.clone());
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
    let verifier = WormholeVerifier::new(CIRCUIT_CONFIG, None);

    let proof_bytes = proof.to_bytes();
    for ix in 0..proof_bytes.len() {
        let mut b = proof_bytes.clone();
        b[ix] ^= 255;
        let result1 = ProofWithPublicInputs::from_bytes(b, &verifier.circuit_data.common);
        match result1 {
            Ok(p) => {
                let result2 = verifier.verify(p.clone());
                assert!(result2.is_err(), "Expected modified proof to fail");
            }
            Err(_) => {
                continue;
            }
        }
    }
}
