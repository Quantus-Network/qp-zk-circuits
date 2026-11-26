use ownership_circuit::inputs::{CircuitInputs, ParsePublicInputs, PublicCircuitInputs};
use ownership_circuit::PUBLIC_INPUTS_FELTS_LEN;
use ownership_prover::OwnershipProver;
use plonky2::plonk::circuit_data::CircuitConfig;
use wormhole_circuit::sensitive::Secret;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::utils::{digest_to_bytes, BytesDigest};

fn sample_inputs() -> CircuitInputs {
    let secret = Secret::try_from([0x11; 32]).unwrap();
    let claim = BytesDigest::try_from([0x22; 32].as_slice()).unwrap();
    CircuitInputs::from_secret(secret, claim)
}

#[test]
fn commit_and_prove() {
    let prover = OwnershipProver::new(CircuitConfig::standard_recursion_config()).unwrap();
    prover.commit(&sample_inputs()).unwrap().prove().unwrap();
}

#[test]
fn public_inputs_match_committed_values() {
    let inputs = sample_inputs();
    let prover = OwnershipProver::new(CircuitConfig::standard_recursion_config()).unwrap();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    assert_eq!(proof.public_inputs.len(), PUBLIC_INPUTS_FELTS_LEN);
    let parsed = PublicCircuitInputs::try_from_proof(&proof).unwrap();
    assert_eq!(parsed, inputs.public);
}

#[test]
fn mismatched_address_fails_to_prove() {
    let secret = Secret::try_from([0x11; 32]).unwrap();
    let claim = BytesDigest::try_from([0x22; 32].as_slice()).unwrap();
    let mut inputs = CircuitInputs::from_secret(secret, claim);
    inputs.public.wormhole_address = BytesDigest::try_from([0x33; 32].as_slice()).unwrap();

    let prover = OwnershipProver::new(CircuitConfig::standard_recursion_config()).unwrap();
    assert!(prover.commit(&inputs).unwrap().prove().is_err());
}

#[test]
fn derived_address_matches_unspendable_account() {
    let secret_bytes = [0x44u8; 32];
    let secret = Secret::try_from(secret_bytes).unwrap();
    let claim = BytesDigest::try_from([0x55; 32].as_slice()).unwrap();
    let inputs = CircuitInputs::from_secret(secret, claim);
    let account = UnspendableAccount::from_secret(secret_bytes.try_into().unwrap());
    assert_eq!(
        inputs.public.wormhole_address,
        digest_to_bytes(account.account_id)
    );
}

#[test]
fn commit_twice_is_rejected() {
    let prover = OwnershipProver::new(CircuitConfig::standard_recursion_config()).unwrap();
    let committed = prover.commit(&sample_inputs()).unwrap();
    let err = committed.commit(&sample_inputs()).unwrap_err();
    assert!(err.to_string().contains("already commited"), "got: {err}");
}
