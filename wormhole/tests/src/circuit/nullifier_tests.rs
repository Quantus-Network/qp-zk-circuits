use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use test_helpers::{DEFAULT_SECRET, DEFAULT_TRANSFER_COUNT};
use wormhole_circuit::{
    codec::FieldElementCodec,
    nullifier::{Nullifier, NullifierTargets},
};
use zk_circuits_common::circuit::{CircuitFragment, C, D, F};
use zk_circuits_common::utils::injective_bytes_to_felts;

#[cfg(test)]
fn run_test(nullifier: &Nullifier) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = NullifierTargets::new(&mut builder);
    Nullifier::circuit(&targets, &mut builder);

    nullifier.fill_targets(&mut pw, targets)?;
    crate::circuit_helpers::build_and_prove_test(builder, pw)
}

pub trait TestInputs {
    fn test_inputs() -> Self;
}

impl TestInputs for Nullifier {
    fn test_inputs() -> Self {
        let secret = hex::decode(DEFAULT_SECRET).unwrap();
        Self::from_preimage(&secret, DEFAULT_TRANSFER_COUNT)
    }
}

#[test]
fn build_and_verify_nullifier_proof() {
    let nullifier = Nullifier::test_inputs();
    run_test(&nullifier).unwrap();
}

#[test]
fn invalid_secret_fails_proof() {
    let mut valid_nullifier = Nullifier::test_inputs();

    // Flip the first byte of the preimage.
    let mut invalid_bytes = hex::decode(DEFAULT_SECRET).unwrap();
    invalid_bytes[0] ^= 0xFF;
    valid_nullifier.secret = injective_bytes_to_felts(&invalid_bytes);

    let res = run_test(&valid_nullifier);
    assert!(res.is_err());
}

#[test]
fn all_zero_preimage_is_valid_and_hashes() {
    let preimage_bytes = vec![0u8; 64];
    let nullifier = Nullifier::from_preimage(&preimage_bytes, DEFAULT_TRANSFER_COUNT);
    let field_elements = nullifier.to_field_elements();
    assert!(!field_elements.iter().all(Field::is_zero));
}

#[test]
fn nullifier_codec() {
    let nullifier = Nullifier::from_preimage(&[1u8; 32], DEFAULT_TRANSFER_COUNT);

    // Encode the account as field elements and compare.
    let field_elements = nullifier.to_field_elements();
    assert_eq!(field_elements.len(), 14);

    // Decode the field elements back into a Nullifier
    let recovered_nullifier = Nullifier::from_field_elements(&field_elements).unwrap();
    assert_eq!(nullifier, recovered_nullifier);
}

#[test]
fn codec_invalid_length() {
    let invalid_elements = vec![F::from_noncanonical_u64(1), F::from_noncanonical_u64(2)];
    let recovered_nullifier_result = Nullifier::from_field_elements(&invalid_elements);

    assert!(recovered_nullifier_result.is_err());
    assert_eq!(
        recovered_nullifier_result.unwrap_err().to_string(),
        "Expected 14 field elements for Nullifier, got: 2"
    );
}

#[test]
fn codec_empty_elements() {
    let empty_elements: Vec<F> = vec![];
    let recovered_nullifier_result = Nullifier::from_field_elements(&empty_elements);

    assert!(recovered_nullifier_result.is_err());
    assert_eq!(
        recovered_nullifier_result.unwrap_err().to_string(),
        "Expected 14 field elements for Nullifier, got: 0"
    );
}
