use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use wormhole_circuit::substrate_account::{ExitAccountTargets, SubstrateAccount};
use zk_circuits_common::circuit::{CircuitFragment, C, D, F};
use zk_circuits_common::{
    codec::ByteCodec,
    codec::FieldElementCodec,
    utils::{felts_to_digest, DIGEST_NUM_FELTS, ZERO_ACCOUNT_ID},
};

#[cfg(test)]
fn run_test(exit_account: &SubstrateAccount) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = ExitAccountTargets::new(&mut builder);
    SubstrateAccount::circuit(&targets, &mut builder);

    exit_account.fill_targets(&mut pw, targets)?;
    crate::circuit_helpers::build_and_prove_test(builder, pw)
}

#[test]
fn run_circuit() {
    let exit_account = SubstrateAccount::default();
    run_test(&exit_account).unwrap();
}

#[test]
fn test_exit_account_round_trip() -> anyhow::Result<()> {
    let exit_account = SubstrateAccount::new(&[42u8; 32])?;
    let elements = exit_account.to_field_elements();
    assert_eq!(
        elements.len(),
        DIGEST_NUM_FELTS,
        "Expected 8 field elements"
    );
    let decoded = SubstrateAccount::from_field_elements(&elements)?;
    assert_eq!(exit_account, decoded, "Round-trip failed");
    Ok(())
}

#[test]
fn test_exit_account_zero_address() -> anyhow::Result<()> {
    let exit_account = SubstrateAccount::new(&[0u8; 32])?;
    let elements = exit_account.to_field_elements();
    assert_eq!(
        elements.len(),
        DIGEST_NUM_FELTS,
        "Expected 8 field elements"
    );
    assert_eq!(
        elements,
        ZERO_ACCOUNT_ID.to_vec(),
        "Zero address should encode to zero elements"
    );
    let decoded = SubstrateAccount::from_field_elements(&elements)?;
    assert_eq!(exit_account, decoded, "Zero address round-trip failed");
    Ok(())
}

#[test]
fn test_exit_account_max_address() -> anyhow::Result<()> {
    // Each field element now holds 4 bytes (u32), so max is 0xFFFFFFFF
    let felts = [F::from_noncanonical_u64(0xFFFFFFFF); DIGEST_NUM_FELTS];
    let digest_bytes = felts_to_digest(felts);
    let exit_account = SubstrateAccount::new(&*digest_bytes)?;
    let elements = exit_account.to_field_elements();
    assert_eq!(
        elements.len(),
        DIGEST_NUM_FELTS,
        "Expected 8 field elements"
    );
    // Each element should be 0xFFFFFFFF
    let expected_value = F::from_noncanonical_u64(0xFFFFFFFF);
    assert_eq!(
        elements,
        vec![expected_value; DIGEST_NUM_FELTS],
        "Max address encoding incorrect"
    );
    let decoded = SubstrateAccount::from_field_elements(&elements)?;
    assert_eq!(exit_account, decoded, "Max address round-trip failed");
    Ok(())
}

#[test]
fn test_exit_account_insufficient_elements() {
    let elements = vec![F::ZERO; 7]; // Too few elements (needs 8)
    let result = SubstrateAccount::from_field_elements(&elements);
    assert!(
        result.is_err(),
        "Decoding with insufficient elements should fail"
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "Expected 8 field elements for SubstrateAccount, got: 7"
    );
}

#[test]
fn test_exit_account_specific_address() -> anyhow::Result<()> {
    let mut address = [0u8; 32];
    address[0] = 1;
    address[31] = 255; // Non-zero first and last bytes
    let exit_account = SubstrateAccount::new(&address)?;
    let elements = exit_account.to_field_elements();
    assert_eq!(
        elements.len(),
        DIGEST_NUM_FELTS,
        "Expected 8 field elements"
    );
    // With 4 bytes/felt (little-endian):
    // First element (bytes 0-3): 0x00000001
    // Last element (bytes 28-31): 0xFF000000
    let expected_first = F::from_canonical_u64(1);
    let expected_last = F::from_canonical_u64(255u64 << 24);
    assert_eq!(elements[0], expected_first, "First element incorrect");
    assert_eq!(elements[7], expected_last, "Last element incorrect");
    let decoded = SubstrateAccount::from_field_elements(&elements)?;
    assert_eq!(exit_account, decoded, "Specific address round-trip failed");
    Ok(())
}

#[test]
fn exit_account_codec() {
    let address_bytes = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let account = SubstrateAccount::new(&address_bytes).unwrap();

    // Encode the account's address into field elements.
    let field_elements = account.to_field_elements();
    assert_eq!(field_elements.len(), DIGEST_NUM_FELTS);

    // Reconstruct the original bytes from the field elements.
    // With 4 bytes/felt encoding:
    let mut expected_elements = Vec::new();
    for i in 0..DIGEST_NUM_FELTS {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&address_bytes[i * 4..(i + 1) * 4]);
        let value = u32::from_le_bytes(bytes);
        expected_elements.push(F::from_noncanonical_u64(value as u64));
    }
    assert_eq!(field_elements, expected_elements);

    // Decode the field elements back into an ExitAccount.
    let recovered_account = SubstrateAccount::from_field_elements(&field_elements).unwrap();
    assert_eq!(account, recovered_account);
}

#[test]
fn codec_invalid_length() {
    let short_elements = vec![F::from_noncanonical_u64(1), F::from_noncanonical_u64(2)];
    let recovered_account_result = SubstrateAccount::from_field_elements(&short_elements);

    assert!(recovered_account_result.is_err());
    assert_eq!(
        recovered_account_result.unwrap_err().to_string(),
        "Expected 8 field elements for SubstrateAccount, got: 2"
    );

    let long_elements = vec![
        F::from_noncanonical_u64(1),
        F::from_noncanonical_u64(2),
        F::from_noncanonical_u64(3),
        F::from_noncanonical_u64(4),
        F::from_noncanonical_u64(5),
        F::from_noncanonical_u64(6),
        F::from_noncanonical_u64(7),
        F::from_noncanonical_u64(8),
        F::from_noncanonical_u64(9),
    ];

    let recovered_account_result = SubstrateAccount::from_field_elements(&long_elements);
    assert!(recovered_account_result.is_err());
    assert_eq!(
        recovered_account_result.unwrap_err().to_string(),
        "Expected 8 field elements for SubstrateAccount, got: 9"
    );
}

#[test]
fn codec_empty_elements() {
    let empty_elements: Vec<F> = vec![];
    let recovered_account_result = SubstrateAccount::from_field_elements(&empty_elements);
    assert!(recovered_account_result.is_err());
    assert_eq!(
        recovered_account_result.unwrap_err().to_string(),
        "Expected 8 field elements for SubstrateAccount, got: 0"
    );
}

#[test]
fn codec_different_byte_patterns() {
    // Test with all zeros.
    let zero_address = [0u8; 32];
    let account_zero = SubstrateAccount::new(&zero_address).unwrap();
    let field_elements_zero = account_zero.to_field_elements();
    let recovered_zero = SubstrateAccount::from_field_elements(&field_elements_zero).unwrap();
    assert_eq!(account_zero, recovered_zero);

    // Test with all ones.
    let one_address = [1u8; 32];
    let account_one = SubstrateAccount::new(&one_address).unwrap();
    let field_elements_one = account_one.to_field_elements();
    let recovered_one = SubstrateAccount::from_field_elements(&field_elements_one).unwrap();
    assert_eq!(account_one, recovered_one);

    // Test with a more varied pattern.
    let varied_address = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10,
        0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xE1, 0xF0,
        0x34, 0x56,
    ];
    let account_varied = SubstrateAccount::new(&varied_address).unwrap();
    let field_elements_varied = account_varied.to_field_elements();
    let recovered_varied = SubstrateAccount::from_field_elements(&field_elements_varied).unwrap();
    assert_eq!(account_varied, recovered_varied);
}

#[test]
fn from_bytes_round_trip() {
    // Test that from_bytes and to_bytes round-trip correctly
    let address_bytes = [42u8; 32];
    let account = SubstrateAccount::new(&address_bytes).unwrap();
    let encoded = account.to_bytes();
    let decoded = SubstrateAccount::from_bytes(&encoded).unwrap();
    assert_eq!(account, decoded);
}
