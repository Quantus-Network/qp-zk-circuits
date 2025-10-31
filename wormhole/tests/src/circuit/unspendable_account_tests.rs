use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use wormhole_circuit::{
    codec::FieldElementCodec,
    unspendable_account::{UnspendableAccount, UnspendableAccountTargets},
};
use zk_circuits_common::{
    circuit::{CircuitFragment, C, D, F},
    utils::BytesDigest,
};

#[cfg(test)]
const SECRETS: [&str; 5] = [
    "cd94df2e3c38a87f3e429b62af022dbe4363143811219d80037e8798b2ec9229",
    "8b680b2421968a0c1d3cff6f3408e9d780157ae725724a78c3bc0998d1ac8194",
    "87f5fc11df0d12f332ccfeb92ddd8995e6c11709501a8b59c2aaf9eefee63ec1",
    "ef69da4e3aa2a6f15b3a9eec5e481f17260ac812faf1e685e450713327c3ab1c",
    "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7",
];

#[cfg(test)]
const ADDRESSES: [&str; 5] = [
    "b209bdf6636fd7a3a224b9e62dde4acf7a93ecc7d19f618990e34bdeae8e1455",
    "aebdf7b4136139bbda4d8b5b4cfe3726dfdd64c842e16f79ad8033f8044c3b7e",
    "f5fc29c796b56aeabc3d3d9bd113d6b958f434b0919e207d81c3ded261331677",
    "c18c0dfb3f71945ea7cf1ecfdd110a6ed1c2d0cdde5db0b2d05c60e14bc2da83",
    "96d45bf29b88b160511748dba781606b10e1f5f9dfdc9d7350e7d57676f65e43",
];

#[cfg(test)]
fn run_test(
    unspendable_account: &UnspendableAccount,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = UnspendableAccountTargets::new(&mut builder);
    UnspendableAccount::circuit(&targets, &mut builder);

    unspendable_account.fill_targets(&mut pw, targets)?;
    crate::circuit_helpers::build_and_prove_test(builder, pw)
}

#[test]
fn build_and_verify_unspendable_account_proof() {
    let unspendable_account = UnspendableAccount::default();
    run_test(&unspendable_account).unwrap();
}

#[test]
fn preimage_matches_right_address() {
    for (secret, address) in SECRETS.iter().zip(ADDRESSES) {
        let decoded_secret: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
        let decoded_address = hex::decode(address).unwrap();
        let unspendable_account =
            UnspendableAccount::from_secret(decoded_secret.try_into().unwrap());

        let decoded_address = BytesDigest::try_from(decoded_address.as_slice()).unwrap();

        let address = zk_circuits_common::utils::digest_bytes_to_felts(decoded_address);
        assert_eq!(unspendable_account.account_id.to_vec(), address);
        let result = run_test(&unspendable_account);
        assert!(result.is_ok());
    }
}

#[test]
fn preimage_does_not_match_wrong_address() {
    let (secret, wrong_address) = (SECRETS[0], ADDRESSES[1]);
    let decoded_secret: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
    let mut unspendable_account =
        UnspendableAccount::from_secret(decoded_secret.try_into().unwrap());

    // Override the correct hash with the wrong one.
    let wrong_address =
        BytesDigest::try_from(hex::decode(wrong_address).unwrap().as_slice()).unwrap();
    let wrong_hash = zk_circuits_common::utils::digest_bytes_to_felts(wrong_address);
    unspendable_account.account_id = wrong_hash;

    let result = run_test(&unspendable_account);
    assert!(result.is_err());
}

#[test]
fn all_zero_preimage_is_valid_and_hashes() {
    let preimage_bytes = [0u8; 32];
    let account = UnspendableAccount::from_secret(preimage_bytes.try_into().unwrap());
    assert!(!account.account_id.to_vec().iter().all(Field::is_zero));
}

#[test]
fn unspendable_account_codec() {
    let account = UnspendableAccount {
        account_id: [
            F::from_noncanonical_u64(1),
            F::from_noncanonical_u64(2),
            F::from_noncanonical_u64(3),
            F::from_noncanonical_u64(4),
        ],
        secret: [
            F::from_noncanonical_u64(5),
            F::from_noncanonical_u64(6),
            F::from_noncanonical_u64(7),
            F::from_noncanonical_u64(8),
        ],
    };

    // Encode the account as field elements and compare.
    let field_elements = account.to_field_elements();
    assert_eq!(field_elements.len(), 8);
    assert_eq!(field_elements[0], F::from_noncanonical_u64(1));
    assert_eq!(field_elements[1], F::from_noncanonical_u64(2));
    assert_eq!(field_elements[2], F::from_noncanonical_u64(3));
    assert_eq!(field_elements[3], F::from_noncanonical_u64(4));
    assert_eq!(field_elements[4], F::from_noncanonical_u64(5));
    assert_eq!(field_elements[5], F::from_noncanonical_u64(6));
    assert_eq!(field_elements[6], F::from_noncanonical_u64(7));
    assert_eq!(field_elements[7], F::from_noncanonical_u64(8));

    // Decode the field elements back into an UnspendableAccount
    let recovered_account = UnspendableAccount::from_field_elements(&field_elements).unwrap();
    assert_eq!(account, recovered_account);
}
