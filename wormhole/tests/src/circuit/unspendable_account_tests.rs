use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use wormhole_circuit::unspendable_account::{UnspendableAccount, UnspendableAccountTargets};
use zk_circuits_common::{
    circuit::{CircuitFragment, C, D, F},
    codec::FieldElementCodec,
    utils::BytesDigest,
};

#[cfg(test)]
const SECRETS: [&str; 5] = [
    "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05",
    "c6034553e5556630d24a593d2c92de9f1ede81d48f0fb3371764462cc3594b3f",
    "87f5fc11df0d12f332ccfeb92ddd8995e6c11709501a8b59c2aaf9eefee63ec1",
    "ef69da4e3aa2a6f15b3a9eec5e481f17260ac812faf1e685e450713327c3ab1c",
    "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7",
];

#[cfg(test)]
const ADDRESSES: [&str; 5] = [
    "4d38abc959eb7e11526fd632c73d47e8945972fa3d9ce3d62532d5f386353993",
    "8213d62e0104abe36482ef26346e0d5cd1d7511b22e4b03c770ca2c687b0ed04",
    "7c281f0265adab691f06195b30deb4d133477a363355c584143827210b19bb09",
    "5511b416ec05918b6fbc78fbd61d2575be3bd9d5f931b0f2438f7f5f7d46ae6e",
    "ae18069d04d3fb4b3eb1fb41d6b5bf51b1bad41ff95d067b65116a1f5a68ba09",
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
        // print the decoded address
        println!("decoded_address: {:?}", decoded_address);
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
