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
    "582d3b97e9b09c7776921d3ead2d8186e3aa199cf8d63f5d014e65d04ac80f26",
    "b0807446c24263def407aa8328400fef981ec30fc8453d7adbcc57bcf8af3bbf",
    "ac081f035cc995574fef749f33b455c31cb02759932d01b6367ab852bb5599ac",
    "a5073c13573f10552c37f35080dc0118bda22f1217381611cf4644909377ce05",
    "73378f4b54f48a38b17073e08440531594f2b771ceefc5c3cd621e1309fbe927",
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
    assert_eq!(field_elements.len(), 12);
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
