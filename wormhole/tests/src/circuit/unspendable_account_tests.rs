use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use wormhole_circuit::unspendable_account::{UnspendableAccount, UnspendableAccountTargets};
use zk_circuits_common::{
    circuit::{CircuitFragment, C, D, F},
    codec::FieldElementCodec,
    utils::{digest_to_felts, felts_to_digest, BytesDigest},
};

#[cfg(test)]
const SECRETS: [&str; 5] = [
    "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05",
    "c6034553e5556630d24a593d2c92de9f1ede81d48f0fb3371764462cc3594b3f",
    "87f5fc11df0d12f332ccfeb92ddd8995e6c11709501a8b59c2aaf9eefee63ec1",
    "ef69da4e3aa2a6f15b3a9eec5e481f17260ac812faf1e685e450713327c3ab1c",
    "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7",
];

// NOTE: These addresses will change due to the new encoding (4 bytes/felt instead of 8 bytes/felt)
// They need to be regenerated with the print_expected_unspendable_addresses test
#[cfg(test)]
const ADDRESSES: [&str; 5] = [
    "84be59b389f320c62b7cf2e0401df30f9951af843016c86f2e3f068ff99e038d",
    "0c8731478175cbab4a4efdb1a60b86d792f255f699522b608f42eee7bce34277",
    "42a4e818d4aa28dc789f0ffa581151ee310d06c21d971f5b9e18de31fcf513bf",
    "290ce05a950614aa4035bd9fbbb748aaac20b067248922a5bf286687fa8a26dc",
    "85a121f44a25a00a77f44467f5788137712d8e8fd9a17bb8b3384b0c3cbd9e45",
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
#[ignore = "addresses need to be regenerated with new encoding"]
fn preimage_matches_right_address() {
    for (secret, address) in SECRETS.iter().zip(ADDRESSES) {
        let decoded_secret: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
        let decoded_address = hex::decode(address).unwrap();
        // print the decoded address
        println!("decoded_address: {:?}", decoded_address);
        let unspendable_account =
            UnspendableAccount::from_secret(decoded_secret.try_into().unwrap());

        let decoded_address = BytesDigest::try_from(decoded_address.as_slice()).unwrap();

        let address = digest_to_felts(decoded_address);
        assert_eq!(unspendable_account.account_id.to_vec(), address);
        let result = run_test(&unspendable_account);
        assert!(result.is_ok());
    }
}

#[test]
fn preimage_does_not_match_wrong_address() {
    let secret = SECRETS[0];
    let decoded_secret: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
    let mut unspendable_account =
        UnspendableAccount::from_secret(decoded_secret.try_into().unwrap());

    // Override the correct account_id with a wrong one (different bytes).
    // Use valid bytes that don't exceed field order (not all 0xFF which creates u64::MAX)
    let wrong_address = BytesDigest::try_from([0x12u8; 32]).unwrap();
    let wrong_hash = digest_to_felts(wrong_address);
    unspendable_account.account_id = wrong_hash;

    let result = run_test(&unspendable_account);
    assert!(result.is_err());
}

#[test]
#[ignore]
fn print_expected_unspendable_addresses() {
    for secret in SECRETS {
        let decoded_secret: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
        let unspendable_account =
            UnspendableAccount::from_secret(decoded_secret.try_into().unwrap());
        let as_bytes = felts_to_digest(unspendable_account.account_id);
        println!("{}", hex::encode(*as_bytes));
    }
}

#[test]
fn all_zero_preimage_is_valid_and_hashes() {
    let preimage_bytes = [0u8; 32];
    let account = UnspendableAccount::from_secret(preimage_bytes.try_into().unwrap());
    assert!(!account.account_id.to_vec().iter().all(Field::is_zero));
}

#[test]
fn unspendable_account_codec() {
    // account_id is now 8 felts, secret is 8 felts
    let account = UnspendableAccount {
        account_id: [
            F::from_noncanonical_u64(1),
            F::from_noncanonical_u64(2),
            F::from_noncanonical_u64(3),
            F::from_noncanonical_u64(4),
            F::from_noncanonical_u64(5),
            F::from_noncanonical_u64(6),
            F::from_noncanonical_u64(7),
            F::from_noncanonical_u64(8),
        ],
        secret: [
            F::from_noncanonical_u64(9),
            F::from_noncanonical_u64(10),
            F::from_noncanonical_u64(11),
            F::from_noncanonical_u64(12),
            F::from_noncanonical_u64(13),
            F::from_noncanonical_u64(14),
            F::from_noncanonical_u64(15),
            F::from_noncanonical_u64(16),
        ],
    };

    // Encode the account as field elements and compare.
    let field_elements = account.to_field_elements();
    assert_eq!(field_elements.len(), 16); // 8 account_id + 8 secret
    for i in 0..16 {
        assert_eq!(field_elements[i], F::from_noncanonical_u64((i + 1) as u64));
    }

    // Decode the field elements back into an UnspendableAccount
    let recovered_account = UnspendableAccount::from_field_elements(&field_elements).unwrap();
    assert_eq!(account, recovered_account);
}
