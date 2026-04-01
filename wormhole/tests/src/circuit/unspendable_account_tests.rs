use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use qp_poseidon_core::rehash_to_bytes;
use qp_rusty_crystals_hdwallet::wormhole::WormholePair;
use wormhole_circuit::unspendable_account::{UnspendableAccount, UnspendableAccountTargets};
use zk_circuits_common::{
    circuit::{CircuitFragment, C, D, F},
    codec::FieldElementCodec,
    utils::{bytes_to_digest, digest_to_bytes, BytesDigest},
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
    "de68c6fcb3e38d6736b79a010e4504b98c6321f1e4d11cd8484f67c187ca090e",
    "2dcf4b944c13da31a748ed04a251557d9bfb8eed7c4a8af5593c59d6142642b7",
    "e84689fa523459215ac1c5a930a7898ace511c7e201bdb7295b04fc87037988f",
    "2a96bf97fb63467396ddd298ac931eb22add9a527d02764520040e5e32a31ad6",
    "c6a587f78e270025b7e9517da47e07c7f614c21be9a1460b5214eee7ef33ac68",
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

        // account_id is now 4 felts (8 bytes/felt)
        let address = bytes_to_digest(decoded_address);
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
    // account_id is now 4 felts (8 bytes/felt)
    let wrong_hash = bytes_to_digest(wrong_address);
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
        // account_id is now 4 felts, convert to bytes
        let as_bytes = digest_to_bytes(unspendable_account.account_id);
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
    // account_id is 4 felts and secret is 4 felts.
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
    assert_eq!(field_elements.len(), 8); // 4 account_id + 4 secret
    for (i, elem) in field_elements.iter().enumerate() {
        assert_eq!(*elem, F::from_noncanonical_u64((i + 1) as u64));
    }

    // Decode the field elements back into an UnspendableAccount
    let recovered_account = UnspendableAccount::from_field_elements(&field_elements).unwrap();
    assert_eq!(account, recovered_account);
}

// ============================================================================
// Cross-codebase compatibility tests
//
// These tests verify that the three different code paths for wormhole address
// derivation produce identical results:
//
// 1. qp-rusty-crystals-hdwallet: WormholePair::generate_pair_from_secret
//    - Used by: miner app, CLI wallet generation
//    - Computes: first_hash = H(salt || secret), address = H(first_hash)
//
// 2. qp-zk-circuits: UnspendableAccount::from_secret
//    - Used by: ZK proof generation/verification
//    - Computes: account_id = H(H(salt || secret))
//
// 3. qp-poseidon-core: rehash_to_bytes (used by chain)
//    - Used by: chain's derive_wormhole_address
//    - Computes: address = H(first_hash) given the preimage
//
// All three must produce the same address for the same secret, otherwise
// miners cannot withdraw their rewards via ZK proofs.
// ============================================================================

/// Helper to create a WormholePair from a secret byte array.
/// The secret must be a valid Poseidon hash output (each 8-byte chunk < Goldilocks order).
fn wormhole_pair_from_secret(secret: [u8; 32]) -> WormholePair {
    let mut secret_copy = secret;
    WormholePair::generate_pair_from_secret((&mut secret_copy).into())
}

/// Test that WormholePair and UnspendableAccount produce the same address
/// for known test vectors (the SECRETS array).
#[test]
fn cross_codebase_wormhole_pair_matches_unspendable_account() {
    for secret_hex in SECRETS {
        let secret: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();

        // Path 1: qp-rusty-crystals-hdwallet (WormholePair)
        let wormhole_pair = wormhole_pair_from_secret(secret);

        // Path 2: qp-zk-circuits (UnspendableAccount)
        let unspendable = UnspendableAccount::from_secret(secret.try_into().unwrap());
        let circuit_address_bytes: [u8; 32] = *digest_to_bytes(unspendable.account_id);

        // Assertion 1: WormholePair address == UnspendableAccount address
        assert_eq!(
            wormhole_pair.address, circuit_address_bytes,
            "WormholePair and UnspendableAccount produce different addresses for secret {}",
            secret_hex
        );

        // Path 3: Chain's rehash_to_bytes (given first_hash)
        let chain_address = rehash_to_bytes(&wormhole_pair.first_hash);

        // Assertion 2: Chain's rehash of first_hash == WormholePair address
        assert_eq!(
            chain_address, wormhole_pair.address,
            "Chain's rehash_to_bytes produces different address for secret {}",
            secret_hex
        );

        // Verify the ZK proof also works with this data
        let result = run_test(&unspendable);
        assert!(
            result.is_ok(),
            "ZK proof failed for secret {} with matching addresses",
            secret_hex
        );
    }
}

/// Test cross-codebase compatibility with edge case inputs.
/// Note: secrets must be valid Poseidon hash outputs (each 8-byte chunk < Goldilocks order).
/// Values like [0xff; 32] would fail validation in WormholePair::generate_pair_from_secret.
#[test]
fn cross_codebase_edge_cases() {
    let edge_cases: [([u8; 32], &str); 4] = [
        ([0u8; 32], "all zeros"),
        ([1u8; 32], "all ones"),
        ([42u8; 32], "all 42s"),
        (core::array::from_fn(|i| i as u8), "sequential 0..31"),
    ];

    for (secret, description) in edge_cases {
        // Path 1: WormholePair (qp-rusty-crystals-hdwallet)
        let wormhole_pair = wormhole_pair_from_secret(secret);

        // Path 2: UnspendableAccount (qp-zk-circuits)
        let unspendable = UnspendableAccount::from_secret(secret.try_into().unwrap());
        let circuit_address_bytes: [u8; 32] = *digest_to_bytes(unspendable.account_id);

        // Path 3: Chain rehash (qp-poseidon-core)
        let chain_address = rehash_to_bytes(&wormhole_pair.first_hash);

        // All three paths must match
        assert_eq!(
            wormhole_pair.address, circuit_address_bytes,
            "Address mismatch between WormholePair and UnspendableAccount for {}",
            description
        );
        assert_eq!(
            chain_address, wormhole_pair.address,
            "Address mismatch between chain rehash and WormholePair for {}",
            description
        );

        // Print the test vectors for debugging and documentation
        println!(
            "{}: secret={} first_hash={} address={}",
            description,
            hex::encode(secret),
            hex::encode(wormhole_pair.first_hash),
            hex::encode(wormhole_pair.address)
        );
    }
}

/// Test that the derivation is deterministic across all code paths
#[test]
fn cross_codebase_determinism() {
    let secret = [42u8; 32];

    // Run each path multiple times
    for _ in 0..3 {
        let pair1 = wormhole_pair_from_secret(secret);
        let pair2 = wormhole_pair_from_secret(secret);

        let account1 = UnspendableAccount::from_secret(secret.try_into().unwrap());
        let account2 = UnspendableAccount::from_secret(secret.try_into().unwrap());

        let rehash1 = rehash_to_bytes(&pair1.first_hash);
        let rehash2 = rehash_to_bytes(&pair2.first_hash);

        // All results must be identical
        assert_eq!(pair1.address, pair2.address, "WormholePair address not deterministic");
        assert_eq!(pair1.first_hash, pair2.first_hash, "WormholePair first_hash not deterministic");
        assert_eq!(account1.account_id, account2.account_id, "UnspendableAccount not deterministic");
        assert_eq!(rehash1, rehash2, "rehash_to_bytes not deterministic");

        // Cross-path consistency
        let circuit_bytes: [u8; 32] = *digest_to_bytes(account1.account_id);
        assert_eq!(pair1.address, circuit_bytes);
        assert_eq!(rehash1, pair1.address);
    }
}

/// Generate and print test vectors for use in other codebases (chain, miner-app)
/// Run with: cargo test print_cross_codebase_test_vectors -- --nocapture --ignored
#[test]
#[ignore]
fn print_cross_codebase_test_vectors() {
    println!("\n// Cross-codebase test vectors for wormhole address derivation");
    println!("// Format: (secret, first_hash, address)");
    println!("// All values are hex-encoded 32-byte arrays");
    println!("// Note: secrets must be valid field elements (each 8-byte chunk < Goldilocks order)\n");

    let test_secrets: [[u8; 32]; 6] = [
        [0u8; 32],
        [1u8; 32],
        core::array::from_fn(|i| i as u8),
        hex::decode("4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05")
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode("c6034553e5556630d24a593d2c92de9f1ede81d48f0fb3371764462cc3594b3f")
            .unwrap()
            .try_into()
            .unwrap(),
        [42u8; 32],
    ];

    println!("let test_vectors: [(&str, &str, &str); {}] = [", test_secrets.len());
    for secret in test_secrets {
        let pair = wormhole_pair_from_secret(secret);

        println!(
            "    (\"{}\", \"{}\", \"{}\"),",
            hex::encode(secret),
            hex::encode(pair.first_hash),
            hex::encode(pair.address)
        );
    }
    println!("];");
}
