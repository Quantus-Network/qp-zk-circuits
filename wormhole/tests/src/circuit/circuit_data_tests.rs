use anyhow::Context;
use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use rand::RngCore;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};
use test_helpers::storage_proof::TestInputs;
use test_helpers::DEFAULT_FUNDING_ACCOUNT;
use test_helpers::DEFAULT_SECRETS;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use wormhole_circuit::circuit::{circuit_data_from_bytes, circuit_data_to_bytes};
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::storage_proof::leaf::LeafInputs;
use wormhole_circuit::storage_proof::ProcessedStorageProof;
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;
use zk_circuits_common::circuit::{TransferProofJson, D, F};
use zk_circuits_common::utils::felts_to_u128;
use zk_circuits_common::utils::felts_to_u64;
use zk_circuits_common::utils::BytesDigest;
use zk_circuits_common::utils::{digest_felts_to_bytes, u128_to_felts};

/// Extract the last valid JSON object of type T from an arbitrary stdout blob.
/// Robust against extra logs before/after the JSON.
fn extract_last_json<T: DeserializeOwned>(s: &str) -> Result<T> {
    let bytes = s.as_bytes();
    let mut last_ok: Option<T> = None;

    for i in 0..bytes.len() {
        if bytes[i] == b'{' {
            let slice = &s[i..];
            let mut de = serde_json::Deserializer::from_str(slice);
            if let Ok(val) = T::deserialize(&mut de) {
                // We consumed a full JSON object starting at i. Keep the latest one.
                last_ok = Some(val);
            }
        }
    }

    last_ok.ok_or_else(|| anyhow::anyhow!("no valid JSON object found in stdout"))
}

fn run_remote_example(secret_hex: &str, amount: u128) -> Result<TransferProofJson> {
    let example_dir = PathBuf::from(env::var("QUANTUS_API_CLIENT_EXAMPLE_DIR").context(
        "QUANTUS_API_CLIENT_EXAMPLE_DIR not set; run `setup_qac.sh` and `source .env.qac`",
    )?);

    let output = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--example",
            "sample_proof",
            "--",
            secret_hex,
            &amount.to_string(),
        ])
        .current_dir(&example_dir)
        .output()
        .context("failed to run remote example")?;

    // parse JSON from stdout (use your extract_last_json if you have logs)
    let stdout = String::from_utf8(output.stdout).context("stdout not UTF-8")?;
    let parsed: TransferProofJson =
        serde_json::from_str(&stdout).or_else(|_| extract_last_json(&stdout))?;
    Ok(parsed)
}

#[test]
fn test_circuit_data_serialization() {
    // Build the circuit from source
    let config = CircuitConfig::standard_recursion_config();
    let circuit = WormholeCircuit::new(config);
    let built_circuit_data = circuit.build_circuit();

    // Serialize the circuit data to bytes
    let serialized_bytes =
        circuit_data_to_bytes(&built_circuit_data).expect("Failed to serialize circuit data");

    // Deserialize the bytes back to circuit data
    let deserialized_circuit_data =
        circuit_data_from_bytes(&serialized_bytes).expect("Failed to deserialize circuit data");

    // Re-serialize the deserialized circuit data
    let reserialized_bytes = circuit_data_to_bytes(&deserialized_circuit_data)
        .expect("Failed to re-serialize circuit data");

    // Assert that the original and re-serialized bytes are identical
    assert_eq!(serialized_bytes, reserialized_bytes);
}

#[test]
fn test_prover_and_verifier_from_file_e2e() -> Result<()> {
    // Create a temp directory for the test files
    let temp_dir = "temp_test_bins_e2e";
    fs::create_dir_all(temp_dir)?;

    // Generate circuit and write component files to the temporary directory.
    let config = CircuitConfig::standard_recursion_config();
    let circuit_data = WormholeCircuit::new(config).build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    // Serialize and write common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let common_path = Path::new(temp_dir).join("common.bin");
    fs::write(&common_path, &common_bytes)?;

    // Serialize and write verifier only data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let verifier_path = Path::new(temp_dir).join("verifier.bin");
    fs::write(&verifier_path, &verifier_only_bytes)?;

    // Serialize and write prover only data
    let prover_only_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, common_data)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let prover_path = Path::new(temp_dir).join("prover.bin");
    fs::write(&prover_path, &prover_only_bytes)?;

    // Create a prover and verifier from the temporary files.
    let prover = WormholeProver::new_from_files(&prover_path, &common_path)?;
    let verifier = WormholeVerifier::new_from_files(&verifier_path, &common_path)?;

    // Create inputs
    let leaf_inputs = LeafInputs::test_inputs_0();
    let secret =
        BytesDigest::try_from(hex::decode(DEFAULT_SECRETS[0]).unwrap().as_slice()).unwrap();
    let funding_account = leaf_inputs.funding_account;
    // let secret = BytesDigest::try_from([1u8; 32]).unwrap();
    let unspendable_account = leaf_inputs.to_account;
    let funding_amount = leaf_inputs.funding_amount;
    let transfer_count = leaf_inputs.transfer_count;

    let mut leaf_inputs_felts = Vec::new();
    leaf_inputs_felts.extend(transfer_count);
    leaf_inputs_felts.extend_from_slice(funding_account.as_slice());
    leaf_inputs_felts.extend_from_slice(unspendable_account.as_slice());
    leaf_inputs_felts.extend(funding_amount);

    let transfer_count = felts_to_u64(transfer_count).unwrap();
    let funding_amount = felts_to_u128(funding_amount).unwrap();

    let leaf_inputs_hash = Poseidon2Hash::hash_no_pad(&leaf_inputs_felts);
    let root_hash: [u8; 32] = *digest_felts_to_bytes(leaf_inputs_hash.elements);

    // print the hex of the root hash
    println!("root_hash: {}", hex::encode(root_hash));

    let exit_account = SubstrateAccount::new(&[2u8; 32])?;
    let inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret,
            funding_account: (*funding_account).into(),
            storage_proof: ProcessedStorageProof::new(vec![], vec![]).unwrap(),
            unspendable_account: (*unspendable_account).into(),
            transfer_count,
        },
        public: PublicCircuitInputs {
            funding_amount,
            nullifier: Nullifier::from_preimage(secret, transfer_count).hash.into(),
            root_hash: root_hash.try_into().unwrap(),
            exit_account: (*exit_account).into(),
        },
    };

    // Generate and verify a proof
    let prover_next = prover.commit(&inputs)?;
    let proof = prover_next.prove()?;
    verifier.verify(proof)?;

    // Clean up the temporary directory
    fs::remove_dir_all(temp_dir)?;

    Ok(())
}

#[ignore = "performance"]
#[test]
fn test_prover_and_verifier_fuzzing() -> Result<()> {
    // ---- temp dirs
    let temp_dir = Path::new("temp_test_bins_fuzzing");
    fs::create_dir_all(temp_dir)?;

    // ---- circuit build (unchanged)
    let config = CircuitConfig::standard_recursion_config();
    let circuit_data = WormholeCircuit::new(config).build_circuit();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };

    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    // ---- write bins
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let common_path = temp_dir.join("common.bin");
    fs::write(&common_path, &common_bytes)?;

    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let verifier_path = temp_dir.join("verifier.bin");
    fs::write(&verifier_path, &verifier_only_bytes)?;

    let prover_only_bytes = prover_data
        .prover_only
        .to_bytes(&generator_serializer, common_data)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let prover_path = temp_dir.join("prover.bin");
    fs::write(&prover_path, &prover_only_bytes)?;

    // ---- create verifier
    let verifier = WormholeVerifier::new_from_files(&verifier_path, &common_path)?;

    const FUZZ_ITERATIONS: usize = 100;
    let mut panic_count = 0;

    for i in 0..FUZZ_ITERATIONS {
        // keep prover fresh each iteration
        let prover = WormholeProver::new_from_files(&prover_path, &common_path)?;

        // fuzzed inputs
        let funding_amount = rand::random_range(0..100) * 1_000_000_000;
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let secret_hex = hex::encode(secret);

        println!(
            "[FUZZ] Iteration {}: secret_hex = {}, funding_amount = {}",
            i, secret_hex, funding_amount
        );

        // wrap iteration in its own scope for error capture
        let iter_result: Result<()> = (|| {
            // Run CLI and parse proof JSON
            let proof_json = run_remote_example(&secret_hex, funding_amount)?;

            // Convert JSON to chain values
            let state_root_bytes: [u8; 32] = hex::decode(&proof_json.state_root)
                .map_err(|e| anyhow::anyhow!("bad state_root hex: {}", e))?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("state_root must be 32 bytes"))?;

            let storage_proof_bytes: Vec<Vec<u8>> = proof_json
                .storage_proof
                .iter()
                .map(|s| {
                    hex::decode(s).map_err(|e| anyhow::anyhow!("bad storage_proof hex: {}", e))
                })
                .collect::<Result<Vec<_>>>()?;

            let processed_proof =
                ProcessedStorageProof::new(storage_proof_bytes, proof_json.indices.clone())
                    .context("failed to build ProcessedStorageProof")?;

            let funding_account = SubstrateAccount::new(&DEFAULT_FUNDING_ACCOUNT)?;
            let secret = BytesDigest::try_from(secret.as_slice()).unwrap();
            let unspendable_account = UnspendableAccount::from_secret(secret).account_id;

            let transfer_count_from_chain = proof_json.transfer_count;

            let mut leaf_inputs_felts = Vec::new();
            leaf_inputs_felts.push(F::from_noncanonical_u64(transfer_count_from_chain));
            leaf_inputs_felts.extend_from_slice(&funding_account.0);
            leaf_inputs_felts.extend_from_slice(&unspendable_account);
            leaf_inputs_felts.extend_from_slice(&u128_to_felts(funding_amount));

            let exit_account = SubstrateAccount::new(&[2u8; 32])?;
            let inputs = CircuitInputs {
                private: PrivateCircuitInputs {
                    secret,
                    funding_account: (*funding_account).into(),
                    storage_proof: processed_proof,
                    unspendable_account: (unspendable_account).into(),
                    transfer_count: transfer_count_from_chain,
                },
                public: PublicCircuitInputs {
                    funding_amount,
                    nullifier: Nullifier::from_preimage(secret, transfer_count_from_chain)
                        .hash
                        .into(),
                    root_hash: state_root_bytes.try_into().unwrap(),
                    exit_account: (*exit_account).into(),
                },
            };

            let prover_next = prover.commit(&inputs)?;
            let proof = prover_next.prove()?;
            verifier.verify(proof)?;
            Ok(())
        })();

        if let Err(e) = iter_result {
            eprintln!(
                "[FUZZ][ERROR] Iteration {} failed.\n  secret_hex: {}\n  funding_amount: {}\n  error: {:#}",
                i, secret_hex, funding_amount, e
            );
            panic_count += 1;
            // continue with next fuzz iteration
            continue;
        }
    }

    println!(
        "[FUZZ] Completed {} iterations with {} failures",
        FUZZ_ITERATIONS, panic_count
    );

    // cleanup
    fs::remove_dir_all(temp_dir)?;
    Ok(())
}
