//! End-to-end wormhole transfer proof and values for public and private inputs:
//!
//! - Makes a transfer to a specified destination account.
//! - Fetches a proof for storage key where the previous proof is stored
//! - Combines and passes the necessary inputs to the wormhole prover
//! - Generate the proof for the wormhole transfer

use anyhow::anyhow;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_poseidon::PoseidonHasher;
use quantus_cli::chain::quantus_subxt as quantus_node;
use quantus_cli::chain::quantus_subxt::api::balances;
use quantus_cli::cli::common::submit_transaction;
use quantus_cli::qp_dilithium_crypto::DilithiumPair;
use quantus_cli::wallet::QuantumKeyPair;
use quantus_cli::{AccountId32, ChainConfig, QuantusClient};
use serde::{Deserialize, Serialize};
use sp_core::{Hasher, H256};
use std::str::FromStr;
use subxt::backend::legacy::rpc_methods::{Bytes, ReadProof};
use subxt::blocks::Block;
use subxt::ext::codec::Encode;
use subxt::ext::jsonrpsee::core::client::ClientT;
use subxt::ext::jsonrpsee::rpc_params;
use subxt::utils::{to_hex, AccountId32 as SubxtAccountId};
use subxt::OnlineClient;
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_prover::WormholeProver;
use zk_circuits_common::utils::{BytesDigest, Digest};

mod utils;

const DEBUG_FILE: &str = "proof_debug.json";

#[derive(Serialize, Deserialize, Debug)]
struct DebugInputs {
    secret_hex: String,
    proof_hex: Vec<String>,
    state_root_hex: String,
    last_idx: usize,
    leaf_hash_hex: String,
    transfer_count: u64,
    funding_account_hex: String,
    dest_account_hex: String,
    funding_amount: u128,
    block_hash_hex: String,
    extrinsics_root_hex: String,
    digest_hex: String,
    parent_hash_hex: String,
    block_number: u32,
}

impl From<CircuitInputs> for DebugInputs {
    fn from(inputs: CircuitInputs) -> Self {
        let hash = qp_poseidon::PoseidonHasher::hash_storage::<AccountId32>(
            &(
                inputs.private.transfer_count,
                AccountId32::new(*inputs.private.funding_account),
                AccountId32::new(*inputs.private.unspendable_account),
                inputs.public.funding_amount,
            )
                .encode(),
        );

        DebugInputs {
            secret_hex: hex::encode(inputs.private.secret.as_ref()),
            proof_hex: inputs
                .private
                .storage_proof
                .proof
                .iter()
                .map(hex::encode)
                .collect(),
            state_root_hex: hex::encode(inputs.private.state_root.as_ref()),
            last_idx: *inputs
                .private
                .storage_proof
                .indices
                .last()
                .expect("non-empty indices; qed"),
            leaf_hash_hex: hex::encode(hash),
            transfer_count: inputs.private.transfer_count,
            funding_account_hex: hex::encode(inputs.private.funding_account.as_ref()),
            dest_account_hex: hex::encode(inputs.public.exit_account.as_ref()),
            funding_amount: inputs.public.funding_amount,
            block_hash_hex: hex::encode(inputs.public.block_hash.as_ref()),
            extrinsics_root_hex: hex::encode(inputs.private.extrinsics_root.as_ref()),
            digest_hex: hex::encode(inputs.private.digest.as_ref()),
            parent_hash_hex: hex::encode(inputs.public.parent_hash.as_ref()),
            block_number: inputs.public.block_number,
        }
    }
}

/// Generate a proof from the given inputs
fn generate_zk_proof(inputs: DebugInputs) -> anyhow::Result<()> {
    // Print the debug inputs being used
    println!(
        "Generating ZK proof with the following inputs:\n{:#?}",
        inputs
    );
    println!("Processing storage proof to generate ordered path and indices...");

    let proof_bytes = inputs
        .proof_hex
        .into_iter()
        .map(|s| Bytes(hex::decode(s.trim_start_matches("0x")).unwrap()))
        .collect();

    let processed_storage_proof = utils::prepare_proof_for_circuit(
        proof_bytes,
        inputs.state_root_hex.clone(),
        hex::decode(inputs.leaf_hash_hex)
            .expect("couldn't decode leaf hash")
            .try_into()
            .expect("stored leaf hash len is not 32;"),
    )?;

    println!("Assembling circuit inputs...");
    let secret =
        BytesDigest::try_from(&hex::decode(inputs.secret_hex)?[..]).expect("valid secret; qed");
    let unspendable_account =
        wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret).account_id;

    let alice_account_bytes = hex::decode(&inputs.funding_account_hex)?;
    let alice_account = AccountId32::try_from(&alice_account_bytes[..])
        .map_err(|_| anyhow!("Invalid funding account length"))?;
    let dest_account_bytes = hex::decode(&inputs.dest_account_hex)?;
    let dest_account_id = SubxtAccountId(
        dest_account_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid dest account length"))?,
    );
    let block_hash = H256::from_str(&inputs.block_hash_hex).map_err(|e| anyhow!(e))?;

    // Decode individual header components
    let state_root = BytesDigest::try_from(&hex::decode(&inputs.state_root_hex)?[..])?;
    let extrinsics_root = BytesDigest::try_from(&hex::decode(inputs.extrinsics_root_hex)?[..])?;
    let digest_bytes = hex::decode(inputs.digest_hex)?;
    let digest: [u8; 110] = digest_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid digest length, expected 110 bytes"))?;
    let parent_hash = BytesDigest::try_from(&hex::decode(inputs.parent_hash_hex)?[..])?;

    let circuit_inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret,
            transfer_count: inputs.transfer_count,
            funding_account: BytesDigest::try_from(alice_account.as_ref() as &[u8])?,
            storage_proof: processed_storage_proof,
            unspendable_account: Digest::from(unspendable_account).into(),
            state_root,
            extrinsics_root,
            digest,
        },
        public: PublicCircuitInputs {
            funding_amount: inputs.funding_amount,
            nullifier: Nullifier::from_preimage(secret, inputs.transfer_count)
                .hash
                .into(),
            exit_account: BytesDigest::try_from(dest_account_id.as_ref() as &[u8])?,
            block_hash: BytesDigest::try_from(block_hash.as_ref())?,
            parent_hash,
            block_number: inputs.block_number,
        },
    };

    println!("Generating ZK proof...");
    let config = CircuitConfig::standard_recursion_config();
    let prover = WormholeProver::new(config);
    let prover_next = prover.commit(&circuit_inputs)?;
    let proof: ProofWithPublicInputs<_, _, 2> = prover_next.prove().expect("proof failed; qed");

    let public_inputs = PublicCircuitInputs::try_from(&proof)?;
    println!(
        "\nSuccessfully generated and verified proof!\nPublic Inputs: {:?}\n",
        public_inputs
    );

    let proof_hex = hex::encode(proof.to_bytes());
    let proof_file = "proof.hex";
    std::fs::write(proof_file, proof_hex)?;
    println!("Proof written to {}", proof_file);

    Ok(())
}

/// Fetches the block at the best block number from the Quantus client.
///
/// Unlike `Block::at_latest()`, this doesn't get the finalized block details.
async fn at_best_block(
    quantus_client: &QuantusClient,
) -> anyhow::Result<Block<ChainConfig, OnlineClient<ChainConfig>>> {
    let best_block = quantus_client.get_latest_block().await?;
    let block = quantus_client.client().blocks().at(best_block).await?;

    Ok(block)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let use_live = args.iter().any(|arg| arg == "--live");
    if !use_live && std::path::Path::new(DEBUG_FILE).exists() {
        println!("Found {}, running in offline debug mode.", DEBUG_FILE);
        let data = std::fs::read_to_string(DEBUG_FILE)?;
        let inputs: DebugInputs = serde_json::from_str(&data)?;
        println!("Loaded debug inputs: {:?}", inputs);
        return generate_zk_proof(inputs);
    }

    println!("{} not found, running in live mode.", DEBUG_FILE);
    // let quantus_client = QuantusClient::new("wss://a.t.res.fm").await?;
    let quantus_client = QuantusClient::new("ws://localhost:9944").await?;
    let client = quantus_client.client();

    println!("Connected to Substrate node.");

    let alice_pair = DilithiumPair::from_seed(&[0u8; 32]).expect("valid seed");
    let quantum_keypair = QuantumKeyPair {
        public_key: alice_pair.public().0.to_vec(),
        private_key: alice_pair.secret.to_vec(),
    };
    let alice_account = AccountId32::new(PoseidonHasher::hash(alice_pair.public().as_ref()).0);
    // alice_account
    println!("Alice account (funding account): {:?}", &alice_account);

    // Generate secret and unspendable account for the wormhole transfer
    let secret: BytesDigest = [1u8; 32].try_into()?;
    let unspendable_account =
        wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret).account_id;
    // Convert Digest (field elements) to BytesDigest (bytes)
    use zk_circuits_common::utils::digest_felts_to_bytes;
    let unspendable_account_bytes_digest = digest_felts_to_bytes(unspendable_account);
    let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
        .as_ref()
        .try_into()
        .expect("BytesDigest is always 32 bytes");
    let unspendable_account_id = SubxtAccountId(unspendable_account_bytes);

    println!(
        "Unspendable account (transfer destination): {:?}",
        &unspendable_account_id
    );

    // The exit account is where funds will eventually be withdrawn to
    // NOTE: Cannot use [255u8; 32] as it contains u64::MAX which is out of Goldilocks field range
    let exit_account_id = SubxtAccountId([42u8; 32]);
    println!(
        "Exit account (withdrawal destination): {:?}",
        &exit_account_id
    );

    let funding_amount = 1_000_000_000_001u128;

    // Make the transfer TO the unspendable account
    let transfer_tx = quantus_cli::chain::quantus_subxt::api::tx()
        .balances()
        .transfer_keep_alive(
            subxt::ext::subxt_core::utils::MultiAddress::Id(unspendable_account_id.clone()),
            funding_amount,
        );

    println!("Submitting transfer from Alice to unspendable account...");

    let blocks = at_best_block(&quantus_client).await?;
    let block_hash = blocks.hash();
    println!("Transfer submitted in block: {:?}", block_hash);

    let storage_api = client.storage().at(block_hash);
    let transfer_count_previous = storage_api
        .fetch(&quantus_node::api::storage().balances().transfer_count())
        .await?
        .unwrap_or_default();

    submit_transaction(&quantus_client, &quantum_keypair, transfer_tx, None).await?;

    let blocks = at_best_block(&quantus_client).await?;
    let block_hash = blocks.hash();

    println!("Transfer included in block: {:?}", block_hash);

    let events_api = client.events().at(block_hash).await?;

    let event = events_api
        .find::<balances::events::TransferProofStored>()
        .next()
        .expect("should find transfer proof event")
        .expect("should be valid transfer proof");

    let storage_api = client.storage().at(block_hash);
    let transfer_count = storage_api
        .fetch(&quantus_node::api::storage().balances().transfer_count())
        .await?
        .unwrap_or_default();

    assert!(
        transfer_count > transfer_count_previous,
        "Transfer count should've been incremented"
    );

    let leaf_hash = qp_poseidon::PoseidonHasher::hash_storage::<AccountId32>(
        &(
            event.transfer_count,
            event.source.clone(),
            event.dest.clone(),
            event.funding_amount,
        )
            .encode(),
    );
    let proof_address = quantus_node::api::storage().balances().transfer_proof((
        event.transfer_count,
        event.source.clone(),
        event.dest.clone(),
        event.funding_amount,
    ));
    let mut final_key = proof_address.to_root_bytes();
    final_key.extend_from_slice(&leaf_hash);
    let val = storage_api.fetch_raw(final_key.clone()).await?;
    assert!(val.is_some(), "Storage key not found");

    println!(
        "final key {}, leaf_hash: {}, count: {}",
        hex::encode(&final_key),
        hex::encode(&leaf_hash),
        event.transfer_count
    );
    let proof_params = rpc_params![vec![to_hex(&final_key)], block_hash];
    let read_proof: ReadProof<H256> = quantus_client
        .rpc_client()
        .request("state_getReadProof", proof_params)
        .await?;

    println!(
        "storage proofs {:?}",
        read_proof
            .proof
            .iter()
            .map(|proof| hex::encode(&proof.0))
            .collect::<Vec<String>>()
    );

    println!("Fetching block header...");
    let header = blocks.header();

    // Debug: Save proof nodes to a file for analysis
    println!("\n=== Saving proof data for analysis ===");
    let proof_data: Vec<String> = read_proof.proof.iter().map(|p| hex::encode(&p.0)).collect();
    let debug_data = serde_json::json!({
        "state_root": hex::encode(header.state_root.0),
        "transfer_count": event.transfer_count,
        "funding_account": hex::encode(alice_account.as_ref() as &[u8]),
        "unspendable_account": hex::encode(unspendable_account_bytes),
        "funding_amount": funding_amount,
        "proof_nodes": proof_data,
        "storage_key": hex::encode(&final_key),
    });
    std::fs::write(
        "proof_debug.json",
        serde_json::to_string_pretty(&debug_data)?,
    )?;
    println!("✓ Proof data saved to proof_debug.json");

    let state_root = BytesDigest::try_from(header.state_root.as_bytes())?;
    let parent_hash = BytesDigest::try_from(header.parent_hash.as_bytes())?;
    let extrinsics_root = BytesDigest::try_from(header.extrinsics_root.as_bytes())?;
    let digest = header.digest.encode().try_into().unwrap();

    let block_number = header.number;
    println!("Assembling circuit inputs...");

    // Verify that our local unspendable_account matches event.dest
    println!("\n=== UNSPENDABLE ACCOUNT VERIFICATION ===");
    println!(
        "Local unspendable_account_id: {}",
        hex::encode(unspendable_account_id.0)
    );
    println!(
        "Event dest:                   {}",
        hex::encode(event.dest.0)
    );
    println!("Match: {}", unspendable_account_id.0 == event.dest.0);
    println!("=====================================\n");

    // Prepare the storage proof with the correct accounts
    let processed_storage_proof = utils::prepare_proof_for_circuit(
        read_proof.proof,
        hex::encode(header.state_root.0),
        leaf_hash,
    )?;

    let inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret,
            transfer_count: event.transfer_count, // Use the actual transfer count from the event
            funding_account: BytesDigest::try_from(alice_account.as_ref() as &[u8])?,
            storage_proof: processed_storage_proof,
            unspendable_account: Digest::from(unspendable_account).into(),
            state_root,
            extrinsics_root,
            digest,
        },
        public: PublicCircuitInputs {
            funding_amount,
            nullifier: Nullifier::from_preimage(secret, event.transfer_count)
                .hash
                .into(),
            exit_account: BytesDigest::try_from(exit_account_id.as_ref() as &[u8])?,
            block_hash: BytesDigest::try_from(block_hash.as_ref())?,
            parent_hash,
            block_number,
        },
    };

    generate_zk_proof(inputs.into())?;
    Ok(())
}
