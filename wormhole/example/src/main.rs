//! End-to-end wormhole transfer proof and values for public and private inputs:
//!
//! - Makes a transfer to a specified destination account.
//! - Fetches a proof for storage key where the previous proof is stored
//! - Combines and passes the necessary inputs to the wormhole prover
//! - Generate the proof for the wormhole transfer

use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_poseidon::PoseidonHasher;
use quantus_cli::chain::quantus_subxt as quantus_node;
use quantus_cli::cli::common::submit_transaction;
use quantus_cli::qp_dilithium_crypto::DilithiumPair;
use quantus_cli::wallet::QuantumKeyPair;
use quantus_cli::{AccountId32, QuantusClient};
use sp_core::{Hasher, H256};
use subxt::backend::legacy::rpc_methods::ReadProof;
use subxt::ext::codec::Encode;
use subxt::ext::jsonrpsee::core::client::ClientT;
use subxt::ext::jsonrpsee::rpc_params;
use subxt::utils::{to_hex, AccountId32 as SubxtAccountId};
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_prover::WormholeProver;
use zk_circuits_common::utils::{BytesDigest, Digest};

use crate::utils::check_leaf;

mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // let quantus_client = QuantusClient::new("wss://a.t.res.fm").await?;
    let quantus_client = QuantusClient::new("ws://localhost:9944").await?;
    let client = quantus_client.client();

    println!("Connected to Substrate node.");

    // get latest header
    let blocks = client.blocks().at_latest().await?;
    let header = blocks.header();

    println!("digests {:?}", header.digest);

    let alice_pair = DilithiumPair::from_seed(&[0u8; 32]).expect("valid seed");
    let quantum_keypair = QuantumKeyPair {
        public_key: alice_pair.public().0.to_vec(),
        private_key: alice_pair.secret.to_vec(),
    };
    let alice_account = AccountId32::new(PoseidonHasher::hash(alice_pair.public().as_ref()).0);

    // Generate a random destination account to ensure the transaction is unique.
    let dest_account_id = SubxtAccountId([255u8; 32]);

    println!(
        "Generated random destination account: {:?}",
        &dest_account_id
    );

    let funding_amount = 1_000_000_000_001u128;

    // 3. Create and submit a balances transfer extrinsic.
    let transfer_tx = quantus_cli::chain::quantus_subxt::api::tx()
        .balances()
        .transfer_keep_alive(
            subxt::ext::subxt_core::utils::MultiAddress::Id(dest_account_id.clone()),
            funding_amount,
        );

    println!("Submitting transfer from Alice to {}...", &dest_account_id);

    submit_transaction(&quantus_client, &quantum_keypair, transfer_tx, None).await?;

    let block_hash = client.blocks().at_latest().await?.hash();

    println!("Transfer finalized in block: {:?}", block_hash);

    let storage_api = client.storage().at(block_hash);
    let transfer_count = storage_api
        .fetch(&quantus_node::api::storage().balances().transfer_count())
        .await?
        .unwrap_or_default();

    let transfer_proof_hash = qp_poseidon::PoseidonHasher::hash_storage::<AccountId32>(
        &(
            transfer_count,
            alice_account.clone(),
            dest_account_id.clone(),
            funding_amount,
        )
            .encode(),
    );

    let proof_address = quantus_node::api::storage().balances().transfer_proof((
        transfer_count,
        SubxtAccountId(alice_account.clone().into()),
        dest_account_id.clone(),
        funding_amount,
    ));
    let mut final_key = proof_address.to_root_bytes();
    final_key.extend_from_slice(&transfer_proof_hash);

    // assert the above key exists
    assert!(storage_api.fetch_raw_keys(final_key.clone()).await.is_ok());

    println!("Fetching storage proof for Alice's account...");
    let proof_params = rpc_params![vec![to_hex(final_key)], block_hash];
    let read_proof: ReadProof<H256> = quantus_client
        .rpc_client()
        .request("state_getReadProof", proof_params)
        .await?;

    println!("storage proofs {:?}", read_proof);

    println!("Fetching block header...");
    let blocks = client.blocks().at(block_hash).await?;
    let header = blocks.header();

    println!("state root {:?}", header.state_root.clone());
    let state_root = BytesDigest::try_from(header.state_root.as_bytes())?;
    let parent_hash = BytesDigest::try_from(header.parent_hash.as_bytes())?;
    let block_number = header.number;
    println!("Assembling circuit inputs...");
    let secret: BytesDigest = [1u8; 32].try_into()?;
    let unspendable_account =
        wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret).account_id;

    let (_, last_idx) = check_leaf(
        &transfer_proof_hash,
        read_proof.proof[read_proof.proof.len() - 1].clone().0,
    );

    println!("Processing storage proof to generate ordered path and indices...");
    let processed_storage_proof = utils::prepare_proof_for_circuit(
        read_proof.proof,
        hex::encode(header.state_root.0),
        last_idx,
    )?;

    let inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret,
            transfer_count: 0, // In a real scenario, this would be tracked.
            funding_account: BytesDigest::try_from(alice_account.as_ref() as &[u8])?,
            storage_proof: processed_storage_proof,
            unspendable_account: Digest::from(unspendable_account).into(),
            block_header: header.encode().try_into().expect("block header size; qed"),
            state_root,
        },
        public: PublicCircuitInputs {
            funding_amount,
            nullifier: Nullifier::from_preimage(secret, 0).hash.into(),
            exit_account: BytesDigest::try_from(dest_account_id.as_ref() as &[u8])?,
            block_hash: BytesDigest::try_from(block_hash.as_ref())?,
            parent_hash,
            block_number,
        },
    };

    println!("Generating ZK proof...");
    let config = CircuitConfig::standard_recursion_config();
    let prover = WormholeProver::new(config);
    let prover_next = prover.commit(&inputs)?;
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
