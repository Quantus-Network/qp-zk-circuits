//! End-to-end wormhole transfer proof and values for public and private inputs:
//!
//! - Makes a transfer to a specified destination account.
//! - Fetches a proof for storage key where the previous proof is stored
//! - Combines and passes the necessary inputs to the wormhole prover
//! - Generate the proof for the wormhole transfer

use qp_poseidon::PoseidonHasher;
use quantus_cli::chain::quantus_subxt as quantus_node;
use quantus_cli::qp_dilithium_crypto::{DilithiumPair, DilithiumPublic, DilithiumSigner};
use quantus_cli::{qp_dilithium_crypto, AccountId32, QuantusClient};
use sp_core::Hasher;
use subxt::client::OfflineClientT;
use subxt::config::{DefaultExtrinsicParams, DefaultExtrinsicParamsBuilder, ExtrinsicParams};
use subxt::ext::codec::Encode;
use subxt::ext::jsonrpsee::core::client::ClientT;
use subxt::ext::jsonrpsee::rpc_params;
use subxt::utils::AccountId32 as SubxtAccountId;
use wormhole_circuit::inputs::{
    BlockHeaderInputs, CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs,
};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::storage_proof::ProcessedStorageProof;
use wormhole_prover::WormholeProver;
use zk_circuits_common::utils::{BytesDigest, Digest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // let quantus_client = QuantusClient::new("wss://a.t.res.fm").await?;
    let quantus_client = QuantusClient::new("ws://localhost:9944").await?;
    let client = quantus_client.client();

    println!("Connected to Substrate node.");

    let alice_pair = DilithiumPair::from_seed(&[0u8; 32]).expect("valid seed");
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
    let ext_params = DefaultExtrinsicParamsBuilder::new()
        .nonce(
            quantus_client
                .client()
                .tx()
                .account_nonce(&alice_account)
                .await?,
        )
        .build();

    let signed_extrinsic = quantus_client
        .client()
        .tx()
        .sign_and_submit(&transfer_tx, &alice_pair, &ext_params)
        .await?;

    // println!("Events: {:?}", events);

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
        SubxtAccountId(alice_account.into()),
        dest_account_id,
        funding_amount,
    ));
    let mut final_key = proof_address.to_root_bytes();
    final_key.extend_from_slice(&transfer_proof_hash);

    // assert the above key exists
    assert!(storage_api.fetch_raw_keys(final_key.clone()).await.is_ok());

    println!("Fetching storage proof for Alice's account...");
    let proof_params = rpc_params![final_key, block_hash];
    let read_proof = quantus_client
        .rpc_client()
        .request("state_getReadProof", proof_params)
        .await?;

    println!("storage proofs {:?}", read_proof);

    // println!("Fetching block header...");
    // let header = api
    //     .rpc()
    //     .header(Some(block_hash))
    //     .await?
    //     .context("Header not found")?;
    // let state_root = BytesDigest::try_from(*header.state_root.as_bytes())?;
    // let parent_hash = BytesDigest::try_from(*header.parent_hash.as_bytes())?;
    // let extrinsics_root = BytesDigest::try_from(*header.extrinsics_root.as_bytes())?;
    // let block_number = header.number;

    // println!("Assembling circuit inputs...");
    // let secret = [1u8; 32];
    // let unspendable_account =
    //     wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(&secret).account_id;

    // // NOTE: The `indices` for the storage proof are non-trivial to calculate.
    // // They depend on the structure of the Patricia Merkle Trie and the path to the
    // // specific leaf. For this example, we are passing an empty vec, which will
    // // likely fail in a real circuit that properly validates them. A real implementation
    // // would require a client-side trie library to determine these indices.
    // let processed_storage_proof = ProcessedStorageProof::new(proof_nodes, vec![])?;

    // let inputs = CircuitInputs {
    //     private: PrivateCircuitInputs {
    //         secret,
    //         transfer_count: 0, // In a real scenario, this would be tracked.
    //         funding_account: BytesDigest::try_from(alice_account_id.as_ref())?,
    //         storage_proof: processed_storage_proof,
    //         unspendable_account: Digest::from(unspendable_account).into(),
    //         block_header: BlockHeaderInputs {
    //             block_hash: BytesDigest::try_from(block_hash.as_ref())?,
    //             parent_hash,
    //             block_number: block_number as u64,
    //             state_root,
    //             extrinsics_root,
    //         },
    //     },
    //     public: PublicCircuitInputs {
    //         funding_amount,
    //         nullifier: Nullifier::from_preimage(&secret, 0).hash.into(),
    //         exit_account: BytesDigest::try_from(dest_account_id.as_ref())?,
    //         block_hash: BytesDigest::try_from(block_hash.as_ref())?,
    //     },
    // };

    // println!("Generating ZK proof...");
    // let config = CircuitConfig::standard_recursion_config();
    // let prover = WormholeProver::new(config);
    // let prover_next = prover.commit(&inputs)?;
    // let proof: ProofWithPublicInputs<_, _, 2> = prover_next.prove().expect("proof failed; qed");

    // let public_inputs = PublicCircuitInputs::try_from(&proof)?;
    // println!(
    //     "\nSuccessfully generated and verified proof!\nPublic Inputs: {:?}\n",
    //     public_inputs
    // );

    // let proof_hex = hex::encode(proof.to_bytes());
    // let proof_file = "proof.hex";
    // std::fs::write(proof_file, proof_hex)?;
    // println!("Proof written to {}", proof_file);

    Ok(())
}
