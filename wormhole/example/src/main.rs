//! End-to-end wormhole transfer proof and values for public and private inputs:
//!
//! - Makes a transfer to a specified destination account.
//! - Fetches a proof for storage key where the previous proof is stored
//! - Combines and passes the necessary inputs to the wormhole prover
//! - Generate the proof for the wormhole transfer

use anyhow::Context;
use clap::Parser;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_poseidon::PoseidonHasher;
use quantus_cli::chain::quantus_subxt::api as quantus_node;
use quantus_cli::chain::quantus_subxt::api::runtime_types::pallet_wormhole::pallet::Call as WormholeCall;
use quantus_cli::chain::quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall;
use quantus_cli::chain::quantus_subxt::api::wormhole;
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
use wormhole_aggregator::aggregator::WormholeProofAggregator;
use wormhole_aggregator::circuits::tree::TreeAggregationConfig;
use wormhole_circuit::inputs::{
    AggregatedPublicCircuitInputs, CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs,
};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::storage_proof::prepare_proof_for_circuit;
use zk_circuits_common::utils::{digest_felts_to_bytes, BytesDigest, Digest};

const DEBUG_FILE: &str = "proof_debug.json";
const SCALE_DOWN_FACTOR: u128 = 10_000_000_000u128; // 10^10

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
    funding_amount: u32,
    block_hash_hex: String,
    extrinsics_root_hex: String,
    digest_hex: String,
    parent_hash_hex: String,
    block_number: u32,
}

impl From<CircuitInputs> for DebugInputs {
    fn from(inputs: CircuitInputs) -> Self {
        type TransferKey = (u32, u64, AccountId32, AccountId32, u128);
        let hash = qp_poseidon::PoseidonHasher::hash_storage::<TransferKey>(
            &(
                inputs.public.asset_id,
                inputs.private.transfer_count,
                AccountId32::new(*inputs.private.funding_account),
                AccountId32::new(*inputs.private.unspendable_account),
                (inputs.public.funding_amount as u128) * SCALE_DOWN_FACTOR,
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

pub type TransferProofKey = (u32, u64, AccountId32, AccountId32, u128);

impl TryFrom<DebugInputs> for CircuitInputs {
    type Error = anyhow::Error;

    fn try_from(inputs: DebugInputs) -> anyhow::Result<Self> {
        use anyhow::{anyhow, Context};

        // Helper: decode hex string into BytesDigest
        fn hex_to_bytes_digest(src: &str, name: &str) -> anyhow::Result<BytesDigest> {
            let bytes =
                hex::decode(src).with_context(|| format!("failed to decode {name} as hex"))?;
            BytesDigest::try_from(bytes.as_slice())
                .map_err(|e| anyhow!("invalid {name} length: {e:?}"))
        }

        // Helper: decode hex string into fixed-size byte array
        fn hex_to_array<const N: usize>(src: &str, name: &str) -> anyhow::Result<[u8; N]> {
            let bytes =
                hex::decode(src).with_context(|| format!("failed to decode {name} as hex"))?;
            let len = bytes.len();
            bytes
                .try_into()
                .map_err(|_| anyhow!("invalid {name} length, expected {N} bytes, got {}", len))
        }

        let proof_bytes: Vec<Bytes> = inputs
            .proof_hex
            .into_iter()
            .map(|s| {
                let s = s.trim_start_matches("0x");
                let bytes = hex::decode(s).context("failed to decode proof_hex entry")?;
                Ok(Bytes(bytes))
            })
            .collect::<anyhow::Result<_>>()?;

        let leaf_hash: [u8; 32] = hex_to_array::<32>(&inputs.leaf_hash_hex, "leaf_hash_hex")?;

        let processed_storage_proof = prepare_proof_for_circuit(
            proof_bytes.iter().map(|bytes| bytes.0.clone()).collect(),
            inputs.state_root_hex.clone(),
            leaf_hash,
        )
        .context("failed to prepare storage proof for circuit")?;

        let secret = hex_to_bytes_digest(&inputs.secret_hex, "secret_hex")?;
        let unspendable_account =
            wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret)
                .account_id;

        let funding_account_bytes = hex::decode(&inputs.funding_account_hex)
            .context("failed to decode funding_account_hex")?;
        let funding_account = AccountId32::try_from(funding_account_bytes.as_slice())
            .map_err(|_| anyhow!("invalid funding account length"))?;

        let dest_account_bytes =
            hex::decode(&inputs.dest_account_hex).context("failed to decode dest_account_hex")?;
        let dest_account_id = SubxtAccountId(
            dest_account_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("invalid dest account length"))?,
        );

        let block_hash = H256::from_str(&inputs.block_hash_hex)
            .map_err(anyhow::Error::from)
            .context("invalid block_hash_hex")?;

        let state_root = hex_to_bytes_digest(&inputs.state_root_hex, "state_root_hex")?;
        let extrinsics_root =
            hex_to_bytes_digest(&inputs.extrinsics_root_hex, "extrinsics_root_hex")?;
        let digest: [u8; 110] = hex_to_array::<110>(&inputs.digest_hex, "digest_hex")?;
        let parent_hash = hex_to_bytes_digest(&inputs.parent_hash_hex, "parent_hash_hex")?;

        Ok(CircuitInputs {
            private: PrivateCircuitInputs {
                secret,
                transfer_count: inputs.transfer_count,
                funding_account: BytesDigest::try_from(funding_account.as_ref() as &[u8])?,
                storage_proof: processed_storage_proof,
                unspendable_account: Digest::from(unspendable_account).into(),
                state_root,
                extrinsics_root,
                digest,
            },
            public: PublicCircuitInputs {
                asset_id: 0u32,
                funding_amount: inputs.funding_amount,
                nullifier: Nullifier::from_preimage(secret, inputs.transfer_count)
                    .hash
                    .into(),
                exit_account: BytesDigest::try_from(dest_account_id.as_ref() as &[u8])?,
                block_hash: BytesDigest::try_from(block_hash.as_ref())?,
                parent_hash,
                block_number: inputs.block_number,
            },
        })
    }
}

/// Generate a proof from the given inputs
fn generate_zk_proof(inputs: CircuitInputs) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    println!("Generating ZK proof...");
    // Must use zk_config to match the aggregator's dummy proof
    let config = CircuitConfig::standard_recursion_config();
    let prover = WormholeProver::new(config);
    let prover_next = prover.commit(&inputs)?;
    let proof: ProofWithPublicInputs<F, C, D> = prover_next.prove().expect("proof failed; qed");

    let public_inputs = PublicCircuitInputs::try_from(&proof)?;
    println!(
        "\nSuccessfully generated and verified proof!\nPublic Inputs: {:?}\n",
        public_inputs
    );

    Ok(proof)
}

/// Save a proof to a file
fn save_proof(proof: &ProofWithPublicInputs<F, C, D>, file_path: &str) -> anyhow::Result<()> {
    let proof_hex = hex::encode(proof.to_bytes());
    std::fs::write(file_path, proof_hex)?;
    println!("Proof written to {}", file_path);
    Ok(())
}

/// Load a proof from a file
fn load_proof(
    file_path: &str,
    common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let proof_hex = std::fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read proof file: {}", file_path))?;
    let proof_bytes = hex::decode(proof_hex.trim())
        .with_context(|| format!("Failed to decode hex from file: {}", file_path))?;
    let proof = ProofWithPublicInputs::from_bytes(proof_bytes, common_data)
        .with_context(|| format!("Failed to deserialize proof from file: {}", file_path))?;
    Ok(proof)
}

/// Aggregate multiple proofs from files
fn aggregate_proofs(
    proof_files: Vec<String>,
    output_file: &str,
    aggregation_config: TreeAggregationConfig,
) -> anyhow::Result<()> {
    println!("\n=== Starting Proof Aggregation ===");
    println!("Loading {} proof files...", proof_files.len());

    // Build the wormhole verifier and prover circuit data
    let config = CircuitConfig::standard_recursion_config();
    let verifier = WormholeVerifier::new(config.clone(), None);
    let prover = WormholeProver::new(config);
    let common_data = &prover.circuit_data.common;

    let mut aggregator =
        WormholeProofAggregator::new(verifier.circuit_data).with_config(aggregation_config);

    println!(
        "Aggregator configured for {} leaf proofs (branching factor: {}, depth: {})",
        aggregator.config.num_leaf_proofs,
        aggregator.config.tree_branching_factor,
        aggregator.config.tree_depth
    );

    if proof_files.len() > aggregator.config.num_leaf_proofs {
        anyhow::bail!(
            "Too many proof files provided: {} (max: {})",
            proof_files.len(),
            aggregator.config.num_leaf_proofs
        );
    }

    // Load and add proofs to aggregator
    for (idx, proof_file) in proof_files.iter().enumerate() {
        println!(
            "Loading proof {}/{}: {}",
            idx + 1,
            proof_files.len(),
            proof_file
        );
        let proof = load_proof(proof_file, common_data)?;
        aggregator.push_proof(proof)?;
    }

    aggregate_and_save(aggregator, output_file)
}

/// Aggregate proofs directly (without loading from files)
fn aggregate_proofs_direct(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    output_file: &str,
    aggregation_config: TreeAggregationConfig,
) -> anyhow::Result<()> {
    println!("\n=== Starting Proof Aggregation ===");
    println!("Aggregating {} proofs...", proofs.len());

    // Build the wormhole verifier circuit data
    let config = CircuitConfig::standard_recursion_config();
    let verifier = WormholeVerifier::new(config, None);

    let mut aggregator =
        WormholeProofAggregator::new(verifier.circuit_data).with_config(aggregation_config);

    println!(
        "Aggregator configured for {} leaf proofs (branching factor: {}, depth: {})",
        aggregator.config.num_leaf_proofs,
        aggregator.config.tree_branching_factor,
        aggregator.config.tree_depth
    );

    if proofs.len() > aggregator.config.num_leaf_proofs {
        anyhow::bail!(
            "Too many proofs provided: {} (max: {})",
            proofs.len(),
            aggregator.config.num_leaf_proofs
        );
    }

    // Add proofs to aggregator
    for proof in proofs {
        aggregator.push_proof(proof)?;
    }

    aggregate_and_save(aggregator, output_file)
}

/// Common aggregation logic - aggregate and save
fn aggregate_and_save(
    mut aggregator: WormholeProofAggregator,
    output_file: &str,
) -> anyhow::Result<()> {
    println!("\nRunning aggregation...");
    let aggregated_proof = aggregator.aggregate()?;

    // Parse and display aggregated public inputs
    let aggregated_public_inputs = AggregatedPublicCircuitInputs::try_from_slice(
        aggregated_proof.proof.public_inputs.as_slice(),
    )?;
    println!("\n=== Aggregated Public Inputs ===");
    println!("{:#?}", aggregated_public_inputs);

    // Verify the aggregated proof
    println!("\nVerifying aggregated proof...");
    aggregated_proof
        .circuit_data
        .verify(aggregated_proof.proof.clone())?;
    println!("Aggregated proof verified successfully!");

    // Save aggregated proof
    save_proof(&aggregated_proof.proof, output_file)?;
    println!("\n=== Aggregation Complete ===");
    println!("Aggregated proof saved to: {}", output_file);

    Ok(())
}

/// Generates a secret by incrementing the base secret by index
fn derive_secret(base_secret: [u8; 32], index: usize) -> [u8; 32] {
    let mut secret = base_secret;
    // Add index to the last 8 bytes as a little-endian u64
    let current = u64::from_le_bytes(secret[24..32].try_into().unwrap());
    let new_value = current.wrapping_add(index as u64);
    secret[24..32].copy_from_slice(&new_value.to_le_bytes());
    secret
}

/// Gets unspendable account from secret
fn get_unspendable_account(
    secret_bytes: [u8; 32],
) -> anyhow::Result<(BytesDigest, SubxtAccountId, Digest)> {
    let secret: BytesDigest = secret_bytes.try_into()?;
    let unspendable_account =
        wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret).account_id;

    let unspendable_account_bytes_digest = digest_felts_to_bytes(unspendable_account);
    let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
        .as_ref()
        .try_into()
        .expect("BytesDigest is always 32 bytes");
    let unspendable_account_id = SubxtAccountId(unspendable_account_bytes);

    Ok((secret, unspendable_account_id, unspendable_account))
}

/// Performs batched transfers and returns circuit inputs for all of them
async fn perform_batched_transfers(
    quantus_client: &QuantusClient,
    quantum_keypair: &QuantumKeyPair,
    funding_account: &AccountId32,
    base_secret: [u8; 32],
    exit_account_bytes: [u8; 32],
    funding_amount: u128,
    num_transfers: usize,
) -> anyhow::Result<Vec<CircuitInputs>> {
    let client = quantus_client.client();
    let exit_account_id = SubxtAccountId(exit_account_bytes);

    // Prepare all transfers
    let mut secrets = Vec::with_capacity(num_transfers);
    let mut unspendable_accounts = Vec::with_capacity(num_transfers);
    let mut calls = Vec::with_capacity(num_transfers);

    println!("\n=== Preparing {} batched transfers ===", num_transfers);

    for i in 0..num_transfers {
        let secret_bytes = derive_secret(base_secret, i);
        let (secret, unspendable_account_id, unspendable_account) =
            get_unspendable_account(secret_bytes)?;

        println!(
            "Transfer {}: unspendable account {:?}",
            i + 1,
            &unspendable_account_id
        );

        // Create transfer call
        let call = RuntimeCall::Wormhole(WormholeCall::transfer_native {
            dest: subxt::ext::subxt_core::utils::MultiAddress::Id(unspendable_account_id.clone()),
            amount: funding_amount,
        });

        secrets.push(secret);
        unspendable_accounts.push((unspendable_account_id, unspendable_account));
        calls.push(call);
    }

    // Batch all transfers
    println!("\nSubmitting batch of {} transfers...", num_transfers);
    let batch_tx = quantus_node::tx().utility().batch_all(calls);

    let _blocks = at_best_block(quantus_client).await?;
    submit_transaction(quantus_client, quantum_keypair, batch_tx, None).await?;

    let blocks = at_best_block(quantus_client).await?;
    let block_hash = blocks.hash();

    println!("Batch included in block: {:?}", block_hash);

    // Get all events from the block and filter by our unspendable accounts
    let events_api = client.events().at(block_hash).await?;
    let all_transfer_events: Vec<_> = events_api
        .find::<wormhole::events::NativeTransferred>()
        .collect::<Result<Vec<_>, _>>()?;

    println!(
        "Found {} total transfer events in block",
        all_transfer_events.len()
    );

    // Filter to only our transfers by matching destination addresses
    let expected_dests: Vec<_> = unspendable_accounts.iter().map(|(id, _)| id.0).collect();
    let transfer_events: Vec<_> = all_transfer_events
        .into_iter()
        .filter(|e| expected_dests.contains(&e.to.0))
        .collect();

    println!(
        "Filtered to {} matching transfer events",
        transfer_events.len()
    );

    if transfer_events.len() != num_transfers {
        anyhow::bail!(
            "Expected {} transfer events, found {}",
            num_transfers,
            transfer_events.len()
        );
    }

    // Process each event and create circuit inputs
    let header = blocks.header();
    let state_root = BytesDigest::try_from(header.state_root.as_bytes())?;
    let parent_hash = BytesDigest::try_from(header.parent_hash.as_bytes())?;
    let extrinsics_root = BytesDigest::try_from(header.extrinsics_root.as_bytes())?;
    let digest: [u8; 110] = header.digest.encode().try_into().unwrap();
    let block_number = header.number;

    let mut all_inputs = Vec::with_capacity(num_transfers);

    for (i, event) in transfer_events.iter().enumerate() {
        println!(
            "\nProcessing transfer {}: count={}, amount={}",
            i + 1,
            event.transfer_count,
            event.amount
        );

        let (secret, (_, unspendable_account)) = (&secrets[i], &unspendable_accounts[i]);

        // Native token transfers use asset_id = 0
        let asset_id = 0u32;

        // Convert subxt AccountId32 to sp_core AccountId32 for hash_storage
        let from_account = AccountId32::new(event.from.0);
        let to_account = AccountId32::new(event.to.0);

        let leaf_hash = qp_poseidon::PoseidonHasher::hash_storage::<TransferProofKey>(
            &(
                asset_id,
                event.transfer_count,
                from_account.clone(),
                to_account.clone(),
                event.amount,
            )
                .encode(),
        );
        let proof_address = quantus_node::storage().wormhole().transfer_proof((
            asset_id,
            event.transfer_count,
            event.from.clone(),
            event.to.clone(),
            event.amount,
        ));
        let mut final_key = proof_address.to_root_bytes();
        final_key.extend_from_slice(&leaf_hash);

        let proof_params = rpc_params![vec![to_hex(&final_key)], block_hash];
        let read_proof: ReadProof<H256> = quantus_client
            .rpc_client()
            .request("state_getReadProof", proof_params)
            .await?;

        // Prepare the storage proof
        let proof_bytes: Vec<Vec<u8>> = read_proof.proof.iter().map(|b| b.0.clone()).collect();
        let processed_storage_proof =
            prepare_proof_for_circuit(proof_bytes, hex::encode(header.state_root.0), leaf_hash)?;

        let inputs = CircuitInputs {
            private: PrivateCircuitInputs {
                secret: *secret,
                transfer_count: event.transfer_count,
                funding_account: BytesDigest::try_from(funding_account.as_ref() as &[u8])?,
                storage_proof: processed_storage_proof,
                unspendable_account: Digest::from(*unspendable_account).into(),
                state_root,
                extrinsics_root,
                digest,
            },
            public: PublicCircuitInputs {
                asset_id: 0u32,
                funding_amount: event.amount,
                nullifier: Nullifier::from_preimage(*secret, event.transfer_count)
                    .hash
                    .into(),
                exit_account: BytesDigest::try_from(exit_account_id.as_ref() as &[u8])?,
                block_hash: BytesDigest::try_from(block_hash.as_ref())?,
                parent_hash,
                block_number,
            },
        };

        all_inputs.push(inputs);
    }

    Ok(all_inputs)
}

/// Performs a single transfer and generates circuit inputs
async fn perform_transfer_and_get_inputs(
    quantus_client: &QuantusClient,
    quantum_keypair: &QuantumKeyPair,
    funding_account: &AccountId32,
    secret_bytes: [u8; 32],
    exit_account_bytes: [u8; 32],
    funding_amount: u128,
    proof_index: usize,
) -> anyhow::Result<CircuitInputs> {
    let client = quantus_client.client();

    // Secret from input
    let secret: BytesDigest = secret_bytes.try_into()?;
    let unspendable_account =
        wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret).account_id;

    // Convert Digest (field elements) to BytesDigest (bytes)
    let unspendable_account_bytes_digest = digest_felts_to_bytes(unspendable_account);
    let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
        .as_ref()
        .try_into()
        .expect("BytesDigest is always 32 bytes");
    let unspendable_account_id = SubxtAccountId(unspendable_account_bytes);

    // Exit account from input
    let exit_account_id = SubxtAccountId(exit_account_bytes);

    println!("\n=== Transfer {} ===", proof_index + 1);
    println!("Unspendable account: {:?}", &unspendable_account_id);

    // Make the transfer TO the unspendable account using wormhole pallet
    let transfer_tx = quantus_cli::chain::quantus_subxt::api::tx()
        .wormhole()
        .transfer_native(
            subxt::ext::subxt_core::utils::MultiAddress::Id(unspendable_account_id.clone()),
            funding_amount,
        );

    println!("Submitting transfer...");

    let _blocks = at_best_block(quantus_client).await?;
    submit_transaction(quantus_client, quantum_keypair, transfer_tx, None).await?;

    let blocks = at_best_block(quantus_client).await?;
    let block_hash = blocks.hash();

    println!("Transfer included in block: {:?}", block_hash);

    let events_api = client.events().at(block_hash).await?;

    let event = events_api
        .find::<wormhole::events::NativeTransferred>()
        .next()
        .expect("should find transfer proof event")
        .expect("should be valid transfer proof");

    println!(
        "Amount: {}, Transfer count: {}",
        event.amount, event.transfer_count
    );

    // Native token transfers use asset_id = 0
    let asset_id = 0u32;
    type TransferKey = (u32, u64, AccountId32, AccountId32, u128);
    let leaf_hash = qp_poseidon::PoseidonHasher::hash_storage::<TransferKey>(
        &(
            asset_id,
            event.transfer_count,
            from_account.clone(),
            to_account.clone(),
            event.amount,
        )
            .encode(),
    );
    let proof_address = quantus_node::storage().wormhole().transfer_proof((
        asset_id,
        event.transfer_count,
        event.from.clone(),
        event.to.clone(),
        event.amount,
    ));
    let mut final_key = proof_address.to_root_bytes();
    final_key.extend_from_slice(&leaf_hash);

    let proof_params = rpc_params![vec![to_hex(&final_key)], block_hash];
    let read_proof: ReadProof<H256> = quantus_client
        .rpc_client()
        .request("state_getReadProof", proof_params)
        .await?;

    let header = blocks.header();

    let state_root = BytesDigest::try_from(header.state_root.as_bytes())?;
    let parent_hash = BytesDigest::try_from(header.parent_hash.as_bytes())?;
    let extrinsics_root = BytesDigest::try_from(header.extrinsics_root.as_bytes())?;
    let digest: [u8; 110] = header.digest.encode().try_into().unwrap();

    let block_number = header.number;

    // Prepare the storage proof with the correct accounts
    let proof_bytes: Vec<Vec<u8>> = read_proof.proof.iter().map(|b| b.0.clone()).collect();
    let processed_storage_proof =
        prepare_proof_for_circuit(proof_bytes, hex::encode(header.state_root.0), leaf_hash)?;

    // We need to quantize the funding amount to use 2 decimal places of precision (divide by 10^10 since original uses 12)
    let funding_amount = (event.amount / SCALE_DOWN_FACTOR) as u32;

    let inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret,
            transfer_count: event.transfer_count,
            funding_account: BytesDigest::try_from(funding_account.as_ref() as &[u8])?,
            storage_proof: processed_storage_proof,
            unspendable_account: Digest::from(unspendable_account).into(),
            state_root,
            extrinsics_root,
            digest,
        },
        public: PublicCircuitInputs {
            asset_id: 0u32,
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

    Ok(inputs)
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

// Minimum allowed funding amount
const MIN_FUNDING_AMOUNT: u128 = 1_000_000_000_000;

// Dev account seeds
const ALICE_SEED: [u8; 32] = [0u8; 32];
const BOB_SEED: [u8; 32] = [1u8; 32];
const CHARLIE_SEED: [u8; 32] = [2u8; 32];

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
enum DevAccount {
    Alice,
    Bob,
    Charlie,
}

impl DevAccount {
    fn seed(&self) -> [u8; 32] {
        match self {
            DevAccount::Alice => ALICE_SEED,
            DevAccount::Bob => BOB_SEED,
            DevAccount::Charlie => CHARLIE_SEED,
        }
    }
}

/// Wormhole proof generator
#[derive(Parser, Debug)]
#[command(name = "wormhole-example")]
#[command(about = "Generate and verify Wormhole ZK proofs", long_about = None)]
struct Cli {
    /// Run in live mode (connect to blockchain)
    #[arg(long)]
    live: bool,

    /// Funding account (alice, bob, or charlie)
    #[arg(long, value_enum, required_if_eq_any([("live", "true"), ("generate_and_aggregate", "true")]))]
    funding_account: Option<DevAccount>,

    /// Secret as 64-character hex string (32 bytes)
    #[arg(long, value_parser = parse_hex_32, required_if_eq_any([("live", "true"), ("generate_and_aggregate", "true")]))]
    secret: Option<[u8; 32]>,

    /// Exit account as 64-character hex string (32 bytes)
    #[arg(long, value_parser = parse_hex_32, required_if_eq_any([("live", "true"), ("generate_and_aggregate", "true")]))]
    exit_account: Option<[u8; 32]>,

    /// Funding amount (minimum: 1_000_000_000_000)
    #[arg(long, value_parser = parse_funding_amount, required_if_eq_any([("live", "true"), ("generate_and_aggregate", "true")]))]
    funding_amount: Option<u128>,

    /// Enable aggregation mode
    #[arg(long)]
    aggregate: bool,

    /// Load proofs from files for aggregation (comma-separated paths)
    #[arg(long, value_delimiter = ',', required_if_eq_all([("aggregate", "true"), ("generate_and_aggregate", "false")]))]
    proof_files: Option<Vec<String>>,

    /// Output file for aggregated proof
    #[arg(long, default_value = "aggregated_proof.hex")]
    aggregated_proof_output: String,

    /// Generate proof and aggregate in one run (combines --live and --aggregate)
    #[arg(long)]
    generate_and_aggregate: bool,

    /// Tree depth for aggregation (default: 3, use 1 for minimal 2-proof aggregation)
    #[arg(long, default_value = "3")]
    aggregation_depth: u32,

    /// Branching factor for aggregation tree (default: 2)
    #[arg(long, default_value = "2")]
    aggregation_branching_factor: usize,

    /// Number of proofs to generate (for --generate-and-aggregate mode)
    /// Defaults to num_leaf_proofs from aggregation config (branching_factor^depth)
    #[arg(long)]
    num_proofs: Option<usize>,
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(format!("Expected 64-character hex string, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| "Failed to convert to [u8; 32]".to_string())
}

fn parse_funding_amount(s: &str) -> Result<u128, String> {
    let amount: u128 = s.parse().map_err(|e| format!("Invalid u128: {}", e))?;
    if amount < MIN_FUNDING_AMOUNT {
        return Err(format!("Amount must be >= {}", MIN_FUNDING_AMOUNT));
    }
    Ok(amount)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Build aggregation config from CLI args
    let aggregation_config =
        TreeAggregationConfig::new(cli.aggregation_branching_factor, cli.aggregation_depth);

    // Aggregation-only mode (from files)
    if cli.aggregate && !cli.generate_and_aggregate {
        let proof_files = cli
            .proof_files
            .context("Missing proof files for aggregation")?;
        return aggregate_proofs(
            proof_files,
            &cli.aggregated_proof_output,
            aggregation_config,
        );
    }

    // Offline debug mode
    if !cli.live && !cli.generate_and_aggregate && std::path::Path::new(DEBUG_FILE).exists() {
        println!("Found {}, running in offline debug mode.", DEBUG_FILE);
        let data = std::fs::read_to_string(DEBUG_FILE)?;
        let inputs: DebugInputs = serde_json::from_str(&data)?;
        println!("Loaded debug inputs: {:?}", inputs);
        let circuit_inputs = CircuitInputs::try_from(inputs)?;
        let proof = generate_zk_proof(circuit_inputs)?;
        save_proof(&proof, "proof.hex")?;
        return Ok(());
    }

    // Live mode or generate-and-aggregate mode - all required fields are enforced by clap
    if !cli.live && !cli.generate_and_aggregate {
        anyhow::bail!("No mode specified. Use --live, --aggregate, or --generate-and-aggregate");
    }

    let dev_account = cli.funding_account.context("Missing funding account")?;
    let secret_bytes = cli.secret.context("Missing secret")?;
    let exit_account_bytes = cli.exit_account.context("Missing exit account")?;
    let funding_amount = cli.funding_amount.context("Missing funding amount")?;

    let quantus_client = QuantusClient::new("ws://localhost:9944").await?;
    println!("Connected to Substrate node.");

    // Get dev account seed
    let seed = dev_account.seed();
    let funding_pair =
        DilithiumPair::from_seed(&seed).expect("valid dev account seed for DilithiumPair");

    let quantum_keypair = QuantumKeyPair {
        public_key: funding_pair.public().0.to_vec(),
        private_key: funding_pair.secret.to_vec(),
    };

    let funding_account = AccountId32::new(PoseidonHasher::hash(funding_pair.public().as_ref()).0);
    println!(
        "Funding account ({:?}): {:?}",
        dev_account, &funding_account
    );

    // Determine number of proofs to generate
    let num_proofs = if cli.generate_and_aggregate {
        cli.num_proofs.unwrap_or(aggregation_config.num_leaf_proofs)
    } else {
        1 // Single proof for --live mode
    };

    if cli.generate_and_aggregate {
        println!("Running in generate-and-aggregate mode.");
        println!(
            "Will generate {} proofs (aggregation config: branching_factor={}, depth={})",
            num_proofs, aggregation_config.tree_branching_factor, aggregation_config.tree_depth
        );
    } else {
        println!("Running in live mode (single proof).");
    }

    // Generate all circuit inputs - use batched transfers for multiple proofs (same block)
    let all_inputs = if num_proofs > 1 {
        perform_batched_transfers(
            &quantus_client,
            &quantum_keypair,
            &funding_account,
            secret_bytes,
            exit_account_bytes,
            funding_amount,
            num_proofs,
        )
        .await?
    } else {
        // Single proof - use the original single transfer function
        let inputs = perform_transfer_and_get_inputs(
            &quantus_client,
            &quantum_keypair,
            &funding_account,
            secret_bytes,
            exit_account_bytes,
            funding_amount,
            0,
        )
        .await?;
        vec![inputs]
    };

    // Generate all proofs
    println!("\n=== Generating {} ZK Proofs ===", num_proofs);
    let mut proofs = Vec::with_capacity(num_proofs);
    for (i, inputs) in all_inputs.iter().enumerate() {
        println!("Generating proof {}/{}...", i + 1, num_proofs);
        let proof = generate_zk_proof(inputs.clone())?;

        // Save individual proof
        let proof_file = format!("proof_{}.hex", i);
        save_proof(&proof, &proof_file)?;
        println!("✓ Proof {} saved to {}", i + 1, proof_file);

        proofs.push(proof);
    }

    // Save last proof as proof.hex for compatibility
    if let Some(last_proof) = proofs.last() {
        save_proof(last_proof, "proof.hex")?;
    }

    // If generate-and-aggregate mode, aggregate all proofs
    if cli.generate_and_aggregate {
        println!("\n=== Aggregating {} Proofs ===", proofs.len());
        println!(
            "Using aggregation config: branching_factor={}, depth={}, num_leaf_proofs={}",
            aggregation_config.tree_branching_factor,
            aggregation_config.tree_depth,
            aggregation_config.num_leaf_proofs
        );
        aggregate_proofs_direct(proofs, &cli.aggregated_proof_output, aggregation_config)?;
    }

    Ok(())
}
