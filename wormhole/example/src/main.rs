use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_circuit::inputs::{
    BlockHeaderInputs, CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs,
};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::storage_proof::ProcessedStorageProof;
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use wormhole_prover::WormholeProver;
use zk_circuits_common::utils::{digest_felts_to_bytes, digest_bytes_to_felts, u128_to_felts, u64_to_felts, BytesDigest};

fn main() -> anyhow::Result<()> {
    // 1. Define base values for the transaction
    let funding_account = SubstrateAccount::new(&[
        226, 124, 203, 9, 80, 60, 124, 205, 165, 5, 178, 216, 195, 15, 149, 38, 116, 1, 238, 133,
        181, 154, 106, 17, 41, 228, 118, 179, 82, 141, 225, 76,
    ])?; // Alice's dev account
    let secret = [1u8; 32];
    let unspendable_account = UnspendableAccount::from_secret(&secret).account_id;
    let funding_amount = 1_000_000_000_000u128;
    let transfer_count = 0u64;

    let mut leaf_inputs_felts = Vec::new();
    leaf_inputs_felts.extend(&u64_to_felts(transfer_count));
    leaf_inputs_felts.extend_from_slice(&funding_account.0);
    leaf_inputs_felts.extend_from_slice(&unspendable_account);
    leaf_inputs_felts.extend_from_slice(&u128_to_felts(funding_amount));
    let leaf_inputs_hash = PoseidonHash::hash_no_pad(&leaf_inputs_felts);

    let parent_hash = BytesDigest::try_from([1u8; 32]).unwrap();
    let block_number = 1337u64;
    let extrinsics_root = BytesDigest::try_from([3u8; 32]).unwrap();
    // For this example, we'll say the state_root *is* the leaf hash. In reality,
    // the state_root would be the root of a large Merkle tree containing the leaf hash.
    let state_root = BytesDigest::try_from(digest_felts_to_bytes(leaf_inputs_hash.elements)).unwrap();

    let mut header_preimage_felts = Vec::new();
    header_preimage_felts.extend(digest_bytes_to_felts(parent_hash));
    header_preimage_felts.extend(u64_to_felts(block_number));
    header_preimage_felts.extend(digest_bytes_to_felts(state_root));
    header_preimage_felts.extend(digest_bytes_to_felts(extrinsics_root));
    let block_hash_felts = PoseidonHash::hash_no_pad(&header_preimage_felts).elements;
    let block_hash = BytesDigest::try_from(digest_felts_to_bytes(block_hash_felts)).unwrap();

    let exit_account_id = 8226349481601990196u64;
    let exit_account_bytes = exit_account_id.to_le_bytes();
    let mut exit_account_bytes_vec = exit_account_bytes.to_vec();
    exit_account_bytes_vec.resize(32, 0);
    let exit_account = SubstrateAccount::new(&exit_account_bytes_vec)?;

    let inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret,
            transfer_count,
            funding_account: (*funding_account).into(),
            // The storage proof is empty, as we are proving inclusion in the `state_root`
            // which we have defined as being equal to the leaf hash itself.
            storage_proof: ProcessedStorageProof::new(vec![], vec![]).unwrap(),
            unspendable_account: (unspendable_account).into(),
            block_header: BlockHeaderInputs {
                block_hash,
                parent_hash,
                block_number,
                state_root,
                extrinsics_root,
            },
        },
        public: PublicCircuitInputs {
            funding_amount,
            nullifier: Nullifier::from_preimage(&secret, 0).hash.into(),
            exit_account: (*exit_account).into(),
            block_hash,
        },
    };

    // 7. Generate and verify the proof
    let config = CircuitConfig::standard_recursion_config();
    let prover = WormholeProver::new(config);
    let prover_next = prover.commit(&inputs)?;
    let proof: ProofWithPublicInputs<_, _, 2> = prover_next.prove().expect("proof failed; qed");

    let public_inputs = PublicCircuitInputs::try_from(&proof)?;
    println!("Successfully verified proof with public inputs: {:?}", public_inputs);

    let proof_hex = hex::encode(proof.to_bytes());
    std::fs::write("proof_from_bins.hex", proof_hex)?;
    println!("Proof written to proof_from_bins.hex");

    Ok(())
}
