use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::storage_proof::ProcessedStorageProof;
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use wormhole_prover::WormholeProver;
use zk_circuits_common::utils::{digest_felts_to_bytes, u128_to_felts, u64_to_felts, BytesDigest};

fn main() -> anyhow::Result<()> {
    // Create inputs. In practice, each input would be gathered from the real node.
    let funding_account = SubstrateAccount::new(&[
        226, 124, 203, 9, 80, 60, 124, 205, 165, 5, 178, 216, 195, 15, 149, 38, 116, 1, 238, 133,
        181, 154, 106, 17, 41, 228, 118, 179, 82, 141, 225, 76,
    ])?; // Alice's dev account
    let secret = BytesDigest::try_from([1u8; 32]).unwrap();
    let unspendable_account = UnspendableAccount::from_secret(secret).account_id;
    let funding_amount = 1_000_000_000_000u128;
    let transfer_count = 0u64;

    let mut leaf_inputs_felts = Vec::new();
    leaf_inputs_felts.extend(&u64_to_felts(transfer_count));
    leaf_inputs_felts.extend_from_slice(&funding_account.0);
    leaf_inputs_felts.extend_from_slice(&unspendable_account);
    leaf_inputs_felts.extend_from_slice(&u128_to_felts(funding_amount));
    let leaf_inputs_hash = PoseidonHash::hash_no_pad(&leaf_inputs_felts);
    let root_hash = digest_felts_to_bytes(leaf_inputs_hash.elements);

    let exit_account_id = 8226349481601990196u64;
    let exit_account_bytes = exit_account_id.to_le_bytes();
    // pad with 0 bytes to make it 32 bytes long
    let mut exit_account_bytes = exit_account_bytes.to_vec();
    exit_account_bytes.resize(32, 0);

    let exit_account = SubstrateAccount::new(&exit_account_bytes)?;

    let inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret,
            transfer_count: 0,
            funding_account: (*funding_account).into(),
            storage_proof: ProcessedStorageProof::new(vec![], vec![]).unwrap(),
            unspendable_account: (unspendable_account).into(),
        },
        public: PublicCircuitInputs {
            funding_amount,
            nullifier: Nullifier::from_preimage(secret, 0).hash.into(),
            root_hash,
            exit_account: (*exit_account).into(),
        },
    };

    let config = CircuitConfig::standard_recursion_config();
    let prover = WormholeProver::new(config);
    let prover_next = prover.commit(&inputs)?;
    let proof: ProofWithPublicInputs<
        plonky2::field::goldilocks_field::GoldilocksField,
        plonky2::plonk::config::PoseidonGoldilocksConfig,
        2,
    > = prover_next.prove().expect("proof failed; qed");

    let public_inputs = PublicCircuitInputs::try_from(&proof)?;
    // print the public inputs
    println!("{:?}", public_inputs);

    // write the proof as hex
    let proof_hex = hex::encode(proof.to_bytes());
    // store the proof hex to file
    std::fs::write("proof_from_bins.hex", proof_hex)?;
    Ok(())
}
