//! Universal dummy proof for padding aggregation batches.
//!
//! Dummy proofs use `block_hash = 0` AND `output_amounts = 0` as sentinel values.
//! The leaf circuit skips all validation (storage proof, block header, nullifier)
//! for proofs with these sentinels, allowing a single universal dummy proof to be
//! used for all aggregation batches.
//!
//! # Sentinel Values
//!
//! - `block_hash = [0u8; 32]` AND `output_amount_1 = 0` AND `output_amount_2 = 0`:
//!   Triggers bypass of all validation. Both conditions must be met to prevent
//!   an attacker from slipping funds through with a zero block hash.
//! - `exit_account = [0u8; 32]`: Dummies form their own exit group, contributing 0 to sums
//!
//! # Usage
//!
//! To generate a dummy proof, use [`build_dummy_circuit_inputs`] to get the inputs,
//! then prove them with your own prover instance:
//!
//! ```ignore
//! let inputs = build_dummy_circuit_inputs()?;
//! let proof = prover.commit(&inputs)?.prove()?;
//! ```
//!
//! Note: Each dummy proof requires a fresh proof generation. There is no way to
//! "clone" a proof and modify its public inputs - the plonky2 proof is a cryptographic
//! commitment to the public inputs, and modifying them invalidates the proof.

use anyhow::Result;
use qp_wormhole_inputs::PublicCircuitInputs;
use rand::Rng;
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs};
use wormhole_circuit::storage_proof::ProcessedStorageProof;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::utils::{digest_felts_to_bytes, BytesDigest};

// ============================================================================
// Public sentinel constants
// ============================================================================

/// Sentinel block hash for dummy proofs (all zeros).
/// The leaf circuit skips all validation when block_hash == 0.
pub const DUMMY_BLOCK_HASH: [u8; 32] = [0u8; 32];

/// Exit account used by dummy proofs (all zeros).
/// Dummies form their own exit account group but contribute 0 to the sum.
pub const DUMMY_EXIT_ACCOUNT: [u8; 32] = [0u8; 32];

// ============================================================================
// Internal constants for dummy proof generation
// ============================================================================

const DEFAULT_SECRET: &str = "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05";
const DEFAULT_TRANSFER_COUNT: u64 = 4;
const DEFAULT_FUNDING_ACCOUNT: [u8; 32] = [
    226, 124, 203, 9, 80, 60, 124, 205, 165, 5, 178, 216, 195, 15, 149, 38, 116, 1, 238, 133, 181,
    154, 106, 17, 41, 228, 118, 179, 82, 141, 225, 76,
];
const DEFAULT_INPUT_AMOUNT: u32 = 100;
const DEFAULT_OUTPUT_AMOUNT: u32 = 0;
const DEFAULT_VOLUME_FEE_BPS: u32 = 10;

// Block data - all zeros for dummy sentinel
const DEFAULT_PARENT_HASH: [u8; 32] = [0u8; 32];
const DEFAULT_BLOCK_NUMBER: u32 = 0;

// These values are from the original hardcoded dummy proof.
// Even though validation is skipped for dummies, the circuit still needs
// structurally valid data to fill witness targets.
const DEFAULT_ROOT_HASH: &str = "713c0468ddc5b657ce758a3fb75ec5ae906d95b334f24a4f5661cc775e1cdb43";
const DEFAULT_EXTRINSICS_ROOT: [u8; 32] = [0u8; 32];

const DEFAULT_DIGEST: [u8; 110] = [
    8, 6, 112, 111, 119, 95, 128, 233, 182, 183, 107, 158, 1, 115, 19, 219, 126, 253, 86, 30, 208,
    176, 70, 21, 45, 180, 229, 9, 62, 91, 4, 6, 53, 245, 52, 48, 38, 123, 225, 5, 112, 111, 119,
    95, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 18, 79, 226,
];

// Original storage proof data (structurally valid for witness filling)
const DEFAULT_STORAGE_PROOF: [&str; 7] = [
    "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000545576a55a3f69e109b776d252064d3c9bf2fd3a0cd0447c8d82ec12b0343f3a20000000000000000f3ed746dd90e0e2a0d3f8faf0b8a41d5fafd9edcbc88630e389f2db76dd44b7200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000e6f538f42cbc6e72d6a302a648da34c475bcfa104e7cb80625fcf3219bd12172200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb200000000000000025d8d4ad318c66f23547af850000c9790100abdb72c268b1f4d363dca56dee1c2000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000003687179c5ce1cb12b50e50d421bcbdceb82ec583de7585fb7898e167108168b5",
    "000000000000002004100000000000002000000000000000a5267873a1e7e0a5fcc3ff7e87341a4bef02d87b0db8077474a6ecbc064768a22000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
    "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f003280000000000000200000000000000036eed7029a2181549ea0a84a554dd682b0184a06f1c56a53ebf70c127123252920000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b2000000000000000d78c0123abb12433fde4c596240046e451e465ec2a6581fcfea5f8ba0ec0815e200000000000000016b14e363d6ed03d0f13adc683dab364d051a8394db2f605adfe69d0ef5dd78a",
    "0000000000000020840000000000000020000000000000000b9e09e6eaf4417ba88754314fb68e74b956d52e74a87d703d5aabe8b0a409d12000000000000000abf9dfa05f2adc8c6b9447a6dae41d898ac8d77d683c8fe8c9a563a0cd05e0d7",
    "1e00000000000020857e7ea49e785c4e3e1f77a710cfc20085eb00000000000020000000000000007f6a20004a9e9c8534de8e4a017e3795c9d8a30e036108eb593d2ac31f6a34e420000000000000003b9dfda637be517cf8df45f9b9d646c296ceb17aef15f3c9321c84488ea5e67920000000000000006e19211b4ff0a3feb43b34373129676d22378dfe1303191a96b34012713b65832000000000000000f6885f81a0d9ee08a3a67c4f2ef71a2ec725c8a9c79599eb975c2319e4aae5e920000000000000008d4b3c32ff1324fe3b7a05467e88e9f69b0df523bc3b6fbfdc888f06401bc9e72000000000000000ea72cebf4e99ec5a02713c47fa3198ea718fabce8eaf27707c3ec03eafa34174200000000000000077c5198a04b75c9795fe20a45d68df141ef53182a243c6102607da94ee03a9a82000000000000000ee55785e535fe32542b8b7f8537d8f921df34012c8f8dfd97087159ac05b99d1200000000000000013da88523a40420379a2776f484740dd9e78e858b11c7f43d5db16dc923b5e71",
    "0000000000000020a0000000000000002000000000000000439f73a9fe5a17162de32efd7abca06f0c880dc966613afdcf1ab350e1619c4a20000000000000000c8c537d72cc7704d8837da6c8b732d28e3c199124d483b6f2c5ab67a6f03589",
    "3e000000000000306e6d19d641a854b008e6634d9cabf8403cdd67f227f58fc4515d259e8f8bc6d00000000000000000",
];

const DEFAULT_STORAGE_PROOF_INDICES: [usize; 7] = [768, 48, 240, 48, 160, 128, 16];

// ============================================================================
// Public API
// ============================================================================

/// Build circuit inputs for a dummy proof.
///
/// Use these inputs with your prover to generate a dummy proof:
/// ```ignore
/// let inputs = build_dummy_circuit_inputs()?;
/// let proof = prover.commit(&inputs)?.prove()?;
/// ```
///
/// Each call generates a fresh random nullifier, so each proof will be unique.
pub fn build_dummy_circuit_inputs() -> Result<CircuitInputs> {
    let secret_bytes: [u8; 32] = hex::decode(DEFAULT_SECRET)?[..32].try_into().unwrap();
    let secret = BytesDigest::try_from(secret_bytes)?;

    let root_hash: [u8; 32] = hex::decode(DEFAULT_ROOT_HASH)?[..32].try_into().unwrap();

    let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT)?;

    // Use a random nullifier instead of computing from secret.
    // Since block_hash = 0 (dummy sentinel), nullifier validation is skipped.
    let nullifier = BytesDigest::try_from(generate_random_nullifier())?;

    let unspendable_account =
        digest_felts_to_bytes(UnspendableAccount::from_secret(secret).account_id);
    let exit_account = BytesDigest::try_from(DUMMY_EXIT_ACCOUNT)?;

    let storage_proof = build_storage_proof()?;

    Ok(CircuitInputs {
        public: PublicCircuitInputs {
            asset_id: 0u32,
            output_amount_1: DEFAULT_OUTPUT_AMOUNT, // Dummy proofs output 0
            output_amount_2: 0u32,                  // No second output for dummies
            volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
            nullifier,
            exit_account_1: exit_account,
            exit_account_2: BytesDigest::default(), // No second exit account
            // Sentinel: block_hash = 0 triggers validation bypass
            block_hash: BytesDigest::try_from(DUMMY_BLOCK_HASH)?,
            parent_hash: BytesDigest::try_from(DEFAULT_PARENT_HASH)?,
            block_number: DEFAULT_BLOCK_NUMBER,
        },
        private: PrivateCircuitInputs {
            secret,
            storage_proof,
            transfer_count: DEFAULT_TRANSFER_COUNT,
            funding_account,
            unspendable_account,
            // These values are not validated for dummies but needed for witness structure
            state_root: root_hash.try_into()?,
            extrinsics_root: BytesDigest::try_from(DEFAULT_EXTRINSICS_ROOT)?,
            digest: DEFAULT_DIGEST,
            input_amount: DEFAULT_INPUT_AMOUNT,
        },
    })
}

// ============================================================================
// Internal implementation
// ============================================================================

/// Generate a random 32-byte nullifier for dummy proofs.
fn generate_random_nullifier() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut nullifier = [0u8; 32];
    rng.fill(&mut nullifier);
    nullifier
}

fn build_storage_proof() -> Result<ProcessedStorageProof> {
    let proof: Vec<Vec<u8>> = DEFAULT_STORAGE_PROOF
        .iter()
        .map(hex::decode)
        .collect::<std::result::Result<_, _>>()?;

    let indices = DEFAULT_STORAGE_PROOF_INDICES.to_vec();

    ProcessedStorageProof::new(proof, indices)
}
