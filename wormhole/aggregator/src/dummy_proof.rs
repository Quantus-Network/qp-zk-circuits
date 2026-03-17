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

use anyhow::Result;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::PublicCircuitInputs;
use rand::Rng;
use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs};
use wormhole_circuit::storage_proof::ProcessedStorageProof;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{digest_felts_to_bytes, BytesDigest};

// ============================================================================
// Public sentinel constants
// ============================================================================

/// Sentinel block hash for dummy proofs (all zeros).
/// The leaf circuit skips all validation when block_hash == 0.
pub const DUMMY_BLOCK_HASH: [u8; 32] = [0u8; 32];

/// Exit account used by dummy proofs (all zeros).
/// Dummies form their own exit-account group but contribute 0 to the sum; this batching
/// constraint is intentional so padding cannot influence any real payout bucket.
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

// Nullifier is all zeroes as well. During aggregation, we replace the dummy nullifier targets
// with hashes of random preimages to prevent deduplication of dummy proofs.
const DEFAULT_NULLIFIER: [u8; 32] = [0u8; 32];

// These values are from the original hardcoded dummy proof.
// Even though validation is skipped for dummies, the circuit still needs
// structurally valid data to fill witness targets.
const DEFAULT_ROOT_HASH: &str = "ae6e4ff0dca1ef5ede9dccc84365cecfab4e431c6f3086216bc3b819cdf0a893";
const DEFAULT_EXTRINSICS_ROOT: [u8; 32] = [0u8; 32];

const DEFAULT_DIGEST: [u8; 110] = [
    8, 6, 112, 111, 119, 95, 128, 233, 182, 183, 107, 158, 1, 115, 19, 219, 126, 253, 86, 30, 208,
    176, 70, 21, 45, 180, 229, 9, 62, 91, 4, 6, 53, 245, 52, 48, 38, 123, 225, 5, 112, 111, 119,
    95, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 18, 79, 226,
];

// Original storage proof data (structurally valid for witness filling)
const DEFAULT_STORAGE_PROOF: [&str; 8] = [
    "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000545576a55a3f69e109b776d252064d3c9bf2fd3a0cd0447c8d82ec12b0343f3a20000000000000000f3ed746dd90e0e2a0d3f8faf0b8a41d5fafd9edcbc88630e389f2db76dd44b7200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000e6f538f42cbc6e72d6a302a648da34c475bcfa104e7cb80625fcf3219bd12172200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb20000000000000003e59c11d3ed854c15155cb012e7525931448f86c5eb5e73542a66080f636af942000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000003687179c5ce1cb12b50e50d421bcbdceb82ec583de7585fb7898e167108168b5",
    "00000000000000200410000000000000200000000000000010632c05772c9a2e9121b53768b121d934b7d6278446a2a0773c9587ad7bd7012000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
    "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f003280000000000000200000000000000036eed7029a2181549ea0a84a554dd682b0184a06f1c56a53ebf70c127123252920000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b2000000000000000384bdce3289bf96dc1c6ca2d40a2ad8fad5679ba65f0b54fc93e7e70253094b8200000000000000016b14e363d6ed03d0f13adc683dab364d051a8394db2f605adfe69d0ef5dd78a",
    "000000000000002084000000000000002000000000000000077002f8a70a8440d0264efa041f82c4c2907c15ff1f0b8f87ab8d3af3d844b32000000000000000abf9dfa05f2adc8c6b9447a6dae41d898ac8d77d683c8fe8c9a563a0cd05e0d7",
    "1e00000000000020857e7ea49e785c4e3e1f77a710cfc20085eb00000000000020000000000000007f6a20004a9e9c8534de8e4a017e3795c9d8a30e036108eb593d2ac31f6a34e42000000000000000cd39db03c0661d5585167c901a3ecf6bb22b39a6853e19611c961f0dfafe271e20000000000000006e19211b4ff0a3feb43b34373129676d22378dfe1303191a96b34012713b65832000000000000000f6885f81a0d9ee08a3a67c4f2ef71a2ec725c8a9c79599eb975c2319e4aae5e920000000000000008d4b3c32ff1324fe3b7a05467e88e9f69b0df523bc3b6fbfdc888f06401bc9e72000000000000000ea72cebf4e99ec5a02713c47fa3198ea718fabce8eaf27707c3ec03eafa34174200000000000000077c5198a04b75c9795fe20a45d68df141ef53182a243c6102607da94ee03a9a82000000000000000ee55785e535fe32542b8b7f8537d8f921df34012c8f8dfd97087159ac05b99d1200000000000000013da88523a40420379a2776f484740dd9e78e858b11c7f43d5db16dc923b5e71",
    "0000000000000020a0000000000000002000000000000000439f73a9fe5a17162de32efd7abca06f0c880dc966613afdcf1ab350e1619c4a200000000000000030085033127efa78f3d8d3209e1ece18d52682030337bbc8d40240c34a871700",
    "3e00000000000050586b872baf44ae4e42cae4082e01a8aecc96287b9252e0f0b97477682dfb32eb0000000000000000",
    "6e6d19d641a854b008e6634d9cabf8403cdd67f227f58fc4515d259e8f8bc6d0",
];

// Indices for the first N-1 nodes (the last node is the value node, always index 0)
const DEFAULT_STORAGE_PROOF_INDICES: [usize; 6] = [768, 48, 240, 48, 160, 128];

// ============================================================================
// Public API
// ============================================================================

/// Deserialize a dummy proof from raw bytes.
pub fn load_dummy_proof(
    bytes: Vec<u8>,
    common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    ProofWithPublicInputs::<F, C, D>::from_bytes(bytes, common_data)
}

/// Generate a fresh dummy proof from circuit data and targets.
///
/// Used by the circuit builder to produce a `dummy_proof.bin` that is guaranteed
/// to be compatible with the circuit binaries generated in the same run.
pub fn generate_dummy_proof(
    circuit_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    targets: &wormhole_circuit::circuit::circuit_logic::CircuitTargets,
) -> anyhow::Result<Vec<u8>> {
    use plonky2::iop::witness::PartialWitness;

    let inputs = build_dummy_circuit_inputs()?;
    let mut pw = PartialWitness::new();
    wormhole_prover::fill_witness(&mut pw, &inputs, targets)?;
    let proof = circuit_data.prove(pw)?;
    Ok(proof.to_bytes())
}

/// Build circuit inputs for a dummy proof.
///
/// Use these inputs with your prover to generate a dummy proof:
/// ```ignore
/// let inputs = build_dummy_circuit_inputs()?;
/// let proof = prover.commit(&inputs)?.prove()?;
/// ```
///
pub fn build_dummy_circuit_inputs() -> Result<CircuitInputs> {
    let secret_bytes: [u8; 32] = hex::decode(DEFAULT_SECRET)?[..32].try_into().unwrap();
    let secret = BytesDigest::try_from(secret_bytes)?;

    let root_hash: [u8; 32] = hex::decode(DEFAULT_ROOT_HASH)?[..32].try_into().unwrap();

    let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT)?;

    let nullifier = BytesDigest::try_from(DEFAULT_NULLIFIER)?;

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
            block_number: DEFAULT_BLOCK_NUMBER,
        },
        private: PrivateCircuitInputs {
            secret,
            storage_proof,
            transfer_count: DEFAULT_TRANSFER_COUNT,
            funding_account,
            unspendable_account,
            parent_hash: BytesDigest::try_from(DEFAULT_PARENT_HASH)?,
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

/// Generate a random 32-byte nullifier preimage for dummy proofs.
/// The circuit will hash this to produce the actual nullifier.
pub fn generate_random_nullifier_preimage() -> BytesDigest {
    let mut rng = rand::thread_rng();
    loop {
        let mut nullifier = [0u8; 32];
        rng.fill(&mut nullifier);
        if let Ok(digest) = BytesDigest::try_from(nullifier) {
            return digest;
        }
    }
}

fn build_storage_proof() -> Result<ProcessedStorageProof> {
    let proof: Vec<Vec<u8>> = DEFAULT_STORAGE_PROOF
        .iter()
        .map(hex::decode)
        .collect::<std::result::Result<_, _>>()?;

    let indices = DEFAULT_STORAGE_PROOF_INDICES.to_vec();

    ProcessedStorageProof::new(proof, indices)
}
