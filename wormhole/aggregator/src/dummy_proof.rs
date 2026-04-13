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
use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{digest_to_bytes, BytesDigest};
use zk_circuits_common::zk_merkle::SIBLINGS_PER_LEVEL;

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

// ============================================================================
// Public API
// ============================================================================

/// Deserialize a dummy proof from raw bytes.
///
/// This is kept public for use by benchmarks which need to load serialized proofs.
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

    let nullifier = BytesDigest::try_from(DEFAULT_NULLIFIER)?;

    let unspendable_account = digest_to_bytes(UnspendableAccount::from_secret(secret).account_id);
    let exit_account = BytesDigest::try_from(DUMMY_EXIT_ACCOUNT)?;

    // For dummy proofs, we use an empty ZK Merkle proof (depth 0)
    // The circuit skips validation when block_hash == 0 and outputs == 0
    let zk_tree_root = [0u8; 32];
    let zk_merkle_siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]> = vec![];
    let zk_merkle_positions: Vec<u8> = vec![];

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
            transfer_count: DEFAULT_TRANSFER_COUNT,
            unspendable_account,
            parent_hash: BytesDigest::try_from(DEFAULT_PARENT_HASH)?,
            // These values are not validated for dummies but needed for witness structure
            state_root: root_hash.try_into()?,
            extrinsics_root: BytesDigest::try_from(DEFAULT_EXTRINSICS_ROOT)?,
            digest: DEFAULT_DIGEST,
            input_amount: DEFAULT_INPUT_AMOUNT,
            zk_tree_root,
            zk_merkle_siblings,
            zk_merkle_positions,
        },
    })
}

// ============================================================================
// Internal implementation
// ============================================================================

/// Generate a random 32-byte nullifier preimage for dummy proofs.
/// The circuit will hash this to produce the actual nullifier.
pub(crate) fn generate_random_nullifier_preimage() -> BytesDigest {
    let mut rng = rand::thread_rng();
    loop {
        let mut nullifier = [0u8; 32];
        rng.fill(&mut nullifier);
        if let Ok(digest) = BytesDigest::try_from(nullifier) {
            return digest;
        }
    }
}
