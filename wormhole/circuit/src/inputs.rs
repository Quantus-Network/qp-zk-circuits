#![allow(clippy::new_without_default)]
use crate::block_header::header::DIGEST_LOGS_SIZE;
use crate::storage_proof::ProcessedStorageProof;
use alloc::vec::Vec;
use anyhow::{bail, Context};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{BytesDigest, DIGEST_BYTES_LEN};

/// The total size of the public inputs field element vector.
pub const PUBLIC_INPUTS_FELTS_LEN: usize = 19;
pub const ASSET_ID_INDEX: usize = 0;
// Note: funding_amount comes before nullifier because LeafTargets::new() is called
// before NullifierTargets::new() to ensure asset_id is the first public input.
pub const FUNDING_AMOUNT_INDEX: usize = 1;
pub const NULLIFIER_START_INDEX: usize = 2;
pub const NULLIFIER_END_INDEX: usize = 6;
pub const EXIT_ACCOUNT_START_INDEX: usize = 6;
pub const EXIT_ACCOUNT_END_INDEX: usize = 10;
pub const BLOCK_HASH_START_INDEX: usize = 10;
pub const BLOCK_HASH_END_INDEX: usize = 14;
pub const PARENT_HASH_START_INDEX: usize = 14;
pub const PARENT_HASH_END_INDEX: usize = 18;
pub const BLOCK_NUMBER_INDEX: usize = 18;
pub const BLOCK_NUMBER_END_INDEX: usize = 19;

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug, Clone)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the public inputs required for the circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCircuitInputs {
    /// The asset ID (0 for native token).
    pub asset_id: u32,
    /// Amount to be withdrawn. This value is quantized with 0.01 units of precision.
    /// **DEV NOTE**: The funding amount unit on chain is still u128 with 12 decimals so we will need to
    /// scale by 10^10 when constructing the funding amount during on-chain verification.
    pub funding_amount: u32,
    /// The nullifier.
    pub nullifier: BytesDigest,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
    /// The hash of the block header.
    pub block_hash: BytesDigest,
    /// The parent hash of the block, parsed from the block header
    pub parent_hash: BytesDigest,
    /// The block number, parsed from the block header
    pub block_number: u32,
}

/// The exit account and its given sum total funding amount
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputsByAccount {
    /// Funding amounts of duplicate exit accounts summed.
    pub summed_funding_amount: u32,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
}

/// The block data (block_hash, parent_hash, block_number) in the aggregated proofs
#[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct BlockData {
    /// The hash of the block header.
    pub block_hash: BytesDigest,
    /// The block number, parsed from the block header
    pub block_number: u32,
}

/// Aggregated public inputs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedPublicCircuitInputs {
    /// The asset ID of the set (0 for native token).
    pub asset_id: u32,
    /// The last set block data (block_hash, block_number) in the aggregated proofs.
    /// This the only block data we need to commit to in the aggregated proof.
    /// All prior blocks are enforced to be contigious and their connectivity is verified via parent_hash checks.
    pub block_data: BlockData,
    /// The set of exit accounts and their summed funding amounts
    pub account_data: Vec<PublicInputsByAccount>,
    /// The nullifiers of each individual transfer proof
    pub nullifiers: Vec<BytesDigest>,
}
pub const BLOCK_HEADER_PADDING_FELTS: usize = 53;
pub const BLOCK_HEADER_SIZE: usize = (DIGEST_BYTES_LEN * 3) + 4 + DIGEST_LOGS_SIZE; // 32 bytes each for parent hash, state root, extrinsics root + 4 bytes for block number + digest logs

/// All of the private inputs required for the circuit.
#[derive(Debug, Clone)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
    pub secret: BytesDigest,
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: ProcessedStorageProof,
    pub transfer_count: u64,
    pub funding_account: BytesDigest,
    /// The unspendable account hash.
    pub unspendable_account: BytesDigest,
    /// The state root of the storage proof
    pub state_root: BytesDigest,
    /// The extrinsics root of the block header
    pub extrinsics_root: BytesDigest,
    /// The digest logs of the block header
    pub digest: [u8; DIGEST_LOGS_SIZE],
}

impl AggregatedPublicCircuitInputs {
    pub fn try_from_slice(pis: &[GoldilocksField]) -> anyhow::Result<Self> {
        // Layout in the FINAL (deduped) wrapper proof PIs:
        // [account_count, block_data(5), [funding_sum(4), exit_account(4)]*, nullifiers(4)*]
        let account_count = pis[0].to_canonical_u64() as usize;
        let asset_id = pis[1].to_canonical_u64() as u32;

        // Numbers of leaf proofs we aggregated over into a tree according the length of the public inputs.
        let n_leaf = pis.len() / PUBLIC_INPUTS_FELTS_LEN;
        // Compute expected total PI length from indices and sanity-check.

        let mut expected_felts = 7usize; // for account_count + asset_id + block_data (5 felts)

        let hash_item_felts = 4;
        expected_felts += account_count; // funding_sum (1 felt each)
        expected_felts += hash_item_felts * (account_count); // exit_account (4 felts each)
        expected_felts += hash_item_felts * (n_leaf); // nullifiers (4 felts each)
        anyhow::ensure!(
            expected_felts <= pis.len(),
            "Deduped PI length must be less than or equal to {}, but got {} (computed from indices).",
            expected_felts,
            pis.len()
        );

        // Helpers
        #[inline]
        fn read_digest(slice: &[F]) -> anyhow::Result<BytesDigest> {
            BytesDigest::try_from(slice).context("failed to deserialize BytesDigest")
        }

        let block_data = BlockData {
            block_hash: read_digest(&pis[2..6]).context("parsing block_hash")?,
            block_number: pis[6]
                .to_canonical_u64()
                .try_into()
                .context("parsing block_number")?,
        };

        let mut cursor = 7usize; // start after metadata felts
        let mut account_data: Vec<PublicInputsByAccount> = Vec::with_capacity(account_count);
        let mut nullifiers: Vec<BytesDigest> = Vec::with_capacity(n_leaf);

        for _ in 0..account_count {
            // funding_sum (1 felt)
            let summed_funding_amount = pis[cursor].to_canonical_u64() as u32;
            cursor += 1;

            // exit_account (4 felts)
            let exit_account =
                read_digest(&pis[cursor..cursor + 4]).context("parsing exit_account")?;
            cursor += 4;
            account_data.push(PublicInputsByAccount {
                summed_funding_amount,
                exit_account,
            });
        }

        for _ in 0..n_leaf {
            // nullifiers: one 4-felt digest per leaf index in this group
            let n = read_digest(&pis[cursor..cursor + 4]).context("parsing nullifier")?;
            cursor += 4;
            nullifiers.push(n);
        }

        // Final safety: we should have consumed exactly all expected felts, the rest of the felts should be zero.
        if cursor != expected_felts {
            bail!(
                "Internal parsing error: consumed {} felts, but expected {}.",
                cursor,
                expected_felts
            );
        }

        Ok(AggregatedPublicCircuitInputs {
            asset_id,
            block_data,
            account_data,
            nullifiers,
        })
    }
}

impl PublicCircuitInputs {
    pub fn try_from_slice(pis: &[GoldilocksField]) -> anyhow::Result<Self> {
        // Public inputs are ordered as follows:
        // asset_id: 1 felt
        // StorageProof.funding_amount: 1 felt
        // Nullifier.hash: 4 felts
        // ExitAccount.address: 4 felts
        // BlockHeader.block_hash: 4 felts
        // BlockHeader.parent_hash: 4 felts
        // BlockHeader.block_number: 1 felt
        if pis.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain: {} field elements, got: {}",
                PUBLIC_INPUTS_FELTS_LEN,
                pis.len()
            )
        }
        let asset_id = pis[ASSET_ID_INDEX]
            .to_canonical_u64()
            .try_into()
            .context("failed to convert asset_id felt to u32")?;
        let nullifier = BytesDigest::try_from(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
            .context("failed to deserialize nullifier hash")?;
        let block_hash = BytesDigest::try_from(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
            .context("failed to deserialize block hash")?;
        let funding_amount = pis[FUNDING_AMOUNT_INDEX]
            .to_canonical_u64()
            .try_into()
            .context("failed to convert asset_id felt to u32")?;

        let exit_account =
            BytesDigest::try_from(&pis[EXIT_ACCOUNT_START_INDEX..EXIT_ACCOUNT_END_INDEX])
                .context("failed to deserialize exit account")?;
        let parent_hash =
            BytesDigest::try_from(&pis[PARENT_HASH_START_INDEX..PARENT_HASH_END_INDEX])
                .context("failed to deserialize parent hash")?;
        let block_number_felt = pis[BLOCK_NUMBER_INDEX];
        let block_number = block_number_felt
            .to_canonical_u64()
            .try_into()
            .context("failed to convert block number felt to u32")?;

        Ok(PublicCircuitInputs {
            asset_id,
            funding_amount,
            nullifier,
            block_hash,
            exit_account,
            parent_hash,
            block_number,
        })
    }
}

impl TryFrom<&ProofWithPublicInputs<F, C, D>> for PublicCircuitInputs {
    type Error = anyhow::Error;

    fn try_from(proof: &ProofWithPublicInputs<F, C, D>) -> Result<Self, Self::Error> {
        Self::try_from_slice(&proof.public_inputs)
            .context("failed to deserialize public inputs from proof")
    }
}
