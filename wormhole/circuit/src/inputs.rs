#![allow(clippy::new_without_default)]
use crate::storage_proof::ProcessedStorageProof;
use alloc::vec::Vec;
use anyhow::{bail, Context};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{felts_to_u128, BytesDigest};

/// The total size of the public inputs field element vector.
pub const PUBLIC_INPUTS_FELTS_LEN: usize = 16;
pub const NULLIFIER_START_INDEX: usize = 0;
pub const NULLIFIER_END_INDEX: usize = 4;
pub const ROOT_HASH_START_INDEX: usize = 4;
pub const ROOT_HASH_END_INDEX: usize = 8;
pub const FUNDING_AMOUNT_START_INDEX: usize = 8;
pub const FUNDING_AMOUNT_END_INDEX: usize = 12;
pub const EXIT_ACCOUNT_START_INDEX: usize = 12;
pub const EXIT_ACCOUNT_END_INDEX: usize = 16;

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug, Clone)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the public inputs required for the circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCircuitInputs {
    /// Amount to be withdrawn.
    pub funding_amount: u128,
    /// The nullifier.
    pub nullifier: BytesDigest,
    /// The root hash of the storage trie.
    pub root_hash: BytesDigest,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
}

/// The exit account and its given sum total funding amount
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputsByAccount {
    /// Funding amounts of duplicate exit accounts summed.
    pub summed_funding_amount: u128,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
}

/// Aggregated public inputs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedPublicCircuitInputs {
    /// The root hash of the block's storage trie.
    pub root_hashes: Vec<BytesDigest>,
    /// Public inputs indexed by exit accounts.
    pub account_data: Vec<PublicInputsByAccount>,
    /// The nullifiers of each individual transfer proof.
    pub nullifiers: Vec<BytesDigest>,
}

/// All of the private inputs required for the circuit.
#[derive(Debug, Clone)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
    pub secret: [u8; 32],
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: ProcessedStorageProof,
    pub transfer_count: u64,
    pub funding_account: BytesDigest,
    /// The unspendable account hash.
    pub unspendable_account: BytesDigest,
}

impl AggregatedPublicCircuitInputs {
    pub fn try_from_slice(pis: &[GoldilocksField]) -> anyhow::Result<Self> {
        // Layout in the FINAL (deduped) wrapper proof PIs:
        // [block_count, account_count, root_hashes(4)*, [funding_sum(4), exit_account(4)]*, nullifiers(4)*]

        let block_count = pis[0].to_canonical_u64() as usize;
        let account_count = pis[1].to_canonical_u64() as usize;

        // Numbers of leaf proofs we aggm,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,regated over into a tree according the length of the public inputs.
        let n_leaf = pis.len() / PUBLIC_INPUTS_FELTS_LEN;
        // Compute expected total PI length from indices and sanity-check.

        let mut expected_felts = 2usize; // for block_count and account_count

        let data_item_felts = 4;
        expected_felts += data_item_felts * (block_count); // root_hashes (4 felts each)
        expected_felts += data_item_felts * (account_count * 2); // funding_sum + exit_account (4 felts each)
        expected_felts += data_item_felts * (n_leaf); // nullifiers (4 felts each)
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
        #[inline]
        fn read_u128(slice4: &[F]) -> anyhow::Result<u128> {
            let arr: [F; 4] = slice4.try_into().expect("slice of 4 felts");
            felts_to_u128(arr).map_err(|e| anyhow::anyhow!("felts_to_u128 error: {:?}", e))
        }

        let mut cursor = 2usize; // start after block_count and account_count
        let mut root_hashes: Vec<BytesDigest> = Vec::with_capacity(block_count);
        let mut account_data: Vec<PublicInputsByAccount> = Vec::with_capacity(account_count);
        let mut nullifiers: Vec<BytesDigest> = Vec::with_capacity(n_leaf);

        for _ in 0..block_count {
            // 1) root hash
            let root_hash =
                read_digest(&pis[cursor..cursor + 4]).context("parsing root_hash for block")?;
            cursor += data_item_felts;
            root_hashes.push(root_hash);
        }

        for _ in 0..account_count {
            // funding_sum (4 felts, BE limbs)
            let summed_funding_amount = read_u128(&pis[cursor..cursor + 4])?;
            cursor += 4;

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
            root_hashes,
            account_data,
            nullifiers,
        })
    }
}

impl PublicCircuitInputs {
    pub fn try_from_slice(pis: &[GoldilocksField]) -> anyhow::Result<Self> {
        // Public inputs are ordered as follows:
        // Nullifier.hash: 4 felts
        // StorageProof.root_hash: 4 felts
        // StorageProof.funding_amount: 4 felts
        // ExitAccount.address: 4 felts
        if pis.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain: {} field elements, got: {}",
                PUBLIC_INPUTS_FELTS_LEN,
                pis.len()
            )
        }
        let nullifier = BytesDigest::try_from(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
            .context("failed to deserialize nullifier hash")?;
        let root_hash = BytesDigest::try_from(&pis[ROOT_HASH_START_INDEX..ROOT_HASH_END_INDEX])
            .context("failed to deserialize root hash")?;
        let funding_amount = felts_to_u128(
            <[F; 4]>::try_from(&pis[FUNDING_AMOUNT_START_INDEX..FUNDING_AMOUNT_END_INDEX])
                .context("failed to deserialize funding amount")?,
        )
        .unwrap();
        let exit_account =
            BytesDigest::try_from(&pis[EXIT_ACCOUNT_START_INDEX..EXIT_ACCOUNT_END_INDEX])
                .context("failed to deserialize exit account")?;

        Ok(PublicCircuitInputs {
            funding_amount,
            nullifier,
            root_hash,
            exit_account,
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
