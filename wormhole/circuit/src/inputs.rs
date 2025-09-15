#![allow(clippy::new_without_default)]
use crate::storage_proof::ProcessedStorageProof;
use alloc::vec::Vec;
use anyhow::{bail, Context};
use plonky2::field::goldilocks_field::GoldilocksField;
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
/// The nullifiers and sum total funding amount for a given exit account within a block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputsByAccount {
    /// Funding amounts of duplicate exit accounts summed.
    pub funding_sum: u128,
    /// The address of the account to pay out to.
    pub exit_account: BytesDigest,
    /// The nullifiers of each individual transfer proof.
    pub nullifiers: Vec<BytesDigest>,
}

/// Aggregated public inputs for a given block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputsByBlock {
    /// The root hash of the block's storage trie.
    pub root_hash: BytesDigest,
    /// Public inputs indexed by exit accounts.
    pub account_data: Vec<PublicInputsByAccount>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
/// Public inputs from aggregated proofs indexed by block.
pub struct AggregatedPublicCircuitInputs(pub Vec<PublicInputsByBlock>);

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
    pub fn try_from_aggregated(
        pis: &[GoldilocksField],
        indices: &[Vec<Vec<usize>>],
    ) -> anyhow::Result<Self> {
        // Layout in the FINAL (deduped) wrapper proof PIs:
        // For each root group i:
        //   - root_hash (4 felts)
        //   - for each exit group j in indices[i]:
        //       - funding_sum (4 felts, big-endian limbs)
        //       - exit_account (4 felts)
        //       - nullifiers: len(indices[i][j]) * (4 felts each)

        // Compute expected total PI length from indices and sanity-check.
        let mut expected_felts = 0usize;
        for per_root in indices {
            expected_felts += 4; // root_hash
            for group in per_root {
                expected_felts += 4; // funding_sum
                expected_felts += 4; // exit_account
                expected_felts += 4 * group.len(); // nullifiers
            }
        }
        anyhow::ensure!(
            pis.len() == expected_felts,
            "Deduped PI length mismatch: got {}, expected {} (computed from indices).",
            pis.len(),
            expected_felts
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

        let mut cursor = 0usize;
        let mut blocks: Vec<PublicInputsByBlock> = Vec::with_capacity(indices.len());

        for per_root in indices {
            // 1) root hash
            let root_hash =
                read_digest(&pis[cursor..cursor + 4]).context("parsing root_hash for block")?;
            cursor += 4;

            let mut accounts: Vec<PublicInputsByAccount> = Vec::with_capacity(per_root.len());

            // 2) groups under this root
            for group in per_root {
                // funding_sum (4 felts, BE limbs)
                let funding_sum = read_u128(&pis[cursor..cursor + 4])?;
                cursor += 4;

                // exit_account (4 felts)
                let exit_account =
                    read_digest(&pis[cursor..cursor + 4]).context("parsing exit_account")?;
                cursor += 4;

                // nullifiers: one 4-felt digest per leaf index in this group
                let mut nullifiers: Vec<BytesDigest> = Vec::with_capacity(group.len());
                for _ in 0..group.len() {
                    let n = read_digest(&pis[cursor..cursor + 4]).context("parsing nullifier")?;
                    cursor += 4;
                    nullifiers.push(n);
                }

                accounts.push(PublicInputsByAccount {
                    funding_sum,
                    nullifiers,
                    exit_account,
                });
            }

            blocks.push(PublicInputsByBlock {
                root_hash,
                account_data: accounts,
            });
        }

        // Final safety: we should have consumed exactly all PIs.
        if cursor != pis.len() {
            bail!(
                "Internal parsing error: consumed {} felts, but PI length is {}.",
                cursor,
                pis.len()
            );
        }

        Ok(AggregatedPublicCircuitInputs(blocks))
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
