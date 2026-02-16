#![allow(clippy::new_without_default)]
use crate::block_header::header::DIGEST_LOGS_SIZE;
use crate::storage_proof::ProcessedStorageProof;
use alloc::vec::Vec;
use anyhow::{bail, Context};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{try_felts_slice_to_bytes_digest, BytesDigest, DIGEST_BYTES_LEN};

// Import public input types and constants from wormhole_inputs (single source of truth)
use qp_wormhole_inputs::{
    AggregatedPublicCircuitInputs, BlockData, PublicCircuitInputs, PublicInputsByAccount,
    ASSET_ID_INDEX, BLOCK_HASH_END_INDEX, BLOCK_HASH_START_INDEX, BLOCK_NUMBER_INDEX,
    EXIT_ACCOUNT_1_END_INDEX, EXIT_ACCOUNT_1_START_INDEX, EXIT_ACCOUNT_2_END_INDEX,
    EXIT_ACCOUNT_2_START_INDEX, NULLIFIER_END_INDEX, NULLIFIER_START_INDEX, OUTPUT_AMOUNT_1_INDEX,
    OUTPUT_AMOUNT_2_INDEX, PUBLIC_INPUTS_FELTS_LEN, VOLUME_FEE_BPS_INDEX,
};

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug, Clone)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
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
    /// The parent hash of the block header (private - used to compute block_hash)
    pub parent_hash: BytesDigest,
    /// The state root of the storage proof
    pub state_root: BytesDigest,
    /// The extrinsics root of the block header
    pub extrinsics_root: BytesDigest,
    /// The digest logs of the block header
    pub digest: [u8; DIGEST_LOGS_SIZE],
    /// The input amount from storage (before fee deduction). This value is quantized with 0.01 units of precision.
    /// The circuit verifies that output_amount <= input_amount - (input_amount * volume_fee_bps / 10000).
    pub input_amount: u32,
}

// ============================================================================
// Traits for parsing from GoldilocksField slices (plonky2-specific)
// ============================================================================

/// Trait for parsing `PublicCircuitInputs` from field element slices.
pub trait ParsePublicInputs {
    /// Parse public inputs from a slice of GoldilocksField elements.
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PublicCircuitInputs>;

    /// Parse public inputs from a ProofWithPublicInputs.
    fn try_from_proof(
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<PublicCircuitInputs>;
}

impl ParsePublicInputs for PublicCircuitInputs {
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PublicCircuitInputs> {
        // Public inputs are ordered as follows:
        // asset_id: 1 felt
        // output_amount_1: 1 felt (spend)
        // output_amount_2: 1 felt (change)
        // volume_fee_bps: 1 felt
        // Nullifier.hash: 4 felts
        // ExitAccount1.address: 4 felts (spend destination)
        // ExitAccount2.address: 4 felts (change destination)
        // BlockHeader.block_hash: 4 felts
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
        let output_amount_1 = pis[OUTPUT_AMOUNT_1_INDEX]
            .to_canonical_u64()
            .try_into()
            .context("failed to convert output_amount_1 felt to u32")?;
        let output_amount_2 = pis[OUTPUT_AMOUNT_2_INDEX]
            .to_canonical_u64()
            .try_into()
            .context("failed to convert output_amount_2 felt to u32")?;
        let volume_fee_bps = pis[VOLUME_FEE_BPS_INDEX]
            .to_canonical_u64()
            .try_into()
            .context("failed to convert volume_fee_bps felt to u32")?;
        let nullifier =
            try_felts_slice_to_bytes_digest(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
                .context("failed to deserialize nullifier hash")?;
        let block_hash =
            try_felts_slice_to_bytes_digest(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
                .context("failed to deserialize block hash")?;

        let exit_account_1 = try_felts_slice_to_bytes_digest(
            &pis[EXIT_ACCOUNT_1_START_INDEX..EXIT_ACCOUNT_1_END_INDEX],
        )
        .context("failed to deserialize exit_account_1")?;
        let exit_account_2 = try_felts_slice_to_bytes_digest(
            &pis[EXIT_ACCOUNT_2_START_INDEX..EXIT_ACCOUNT_2_END_INDEX],
        )
        .context("failed to deserialize exit_account_2")?;
        let block_number_felt = pis[BLOCK_NUMBER_INDEX];
        let block_number = block_number_felt
            .to_canonical_u64()
            .try_into()
            .context("failed to convert block number felt to u32")?;

        Ok(PublicCircuitInputs {
            asset_id,
            output_amount_1,
            output_amount_2,
            volume_fee_bps,
            nullifier,
            block_hash,
            exit_account_1,
            exit_account_2,
            block_number,
        })
    }

    fn try_from_proof(
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<PublicCircuitInputs> {
        Self::try_from_felts(&proof.public_inputs)
            .context("failed to deserialize public inputs from proof")
    }
}

/// Trait for parsing `AggregatedPublicCircuitInputs` from field element slices.
pub trait ParseAggregatedPublicInputs {
    /// Parse aggregated public inputs from a slice of GoldilocksField elements.
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<AggregatedPublicCircuitInputs>;
}

impl ParseAggregatedPublicInputs for AggregatedPublicCircuitInputs {
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<AggregatedPublicCircuitInputs> {
        // Layout in the FINAL (deduped) wrapper proof PIs:
        // [num_unique_exits, asset_id, volume_fee_bps, block_data(5),
        //  [output_sum(1), exit_account(4)] * 2*N,  <-- 2 outputs per leaf
        //  nullifiers(4) * N, padding...]
        //
        // IMPORTANT: With 2 outputs per leaf, we have 2*N exit slots.
        // The num_unique_exits is informational only.
        // Slots with matching exit accounts will have their amounts summed.
        let _num_unique_exits = pis[0].to_canonical_u64() as usize;
        let asset_id: u32 = pis[1]
            .to_canonical_u64()
            .try_into()
            .context("AggregatedPI: asset_id at index 1 exceeds u32 range")?;
        let volume_fee_bps: u32 = pis[2]
            .to_canonical_u64()
            .try_into()
            .context("AggregatedPI: volume_fee_bps at index 2 exceeds u32 range")?;

        // Number of leaf proofs (N) is derived from the total PI length.
        // The circuit pads to root_pi_len + 8, where root_pi_len = n_leaf * LEAF_PI_LEN.
        // So: n_leaf = pis.len() / LEAF_PI_LEN (integer division, rounds down correctly).
        let n_leaf = pis.len() / PUBLIC_INPUTS_FELTS_LEN;

        // Helpers
        #[inline]
        fn read_digest(slice: &[F]) -> anyhow::Result<BytesDigest> {
            try_felts_slice_to_bytes_digest(slice).context("failed to deserialize BytesDigest")
        }

        let block_data = BlockData {
            block_hash: read_digest(&pis[3..7]).context("parsing block_hash")?,
            block_number: pis[7]
                .to_canonical_u64()
                .try_into()
                .context("parsing block_number")?,
        };

        let mut cursor = 8usize; // start after metadata felts

        // Read 2*N exit account slots (two outputs per leaf proof)
        // Slots with duplicate exit accounts will appear multiple times with summed amounts.
        // The chain should deduplicate by exit account after parsing.
        let num_exit_slots = n_leaf * 2;
        let mut account_data: Vec<PublicInputsByAccount> = Vec::with_capacity(num_exit_slots);
        for i in 0..num_exit_slots {
            // output_sum (1 felt)
            let summed_output_amount: u32 =
                pis[cursor].to_canonical_u64().try_into().with_context(|| {
                    format!(
                        "AggregatedPI: summed_output_amount[{}] at cursor {} exceeds u32 range",
                        i, cursor
                    )
                })?;
            cursor += 1;

            // exit_account (4 felts)
            let exit_account =
                read_digest(&pis[cursor..cursor + 4]).context("parsing exit_account")?;
            cursor += 4;
            account_data.push(PublicInputsByAccount {
                summed_output_amount,
                exit_account,
            });
        }

        // Read N nullifiers (one per leaf proof)
        let mut nullifiers: Vec<BytesDigest> = Vec::with_capacity(n_leaf);
        for _ in 0..n_leaf {
            let n = read_digest(&pis[cursor..cursor + 4]).context("parsing nullifier")?;
            cursor += 4;
            nullifiers.push(n);
        }

        // Compute expected felts consumed
        // 8 metadata + 2*N*5 exit slots (2 outputs per leaf) + N*4 nullifiers
        let expected_felts = 8 + num_exit_slots * 5 + n_leaf * 4;
        if cursor != expected_felts {
            bail!(
                "Internal parsing error: consumed {} felts, but expected {} (n_leaf={}, num_exit_slots={}).",
                cursor,
                expected_felts,
                n_leaf,
                num_exit_slots
            );
        }

        Ok(AggregatedPublicCircuitInputs {
            asset_id,
            volume_fee_bps,
            block_data,
            account_data,
            nullifiers,
        })
    }
}
