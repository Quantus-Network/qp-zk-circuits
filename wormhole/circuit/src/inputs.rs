#![allow(clippy::new_without_default)]
use crate::block_header::header::DIGEST_LOGS_SIZE;
use alloc::vec::Vec;
use anyhow::{bail, Context};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{try_4_felts_to_bytes, BytesDigest};
use zk_circuits_common::zk_merkle::SIBLINGS_PER_LEVEL;

// Import public input types and constants from wormhole_inputs (single source of truth)
pub use qp_wormhole_inputs::{
    BlockData, PrivateBatchPublicInputs, PublicCircuitInputs, PublicInputsByAccount,
};
use qp_wormhole_inputs::{
    ASSET_ID_INDEX, BLOCK_HASH_END_INDEX, BLOCK_HASH_START_INDEX, BLOCK_NUMBER_INDEX,
    EXIT_ACCOUNT_1_END_INDEX, EXIT_ACCOUNT_1_START_INDEX, EXIT_ACCOUNT_2_END_INDEX,
    EXIT_ACCOUNT_2_START_INDEX, NULLIFIER_END_INDEX, NULLIFIER_START_INDEX, OUTPUT_AMOUNT_1_INDEX,
    OUTPUT_AMOUNT_2_INDEX, PUBLIC_INPUTS_FELTS_LEN, VOLUME_FEE_BPS_INDEX,
};

/// Inputs required to commit to the wormhole circuit.
#[derive(Clone)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

impl core::fmt::Debug for CircuitInputs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CircuitInputs")
            .field("public", &self.public)
            .field("private", &self.private)
            .finish()
    }
}

/// All of the private inputs required for the circuit.
#[derive(Clone)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
    pub secret: BytesDigest,
    /// Transfer count for this recipient
    pub transfer_count: u64,
    /// The unspendable account hash (recipient of the transfer).
    pub unspendable_account: BytesDigest,
    /// The parent hash of the block header (private - used to compute block_hash)
    pub parent_hash: BytesDigest,
    /// The state root of the block (still needed for block hash computation)
    pub state_root: BytesDigest,
    /// The extrinsics root of the block header
    pub extrinsics_root: BytesDigest,
    /// The digest logs of the block header
    pub digest: [u8; DIGEST_LOGS_SIZE],
    /// The input amount from storage (before fee deduction). This value is quantized with 0.01 units of precision.
    /// The circuit verifies that output_amount <= input_amount - (input_amount * volume_fee_bps / 10000).
    pub input_amount: u32,

    // === ZK Merkle Proof fields (replaces old MPT storage_proof) ===
    /// Root of the ZK tree (from block header's zk_tree_root field).
    /// This is used for both:
    /// - Block hash computation (as part of the header preimage)
    /// - ZK Merkle proof verification (compared against computed root)
    ///
    /// The circuit constrains these two uses to be equal.
    pub zk_tree_root: [u8; 32],
    /// Sibling hashes at each level of the 4-ary Merkle proof.
    /// Each level has 3 siblings in **sorted order** (excluding current hash).
    pub zk_merkle_siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]>,
    /// Position hints (0-3) for each level indicating where current hash
    /// should be inserted among the sorted siblings.
    pub zk_merkle_positions: Vec<u8>,
}

impl core::fmt::Debug for PrivateCircuitInputs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateCircuitInputs")
            .field("secret", &"[REDACTED]")
            .field("transfer_count", &self.transfer_count)
            .field("unspendable_account", &self.unspendable_account)
            .field("parent_hash", &self.parent_hash)
            .field("state_root", &self.state_root)
            .field("extrinsics_root", &self.extrinsics_root)
            .field("digest", &"[REDACTED]")
            .field("input_amount", &self.input_amount)
            .field("zk_tree_root", &self.zk_tree_root)
            .field("zk_merkle_siblings", &"[REDACTED]")
            .field("zk_merkle_positions", &"[REDACTED]")
            .finish()
    }
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
        // Public inputs are ordered as follows (total 21 felts):
        // asset_id: 1 felt
        // output_amount_1: 1 felt (spend)
        // output_amount_2: 1 felt (change)
        // volume_fee_bps: 1 felt
        // Nullifier.hash: 4 felts
        // ExitAccount1.address: 4 felts (8 bytes/felt for hash-derived accounts)
        // ExitAccount2.address: 4 felts (8 bytes/felt for hash-derived accounts)
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
        let nullifier = try_4_felts_to_bytes(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
            .context("failed to deserialize nullifier hash")?;
        let block_hash = try_4_felts_to_bytes(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
            .context("failed to deserialize block hash")?;

        let exit_account_1 =
            try_4_felts_to_bytes(&pis[EXIT_ACCOUNT_1_START_INDEX..EXIT_ACCOUNT_1_END_INDEX])
                .context("failed to deserialize exit_account_1")?;
        let exit_account_2 =
            try_4_felts_to_bytes(&pis[EXIT_ACCOUNT_2_START_INDEX..EXIT_ACCOUNT_2_END_INDEX])
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

/// Trait for parsing `PrivateBatchPublicInputs` from field element slices.
pub trait ParsePrivateBatchPublicInputs {
    /// Parse aggregated public inputs from a slice of GoldilocksField elements.
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PrivateBatchPublicInputs>;
}

impl ParsePrivateBatchPublicInputs for PrivateBatchPublicInputs {
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PrivateBatchPublicInputs> {
        // Layout: [num_unique_exits, asset_id, volume_fee_bps, block_hash(4), block_number,
        //          [output_sum(1), exit_account(4)] * 2*N, nullifiers(4) * N, padding...]

        // Validate layout: total length must be 8 + N * PUBLIC_INPUTS_FELTS_LEN
        let payload_len = pis
            .len()
            .checked_sub(8)
            .filter(|len| len % PUBLIC_INPUTS_FELTS_LEN == 0)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "AggregatedPI: malformed length {} - expected 8 + N*{} felts",
                    pis.len(),
                    PUBLIC_INPUTS_FELTS_LEN
                )
            })?;

        let n_leaf = payload_len / PUBLIC_INPUTS_FELTS_LEN;
        // This invariant is enforced because an aggregator should never legitimately
        // produce a PI vector with zero leaf proofs. See audit finding M-3: "Public-batch
        // has no dummy bypass; all-dummy private-batch batches break aggregation".
        anyhow::ensure!(n_leaf > 0, "AggregatedPI: need at least one leaf proof");

        // Helper to read a u32 from a felt
        let read_u32 = |f: GoldilocksField| -> anyhow::Result<u32> {
            f.to_canonical_u64().try_into().map_err(Into::into)
        };

        // Helper to read 4 felts as a BytesDigest
        let read_digest = |slice: &[GoldilocksField]| -> anyhow::Result<BytesDigest> {
            try_4_felts_to_bytes(slice).context("failed to deserialize digest")
        };

        // Parse header (indices 0-7)
        let num_unique_exits = read_u32(pis[0]).context("num_unique_exits")?;
        let asset_id = read_u32(pis[1]).context("asset_id")?;
        let volume_fee_bps = read_u32(pis[2]).context("volume_fee_bps")?;
        let block_data = BlockData {
            block_hash: read_digest(&pis[3..7]).context("block_hash")?,
            block_number: read_u32(pis[7]).context("block_number")?,
        };

        // Parse 2*N exit accounts (after header at index 8)
        let account_data = pis[8..]
            .chunks(5)
            .take(n_leaf * 2)
            .enumerate()
            .map(|(i, chunk)| {
                Ok(PublicInputsByAccount {
                    summed_output_amount: read_u32(chunk[0])
                        .with_context(|| format!("account[{}].amount", i))?,
                    exit_account: read_digest(&chunk[1..5])
                        .with_context(|| format!("account[{}].address", i))?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        // Parse N nullifiers (after exit accounts)
        let nullifier_start = 8 + n_leaf * 2 * 5;
        let nullifiers = pis[nullifier_start..]
            .chunks(4)
            .take(n_leaf)
            .enumerate()
            .map(|(i, chunk)| read_digest(chunk).with_context(|| format!("nullifier[{}]", i)))
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(PrivateBatchPublicInputs {
            num_unique_exits,
            asset_id,
            volume_fee_bps,
            block_data,
            account_data,
            nullifiers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;

    #[test]
    fn aggregated_try_from_felts_rejects_empty_slice() {
        let result =
            <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(&[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("malformed length"),
            "Expected 'malformed length' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn aggregated_try_from_felts_rejects_short_slice() {
        // Only 5 elements when at least 8 are required for header
        let short_slice: Vec<GoldilocksField> = vec![GoldilocksField::ZERO; 5];
        let result = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(
            &short_slice,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("malformed length"),
            "Expected 'malformed length' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn aggregated_try_from_felts_rejects_malformed_length() {
        // 9 elements: 8 header + 1 extra (not a multiple of PUBLIC_INPUTS_FELTS_LEN)
        let malformed_slice: Vec<GoldilocksField> = vec![GoldilocksField::ZERO; 9];
        let result = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(
            &malformed_slice,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("malformed length"),
            "Expected 'malformed length' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn aggregated_try_from_felts_rejects_header_only() {
        // Exactly 8 elements (header only, n_leaf would be 0)
        let header_only: Vec<GoldilocksField> = vec![GoldilocksField::ZERO; 8];
        let result = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(
            &header_only,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("at least one leaf"),
            "Expected 'at least one leaf' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn aggregated_try_from_felts_accepts_valid_input() {
        // Valid input: 8 header + 21 (one leaf worth of data)
        let valid_slice: Vec<GoldilocksField> =
            vec![GoldilocksField::ZERO; 8 + PUBLIC_INPUTS_FELTS_LEN];
        let result = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(
            &valid_slice,
        );
        assert!(result.is_ok(), "Expected valid input to parse successfully");
        let parsed = result.unwrap();
        assert_eq!(parsed.account_data.len(), 2); // 2 outputs per leaf
        assert_eq!(parsed.nullifiers.len(), 1); // 1 nullifier per leaf
    }

    #[test]
    fn private_circuit_inputs_debug_redacts_secret() {
        let secret = BytesDigest::try_from([0xab; 32].as_slice()).unwrap();
        let inputs = PrivateCircuitInputs {
            secret,
            transfer_count: 1,
            unspendable_account: BytesDigest::default(),
            parent_hash: BytesDigest::default(),
            state_root: BytesDigest::default(),
            extrinsics_root: BytesDigest::default(),
            digest: [0u8; DIGEST_LOGS_SIZE],
            input_amount: 100,
            zk_tree_root: [0u8; 32],
            zk_merkle_siblings: vec![],
            zk_merkle_positions: vec![],
        };
        let dump = format!("{:?}", inputs);
        assert!(dump.contains("[REDACTED]"));
        assert!(!dump.contains("abababab"));
        assert!(!dump.contains("secret: BytesDigest"));
    }
}
