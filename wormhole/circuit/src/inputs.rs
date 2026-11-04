#![allow(clippy::new_without_default)]
use crate::block_header::header::DIGEST_LOGS_SIZE;
use crate::sensitive::Secret;
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
    EXIT_ACCOUNT_2_START_INDEX, INPUT_AMOUNT_INDEX, NULLIFIER_END_INDEX, NULLIFIER_START_INDEX,
    OUTPUT_AMOUNT_1_INDEX, OUTPUT_AMOUNT_2_INDEX, PUBLIC_INPUTS_FELTS_LEN, VOLUME_FEE_BPS_INDEX,
};

/// Inputs required to commit to the wormhole circuit.
///
/// Deliberately not `Clone`: `private.secret` is a zeroize-on-drop
/// [`Secret`], so the spend credential cannot be silently duplicated via
/// this container.
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
///
/// Deliberately not `Clone`: `secret` is a zeroize-on-drop [`Secret`], so
/// the spend credential cannot be silently duplicated via this container.
pub struct PrivateCircuitInputs {
    /// The secret of the nullifier and the unspendable account. Zeroized on
    /// drop; duplication requires an explicit [`Secret::expose_digest`] (or
    /// `expose_felts`) call at the use site.
    pub secret: Secret,
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

/// Redacting `Debug`: these are the *private* witness inputs, so anything that
/// could break deposit/withdrawal unlinkability (or worse, spend authority)
/// must not reach logs, error contexts, or telemetry via `{:?}`.
///
/// Redacted: `secret` (spend authority), `unspendable_account` (the deposit
/// account this proof spends — the direct deposit/withdrawal link),
/// `transfer_count` (deposit-identifying metadata), and the
/// merkle path material (`digest`, siblings, positions — identifies the leaf).
///
/// Kept visible: the block-header fields (`parent_hash`, `state_root`,
/// `extrinsics_root`, `zk_tree_root`) are public chain data fully determined
/// by the proof's public `block_hash`, and are useful when debugging header
/// hash mismatches.
impl core::fmt::Debug for PrivateCircuitInputs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateCircuitInputs")
            .field("secret", &"[REDACTED]")
            .field("transfer_count", &"[REDACTED]")
            .field("unspendable_account", &"[REDACTED]")
            .field("parent_hash", &self.parent_hash)
            .field("state_root", &self.state_root)
            .field("extrinsics_root", &self.extrinsics_root)
            .field("digest", &"[REDACTED]")
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
        // Public inputs are ordered as follows (total 22 felts):
        // asset_id: 1 felt
        // output_amount_1: 1 felt (spend)
        // output_amount_2: 1 felt (change)
        // volume_fee_bps: 1 felt
        // Nullifier.hash: 4 felts
        // ExitAccount1.address: 4 felts (8 bytes/felt for hash-derived accounts)
        // ExitAccount2.address: 4 felts (8 bytes/felt for hash-derived accounts)
        // BlockHeader.block_hash: 4 felts
        // BlockHeader.block_number: 1 felt
        // input_amount: 1 felt (intermediate only; not forwarded by aggregation)
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
        let input_amount = pis[INPUT_AMOUNT_INDEX]
            .to_canonical_u64()
            .try_into()
            .context("failed to convert input_amount felt to u32")?;

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
            input_amount,
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
        let u64s: Vec<u64> = pis.iter().map(|f| f.to_canonical_u64()).collect();
        PrivateBatchPublicInputs::try_from_u64_slice(&u64s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;

    fn parse(pis: &[GoldilocksField]) -> anyhow::Result<PrivateBatchPublicInputs> {
        <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(pis)
    }

    #[test]
    fn aggregated_try_from_felts_rejects_short_slices() {
        for len in [0, 5] {
            let err = parse(&vec![GoldilocksField::ZERO; len]).unwrap_err();
            assert!(err.to_string().contains("too few"), "got: {err}");
        }
    }

    #[test]
    fn aggregated_try_from_felts_rejects_malformed_length() {
        // M = 1 exit slot: 8 + 5 = 13 header+slot felts, then the nullifier
        // region must be a non-empty multiple of 4.
        for len in [13, 14, 19] {
            let mut pis = vec![GoldilocksField::ZERO; len];
            pis[0] = GoldilocksField::ONE;
            assert!(parse(&pis).is_err(), "length {len} must be rejected");
        }
    }

    #[test]
    fn aggregated_try_from_felts_accepts_valid_input() {
        // M = 2 exit slots, N = 1 leaf: 8 + 2*5 + 1*4 = 22 felts.
        let mut pis = vec![GoldilocksField::ZERO; 22];
        pis[0] = GoldilocksField::from_canonical_u64(2);
        let parsed = parse(&pis).expect("valid input must parse");
        assert_eq!(parsed.num_exit_slots, 2);
        assert_eq!(parsed.account_data.len(), 2);
        assert_eq!(parsed.nullifiers.len(), 1);
    }

    /// The exit-slot count at index 0 is a structural constant of the
    /// aggregation circuit and must be in `1..=MAX_PROOF_COUNT`.
    #[test]
    fn aggregated_try_from_felts_rejects_out_of_range_slot_count() {
        let mut pis = vec![GoldilocksField::ZERO; 22];
        assert!(parse(&pis).is_err(), "zero exit slots must be rejected");
        pis[0] = GoldilocksField::from_canonical_u64(65);
        assert!(parse(&pis).is_err(), "65 exit slots must be rejected");
    }

    #[test]
    fn private_circuit_inputs_debug_redacts_private_fields() {
        let secret = Secret::try_from([0xab; 32]).unwrap();
        let unspendable_account = BytesDigest::try_from([0xcd; 32].as_slice()).unwrap();
        let inputs = PrivateCircuitInputs {
            secret,
            transfer_count: 424_242,
            unspendable_account,
            parent_hash: BytesDigest::default(),
            state_root: BytesDigest::default(),
            extrinsics_root: BytesDigest::default(),
            digest: [0u8; DIGEST_LOGS_SIZE],
            zk_tree_root: [0u8; 32],
            zk_merkle_siblings: vec![],
            zk_merkle_positions: vec![],
        };
        let dump = format!("{:?}", inputs);
        assert!(dump.contains("[REDACTED]"));
        // Spend authority.
        assert!(!dump.contains("abababab"));
        assert!(!dump.contains("secret: BytesDigest"));
        // Deposit/withdrawal linkability: the deposit account and transfer
        // count are private witness data.
        assert!(!dump.contains("cdcdcdcd"));
        assert!(!dump.contains("424242"));
    }
}
