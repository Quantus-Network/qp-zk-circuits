//! Verifier logic for the wormhole-address ownership circuit.
//!
//! Typical usage:
//! 1. Load pre-built artifacts via [`OwnershipVerifier::new_from_bytes`].
//! 2. Deserialize a [`ProofWithPublicInputs`].
//! 3. [`OwnershipVerifier::verify`].

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use anyhow::anyhow;
#[cfg(feature = "std")]
use std::path::Path;

pub use qp_plonky2_verifier::{
    CircuitConfig, CommonCircuitData, ProofWithPublicInputs, VerifierCircuitData,
    VerifierOnlyCircuitData, C, D, F,
};

use qp_plonky2_verifier::field::types::PrimeField64;
use qp_plonky2_verifier::util::serialization::DefaultGateSerializer;
use tiny_keccak::{Hasher, Keccak};

pub use qp_ownership_inputs::{
    private_batch_config, BytesDigest, PublicCircuitInputs, MIN_OWNERSHIP_SECURITY_BITS,
    PUBLIC_INPUTS_FELTS_LEN,
};

/// Parse public inputs from a proof.
pub fn parse_public_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> anyhow::Result<PublicCircuitInputs> {
    let u64s: Vec<u64> = proof
        .public_inputs
        .iter()
        .map(|f| f.to_canonical_u64())
        .collect();
    PublicCircuitInputs::try_from_u64_slice(&u64s)
}

/// Verifier for ownership-circuit proofs.
#[derive(Debug)]
pub struct OwnershipVerifier {
    pub circuit_data: VerifierCircuitData<F, C, D>,
}

// Keccak-256 commitments to the byte-exact canonical artifacts produced by
// `OwnershipCircuit::new(ownership_circuit_config())`. Integration tests
// rebuild the circuit and fail if a deliberate circuit change requires these
// commitments to be updated.
const CANONICAL_VERIFIER_KECCAK256: [u8; 32] = [
    0xcf, 0x51, 0x6c, 0x82, 0x55, 0xb1, 0x2a, 0x4d, 0xfe, 0xfa, 0x47, 0x69, 0xe5, 0xce, 0x91, 0xe6,
    0xf8, 0x4c, 0x7e, 0x2c, 0x31, 0xe2, 0xa0, 0xa5, 0x5d, 0x7a, 0x45, 0xa8, 0xd4, 0xe6, 0xd6, 0x04,
];
const CANONICAL_COMMON_KECCAK256: [u8; 32] = [
    0x21, 0x05, 0x96, 0x57, 0x44, 0x35, 0x6e, 0x50, 0xcb, 0x6b, 0x57, 0x67, 0x9a, 0xce, 0xcc, 0xb5,
    0x41, 0x2f, 0xc8, 0x3a, 0x5a, 0x82, 0xca, 0xd1, 0xa5, 0x9e, 0xb8, 0x9e, 0x2a, 0x0c, 0x73, 0x6f,
];

/// Maximum size accepted for a serialized verifier artifact.
///
/// The keccak256 pin rejects everything but the byte-exact canonical
/// artifacts; this cap bounds work done before the pin can fire.
pub const MAX_VERIFIER_ARTIFACT_BYTES: u64 = 1024 * 1024;

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

/// Read a verifier-artifact file, refusing anything larger than
/// [`MAX_VERIFIER_ARTIFACT_BYTES`] before allocating for its contents.
#[cfg(feature = "std")]
fn read_artifact_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context as _;

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat artifact file {}", path.display()))?;
    let claimed_len = metadata.len();
    if claimed_len > MAX_VERIFIER_ARTIFACT_BYTES {
        return Err(anyhow!(
            "artifact file {} is {} bytes, which exceeds the {} byte limit for \
             verifier artifacts; refusing to load it",
            path.display(),
            claimed_len,
            MAX_VERIFIER_ARTIFACT_BYTES
        ));
    }
    std::fs::read(path).with_context(|| format!("failed to read artifact file {}", path.display()))
}

impl OwnershipVerifier {
    /// Creates a new [`OwnershipVerifier`] from verifier and common data bytes.
    ///
    /// Inputs larger than [`MAX_VERIFIER_ARTIFACT_BYTES`] are rejected before
    /// any hashing. Within that bound, both serialized inputs must match the
    /// byte-exact canonical ownership-circuit artifacts (keccak256 pin).
    pub fn new_from_bytes(verifier_bytes: &[u8], common_bytes: &[u8]) -> anyhow::Result<Self> {
        for (label, bytes) in [("verifier-only", verifier_bytes), ("common", common_bytes)] {
            if bytes.len() as u64 > MAX_VERIFIER_ARTIFACT_BYTES {
                return Err(anyhow!(
                    "{} artifact is {} bytes, which exceeds the {} byte limit for \
                     verifier artifacts; refusing to load it",
                    label,
                    bytes.len(),
                    MAX_VERIFIER_ARTIFACT_BYTES
                ));
            }
        }

        let verifier_hash = keccak256(verifier_bytes);
        if verifier_hash != CANONICAL_VERIFIER_KECCAK256 {
            return Err(anyhow!(
                "loaded verifier-only artifact does not match the canonical ownership circuit (keccak256={:02x?})",
                verifier_hash
            ));
        }

        let common_hash = keccak256(common_bytes);
        if common_hash != CANONICAL_COMMON_KECCAK256 {
            return Err(anyhow!(
                "loaded common artifact does not match the canonical ownership circuit (keccak256={:02x?})",
                common_hash
            ));
        }

        let verifier_only = VerifierOnlyCircuitData::from_bytes(verifier_bytes.to_vec())
            .map_err(|e| anyhow!("failed to deserialize verifier data: {}", e))?;

        let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &DefaultGateSerializer)
            .map_err(|e| anyhow!("failed to deserialize common circuit data: {}", e))?;

        Self::ensure_loaded_matches_canonical_profile(&common)?;

        Ok(Self {
            circuit_data: VerifierCircuitData {
                verifier_only,
                common,
            },
        })
    }

    /// The canonical ownership config, mirroring
    /// `zk_circuits_common::circuit::ownership_circuit_config()` from the shared
    /// [`private_batch_config`] parameters. The keccak pins above catch any drift.
    pub fn canonical_circuit_config() -> CircuitConfig {
        let mut config = CircuitConfig::standard_recursion_zk_config();
        config.num_wires = private_batch_config::NUM_WIRES;
        config.num_routed_wires = private_batch_config::NUM_ROUTED_WIRES;
        config.security_bits = private_batch_config::SECURITY_BITS;
        config.num_challenges = private_batch_config::NUM_CHALLENGES;
        config.fri_config.rate_bits = private_batch_config::FRI_RATE_BITS;
        config.fri_config.cap_height = private_batch_config::FRI_CAP_HEIGHT;
        config.fri_config.proof_of_work_bits = private_batch_config::FRI_PROOF_OF_WORK_BITS;
        config.fri_config.num_query_rounds = private_batch_config::FRI_NUM_QUERY_ROUNDS;
        config
    }

    fn ensure_loaded_matches_canonical_profile(
        common: &CommonCircuitData<F, D>,
    ) -> anyhow::Result<()> {
        let expected = Self::canonical_circuit_config();

        if expected.security_bits < MIN_OWNERSHIP_SECURITY_BITS {
            return Err(anyhow!(
                "canonical recursion config provides only {} security bits, below the required minimum of {}",
                expected.security_bits,
                MIN_OWNERSHIP_SECURITY_BITS
            ));
        }

        if common.config != expected {
            return Err(anyhow!(
                "loaded verifier circuit config does not match the canonical ownership config \
                 (security_bits loaded={}, expected={})",
                common.config.security_bits,
                expected.security_bits
            ));
        }

        if common.num_public_inputs != PUBLIC_INPUTS_FELTS_LEN {
            return Err(anyhow!(
                "loaded verifier common data has {} public inputs, expected {} for the canonical ownership circuit",
                common.num_public_inputs,
                PUBLIC_INPUTS_FELTS_LEN
            ));
        }

        Ok(())
    }

    /// Creates a new [`OwnershipVerifier`] from verifier and common data files.
    #[cfg(feature = "std")]
    pub fn new_from_files(
        verifier_data_path: &Path,
        common_data_path: &Path,
    ) -> anyhow::Result<Self> {
        let verifier_bytes = read_artifact_file(verifier_data_path)?;
        let common_bytes = read_artifact_file(common_data_path)?;

        Self::new_from_bytes(&verifier_bytes, &common_bytes)
    }

    /// Verify a [`ProofWithPublicInputs`].
    pub fn verify_ref(&self, proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        self.circuit_data
            .verify(proof.clone())
            .map_err(|e| anyhow!("proof verification failed: {}", e))
    }

    /// Verify a [`ProofWithPublicInputs`].
    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        self.verify_ref(&proof)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qp-ownership-verifier-artifact-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn new_from_bytes_rejects_oversized_slices_before_hashing() {
        let oversized = vec![0u8; MAX_VERIFIER_ARTIFACT_BYTES as usize + 1];

        let err = OwnershipVerifier::new_from_bytes(&oversized, b"irrelevant").unwrap_err();
        assert!(
            format!("{err:#}").contains("exceeds the"),
            "oversized verifier bytes must be rejected by the size cap, got: {err:#}"
        );

        let err = OwnershipVerifier::new_from_bytes(b"irrelevant", &oversized).unwrap_err();
        assert!(
            format!("{err:#}").contains("exceeds the"),
            "oversized common bytes must be rejected by the size cap, got: {err:#}"
        );
    }

    #[test]
    fn new_from_files_rejects_oversized_artifact_before_reading() {
        let dir = temp_dir("oversized");

        let verifier_path = dir.join("verifier.bin");
        let common_path = dir.join("common.bin");
        std::fs::File::create(&verifier_path)
            .unwrap()
            .set_len(MAX_VERIFIER_ARTIFACT_BYTES + 1)
            .unwrap();
        std::fs::write(&common_path, b"irrelevant").unwrap();

        let err = OwnershipVerifier::new_from_files(&verifier_path, &common_path).unwrap_err();
        assert!(
            format!("{err:#}").contains("exceeds the"),
            "oversized artifact must be rejected by the size cap, got: {err:#}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
