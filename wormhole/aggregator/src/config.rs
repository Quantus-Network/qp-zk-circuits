use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs::write;
use std::path::Path;

use zk_circuits_common::aggregation::AggregationConfig;

/// SHA256 hashes of the circuit binary files.
/// Used to detect mismatches between different copies of the binaries.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct BinaryHashes {
    /// Hash of common.bin (leaf circuit common data)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common: Option<String>,
    /// Hash of verifier.bin (leaf circuit verifier data)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    /// Hash of prover.bin (leaf circuit prover data)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover: Option<String>,
    /// Hash of aggregated_common.bin (aggregated circuit common data)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregated_common: Option<String>,
    /// Hash of aggregated_verifier.bin (aggregated circuit verifier data)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregated_verifier: Option<String>,
    /// Hash of dummy_proof.bin (pre-generated dummy proof for aggregation padding)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dummy_proof: Option<String>,
}

impl BinaryHashes {
    /// Compute SHA256 hash of a file and return as hex string
    pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<String> {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(path.as_ref())
            .map_err(|e| anyhow!("Failed to read {}: {}", path.as_ref().display(), e))?;
        let hash = Sha256::digest(&bytes);
        Ok(hex::encode(hash))
    }

    /// Compute hashes for all binary files in a directory
    pub fn from_directory<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let dir = bins_dir.as_ref();
        Ok(Self {
            common: Self::hash_file(dir.join("common.bin")).ok(),
            verifier: Self::hash_file(dir.join("verifier.bin")).ok(),
            prover: Self::hash_file(dir.join("prover.bin")).ok(),
            aggregated_common: Self::hash_file(dir.join("aggregated_common.bin")).ok(),
            aggregated_verifier: Self::hash_file(dir.join("aggregated_verifier.bin")).ok(),
            dummy_proof: Self::hash_file(dir.join("dummy_proof.bin")).ok(),
        })
    }
}

/// Configuration stored alongside circuit binaries (config.json).
/// This struct is used by both circuit-builder (to save config) and
/// aggregator (to load config when aggregating proofs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBinsConfig {
    pub num_leaf_proofs: usize,
    /// SHA256 hashes of the binary files for integrity verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<BinaryHashes>,
}

impl CircuitBinsConfig {
    /// Create a new config without hashes (hashes should be added via `with_hashes_from_directory`)
    pub fn new(num_leaf_proofs: usize) -> Self {
        Self {
            num_leaf_proofs,
            hashes: None,
        }
    }

    /// Add hashes computed from the binary files in a directory
    pub fn with_hashes_from_directory<P: AsRef<Path>>(mut self, bins_dir: P) -> Result<Self> {
        self.hashes = Some(BinaryHashes::from_directory(bins_dir)?);
        Ok(self)
    }

    /// Load config from a directory containing circuit binaries
    pub fn load<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let config_path = bins_dir.as_ref().join("config.json");
        let config_str = std::fs::read_to_string(&config_path)
            .map_err(|e| anyhow!("Failed to read {}: {}", config_path.display(), e))?;
        serde_json::from_str(&config_str)
            .map_err(|e| anyhow!("Failed to parse {}: {}", config_path.display(), e))
    }

    /// Save config to a directory
    pub fn save<P: AsRef<Path>>(&self, bins_dir: P) -> Result<()> {
        let config_path = bins_dir.as_ref().join("config.json");
        let config_str = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize config: {}", e))?;
        write(&config_path, config_str)
            .map_err(|e| anyhow!("Failed to write {}: {}", config_path.display(), e))?;
        println!("Config saved to {}", config_path.display());
        Ok(())
    }

    /// Verify that the binary files in a directory match the stored hashes.
    /// Returns Ok(()) if all present hashes match.
    /// Returns Err if any hash mismatches or if config has hashes but a binary file is missing.
    /// If no hashes are stored in config, verification is skipped.
    pub fn verify_hashes<P: AsRef<Path>>(&self, bins_dir: P) -> Result<()> {
        let Some(ref stored_hashes) = self.hashes else {
            return Ok(());
        };

        let current_hashes = BinaryHashes::from_directory(&bins_dir)?;

        let checks: &[(&str, &Option<String>, &Option<String>)] = &[
            ("common.bin", &stored_hashes.common, &current_hashes.common),
            (
                "verifier.bin",
                &stored_hashes.verifier,
                &current_hashes.verifier,
            ),
            ("prover.bin", &stored_hashes.prover, &current_hashes.prover),
            (
                "aggregated_common.bin",
                &stored_hashes.aggregated_common,
                &current_hashes.aggregated_common,
            ),
            (
                "aggregated_verifier.bin",
                &stored_hashes.aggregated_verifier,
                &current_hashes.aggregated_verifier,
            ),
            (
                "dummy_proof.bin",
                &stored_hashes.dummy_proof,
                &current_hashes.dummy_proof,
            ),
        ];

        let mut mismatches = Vec::new();
        for (filename, stored, current) in checks {
            match (stored, current) {
                (Some(s), Some(c)) if s != c => {
                    mismatches.push(format!(
                        "{}: expected {}..., got {}...",
                        filename,
                        &s[..s.len().min(16)],
                        &c[..c.len().min(16)]
                    ));
                }
                (Some(_), None) => {
                    mismatches.push(format!(
                        "{}: hash in config but file not found or unreadable",
                        filename
                    ));
                }
                _ => {} // Both match, or no stored hash for this file
            }
        }

        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "Binary hash verification failed:\n  {}\n\n\
                 This can happen if binaries were regenerated without updating config.json.\n\
                 Run the circuit builder to regenerate all binaries and config.",
                mismatches.join("\n  ")
            ))
        }
    }

    /// Convert to AggregationConfig
    pub fn to_aggregation_config(&self) -> AggregationConfig {
        AggregationConfig::new(self.num_leaf_proofs)
    }
}
