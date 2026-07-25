use anyhow::{anyhow, Result};
pub use qp_wormhole_inputs::validate_proof_count;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Maximum number of proofs aggregated per layer.
///
/// Re-exported from `qp_wormhole_inputs` (the single source of truth) so every
/// build/parse entry point applies the same bound. Lowered from the previous
/// 1024 headroom to the documented practical per-layer limit (benches currently
/// exercise up to 49 proofs): accepting the old 1024 cap let a single valid
/// artifact-generation request drive circuit construction whose work scales
/// quadratically/multiplicatively with the count (audit #97021).
pub use qp_wormhole_inputs::MAX_PROOF_COUNT;

/// Configuration stored alongside circuit binaries (config.json).
/// This struct is used by both circuit-builder (to save config) and
/// aggregator (to load config when aggregating proofs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBinsConfig {
    pub num_leaf_proofs: usize,
    /// Number of private-batch proofs per public batch (None = private batch only).
    /// Accepts the legacy `num_layer0_proofs` key when loading older config.json files.
    #[serde(alias = "num_layer0_proofs")]
    pub num_private_batch_proofs: Option<usize>,
}

impl CircuitBinsConfig {
    /// Create a new config with validation.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `num_leaf_proofs` is 0 or exceeds `MAX_PROOF_COUNT`
    /// - `num_private_batch_proofs` is `Some(0)` or exceeds `MAX_PROOF_COUNT`
    pub fn new(num_leaf_proofs: usize, num_private_batch_proofs: Option<usize>) -> Result<Self> {
        let config = Self {
            num_leaf_proofs,
            num_private_batch_proofs,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the config values.
    ///
    /// # Errors
    /// Returns an error if proof counts are zero or exceed `MAX_PROOF_COUNT`.
    pub fn validate(&self) -> Result<()> {
        validate_proof_count(self.num_leaf_proofs, "num_leaf_proofs")?;
        if let Some(n) = self.num_private_batch_proofs {
            validate_proof_count(n, "num_private_batch_proofs")?;
        }
        Ok(())
    }

    /// Load config from a directory containing circuit binaries.
    ///
    /// Reads through [`crate::common::utils::read_artifact_file`], which
    /// rejects non-regular files and oversized inputs, so an untrusted bins
    /// directory cannot stall or memory-starve config loading (this runs
    /// before any of the `*.bin` artifacts are touched).
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, parsed, or contains invalid values.
    pub fn load<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let config_path = bins_dir.as_ref().join("config.json");
        let config_bytes = crate::common::utils::read_artifact_file(&config_path)?;
        let config_str = String::from_utf8(config_bytes)
            .map_err(|e| anyhow!("{} is not valid UTF-8: {}", config_path.display(), e))?;
        let config: Self = serde_json::from_str(&config_str)
            .map_err(|e| anyhow!("failed to parse {}: {}", config_path.display(), e))?;
        config.validate()?;
        Ok(config)
    }

    /// Save config to a directory.
    ///
    /// Published through [`crate::common::utils::commit_artifact_set`]
    /// (exclusive-create staging plus rename into place), so a symlink
    /// pre-planted at `config.json` is replaced rather than followed and a
    /// failed write never leaves a truncated config behind.
    pub fn save<P: AsRef<Path>>(&self, bins_dir: P) -> Result<()> {
        let bins_dir = bins_dir.as_ref();
        let config_str = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("failed to serialize config: {}", e))?;
        crate::common::utils::commit_artifact_set(
            bins_dir,
            &[("config.json", config_str.into_bytes())],
            &[],
        )?;
        println!("Config saved to {}", bins_dir.join("config.json").display());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CircuitBinsConfig, MAX_PROOF_COUNT};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("qp-wormhole-config-{name}-{suffix}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn config_round_trip() {
        let dir = temp_dir("round-trip");

        let config = CircuitBinsConfig::new(7, Some(4)).unwrap();
        config.save(&dir).unwrap();

        let loaded = CircuitBinsConfig::load(&dir).unwrap();
        assert_eq!(loaded.num_leaf_proofs, 7);
        assert_eq!(loaded.num_private_batch_proofs, Some(4));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn config_without_public_batch() {
        let dir = temp_dir("no-public_batch");

        let config = CircuitBinsConfig::new(8, None).unwrap();
        config.save(&dir).unwrap();

        let loaded = CircuitBinsConfig::load(&dir).unwrap();
        assert_eq!(loaded.num_leaf_proofs, 8);
        assert_eq!(loaded.num_private_batch_proofs, None);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn new_rejects_zero_num_leaf_proofs() {
        let err = CircuitBinsConfig::new(0, Some(4)).unwrap_err();
        assert!(err.to_string().contains("num_leaf_proofs must be > 0"));
    }

    #[test]
    fn new_rejects_zero_num_private_batch_proofs() {
        let err = CircuitBinsConfig::new(16, Some(0)).unwrap_err();
        assert!(err
            .to_string()
            .contains("num_private_batch_proofs must be > 0"));
    }

    #[test]
    fn new_rejects_excessive_num_leaf_proofs() {
        let err = CircuitBinsConfig::new(MAX_PROOF_COUNT + 1, None).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn new_rejects_excessive_num_private_batch_proofs() {
        let err = CircuitBinsConfig::new(16, Some(MAX_PROOF_COUNT + 1)).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn load_rejects_invalid_config() {
        let dir = temp_dir("invalid-config");
        // Write a config with zero num_leaf_proofs directly (bypassing new())
        let invalid_json = r#"{"num_leaf_proofs": 0, "num_private_batch_proofs": 4}"#;
        fs::write(dir.join("config.json"), invalid_json).unwrap();

        let err = CircuitBinsConfig::load(&dir).unwrap_err();
        assert!(err.to_string().contains("num_leaf_proofs must be > 0"));

        fs::remove_dir_all(dir).unwrap();
    }
}
