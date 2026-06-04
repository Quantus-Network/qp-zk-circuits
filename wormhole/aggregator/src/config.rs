use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::fs::write;
use std::path::Path;

/// Maximum allowed proof count to prevent excessive memory/CPU consumption.
/// This is a reasonable upper bound - aggregating more than 1024 proofs per layer
/// would result in impractically large circuits.
///
/// In practice, even ~64 proofs is near the practical limit on commodity hardware
/// (current benches test up to 49). The 1024 cap is "obviously safe" headroom.
/// Any future need to raise this limit would require a coordinated artifact
/// regeneration across all deployments.
pub const MAX_PROOF_COUNT: usize = 1024;

/// Configuration stored alongside circuit binaries (config.json).
/// This struct is used by both circuit-builder (to save config) and
/// aggregator (to load config when aggregating proofs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBinsConfig {
    pub num_leaf_proofs: usize,
    pub num_layer0_proofs: Option<usize>,
}

impl CircuitBinsConfig {
    /// Create a new config with validation.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `num_leaf_proofs` is 0 or exceeds `MAX_PROOF_COUNT`
    /// - `num_layer0_proofs` is `Some(0)` or exceeds `MAX_PROOF_COUNT`
    pub fn new(num_leaf_proofs: usize, num_layer0_proofs: Option<usize>) -> Result<Self> {
        let config = Self {
            num_leaf_proofs,
            num_layer0_proofs,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the config values.
    ///
    /// # Errors
    /// Returns an error if proof counts are zero or exceed reasonable bounds.
    pub fn validate(&self) -> Result<()> {
        if self.num_leaf_proofs == 0 {
            bail!("num_leaf_proofs must be > 0");
        }
        if self.num_leaf_proofs > MAX_PROOF_COUNT {
            bail!(
                "num_leaf_proofs ({}) exceeds maximum allowed ({})",
                self.num_leaf_proofs,
                MAX_PROOF_COUNT
            );
        }
        if let Some(n) = self.num_layer0_proofs {
            if n == 0 {
                bail!("num_layer0_proofs must be > 0 when specified");
            }
            if n > MAX_PROOF_COUNT {
                bail!(
                    "num_layer0_proofs ({}) exceeds maximum allowed ({})",
                    n,
                    MAX_PROOF_COUNT
                );
            }
        }
        Ok(())
    }

    /// Load config from a directory containing circuit binaries.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, parsed, or contains invalid values.
    pub fn load<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let config_path = bins_dir.as_ref().join("config.json");
        let config_str = std::fs::read_to_string(&config_path)
            .map_err(|e| anyhow!("failed to read {}: {}", config_path.display(), e))?;
        let config: Self = serde_json::from_str(&config_str)
            .map_err(|e| anyhow!("failed to parse {}: {}", config_path.display(), e))?;
        config.validate()?;
        Ok(config)
    }

    /// Save config to a directory
    pub fn save<P: AsRef<Path>>(&self, bins_dir: P) -> Result<()> {
        let config_path = bins_dir.as_ref().join("config.json");
        let config_str = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("failed to serialize config: {}", e))?;
        write(&config_path, config_str)
            .map_err(|e| anyhow!("failed to write {}: {}", config_path.display(), e))?;
        println!("Config saved to {}", config_path.display());
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

        let config = CircuitBinsConfig::new(7, Some(4));
        config.save(&dir).unwrap();

        let loaded = CircuitBinsConfig::load(&dir).unwrap();
        assert_eq!(loaded.num_leaf_proofs, 7);
        assert_eq!(loaded.num_layer0_proofs, Some(4));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn config_without_layer1() {
        let dir = temp_dir("no-layer1");

        let config = CircuitBinsConfig::new(8, None).unwrap();
        config.save(&dir).unwrap();

        let loaded = CircuitBinsConfig::load(&dir).unwrap();
        assert_eq!(loaded.num_leaf_proofs, 8);
        assert_eq!(loaded.num_layer0_proofs, None);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn new_rejects_zero_num_leaf_proofs() {
        let err = CircuitBinsConfig::new(0, Some(4)).unwrap_err();
        assert!(err.to_string().contains("num_leaf_proofs must be > 0"));
    }

    #[test]
    fn new_rejects_zero_num_layer0_proofs() {
        let err = CircuitBinsConfig::new(16, Some(0)).unwrap_err();
        assert!(err.to_string().contains("num_layer0_proofs must be > 0"));
    }

    #[test]
    fn new_rejects_excessive_num_leaf_proofs() {
        let err = CircuitBinsConfig::new(MAX_PROOF_COUNT + 1, None).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn new_rejects_excessive_num_layer0_proofs() {
        let err = CircuitBinsConfig::new(16, Some(MAX_PROOF_COUNT + 1)).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn load_rejects_invalid_config() {
        let dir = temp_dir("invalid-config");
        // Write a config with zero num_leaf_proofs directly (bypassing new())
        let invalid_json = r#"{"num_leaf_proofs": 0, "num_layer0_proofs": 4}"#;
        fs::write(dir.join("config.json"), invalid_json).unwrap();

        let err = CircuitBinsConfig::load(&dir).unwrap_err();
        assert!(err.to_string().contains("num_leaf_proofs must be > 0"));

        fs::remove_dir_all(dir).unwrap();
    }
}
