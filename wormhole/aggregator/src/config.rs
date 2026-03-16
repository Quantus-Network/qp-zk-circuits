use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs::write;
use std::path::Path;

/// Configuration stored alongside circuit binaries (config.json).
/// This struct is used by both circuit-builder (to save config) and
/// aggregator (to load config when aggregating proofs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBinsConfig {
    pub num_leaf_proofs: usize,
    pub num_layer0_proofs: Option<usize>,
}

impl CircuitBinsConfig {
    /// Create a new config
    pub fn new(num_leaf_proofs: usize, num_layer0_proofs: Option<usize>) -> Self {
        Self {
            num_leaf_proofs,
            num_layer0_proofs,
        }
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
}

#[cfg(test)]
mod tests {
    use super::CircuitBinsConfig;
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

        let config = CircuitBinsConfig::new(16, Some(4));
        config.save(&dir).unwrap();

        let loaded = CircuitBinsConfig::load(&dir).unwrap();
        assert_eq!(loaded.num_leaf_proofs, 16);
        assert_eq!(loaded.num_layer0_proofs, Some(4));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn config_without_layer1() {
        let dir = temp_dir("no-layer1");

        let config = CircuitBinsConfig::new(8, None);
        config.save(&dir).unwrap();

        let loaded = CircuitBinsConfig::load(&dir).unwrap();
        assert_eq!(loaded.num_leaf_proofs, 8);
        assert_eq!(loaded.num_layer0_proofs, None);

        fs::remove_dir_all(dir).unwrap();
    }
}
