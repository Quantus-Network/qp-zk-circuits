use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs::write;
use std::path::Path;

use crate::circuits::tree::TreeAggregationConfig;

/// Configuration stored alongside circuit binaries (config.json).
/// This struct is used by both circuit-builder (to save config) and
/// aggregator (to load config when aggregating proofs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBinsConfig {
    pub branching_factor: usize,
    pub depth: u32,
    pub num_leaf_proofs: usize,
}

impl CircuitBinsConfig {
    pub fn new(branching_factor: usize, depth: u32) -> Self {
        Self {
            branching_factor,
            depth,
            num_leaf_proofs: branching_factor.pow(depth),
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

    /// Convert to TreeAggregationConfig
    pub fn to_aggregation_config(&self) -> TreeAggregationConfig {
        TreeAggregationConfig::new(self.branching_factor, self.depth)
    }
}
