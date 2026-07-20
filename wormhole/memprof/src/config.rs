//! Build a customizable aggregator `CircuitConfig` from CLI overrides.
//!
//! The starting point is always `wormhole_private_batch_circuit_config()` (the
//! production config). Each flag, when set, overrides the corresponding
//! field on top of that baseline. Unset flags leave the production value
//! untouched, so a profiler run with no agg-config flags is identical to
//! production.
//!
//! Knobs are split into two groups:
//!
//! - **Memory/time tradeoffs that PRESERVE security.** Use freely.
//! - **Security-affecting knobs.** Hidden behind `--allow-weakening-security`.
//!   Anything that lowers proven-soundness or removes ZK falls in this bucket.
//!
//! Where a knob has both a memory/time dimension AND a soundness dimension,
//! we expose the memory side (via `--rate-bits`) and auto-rebalance the other
//! parameter (`num_query_rounds`) so that the conjectured FRI soundness
//! product stays constant. This lets you trade prover memory for proving time
//! and proof size *without* weakening security.

use clap::{ArgGroup, Args, ValueEnum};
use plonky2::plonk::circuit_data::CircuitConfig;
use zk_circuits_common::circuit::{
    wormhole_leaf_circuit_config, wormhole_private_batch_circuit_config,
};

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum ZkMode {
    /// `RowBlinding` blinding strategy (production default).
    Rowblinding,
    /// No ZK (leaks witness). REQUIRES `--allow-weakening-security`.
    Disabled,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("agg_cfg")
        .multiple(true)
        .args([
            "zk_mode",
            "rate_bits",
            "cap_height",
            "num_wires",
            "num_routed_wires",
            "max_quotient_degree_factor",
            "num_query_rounds",
            "security_bits",
            "num_challenges",
        ])
))]
pub struct AggConfigArgs {
    // ---------- Safe knobs (no security weakening) ----------
    /// Zero-knowledge mode for the aggregation circuit. `rowblinding`
    /// (production default) is fully ZK; `disabled` is NOT ZK and requires
    /// `--allow-weakening-security`. When unset, the production zk mode is used.
    #[arg(long, value_enum)]
    pub zk_mode: Option<ZkMode>,

    /// FRI blowup factor exponent (`blowup = 2^rate_bits`). Lower = less
    /// prover memory, larger proofs, slower verifier. The companion
    /// `num_query_rounds` is automatically adjusted to preserve the original
    /// FRI soundness product (~rate_bits * queries). Production: 3.
    #[arg(long)]
    pub rate_bits: Option<usize>,

    /// FRI Merkle cap height. Affects proof size only, not security or
    /// prover memory. Production: 4.
    #[arg(long)]
    pub cap_height: Option<usize>,

    /// Number of plonk wires (trace columns). Reducing this forces the
    /// circuit to use more rows for the same logic but does not affect
    /// soundness. Must be >= 135 (Poseidon gate floor). Production: 135.
    #[arg(long)]
    pub num_wires: Option<usize>,

    /// Number of routed wires. Must be <= num_wires (routed wires are a
    /// prefix of the wire columns). Production: 60.
    #[arg(long)]
    pub num_routed_wires: Option<usize>,

    /// Max quotient polynomial degree factor. Reducing constrains the kinds
    /// of constraints the circuit can express. Must be >= 7 (Poseidon
    /// constraint degree). Production: 8.
    #[arg(long)]
    pub max_quotient_degree_factor: Option<usize>,

    // ---------- Security-affecting knobs (gated by --allow-weakening-security) ----------
    /// Override FRI query rounds directly. WEAKENS soundness if used to
    /// lower the rate_bits * queries product. By default this is auto-derived
    /// from --rate-bits. Requires `--allow-weakening-security`.
    #[arg(long)]
    pub num_query_rounds: Option<usize>,

    /// Target security bits. Lowering this WEAKENS soundness/ZK security.
    /// Requires `--allow-weakening-security`. Production: 100.
    #[arg(long)]
    pub security_bits: Option<usize>,

    /// Number of challenge points. Lowering WEAKENS soundness. Requires
    /// `--allow-weakening-security`. Production: 2.
    #[arg(long)]
    pub num_challenges: Option<usize>,

    /// Acknowledge that flags in the security-affecting group will weaken
    /// security. Required to use `--num-query-rounds`, `--security-bits`,
    /// `--num-challenges`, or `--zk-mode disabled`.
    #[arg(long, default_value_t = false)]
    pub allow_weakening_security: bool,
}

/// The Poseidon gate needs 135 wire columns; a smaller `num_wires` panics
/// deep inside plonky2's `check_gate_compatibility` mid-build instead of
/// failing at the CLI boundary.
const MIN_NUM_WIRES: usize = 135;

/// Poseidon constraints have degree 7; a smaller quotient degree factor
/// cannot express them and fails during circuit construction.
const MIN_MAX_QUOTIENT_DEGREE_FACTOR: usize = 7;

impl AggConfigArgs {
    /// Validate the override knobs:
    ///   1. Numeric knobs must be > 0 (zero would silently break the
    ///      FRI soundness product or trip a panic deep inside plonky2).
    ///   2. Structural circuit floors documented on the flags
    ///      (`num_wires >= 135`, `max_quotient_degree_factor >= 7`,
    ///      `num_routed_wires <= num_wires`) are enforced here so bad
    ///      sweeps fail at the CLI boundary instead of panicking after the
    ///      leaf context is already built.
    ///   3. Security-affecting knobs must be gated by
    ///      `--allow-weakening-security`.
    pub fn validate(&self) -> Result<(), String> {
        for (name, v) in [
            ("--rate-bits", self.rate_bits),
            ("--cap-height", self.cap_height),
            ("--num-wires", self.num_wires),
            ("--num-routed-wires", self.num_routed_wires),
            (
                "--max-quotient-degree-factor",
                self.max_quotient_degree_factor,
            ),
            ("--num-query-rounds", self.num_query_rounds),
            ("--security-bits", self.security_bits),
            ("--num-challenges", self.num_challenges),
        ] {
            if v == Some(0) {
                return Err(format!("{name} must be greater than 0"));
            }
        }

        if let Some(v) = self.num_wires {
            if v < MIN_NUM_WIRES {
                return Err(format!(
                    "--num-wires must be >= {MIN_NUM_WIRES} (Poseidon gate floor), got {v}"
                ));
            }
        }
        if let Some(v) = self.max_quotient_degree_factor {
            if v < MIN_MAX_QUOTIENT_DEGREE_FACTOR {
                return Err(format!(
                    "--max-quotient-degree-factor must be >= {MIN_MAX_QUOTIENT_DEGREE_FACTOR} \
                     (Poseidon constraint degree), got {v}"
                ));
            }
        }
        if let Some(routed) = self.num_routed_wires {
            let effective_num_wires = self
                .num_wires
                .unwrap_or_else(|| wormhole_private_batch_circuit_config().num_wires);
            if routed > effective_num_wires {
                return Err(format!(
                    "--num-routed-wires ({routed}) must be <= num_wires ({effective_num_wires}); \
                     routed wires are a subset of the wire columns"
                ));
            }
        }

        let mut violations: Vec<&'static str> = Vec::new();
        if matches!(self.zk_mode, Some(ZkMode::Disabled)) {
            violations.push("--zk-mode disabled");
        }
        if self.num_query_rounds.is_some() {
            violations.push("--num-query-rounds");
        }
        if self.security_bits.is_some() {
            violations.push("--security-bits");
        }
        if self.num_challenges.is_some() {
            violations.push("--num-challenges");
        }
        if !violations.is_empty() && !self.allow_weakening_security {
            return Err(format!(
                "the following flags can weaken security: {}\n\
                 pass --allow-weakening-security to acknowledge and proceed",
                violations.join(", ")
            ));
        }
        Ok(())
    }

    pub fn build(&self) -> CircuitConfig {
        let mut cfg = wormhole_private_batch_circuit_config();

        if let Some(mode) = self.zk_mode {
            cfg.zero_knowledge = match mode {
                ZkMode::Rowblinding => true,
                ZkMode::Disabled => false,
            };
        }

        let original_rate = cfg.fri_config.rate_bits;
        let original_queries = cfg.fri_config.num_query_rounds;
        let original_product = original_rate * original_queries;

        if let Some(v) = self.rate_bits {
            cfg.fri_config.rate_bits = v;
            // Preserve `rate_bits * num_query_rounds` product for FRI soundness.
            // Round up to the next integer so we never go below the original.
            let new_queries = original_product.div_ceil(v.max(1));
            cfg.fri_config.num_query_rounds = new_queries;
            eprintln!(
                "[config] rate_bits {} -> {}, auto-adjusted num_query_rounds {} -> {} \
                 (preserving FRI soundness product {})",
                original_rate, v, original_queries, new_queries, original_product
            );
        }

        if let Some(v) = self.cap_height {
            cfg.fri_config.cap_height = v;
        }
        if let Some(v) = self.num_wires {
            cfg.num_wires = v;
        }
        if let Some(v) = self.num_routed_wires {
            cfg.num_routed_wires = v;
        }
        if let Some(v) = self.max_quotient_degree_factor {
            cfg.max_quotient_degree_factor = v;
        }
        if let Some(v) = self.num_query_rounds {
            cfg.fri_config.num_query_rounds = v;
        }
        if let Some(v) = self.security_bits {
            cfg.security_bits = v;
        }
        if let Some(v) = self.num_challenges {
            cfg.num_challenges = v;
        }
        cfg
    }

    pub fn is_default(&self) -> bool {
        self.zk_mode.is_none()
            && self.rate_bits.is_none()
            && self.cap_height.is_none()
            && self.num_wires.is_none()
            && self.num_routed_wires.is_none()
            && self.max_quotient_degree_factor.is_none()
            && self.num_query_rounds.is_none()
            && self.security_bits.is_none()
            && self.num_challenges.is_none()
    }
}

pub fn default_agg_config() -> CircuitConfig {
    wormhole_private_batch_circuit_config()
}

/// Production leaf config — `wormhole_leaf_circuit_config()` verbatim.
/// This is what the chain's leaf prover/verifier uses and is the default
/// for memprof runs.
pub fn default_leaf_config() -> CircuitConfig {
    wormhole_leaf_circuit_config()
}

pub fn print_config_summary(label: &str, cfg: &CircuitConfig) {
    let zk = if cfg.zero_knowledge {
        "Enabled"
    } else {
        "Disabled"
    };
    eprintln!(
        "[config] {}: zk={} num_wires={} num_routed_wires={} \
         max_quotient_degree_factor={} security_bits={} num_challenges={} \
         fri.rate_bits={} fri.cap_height={} fri.num_query_rounds={} \
         fri.product={}",
        label,
        zk,
        cfg.num_wires,
        cfg.num_routed_wires,
        cfg.max_quotient_degree_factor,
        cfg.security_bits,
        cfg.num_challenges,
        cfg.fri_config.rate_bits,
        cfg.fri_config.cap_height,
        cfg.fri_config.num_query_rounds,
        cfg.fri_config.rate_bits * cfg.fri_config.num_query_rounds,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with(f: impl FnOnce(&mut AggConfigArgs)) -> AggConfigArgs {
        let mut args = AggConfigArgs {
            zk_mode: None,
            rate_bits: None,
            cap_height: None,
            num_wires: None,
            num_routed_wires: None,
            max_quotient_degree_factor: None,
            num_query_rounds: None,
            security_bits: None,
            num_challenges: None,
            allow_weakening_security: false,
        };
        f(&mut args);
        args
    }

    #[test]
    fn num_wires_below_poseidon_floor_is_rejected() {
        let err = args_with(|a| a.num_wires = Some(1)).validate().unwrap_err();
        assert!(err.contains("Poseidon gate floor"), "got: {err}");
        let err = args_with(|a| a.num_wires = Some(134))
            .validate()
            .unwrap_err();
        assert!(err.contains(">= 135"), "got: {err}");
    }

    #[test]
    fn quotient_degree_below_poseidon_constraint_degree_is_rejected() {
        let err = args_with(|a| a.max_quotient_degree_factor = Some(6))
            .validate()
            .unwrap_err();
        assert!(err.contains(">= 7"), "got: {err}");
    }

    #[test]
    fn routed_wires_exceeding_num_wires_is_rejected() {
        // Against the explicit --num-wires override.
        let err = args_with(|a| {
            a.num_wires = Some(135);
            a.num_routed_wires = Some(136);
        })
        .validate()
        .unwrap_err();
        assert!(err.contains("must be <= num_wires"), "got: {err}");

        // Against the production baseline when --num-wires is unset.
        let baseline = wormhole_private_batch_circuit_config().num_wires;
        let err = args_with(|a| a.num_routed_wires = Some(baseline + 1))
            .validate()
            .unwrap_err();
        assert!(err.contains("must be <= num_wires"), "got: {err}");
    }

    #[test]
    fn production_and_swept_values_are_accepted() {
        // Production config, no overrides.
        args_with(|_| {}).validate().unwrap();
        // Values the sweep scripts actually use.
        args_with(|a| {
            a.num_wires = Some(135);
            a.num_routed_wires = Some(54);
            a.max_quotient_degree_factor = Some(7);
        })
        .validate()
        .unwrap();
    }

    #[test]
    fn zero_knobs_are_still_rejected() {
        let err = args_with(|a| a.rate_bits = Some(0)).validate().unwrap_err();
        assert!(err.contains("greater than 0"), "got: {err}");
    }
}
