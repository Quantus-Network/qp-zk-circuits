//! Build a customizable aggregator `CircuitConfig` from CLI overrides.
//!
//! The starting point is always `wormhole_aggregator_circuit_config()` (the
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
use zk_circuits_common::circuit::{wormhole_aggregator_circuit_config, wormhole_leaf_circuit_config};

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum ZkMode {
    /// `PolyFri` masked commitments. Higher memory than RowBlinding.
    Polyfri,
    /// `RowBlinding` legacy blinding strategy (production default).
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
    /// (production default) and `polyfri` are both fully ZK; `disabled` is
    /// NOT ZK and requires `--allow-weakening-security`. When unset, the
    /// production zk mode is used.
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

    /// Number of routed wires. Production: 60.
    #[arg(long)]
    pub num_routed_wires: Option<usize>,

    /// Max quotient polynomial degree factor. Reducing constrains the kinds
    /// of constraints the circuit can express. Production: 8.
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

impl AggConfigArgs {
    /// Validate the override knobs:
    ///   1. Numeric knobs must be > 0 (zero would silently break the
    ///      FRI soundness product or trip a panic deep inside plonky2).
    ///   2. Security-affecting knobs must be gated by
    ///      `--allow-weakening-security`.
    pub fn validate(&self) -> Result<(), String> {
        for (name, v) in [
            ("--rate-bits", self.rate_bits),
            ("--cap-height", self.cap_height),
            ("--num-wires", self.num_wires),
            ("--num-routed-wires", self.num_routed_wires),
            ("--max-quotient-degree-factor", self.max_quotient_degree_factor),
            ("--num-query-rounds", self.num_query_rounds),
            ("--security-bits", self.security_bits),
            ("--num-challenges", self.num_challenges),
        ] {
            if v == Some(0) {
                return Err(format!("{name} must be greater than 0"));
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
        let mut cfg = wormhole_aggregator_circuit_config();

        if let Some(mode) = self.zk_mode {
            let template = match mode {
                ZkMode::Polyfri => CircuitConfig::standard_recursion_polyfri_zk_config(),
                ZkMode::Rowblinding => CircuitConfig::standard_recursion_zk_config(),
                ZkMode::Disabled => CircuitConfig::standard_recursion_config(),
            };
            cfg.zk_config = template.zk_config;
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
    wormhole_aggregator_circuit_config()
}

/// Production leaf config — `wormhole_leaf_circuit_config()` verbatim.
/// This is what the chain's leaf prover/verifier uses and is the default
/// for memprof runs.
pub fn default_leaf_config() -> CircuitConfig {
    wormhole_leaf_circuit_config()
}

pub fn print_config_summary(label: &str, cfg: &CircuitConfig) {
    let zk = if cfg.uses_poly_fri_zk() {
        "PolyFri"
    } else if cfg.uses_row_blinding_zk() {
        "RowBlinding"
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
