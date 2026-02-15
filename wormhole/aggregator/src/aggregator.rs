use std::collections::BTreeMap;

use anyhow::{bail, Context};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::{
    AggregatedPublicCircuitInputs, BlockData, PublicCircuitInputs, PublicInputsByAccount,
};
use rand::seq::SliceRandom;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use wormhole_circuit::inputs::ParsePublicInputs;
use wormhole_prover::fill_witness;
use zk_circuits_common::{
    circuit::{C, D, F},
    utils::BytesDigest,
};

use crate::build_dummy_circuit_inputs;
use crate::{
    circuits::tree::{aggregate_to_tree, AggregatedProof, TreeAggregationConfig},
    dummy_proof::load_dummy_proof,
};

// Block hash offset in leaf proof public inputs (4 felts starting at index 16)
const BLOCK_HASH_PI_START: usize = 16;
const BLOCK_HASH_PI_END: usize = 20;

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator {
    pub leaf_circuit_data: VerifierCircuitData<F, C, D>,
    pub config: TreeAggregationConfig,
    pub proofs_buffer: Option<Vec<ProofWithPublicInputs<F, C, D>>>,
    /// Pre-generated dummy proofs compatible with this aggregator's circuit.
    /// Each dummy has a unique nullifier to avoid duplicate nullifier errors on-chain.
    /// Used for padding when fewer proofs are provided than required.
    dummy_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
}

impl WormholeProofAggregator {
    /// Creates a new [`WormholeProofAggregator`] with a given [`VerifierCircuitData`],
    /// pre-generated dummy proofs, and explicit aggregation config.
    ///
    /// The dummy proofs must be compatible with the verifier data (generated from the same circuit).
    /// Each dummy proof should have a unique nullifier to avoid on-chain duplicate errors.
    pub fn new(
        verifier_circuit_data: VerifierCircuitData<F, C, D>,
        dummy_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
        config: TreeAggregationConfig,
    ) -> Self {
        let proofs_buffer = Some(Vec::with_capacity(config.num_leaf_proofs));

        Self {
            leaf_circuit_data: verifier_circuit_data,
            config,
            proofs_buffer,
            dummy_proofs,
        }
    }

    /// Creates a new [`WormholeProofAggregator`] from a directory containing pre-built circuit files.
    ///
    /// Reads the aggregation config from `config.json` in the directory.
    /// Expects the directory to contain: prover.bin, common.bin, verifier.bin, config.json
    ///
    /// # Arguments
    /// * `bins_dir` - Directory containing the circuit files
    /// * `num_real_proofs` - Number of real proofs that will be provided (used to generate only needed dummy proofs)
    pub fn from_prebuilt_dir(
        bins_dir: &std::path::Path,
        num_real_proofs: usize,
    ) -> anyhow::Result<Self> {
        use crate::config::CircuitBinsConfig;

        let config = CircuitBinsConfig::load(bins_dir)?;
        let aggregation_config = config.to_aggregation_config();

        Self::from_prebuilt_with_paths(
            &bins_dir.join("common.bin"),
            &bins_dir.join("verifier.bin"),
            aggregation_config,
            num_real_proofs,
        )
    }

    /// Creates a new [`WormholeProofAggregator`] from pre-built circuit files at custom paths.
    ///
    /// Requires explicit aggregation config (branching_factor, depth).
    ///
    /// # Arguments
    /// * `prover_path` - Path to prover.bin
    /// * `common_path` - Path to common.bin
    /// * `verifier_path` - Path to verifier.bin
    /// * `config` - Aggregation tree configuration
    /// * `num_real_proofs` - Number of real proofs that will be provided (used to clone only needed dummy proofs)
    pub fn from_prebuilt_with_paths(
        common_path: &std::path::Path,
        verifier_path: &std::path::Path,
        config: TreeAggregationConfig,
        num_real_proofs: usize,
    ) -> anyhow::Result<Self> {
        let aggregation_config = config;

        // Calculate how many dummy proofs we need for padding
        let num_dummy_proofs = aggregation_config
            .num_leaf_proofs
            .saturating_sub(num_real_proofs);

        // Build verifier data from the same circuit by loading from files
        let verifier_data = Self::load_verifier_data_from_paths(common_path, verifier_path)?;

        // Clone only the needed dummy proofs for padding
        // The dedupe aggregator circuit will override these with randomly generated unique nullifiers
        let dummy_proof = load_dummy_proof(&verifier_data.common)?;
        let dummy_proofs = vec![dummy_proof; num_dummy_proofs];

        Ok(Self::new(verifier_data, dummy_proofs, aggregation_config))
    }

    /// Load verifier circuit data from pre-built files at default paths.
    #[allow(dead_code)]
    fn load_verifier_data() -> anyhow::Result<VerifierCircuitData<F, C, D>> {
        use std::path::Path;
        Self::load_verifier_data_from_paths(
            Path::new("generated-bins/common.bin"),
            Path::new("generated-bins/verifier.bin"),
        )
    }

    /// Load verifier circuit data from pre-built files at custom paths.
    fn load_verifier_data_from_paths(
        common_path: &std::path::Path,
        verifier_path: &std::path::Path,
    ) -> anyhow::Result<VerifierCircuitData<F, C, D>> {
        use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
        use plonky2::util::serialization::DefaultGateSerializer;
        use std::fs;

        let gate_serializer = DefaultGateSerializer;

        // Load common data
        let common_bytes = fs::read(common_path)
            .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", common_path, e))?;
        let common = CommonCircuitData::from_bytes(common_bytes, &gate_serializer)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize common data: {}", e))?;

        // Load verifier-only data
        let verifier_only_bytes = fs::read(verifier_path)
            .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", verifier_path, e))?;
        let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize verifier data: {}", e))?;

        Ok(VerifierCircuitData {
            verifier_only,
            common,
        })
    }

    /// Creates a new [`WormholeProofAggregator`] with a given [`CircuitConfig`]
    /// by building the circuit, extracting verifier data, and generating compatible dummy proofs.
    ///
    /// Requires explicit aggregation config (branching_factor, depth).
    pub fn from_circuit_config(
        circuit_config: CircuitConfig,
        aggregation_config: TreeAggregationConfig,
    ) -> Self {
        use plonky2::iop::witness::PartialWitness;

        // Build the circuit once to get both prover and verifier data from the SAME build.
        // This is critical - using separate builds causes wire assignment mismatches.
        let circuit = WormholeCircuit::new(circuit_config.clone());
        let targets = circuit.targets();
        let circuit_data = circuit.build_circuit();

        // Extract verifier data from this circuit
        let verifier_data = circuit_data.verifier_data();

        // Generate multiple dummy proofs - one for each potential padding slot.
        let mut dummy_proofs = Vec::with_capacity(aggregation_config.num_leaf_proofs);
        let dummy_inputs =
            build_dummy_circuit_inputs().expect("failed to build dummy circuit inputs");
        for _ in 0..aggregation_config.num_leaf_proofs {
            let mut pw = PartialWitness::new();

            // Use shared fill_witness helper to avoid duplicating the witness filling logic
            fill_witness(&mut pw, &dummy_inputs, &targets).expect("failed to fill witness");

            let dummy_proof = circuit_data
                .prove(pw)
                .expect("failed to generate dummy proof");
            dummy_proofs.push(dummy_proof);
        }

        Self::new(verifier_data, dummy_proofs, aggregation_config)
    }

    pub fn push_proof(&mut self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        if let Some(proofs_buffer) = self.proofs_buffer.as_mut() {
            if proofs_buffer.len() >= self.config.num_leaf_proofs {
                bail!("tried to add proof when proof buffer is full")
            }
            proofs_buffer.push(proof);
        } else {
            self.proofs_buffer = Some(vec![proof]);
        }

        Ok(())
    }

    /// Extract and aggregate leaf public inputs from the filled proof buffer OUTSIDE the circuit.
    /// Groups by `blocks`, then `exit_account`, sums `output_amount`, and collects `nullifiers`.
    /// Used for sanity checks to ensure it matches the public inputs results from the aggregation circuit.
    pub fn parse_aggregated_public_inputs_from_proof_buffer(
        &self,
    ) -> anyhow::Result<AggregatedPublicCircuitInputs> {
        let num_leaves = self.config.num_leaf_proofs;
        let proofs = &self.proofs_buffer;
        let Some(proofs) = proofs else {
            bail!("there are no proofs to aggregate")
        };
        if num_leaves != proofs.len() {
            bail!(
                "proof buffer length {} does not match expected num_leaves {}",
                proofs.len(),
                num_leaves
            )
        };
        let mut leaves: Vec<PublicCircuitInputs> = Vec::new();
        for proof in proofs {
            let pi = PublicCircuitInputs::try_from_proof(proof)?;
            leaves.push(pi);
        }
        aggregate_public_inputs(leaves)
    }

    /// Aggregates `N` number of leaf proofs into an [`AggregatedProof`].
    ///
    /// # Note
    /// Pre-generated dummy proofs use `asset_id = 0` (native token). All real proofs
    /// must also use `asset_id = 0` for the aggregation to succeed, since the circuit
    /// enforces all proofs have the same asset_id.
    pub fn aggregate(&mut self) -> anyhow::Result<AggregatedProof<F, C, D>> {
        let Some(mut proofs) = self.proofs_buffer.take() else {
            bail!("there are no proofs to aggregate")
        };

        // Pad with dummy proofs if needed
        let num_dummies_needed = self.config.num_leaf_proofs.saturating_sub(proofs.len());
        if num_dummies_needed > 0 {
            // Verify asset_id matches dummy proofs (asset_id = 0)
            // We cannot modify public inputs post-proof as that invalidates the proof.
            if let Some(first_proof) = proofs.first() {
                let real_asset_id: u32 = first_proof.public_inputs[0]
                    .to_canonical_u64()
                    .try_into()
                    .context("asset_id in first proof exceeds u32 range")?;
                if real_asset_id != 0 {
                    bail!(
                        "Real proofs have asset_id={}, but dummy proofs use asset_id=0. \
                         All proofs must have the same asset_id for aggregation.",
                        real_asset_id
                    );
                }
            }

            for i in 0..num_dummies_needed {
                proofs.push(self.dummy_proofs[i].clone());
            }
        }

        // Shuffle proofs to hide dummy positions while keeping a real proof in slot 0.
        // This makes dummy proofs indistinguishable from duplicate exit accounts in the output.
        shuffle_proofs_preserving_first_real(&mut proofs);

        let root_proof = aggregate_to_tree(
            proofs,
            &self.leaf_circuit_data.common,
            &self.leaf_circuit_data.verifier_only,
            self.config,
        )?;

        Ok(root_proof)
    }
}

/// Turn flat leaf public inputs into `AggregatedPublicCircuitInputs`.
fn aggregate_public_inputs(
    leaves: Vec<PublicCircuitInputs>,
) -> anyhow::Result<AggregatedPublicCircuitInputs> {
    let first_leaf = leaves
        .first()
        .ok_or_else(|| anyhow::anyhow!("no leaves provided"))?;
    let asset_id = first_leaf.asset_id;
    let volume_fee_bps = first_leaf.volume_fee_bps;

    // Verify all leaves have the same volume_fee_bps
    for leaf in &leaves {
        if leaf.volume_fee_bps != volume_fee_bps {
            anyhow::bail!(
                "all leaves must have the same volume_fee_bps, expected {} but got {}",
                volume_fee_bps,
                leaf.volume_fee_bps
            );
        }
    }

    let mut by_account: BTreeMap<BytesDigest, PublicInputsByAccount> = BTreeMap::new();
    let nullifiers: Vec<BytesDigest> = leaves.iter().map(|leaf| leaf.nullifier).collect();

    let mut block_data = BlockData::default();

    for leaf in leaves {
        // If the block number is greater than the current, update block_data.
        if leaf.block_number > block_data.block_number {
            block_data.block_number = leaf.block_number;
            block_data.block_hash = leaf.block_hash;
        }

        // Process first output (exit_account_1, output_amount_1)
        let acct_entry_1 =
            by_account
                .entry(leaf.exit_account_1)
                .or_insert_with(|| PublicInputsByAccount {
                    summed_output_amount: 0u32,
                    exit_account: leaf.exit_account_1,
                });

        acct_entry_1.summed_output_amount = acct_entry_1
            .summed_output_amount
            .checked_add(leaf.output_amount_1)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "overflow while summing output amounts for exit account {:?}",
                    acct_entry_1.exit_account
                )
            })?;

        // Process second output (exit_account_2, output_amount_2)
        // Only if the exit account is non-zero (skip unused second outputs)
        if leaf.exit_account_2 != BytesDigest::default() || leaf.output_amount_2 > 0 {
            let acct_entry_2 =
                by_account
                    .entry(leaf.exit_account_2)
                    .or_insert_with(|| PublicInputsByAccount {
                        summed_output_amount: 0u32,
                        exit_account: leaf.exit_account_2,
                    });

            acct_entry_2.summed_output_amount = acct_entry_2
                .summed_output_amount
                .checked_add(leaf.output_amount_2)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "overflow while summing output amounts for exit account {:?}",
                        acct_entry_2.exit_account
                    )
                })?;
        }
    }

    let mut accounts: Vec<PublicInputsByAccount> = by_account.into_values().collect();

    // Sort accounts by the same comparator on the exit account.
    accounts.sort_by_key(|a| digest_key_le_u64x4(&a.exit_account));

    Ok(AggregatedPublicCircuitInputs {
        asset_id,
        volume_fee_bps,
        block_data,
        account_data: accounts,
        nullifiers,
    })
}

#[inline]
fn digest_key_le_u64x4(d: &BytesDigest) -> [u64; 4] {
    let bytes: &[u8; 32] = d; // e.g., impl AsRef<[u8;32]> for BytesDigest
    [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ]
}

/// Shuffle proofs while ensuring a real proof remains in slot 0 for valid reference values.
///
/// The aggregation circuit uses slot 0's block_hash, asset_id, and volume_fee_bps as reference
/// values that all other proofs are validated against. A dummy proof in slot 0 would cause
/// the reference block_hash to be [0,0,0,0], breaking validation for real proofs.
///
/// This function:
/// 1. Finds the first real proof (block_hash != 0) and swaps it to slot 0
/// 2. Shuffles all remaining proofs (slots 1..N) with external randomness
///
/// This hides dummy proof positions while maintaining valid circuit semantics.
/// Combined with zeroing duplicate exit slots, dummies become indistinguishable from duplicates.
fn shuffle_proofs_preserving_first_real(proofs: &mut [ProofWithPublicInputs<F, C, D>]) {
    // Find first real proof (block_hash != 0)
    let first_real_idx = proofs.iter().position(|p| {
        // block_hash is 4 felts at BLOCK_HASH_PI_START
        let block_hash_is_zero = p.public_inputs[BLOCK_HASH_PI_START..BLOCK_HASH_PI_END]
            .iter()
            .all(|f| f.is_zero());
        !block_hash_is_zero
    });

    if let Some(idx) = first_real_idx {
        // Swap first real proof to position 0
        proofs.swap(0, idx);
    }
    // If no real proof found (all dummies), leave as-is - circuit handles this case

    // Shuffle remaining proofs (positions 1..N) with external randomness
    if proofs.len() > 1 {
        let mut rng = rand::thread_rng();
        proofs[1..].shuffle(&mut rng);
    }
}
