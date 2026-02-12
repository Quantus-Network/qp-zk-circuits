use std::collections::BTreeMap;

use anyhow::bail;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use wormhole_circuit::inputs::{
    AggregatedPublicCircuitInputs, BlockData, PublicCircuitInputs, PublicInputsByAccount,
};
use wormhole_prover::{fill_witness, WormholeProver};
use zk_circuits_common::{
    circuit::{C, D, F},
    utils::BytesDigest,
};

use crate::{
    circuits::tree::{aggregate_to_tree, AggregatedProof, TreeAggregationConfig},
    dummy_proof::build_dummy_circuit_inputs,
};

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

impl Default for WormholeProofAggregator {
    fn default() -> Self {
        // Try to use pre-built circuit files for consistency
        Self::from_prebuilt().unwrap_or_else(|_| {
            let circuit_config = CircuitConfig::standard_recursion_zk_config();
            Self::from_circuit_config(circuit_config)
        })
    }
}

impl WormholeProofAggregator {
    /// Creates a new [`WormholeProofAggregator`] with a given [`VerifierCircuitData`]
    /// and pre-generated dummy proofs.
    ///
    /// The dummy proofs must be compatible with the verifier data (generated from the same circuit).
    /// Each dummy proof should have a unique nullifier to avoid on-chain duplicate errors.
    pub fn new(
        verifier_circuit_data: VerifierCircuitData<F, C, D>,
        dummy_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Self {
        let aggregation_config = TreeAggregationConfig::default();
        let proofs_buffer = Some(Vec::with_capacity(aggregation_config.num_leaf_proofs));

        Self {
            leaf_circuit_data: verifier_circuit_data,
            config: aggregation_config,
            proofs_buffer,
            dummy_proofs,
        }
    }

    /// Creates a new [`WormholeProofAggregator`] from pre-built circuit files.
    ///
    /// This ensures the aggregator uses the same circuit data as proofs generated
    /// by `WormholeProver::default()`, avoiding wire assignment mismatches.
    ///
    /// Looks for files in `generated-bins/`:
    /// - `common.bin` - Common circuit data
    /// - `verifier.bin` - Verifier-only circuit data
    /// - `prover.bin` - Prover circuit data
    pub fn from_prebuilt() -> anyhow::Result<Self> {
        use std::path::Path;
        Self::from_prebuilt_with_paths(
            Path::new("generated-bins/prover.bin"),
            Path::new("generated-bins/common.bin"),
            Path::new("generated-bins/verifier.bin"),
        )
    }

    /// Creates a new [`WormholeProofAggregator`] from pre-built circuit files at custom paths.
    ///
    /// This is useful when the pre-built files are not in the default `generated-bins/` directory.
    pub fn from_prebuilt_with_paths(
        prover_path: &std::path::Path,
        common_path: &std::path::Path,
        verifier_path: &std::path::Path,
    ) -> anyhow::Result<Self> {
        let aggregation_config = TreeAggregationConfig::default();

        // Generate dummy proofs - one for each potential padding slot
        // Each dummy has a unique nullifier to avoid on-chain duplicate errors
        let mut dummy_proofs = Vec::with_capacity(aggregation_config.num_leaf_proofs);
        for i in 0..aggregation_config.num_leaf_proofs {
            // Load fresh prover for each proof (prover is consumed on commit)
            let prover = WormholeProver::new_from_files(prover_path, common_path).map_err(|e| {
                anyhow::anyhow!("Failed to load prover from pre-built files: {}", e)
            })?;

            // Generate dummy inputs with unique nullifier (build_dummy_circuit_inputs generates random nullifier each call)
            let dummy_inputs = build_dummy_circuit_inputs()?;
            let proof = prover.commit(&dummy_inputs)?.prove()?;
            // Verify the nullifier is not all zeros (would be a bug)
            let pi = PublicCircuitInputs::try_from(&proof)?;
            if pi.nullifier.iter().all(|&b| b == 0) {
                eprintln!("ERROR: dummy_proof[{}] has all-zero nullifier!", i);
            }
            dummy_proofs.push(proof);
        }

        // Build verifier data from the same circuit by loading from files
        let verifier_data = Self::load_verifier_data_from_paths(common_path, verifier_path)?;

        Ok(Self::new(verifier_data, dummy_proofs))
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
    pub fn from_circuit_config(circuit_config: CircuitConfig) -> Self {
        use plonky2::iop::witness::PartialWitness;

        // Build the circuit once to get both prover and verifier data from the SAME build.
        // This is critical - using separate builds causes wire assignment mismatches.
        let circuit = WormholeCircuit::new(circuit_config.clone());
        let targets = circuit.targets();
        let circuit_data = circuit.build_circuit();

        // Extract verifier data from this circuit
        let verifier_data = circuit_data.verifier_data();

        let aggregation_config = TreeAggregationConfig::default();

        // Generate multiple dummy proofs - one for each potential padding slot.
        // Each dummy has a unique nullifier to avoid on-chain duplicate errors.
        let mut dummy_proofs = Vec::with_capacity(aggregation_config.num_leaf_proofs);
        for _ in 0..aggregation_config.num_leaf_proofs {
            // Generate dummy inputs with unique nullifier (build_dummy_circuit_inputs generates random nullifier each call)
            let dummy_inputs =
                build_dummy_circuit_inputs().expect("failed to build dummy circuit inputs");

            let mut pw = PartialWitness::new();

            // Use shared fill_witness helper to avoid duplicating the witness filling logic
            fill_witness(&mut pw, &dummy_inputs, &targets).expect("failed to fill witness");

            let dummy_proof = circuit_data
                .prove(pw)
                .expect("failed to generate dummy proof");
            dummy_proofs.push(dummy_proof);
        }

        Self::new(verifier_data, dummy_proofs)
    }

    pub fn with_config(mut self, config: TreeAggregationConfig) -> Self {
        self.config = config;
        self
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
            let pi = PublicCircuitInputs::try_from(proof)?;
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
                let real_asset_id = first_proof.public_inputs[0].to_canonical_u64() as u32;
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
