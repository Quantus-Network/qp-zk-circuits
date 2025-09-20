use std::collections::BTreeMap;

use anyhow::bail;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use wormhole_circuit::inputs::{
    AggregatedPublicCircuitInputs, PublicCircuitInputs, PublicInputsByAccount,
};
use wormhole_verifier::{ProofWithPublicInputs, WormholeVerifier};
use zk_circuits_common::{
    circuit::{C, D, F},
    utils::BytesDigest,
};

use crate::{
    circuits::tree::{aggregate_to_tree, AggregatedProof, TreeAggregationConfig},
    util::pad_with_dummy_proofs,
};

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator {
    pub leaf_circuit_data: VerifierCircuitData<F, C, D>,
    pub config: TreeAggregationConfig,
    pub proofs_buffer: Option<Vec<ProofWithPublicInputs<F, C, D>>>,
}

impl Default for WormholeProofAggregator {
    fn default() -> Self {
        let circuit_config = CircuitConfig::standard_recursion_zk_config();
        Self::from_circuit_config(circuit_config)
    }
}

impl WormholeProofAggregator {
    /// Creates a new [`WormholeProofAggregator`] with a given [`VerifierCircuitData`].
    pub fn new(verifier_circuit_data: VerifierCircuitData<F, C, D>) -> Self {
        let aggregation_config = TreeAggregationConfig::default();
        let proofs_buffer = Some(Vec::with_capacity(aggregation_config.num_leaf_proofs));

        Self {
            leaf_circuit_data: verifier_circuit_data,
            config: aggregation_config,
            proofs_buffer,
        }
    }

    /// Creates a new [`WormholeProofAggregator`] with a given [`CircuitConfig`]
    /// by compiling the circuit data from a [`WormholeVerifier`].
    pub fn from_circuit_config(circuit_config: CircuitConfig) -> Self {
        let verifier = WormholeVerifier::new(circuit_config.clone(), None);
        Self::new(verifier.circuit_data)
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
    /// Groups by `root_hash`, then `exit_account`, sums `funding_amount`, and collects `nullifiers`.
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
    pub fn aggregate(&mut self) -> anyhow::Result<AggregatedProof<F, C, D>> {
        let Some(proofs) = self.proofs_buffer.take() else {
            bail!("there are no proofs to aggregate")
        };

        let padded_proofs = pad_with_dummy_proofs(
            proofs,
            self.config.num_leaf_proofs,
            &self.leaf_circuit_data.common,
        )?;
        let root_proof = aggregate_to_tree(
            padded_proofs,
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
    // by_block: root_hash -> (exit_account -> PublicInputsByAccount)
    let mut by_block: BTreeMap<BytesDigest, bool> = BTreeMap::new();
    let mut by_account: BTreeMap<BytesDigest, PublicInputsByAccount> = BTreeMap::new();
    let nullifiers: Vec<BytesDigest> = leaves.iter().map(|leaf| leaf.nullifier).collect();

    for leaf in leaves {
        by_block.entry(leaf.root_hash).or_insert_with(|| true);
        let acct_entry =
            by_account
                .entry(leaf.exit_account)
                .or_insert_with(|| PublicInputsByAccount {
                    summed_funding_amount: 0u128,
                    exit_account: leaf.exit_account,
                });

        // Sum funding amounts with overflow check (fail fast if unrealistic overflow happens).
        acct_entry.summed_funding_amount = acct_entry
            .summed_funding_amount
            .checked_add(leaf.funding_amount)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "overflow while summing funding amounts for exit account {:?}",
                    acct_entry.exit_account
                )
            })?;
    }

    // Materialize the nested maps into the desired Vec<PublicInputsByBlock> shape.
    let mut blocks: Vec<BytesDigest> = by_block.into_keys().collect();
    let mut accounts: Vec<PublicInputsByAccount> = by_account.into_values().collect();

    // Sort blocks by the same comparator on the root hash.
    blocks.sort_by_key(digest_key_le_u64x4);
    // Sort accounts by the same comparator on the exit account.
    accounts.sort_by_key(|a| digest_key_le_u64x4(&a.exit_account));

    Ok(AggregatedPublicCircuitInputs {
        root_hashes: blocks,
        account_data: accounts,
        nullifiers, // nullifiers are not aggregated outside the circuit
    })
}

#[inline]
fn digest_key_le_u64x4(d: &BytesDigest) -> [u64; 4] {
    // Adjust this accessor if your BytesDigest stores bytes differently.
    let bytes: &[u8; 32] = d; // e.g., impl AsRef<[u8;32]> for BytesDigest
    [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ]
}
