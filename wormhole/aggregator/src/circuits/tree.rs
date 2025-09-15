use std::collections::BTreeMap;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::GenericConfig,
    },
};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use wormhole_circuit::inputs::AggregatedPublicCircuitInputs;
use wormhole_verifier::ProofWithPublicInputs;
use zk_circuits_common::{
    circuit::{C, D, F},
    gadgets::{add_u128_base2_32_split, bytes_digest_eq},
};

/// The default branching factor of the proof tree. A higher value means more proofs get aggregated
/// into a single proof at each level.
pub const DEFAULT_TREE_BRANCHING_FACTOR: usize = 2;
/// The default depth of the tree of the aggregated proof, counted as the longest path of edges between the
/// leaf nodes and the root node.
pub const DEFAULT_TREE_DEPTH: u32 = 3;

const LEAF_PI_LEN: usize = 16;
const NULLIFIER_START: usize = 0; // 4 felts (not used in dedupe output)
const ROOT_START: usize = 4; // 4 felts
const FUNDING_START: usize = 8; // 4 felts
const EXIT_START: usize = 12; // 4 felts

/// A proof containing both the proof data and the circuit data needed to verify it.
#[derive(Debug)]
pub struct AggregatedProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub circuit_data: CircuitData<F, C, D>,
}

// The root proof that is the result of aggregating multiple leaf proofs, containing the indices of the block -> root hash groups needed to parse the deduped public inputs
#[derive(Debug)]
pub struct AggregatedRootProof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub circuit_data: CircuitData<F, C, D>,
    pub indices: Vec<Vec<Vec<usize>>>,
}

impl AggregatedRootProof<F, C, D> {
    /// Parse the public inputs from the aggregated root proof
    /// Groups by `root_hash`, then `exit_account`, sums `funding_amount`, and collects `nullifiers`.
    /// Should match the output of `aggregator.parse_leaf_public_inputs_from_proof_buffer()` if the same
    /// proof buffer was used
    pub fn parse_public_inputs(&self) -> Result<AggregatedPublicCircuitInputs, anyhow::Error> {
        AggregatedPublicCircuitInputs::try_from_aggregated(&self.proof.public_inputs, &self.indices)
    }
}

/// The tree configuration to use when aggregating proofs into a tree.
#[derive(Debug, Clone, Copy)]
pub struct TreeAggregationConfig {
    pub num_leaf_proofs: usize,
    pub tree_branching_factor: usize,
    pub tree_depth: u32,
}

impl TreeAggregationConfig {
    pub fn new(tree_branching_factor: usize, tree_depth: u32) -> Self {
        let num_leaf_proofs = tree_branching_factor.pow(tree_depth);
        Self {
            num_leaf_proofs,
            tree_branching_factor,
            tree_depth,
        }
    }
}

impl Default for TreeAggregationConfig {
    fn default() -> Self {
        Self::new(DEFAULT_TREE_BRANCHING_FACTOR, DEFAULT_TREE_DEPTH)
    }
}

pub fn aggregate_to_tree(
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
    config: TreeAggregationConfig,
) -> anyhow::Result<AggregatedRootProof<F, C, D>> {
    // Aggregate the first level.
    let mut proofs = aggregate_level(leaf_proofs, common_data, verifier_data, config)?;

    // Do the next levels by utilizing the circuit data within each aggregated proof.
    while proofs.len() > 1 {
        let common_data = &proofs[0].circuit_data.common.clone();
        let verifier_data = &proofs[0].circuit_data.verifier_only.clone();
        let to_aggregate = proofs.into_iter().map(|p| p.proof).collect();

        let aggregated_proofs = aggregate_level(to_aggregate, common_data, verifier_data, config)?;

        proofs = aggregated_proofs;
    }
    let leaves_public_inputs = &proofs[0].proof.public_inputs;
    let indices = find_group_indices(leaves_public_inputs)?;
    println!("group indices = {:?}", indices);
    let root_proof = aggregate_dedupe_public_inputs(proofs, &indices)?;

    Ok(root_proof)
}

#[cfg(not(feature = "multithread"))]
fn aggregate_level(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
    config: TreeAggregationConfig,
) -> anyhow::Result<Vec<AggregatedProof<F, C, D>>> {
    proofs
        .chunks(config.tree_branching_factor)
        .map(|chunk| aggregate_chunk(chunk, common_data, verifier_data))
        .collect()
}

#[cfg(feature = "multithread")]
fn aggregate_level(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
    config: TreeAggregationConfig,
) -> anyhow::Result<Vec<AggregatedProof<F, C, D>>> {
    proofs
        .par_chunks(config.tree_branching_factor)
        .map(|chunk| aggregate_chunk(chunk, common_data, verifier_data))
        .collect()
}

/// Circuit gadget that takes in a pair of proofs, a and b, aggregates it and return the new proof.
fn aggregate_chunk(
    chunk: &[ProofWithPublicInputs<F, C, D>],
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> anyhow::Result<AggregatedProof<F, C, D>> {
    let mut builder = CircuitBuilder::new(common_data.config.clone());
    let verifier_data_t =
        builder.add_virtual_verifier_data(common_data.fri_params.config.cap_height);

    let mut proof_targets = Vec::with_capacity(chunk.len());
    for _ in 0..chunk.len() {
        // Verify the proof.
        let proof_t = builder.add_virtual_proof_with_pis(common_data);
        builder.verify_proof::<C>(&proof_t, &verifier_data_t, common_data);

        // Aggregate public inputs of proof.
        builder.register_public_inputs(&proof_t.public_inputs);

        proof_targets.push(proof_t);
    }

    let circuit_data = builder.build();

    // Fill targets.
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&verifier_data_t, verifier_data)?;
    for (target, proof) in proof_targets.iter().zip(chunk) {
        pw.set_proof_with_pis_target(target, proof)?;
    }

    let proof = circuit_data.prove(pw)?;

    let aggregated_proof = AggregatedProof {
        proof,
        circuit_data,
    };
    Ok(aggregated_proof)
}

fn find_group_indices(leaves_public_inputs: &[F]) -> anyhow::Result<Vec<Vec<Vec<usize>>>> {
    anyhow::ensure!(
        leaves_public_inputs.len() % LEAF_PI_LEN == 0,
        "leaves_public_inputs length ({}) is not a multiple of {}",
        leaves_public_inputs.len(),
        LEAF_PI_LEN
    );
    let n_leaves = leaves_public_inputs.len() / LEAF_PI_LEN;

    // root_hash -> (exit_account -> index)
    let mut groups: BTreeMap<[F; 4], BTreeMap<[F; 4], Vec<usize>>> = BTreeMap::new();

    // chunk leaves into groups of 16
    for (i, chunk) in leaves_public_inputs.chunks(LEAF_PI_LEN).enumerate() {
        let root_hash = chunk[ROOT_START..ROOT_START + 4].try_into().unwrap(); // first felt of root hash
        let exit_account = chunk[EXIT_START..EXIT_START + 4].try_into().unwrap(); // first felt of exit account
        groups
            .entry(root_hash)
            .or_default()
            .entry(exit_account)
            .or_default()
            .push(i);
    }

    // Produce stable Vec<Vec<Vec<usize>>> in sorted order.
    let mut out: Vec<Vec<Vec<usize>>> = Vec::with_capacity(groups.len());
    let mut counted = 0usize;

    for (_root_key, exits_map) in groups {
        let mut per_root: Vec<Vec<usize>> = Vec::with_capacity(exits_map.len());
        for (_exit_key, mut idxs) in exits_map {
            // keep deterministic ascending indices (already ascending by i, but be safe)
            idxs.sort_unstable();
            counted += idxs.len();
            per_root.push(idxs);
        }
        out.push(per_root);
    }

    // Sanity: flattened coverage equals #leaves.
    anyhow::ensure!(
        counted == n_leaves,
        "grouping coverage mismatch: counted {} != n_leaves {}",
        counted,
        n_leaves
    );
    Ok(out)
}

/// Build a tiny wrapper circuit around the *single* root aggregated proof that:
///  - verifies that proof,
///  - enforces groups (indices) have identical root/exit among members,
///  - sums funding across members with add_u128_base2_32
///  - The layout of the aggregated public inputs is as follows:
///   - [root_hash(4), [funding_sum(4), exit(4), nullifiers(4)*] *]
fn aggregate_dedupe_public_inputs(
    proofs: Vec<AggregatedProof<F, C, D>>,
    indices: &[Vec<Vec<usize>>],
) -> anyhow::Result<AggregatedRootProof<F, C, D>> {
    anyhow::ensure!(
        proofs.len() == 1,
        "aggregate_dedupe_public_inputs expects a single root proof"
    );
    let root = &proofs[0];

    // Off-circuit sanity and sizing
    // TODO: figure out how to express these more global checks as a set of constaints in the circuit
    let flat: Vec<usize> = indices
        .iter()
        .flat_map(|v| v.iter().flat_map(|w| w.iter().copied()))
        .collect();
    let n_leaf = flat.len();
    anyhow::ensure!(n_leaf > 0, "indices must not be empty");

    let root_pi_len = root.proof.public_inputs.len();
    anyhow::ensure!(
        root_pi_len % LEAF_PI_LEN == 0,
        "Root PI length {} is not a multiple of {}",
        root_pi_len,
        LEAF_PI_LEN
    );
    anyhow::ensure!(root_pi_len / LEAF_PI_LEN == n_leaf,
        "Flattened indices length {} must equal number of leaf proofs {} (derived from root PI len {})",
        n_leaf, root_pi_len / LEAF_PI_LEN, root_pi_len);

    // - check that all indices are < n_leaf
    anyhow::ensure!(
        flat.iter().all(|&k| k < n_leaf),
        "Index out of range in indices"
    );

    // Build wrapper circuit
    let child_common = &root.circuit_data.common;
    let child_verifier_only = &root.circuit_data.verifier_only;

    let mut builder = CircuitBuilder::new(child_common.config.clone());
    let vd_t = builder.add_virtual_verifier_data(child_common.fri_params.config.cap_height);

    // Child proof target = the (only) root aggregated proof
    let child_pt = builder.add_virtual_proof_with_pis(child_common);
    builder.verify_proof::<C>(&child_pt, &vd_t, child_common);

    // Helpers to slice 4-limb values out of the *child* PI vector
    let limbs4_at = |pis: &Vec<Target>, leaf_idx: usize, start_off: usize| -> [Target; 4] {
        let base = leaf_idx * LEAF_PI_LEN + start_off;
        [pis[base], pis[base + 1], pis[base + 2], pis[base + 3]]
    };

    // Build deduped output
    let mut deduped_pis: Vec<Target> = Vec::new();

    for per_root in indices.iter() {
        let rep = per_root[0][0];
        let root_ref = limbs4_at(&child_pt.public_inputs, rep, ROOT_START);
        // One root hash per group of deduped exit accounts.
        deduped_pis.extend_from_slice(&root_ref);

        for group in per_root.iter() {
            // Representative fields
            let exit_ref = limbs4_at(&child_pt.public_inputs, rep, EXIT_START);

            // Enforce all members share same root & exit
            for &idx in group.iter() {
                let root_i = limbs4_at(&child_pt.public_inputs, idx, ROOT_START);
                let exit_i = limbs4_at(&child_pt.public_inputs, idx, EXIT_START);

                let er = bytes_digest_eq(&mut builder, root_i, root_ref);
                let ee = bytes_digest_eq(&mut builder, exit_i, exit_ref);
                let both = builder.mul(er.target, ee.target);
                let one = builder.one();
                builder.connect(both, one);
            }

            // Sum funding across the group
            let mut acc = [
                builder.zero(),
                builder.zero(),
                builder.zero(),
                builder.zero(),
            ];
            for &idx in group.iter() {
                let fund_i = limbs4_at(&child_pt.public_inputs, idx, FUNDING_START);
                let (sum, top_carry) = add_u128_base2_32_split(&mut builder, acc, fund_i);
                // Enforce no 129-bit overflow.
                let zero = builder.zero();
                builder.connect(top_carry, zero);
                acc = sum;
            }

            // Emit one compressed PI couplet: [funding_sum(4), exit(4)]
            deduped_pis.extend_from_slice(&acc);
            deduped_pis.extend_from_slice(&exit_ref);

            // Forward ALL nullifiers for this group, in the order given by indices[i][j]
            for &idx in group.iter() {
                let null_i = limbs4_at(&child_pt.public_inputs, idx, NULLIFIER_START);
                deduped_pis.extend_from_slice(&null_i); // +4 per leaf in group
            }
        }
    }

    // Register compressed PIs
    builder.register_public_inputs(&deduped_pis);

    // Prove wrapper
    let circuit_data = builder.build();
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&vd_t, child_verifier_only)?;
    pw.set_proof_with_pis_target(&child_pt, &root.proof)?;

    let proof = circuit_data.prove(pw)?;
    Ok(AggregatedRootProof {
        proof,
        circuit_data,
        indices: indices.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Field,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
        },
    };
    use zk_circuits_common::circuit::{C, D, F};

    use crate::circuits::tree::{
        aggregate_chunk, aggregate_to_tree, AggregatedProof, TreeAggregationConfig,
    };

    fn generate_base_circuit() -> (CircuitData<F, C, D>, Target) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let x_sq = builder.mul(x, x);
        builder.register_public_input(x_sq);

        let data = builder.build::<C>();
        (data, x)
    }

    fn prove_square(value: F) -> AggregatedProof<F, C, D> {
        let (circuit_data, target) = generate_base_circuit();

        let mut pw = PartialWitness::new();
        pw.set_target(target, value).unwrap();
        let proof = circuit_data.prove(pw).unwrap();

        AggregatedProof {
            proof,
            circuit_data,
        }
    }

    #[test]
    fn recursive_aggregation_tree() {
        // Generate multiple leaf proofs.
        let inputs = [
            F::from_canonical_u64(3),
            F::from_canonical_u64(4),
            F::from_canonical_u64(5),
            F::from_canonical_u64(6),
        ];
        let proofs = inputs.iter().map(|&v| prove_square(v)).collect::<Vec<_>>();

        let common_data = &proofs[0].circuit_data.common.clone();
        let verifier_data = &proofs[0].circuit_data.verifier_only.clone();
        let to_aggregate = proofs.into_iter().map(|p| p.proof).collect();

        // Aggregate into tree.
        let config = TreeAggregationConfig::default();
        let root_proof =
            aggregate_to_tree(to_aggregate, common_data, verifier_data, config).unwrap();

        // Verify final root proof.
        root_proof.circuit_data.verify(root_proof.proof).unwrap()
    }

    #[test]
    fn pair_aggregation() {
        let proof1 = prove_square(F::from_canonical_u64(7));
        let proof2 = prove_square(F::from_canonical_u64(8));

        let aggregated = aggregate_chunk(
            &[proof1.proof, proof2.proof],
            &proof1.circuit_data.common,
            &proof1.circuit_data.verifier_only,
        )
        .unwrap();

        aggregated.circuit_data.verify(aggregated.proof).unwrap();
    }

    #[test]
    fn public_inputs_are_aggregated() {
        let proof1 = prove_square(F::from_canonical_u64(7));
        let proof2 = prove_square(F::from_canonical_u64(8));

        let aggregated = aggregate_chunk(
            &[proof1.proof, proof2.proof],
            &proof1.circuit_data.common,
            &proof1.circuit_data.verifier_only,
        )
        .unwrap();

        println!("{:?}", aggregated.proof.public_inputs);

        assert_eq!(aggregated.proof.public_inputs.len(), 2);
    }
}
