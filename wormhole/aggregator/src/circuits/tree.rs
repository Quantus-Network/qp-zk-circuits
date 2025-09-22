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
use wormhole_verifier::ProofWithPublicInputs;
use zk_circuits_common::{
    circuit::{C, D, F},
    gadgets::{add_u128_base2_32_split, bytes_digest_eq, count_unique_4x32_keys},
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
/// The groupings of public input indices for the aggregated proof.
#[derive(Debug)]
pub struct Groupings {
    pub root_hashes: Vec<Vec<usize>>,
    pub exit_accounts: Vec<Vec<usize>>,
    pub size: usize,
}

impl Groupings {
    pub fn new(root_hashes: Vec<Vec<usize>>, exit_accounts: Vec<Vec<usize>>) -> Self {
        let len_root_hashes: usize = root_hashes.iter().map(|v| v.len()).sum();
        let len_exit_accounts: usize = exit_accounts.iter().map(|v| v.len()).sum();
        // assert that both lengths are equal
        assert_eq!(
            len_root_hashes, len_exit_accounts,
            "length of root_hashes ({}) must be equal to length of exit_accounts ({}).",
            len_root_hashes, len_exit_accounts
        );
        Self {
            root_hashes,
            exit_accounts,
            size: len_root_hashes,
        }
    }
    pub fn len(&self) -> usize {
        let len_root_hashes: usize = self.root_hashes.iter().map(|v| v.len()).sum();
        let len_exit_accounts: usize = self.exit_accounts.iter().map(|v| v.len()).sum();
        // assert that both lengths are equal
        assert_eq!(
            len_root_hashes, len_exit_accounts,
            "length of root_hashes ({}) must be equal to length of exit_accounts ({}).",
            len_root_hashes, len_exit_accounts
        );
        len_root_hashes
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
) -> anyhow::Result<AggregatedProof<F, C, D>> {
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
    let root_proof = aggregate_dedupe_public_inputs(proofs, indices)?;

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

fn find_group_indices(leaves_public_inputs: &[F]) -> anyhow::Result<Groupings> {
    anyhow::ensure!(
        leaves_public_inputs.len().is_multiple_of(LEAF_PI_LEN),
        "leaves_public_inputs length ({}) is not a multiple of {}",
        leaves_public_inputs.len(),
        LEAF_PI_LEN
    );
    let n_leaves = leaves_public_inputs.len() / LEAF_PI_LEN;

    // root_hash -> (exit_account -> index)
    let mut root_hash_groups: BTreeMap<[F; 4], Vec<usize>> = BTreeMap::new();
    let mut exit_account_groups: BTreeMap<[F; 4], Vec<usize>> = BTreeMap::new();

    // chunk leaves into groups of 16
    for (i, chunk) in leaves_public_inputs.chunks(LEAF_PI_LEN).enumerate() {
        let root_hash = chunk[ROOT_START..ROOT_START + 4].try_into().unwrap(); // first felt of root hash
        let exit_account = chunk[EXIT_START..EXIT_START + 4].try_into().unwrap(); // first felt of exit account
        root_hash_groups.entry(root_hash).or_default().push(i);
        exit_account_groups.entry(exit_account).or_default().push(i);
    }

    // Produce stable Vec<Vec<usize>> in sorted order.
    let mut out_root: Vec<Vec<usize>> = Vec::with_capacity(root_hash_groups.len());

    for (_, root_hash_map) in root_hash_groups {
        out_root.push(root_hash_map);
    }

    // Produce stable Vec<Vec<usize>> in sorted order.
    let mut out_exit: Vec<Vec<usize>> = Vec::with_capacity(exit_account_groups.len());

    for (_, exits_map) in exit_account_groups {
        out_exit.push(exits_map);
    }
    let groupings = Groupings::new(out_root, out_exit);
    // assert that the length equals the n_leaves
    anyhow::ensure!(
        groupings.len() == n_leaves,
        "groupings length ({}) must equal number of leaf proofs ({}).",
        groupings.len(),
        n_leaves
    );
    Ok(groupings)
}

/// Build a wrapper circuit around the root aggregated proof that:
///  - verifies that proof,
///  - enforces groups have identical root/exit among members,
///  - sums funding across members with add_u128_base2_32 (big-endian),
///  - forwards all nullifiers,
///  - and PREPENDS two counts to the PI vector:
///    [ num_root_hashes(1), num_exit_accounts(1),
///    root_hash(4)*,
///    [funding_sum(4), exit(4)]*,
///    nullifiers(4)*,
///    padding... ]
fn aggregate_dedupe_public_inputs(
    proofs: Vec<AggregatedProof<F, C, D>>,
    indices: Groupings,
) -> anyhow::Result<AggregatedProof<F, C, D>> {
    anyhow::ensure!(
        proofs.len() == 1,
        "aggregate_dedupe_public_inputs expects a single root proof"
    );
    let root = &proofs[0];

    // Off-circuit sanity and sizing
    // TODO: figure out how to express these more global checks as a set of constaints in the circuit
    let n_leaf = indices.len();
    anyhow::ensure!(n_leaf > 0, "indices must not be empty");

    let root_pi_len = root.proof.public_inputs.len();
    anyhow::ensure!(
        root_pi_len.is_multiple_of(LEAF_PI_LEN),
        "Root PI length {} is not a multiple of {}",
        root_pi_len,
        LEAF_PI_LEN
    );
    anyhow::ensure!(root_pi_len / LEAF_PI_LEN == n_leaf,
        "Flattened indices length {} must equal number of leaf proofs {} (derived from root PI len {})",
        n_leaf, root_pi_len / LEAF_PI_LEN, root_pi_len);

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

    // Preload all roots & exits (as Targets) so we can count uniques with fixed loops
    let mut all_roots: Vec<[Target; 4]> = Vec::with_capacity(n_leaf);
    let mut all_funding_amounts: Vec<[Target; 4]> = Vec::with_capacity(n_leaf);
    let mut all_exits: Vec<[Target; 4]> = Vec::with_capacity(n_leaf);
    let mut all_nullifiers: Vec<[Target; 4]> = Vec::with_capacity(n_leaf);
    for i in 0..n_leaf {
        all_roots.push(limbs4_at(&child_pt.public_inputs, i, ROOT_START));
        all_exits.push(limbs4_at(&child_pt.public_inputs, i, EXIT_START));
        all_funding_amounts.push(limbs4_at(&child_pt.public_inputs, i, FUNDING_START));
        all_nullifiers.push(limbs4_at(&child_pt.public_inputs, i, NULLIFIER_START));
    }

    // Compute unique counts for roots and exits
    let num_roots_t = count_unique_4x32_keys(&mut builder, &all_roots);
    let num_exits_t = count_unique_4x32_keys(&mut builder, &all_exits);

    // Build deduped output
    let mut deduped_pis: Vec<Target> = Vec::new();

    // 1) PREPEND the two counters (needed for the aggregated circuit public input parser)
    deduped_pis.push(num_roots_t);
    deduped_pis.push(num_exits_t);

    let one = builder.one();

    for per_root in indices.root_hashes.iter() {
        let rep = per_root[0];
        let root_ref = all_roots[rep];
        // One root hash per group of deduped exit accounts.
        deduped_pis.extend_from_slice(&root_ref);

        for &idx in per_root.iter() {
            let root_i = all_roots[idx];
            let ee = bytes_digest_eq(&mut builder, root_i, root_ref);
            builder.connect(ee.target, one);
        }
    }

    for per_exit in indices.exit_accounts.iter() {
        let rep = per_exit[0];
        let exit_ref = all_exits[rep];

        // Sum funding across the group
        let mut acc = [
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
        ];

        for &idx in per_exit.iter() {
            // Enforce all members share same exit
            let exit_i = all_exits[idx];
            let ee = bytes_digest_eq(&mut builder, exit_i, exit_ref);
            builder.connect(ee.target, one);
            // Sum funding amounts
            let fund_i = all_funding_amounts[idx];
            let (sum, top_carry) = add_u128_base2_32_split(&mut builder, acc, fund_i);
            // Enforce no 129-bit overflow.
            let zero = builder.zero();
            builder.connect(top_carry, zero);
            acc = sum;
        }
        // Emit one compressed PI couplet: [funding_sum(4), exit(4)]
        deduped_pis.extend_from_slice(&acc);
        deduped_pis.extend_from_slice(&exit_ref);
    }
    // Forward ALL nullifiers
    deduped_pis.extend_from_slice(
        &all_nullifiers
            .into_iter()
            .flat_map(|n| n.to_vec())
            .collect::<Vec<Target>>(),
    );

    // Pad the rest of the deduped_pis until it is equal to root_pi_len + 2 (for the two counts)
    while deduped_pis.len() < root_pi_len + 2 {
        deduped_pis.push(builder.zero());
    }

    // Register compressed PIs
    builder.register_public_inputs(&deduped_pis);

    // Prove wrapper
    let circuit_data = builder.build();
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&vd_t, child_verifier_only)?;
    pw.set_proof_with_pis_target(&child_pt, &root.proof)?;

    let proof = circuit_data.prove(pw)?;
    Ok(AggregatedProof {
        proof,
        circuit_data,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

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
    use wormhole_circuit::inputs::{AggregatedPublicCircuitInputs, PublicInputsByAccount};
    use zk_circuits_common::circuit::{C, D, F};
    use zk_circuits_common::utils::BytesDigest;

    use crate::circuits::tree::{aggregate_to_tree, AggregatedProof, TreeAggregationConfig};

    // ---------------- Circuit ----------------

    /// Dummy wormhole leaf: PIs = [nullifier(4×u64), root_hash(4×u64), funding(4×u32), exit(4×u64)]
    /// We 32-bit range check the 4 funding limbs only.
    fn generate_dummy_wormhole_circuit() -> (CircuitData<F, C, D>, [Target; 16]) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pis_vec = builder.add_virtual_targets(16);
        let pis: [Target; 16] = pis_vec.clone().try_into().expect("exactly 16 targets");

        const FUNDING_START: usize = 8;

        // 32-bit range checks for funding limbs (indices 8..12).
        for k in 0..4 {
            builder.range_check(pis[FUNDING_START + k], 32);
        }

        builder.register_public_inputs(&pis_vec);

        let data = builder.build::<C>();
        (data, pis)
    }

    fn prove_dummy_wormhole(pis: [F; 16]) -> AggregatedProof<F, C, D> {
        let (circuit_data, targets) = generate_dummy_wormhole_circuit();
        let mut pw = PartialWitness::new();
        for (t, v) in targets.into_iter().zip(pis.into_iter()) {
            pw.set_target(t, v).unwrap();
        }
        let proof = circuit_data.prove(pw).unwrap();
        AggregatedProof {
            proof,
            circuit_data,
        }
    }

    // ---------------- Packing helpers ----------------

    /// u128 -> 4×u32 BE limbs.
    #[inline]
    fn u128_to_be_u32x4(v: u128) -> [u32; 4] {
        [
            ((v >> 96) & 0xFFFF_FFFF) as u32,
            ((v >> 64) & 0xFFFF_FFFF) as u32,
            ((v >> 32) & 0xFFFF_FFFF) as u32,
            (v & 0xFFFF_FFFF) as u32,
        ]
    }

    /// 4×u32 -> 4 felts (each <= 2^32).
    #[inline]
    fn limbs_u32_to_felts_be(l: [u32; 4]) -> [F; 4] {
        [
            F::from_canonical_u64(l[0] as u64),
            F::from_canonical_u64(l[1] as u64),
            F::from_canonical_u64(l[2] as u64),
            F::from_canonical_u64(l[3] as u64),
        ]
    }

    /// 4×u64 -> 4 felts (full 64-bit words).
    #[inline]
    fn limbs_u64_to_felts_be(l: [u64; 4]) -> [F; 4] {
        [
            F::from_canonical_u64(l[0]),
            F::from_canonical_u64(l[1]),
            F::from_canonical_u64(l[2]),
            F::from_canonical_u64(l[3]),
        ]
    }

    #[inline]
    fn make_pi_from_felts(
        nullifier: [F; 4], // 4×u64 as felts
        root: [F; 4],      // 4×u64 as felts
        funding: [F; 4],   // 4×u32 as felts
        exit: [F; 4],      // 4×u64 as felts
    ) -> [F; 16] {
        let mut out = [F::ZERO; 16];
        out[..4].copy_from_slice(&nullifier);
        out[4..8].copy_from_slice(&root);
        out[8..12].copy_from_slice(&funding);
        out[12..16].copy_from_slice(&exit);
        out
    }

    // ---------------- Hardcoded 64-bit-limb digests ----------------
    // 8 distinct exit accounts, roots, nullifiers — each as 4×u64 big-endian limbs.

    const EXIT_ACCOUNTS: [[u64; 4]; 8] = [
        [
            0x1111_0001_0000_0001,
            0x1111_0001_0000_0002,
            0x1111_0001_0000_0003,
            0x1111_0001_0000_0004,
        ],
        [
            0x2222_0001_0000_0001,
            0x2222_0001_0000_0002,
            0x2222_0001_0000_0003,
            0x2222_0001_0000_0004,
        ],
        [
            0x3333_0001_0000_0001,
            0x3333_0001_0000_0002,
            0x3333_0001_0000_0003,
            0x3333_0001_0000_0004,
        ],
        [
            0x4444_0001_0000_0001,
            0x4444_0001_0000_0002,
            0x4444_0001_0000_0003,
            0x4444_0001_0000_0004,
        ],
        [
            0x5555_0001_0000_0001,
            0x5555_0001_0000_0002,
            0x5555_0001_0000_0003,
            0x5555_0001_0000_0004,
        ],
        [
            0x6666_0001_0000_0001,
            0x6666_0001_0000_0002,
            0x6666_0001_0000_0003,
            0x6666_0001_0000_0004,
        ],
        [
            0x7777_0001_0000_0001,
            0x7777_0001_0000_0002,
            0x7777_0001_0000_0003,
            0x7777_0001_0000_0004,
        ],
        [
            0x8888_0001_0000_0001,
            0x8888_0001_0000_0002,
            0x8888_0001_0000_0003,
            0x8888_0001_0000_0004,
        ],
    ];

    const ROOT_HASHES: [[u64; 4]; 8] = [
        [
            0xAAAA_0001_0000_0001,
            0xAAAA_0001_0000_0002,
            0xAAAA_0001_0000_0003,
            0xAAAA_0001_0000_0004,
        ],
        [
            0xBBBB_0001_0000_0001,
            0xBBBB_0001_0000_0002,
            0xBBBB_0001_0000_0003,
            0xBBBB_0001_0000_0004,
        ],
        [
            0xCCCC_0001_0000_0001,
            0xCCCC_0001_0000_0002,
            0xCCCC_0001_0000_0003,
            0xCCCC_0001_0000_0004,
        ],
        [
            0xDDDD_0001_0000_0001,
            0xDDDD_0001_0000_0002,
            0xDDDD_0001_0000_0003,
            0xDDDD_0001_0000_0004,
        ],
        [
            0xEEEE_0001_0000_0001,
            0xEEEE_0001_0000_0002,
            0xEEEE_0001_0000_0003,
            0xEEEE_0001_0000_0004,
        ],
        [
            0xFFFF_0001_0000_0001,
            0xFFFF_0001_0000_0002,
            0xFFFF_0001_0000_0003,
            0xFFFF_0001_0000_0004,
        ],
        [
            0xABCD_0001_0000_0001,
            0xABCD_0001_0000_0002,
            0xABCD_0001_0000_0003,
            0xABCD_0001_0000_0004,
        ],
        [
            0x1234_0001_0000_0001,
            0x1234_0001_0000_0002,
            0x1234_0001_0000_0003,
            0x1234_0001_0000_0004,
        ],
    ];

    const NULLIFIERS: [[u64; 4]; 8] = [
        [
            0x90A0_0001_0000_0001,
            0x90A0_0001_0000_0002,
            0x90A0_0001_0000_0003,
            0x90A0_0001_0000_0004,
        ],
        [
            0x80B0_0001_0000_0001,
            0x80B0_0001_0000_0002,
            0x80B0_0001_0000_0003,
            0x80B0_0001_0000_0004,
        ],
        [
            0x70C0_0001_0000_0001,
            0x70C0_0001_0000_0002,
            0x70C0_0001_0000_0003,
            0x70C0_0001_0000_0004,
        ],
        [
            0x60D0_0001_0000_0001,
            0x60D0_0001_0000_0002,
            0x60D0_0001_0000_0003,
            0x60D0_0001_0000_0004,
        ],
        [
            0x50E0_0001_0000_0001,
            0x50E0_0001_0000_0002,
            0x50E0_0001_0000_0003,
            0x50E0_0001_0000_0004,
        ],
        [
            0x40F0_0001_0000_0001,
            0x40F0_0001_0000_0002,
            0x40F0_0001_0000_0003,
            0x40F0_0001_0000_0004,
        ],
        [
            0x30A1_0001_0000_0001,
            0x30A1_0001_0000_0002,
            0x30A1_0001_0000_0003,
            0x30A1_0001_0000_0004,
        ],
        [
            0x20B2_0001_0000_0001,
            0x20B2_0001_0000_0002,
            0x20B2_0001_0000_0003,
            0x20B2_0001_0000_0004,
        ],
    ];

    #[test]
    fn recursive_aggregation_tree() {
        // Non deterministic RNG.
        let mut rng = StdRng::from_entropy();

        // Choose number of unique roots & exits in [1..=8].
        let k_roots: usize = rng.gen_range(1..=8);
        let k_exits: usize = rng.gen_range(1..=8);

        // Select the first k indices for roots/exits
        let root_idxs: Vec<usize> = (0..k_roots).collect();
        let exit_idxs: Vec<usize> = (0..k_exits).collect();

        // Generate 8 random funding amounts with sum < u128::MAX.
        let funding_vals: [u128; 8] = loop {
            let mut vals = [0u128; 8];
            let mut ok = true;
            let mut acc: u128 = 0;
            for val in &mut vals {
                // pick within 2^96 so sums rarely approach u128::MAX
                let v: u128 = rng.gen::<u128>() & ((1u128 << 96) - 1);
                *val = v;
                if let Some(next) = acc.checked_add(v) {
                    acc = next;
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                break vals;
            }
        };

        // Convert funding to 4×u32-limb felts (BE).
        let funding_felts: [[F; 4]; 8] =
            funding_vals.map(|v| limbs_u32_to_felts_be(u128_to_be_u32x4(v)));

        // Convert hardcoded digests (4×u64 limbs) to felts.
        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let roots_felts: [[F; 4]; 8] = ROOT_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // Build 8 (num of leaf inputs for the default tree config) dummy wormhole PI sets:
        // - Nullifiers: all 8 (distinct).
        // - Roots: cycle through the chosen k_roots.
        // - Exits:  cycle through the chosen k_exits (different phase to avoid perfect pairing).
        // - Funding: the 8 random u128s (as 4×u32 felts).
        let mut pis_list: Vec<[F; 16]> = Vec::with_capacity(8);
        for i in 0..8 {
            let nfel = nullifiers_felts[i];
            let rfel = roots_felts[root_idxs[i % k_roots]];
            let efel = exits_felts[exit_idxs[(7 - i) % k_exits]];
            let ffel = funding_felts[i];

            pis_list.push(make_pi_from_felts(nfel, rfel, ffel, efel));
        }

        // Prove 8 leaf proofs.
        let leaves = pis_list
            .clone()
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();

        // Aggregate them into a tree.
        let common_data = &leaves[0].circuit_data.common.clone();
        let verifier_data = &leaves[0].circuit_data.verifier_only.clone();
        let to_aggregate = leaves.into_iter().map(|p| p.proof).collect();

        let config = TreeAggregationConfig::default();
        let root_proof =
            aggregate_to_tree(to_aggregate, common_data, verifier_data, config).unwrap();

        // Parse the aggregated PIs produced by the circuit.
        let aggregated_public_inputs = AggregatedPublicCircuitInputs::try_from_slice(
            root_proof.proof.public_inputs.as_slice(),
        )
        .unwrap();

        // ---------------------------
        // Build the reference aggregation OFF-CIRCUIT
        // ---------------------------

        // Small helper: convert 4 felts -> BytesDigest
        let felts_to_digest = |a: [F; 4]| -> BytesDigest {
            BytesDigest::try_from(&a[..]).expect("digest from 4 felts")
        };

        // 1) Collect unique roots in a deterministic order (sorted).
        let mut roots_set: BTreeSet<BytesDigest> = BTreeSet::new();

        // 2) Sum funding by exit account (across all roots), deterministic map.
        let mut exit_sums: BTreeMap<BytesDigest, u128> = BTreeMap::new();

        // 3) Collect all nullifiers in **leaf order**.
        let mut nullifiers_ref: Vec<BytesDigest> = Vec::with_capacity(8);

        for (i, pis) in pis_list.iter().enumerate() {
            // Layout: [null(0..4), root(4..8), funding(8..12), exit(12..16)]
            let null_f = [pis[0], pis[1], pis[2], pis[3]];
            let root_f = [pis[4], pis[5], pis[6], pis[7]];
            let exit_f = [pis[12], pis[13], pis[14], pis[15]];

            let null_d = felts_to_digest(null_f);
            let root_d = felts_to_digest(root_f);
            let exit_d = felts_to_digest(exit_f);

            let funding_u128 = funding_vals[i];

            roots_set.insert(root_d);
            exit_sums
                .entry(exit_d)
                .and_modify(|s| *s = s.checked_add(funding_u128).expect("no u128 overflow"))
                .or_insert(funding_u128);
            nullifiers_ref.push(null_d);
        }

        // Materialize sorted roots.
        let root_hashes_ref: Vec<BytesDigest> = roots_set.into_iter().collect();

        // Materialize account_data sorted by exit digest.
        let mut account_data_ref: Vec<PublicInputsByAccount> = Vec::with_capacity(exit_sums.len());
        for (exit_d, sum_u128) in exit_sums.into_iter() {
            account_data_ref.push(PublicInputsByAccount {
                summed_funding_amount: sum_u128,
                exit_account: exit_d,
            });
        }

        let aggregated_public_inputs_ref = AggregatedPublicCircuitInputs {
            root_hashes: root_hashes_ref,
            account_data: account_data_ref,
            nullifiers: nullifiers_ref,
        };

        assert_eq!(
            aggregated_public_inputs, aggregated_public_inputs_ref,
            "aggregated PIs parsed from proof did not match reference aggregation"
        );

        println!(
            "parsed aggregated public inputs: {:?}",
            aggregated_public_inputs
        );

        // Verify the final root proof.
        root_proof.circuit_data.verify(root_proof.proof).unwrap();
    }
}
