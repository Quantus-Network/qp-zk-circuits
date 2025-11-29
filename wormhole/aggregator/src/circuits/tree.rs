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
    gadgets::{
        add_u128_base2_32_split, bytes_digest_eq, count_unique_4x32_keys, limb1_at_offset,
        limbs4_at_offset,
    },
};

/// The default branching factor of the proof tree. A higher value means more proofs get aggregated
/// into a single proof at each level.
pub const DEFAULT_TREE_BRANCHING_FACTOR: usize = 2;
/// The default depth of the tree of the aggregated proof, counted as the longest path of edges between the
/// leaf nodes and the root node.
pub const DEFAULT_TREE_DEPTH: u32 = 3;

const LEAF_PI_LEN: usize = 21;
const NULLIFIER_START: usize = 0; // 4 felts (not used in dedupe output)
const FUNDING_START: usize = 4; // 4 felts
const EXIT_START: usize = 8; // 4 felts
const BLOCK_HASH_START: usize = 12; // 4 felts
const PARENT_HASH_START: usize = 16; // 4 felts
const BLOCK_NUMBER_START: usize = 20; // 1 felt

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
    pub blocks: Vec<Vec<usize>>,
    pub exit_accounts: Vec<Vec<usize>>,
    pub size: usize,
}

impl Groupings {
    pub fn new(blocks: Vec<Vec<usize>>, exit_accounts: Vec<Vec<usize>>) -> Self {
        let len_blocks = blocks.iter().map(|v| v.len()).sum::<usize>();
        let len_exit_accounts = exit_accounts.iter().map(|v| v.len()).sum::<usize>();
        // assert that both lengths are equal
        assert_eq!(
            len_blocks, len_exit_accounts,
            "length of blocks ({}) must be equal to length of exit_accounts ({}).",
            len_blocks, len_exit_accounts
        );
        Self {
            blocks,
            exit_accounts,
            size: len_blocks,
        }
    }
    pub fn len(&self) -> usize {
        self.size
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

    let mut block_groups = BTreeMap::<F, Vec<usize>>::new();
    let mut exit_account_groups = BTreeMap::<[F; 4], Vec<usize>>::new();

    // chunk leaves into groups of 21
    for (i, chunk) in leaves_public_inputs.chunks(LEAF_PI_LEN).enumerate() {
        let block_number = chunk[BLOCK_NUMBER_START];
        let exit_account = chunk[EXIT_START..EXIT_START + 4].try_into().unwrap();
        block_groups.entry(block_number).or_default().push(i);
        exit_account_groups.entry(exit_account).or_default().push(i);
    }

    // Produce stable Vec<Vec<usize>> in sorted order.
    let out_blocks = block_groups.into_values().collect();

    // Produce stable Vec<Vec<usize>> in sorted order.
    let out_exit = exit_account_groups.into_values().collect();

    let groupings = Groupings::new(out_blocks, out_exit);
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
///  - enforces that adjacent blocks are connected via parent_hash
///  - sums funding across members with add_u128_base2_32 (big-endian),
///  - forwards all nullifiers,
///  - and PREPENDS number of orphan blocks, number of exit accounts, and the last block data to the PI vector:
///    [num_orphan_blocks(1), num_exit_accounts(1),
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

    // Off-circuit sanity and sizing checks
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

    let child_pi_targets = &child_pt.public_inputs;

    let num_exits_t = count_unique_4x32_keys::<_, _, LEAF_PI_LEN, EXIT_START>(
        &mut builder,
        child_pi_targets,
        n_leaf,
    );

    // Build deduped output
    let mut deduped_pis: Vec<Target> = Vec::new();

    // 1) PREPEND the number of exit accounts (needed for the aggregated circuit public input parser)
    deduped_pis.push(num_exits_t);

    let one: Target = builder.one();

    let mut parent_hash =
        limbs4_at_offset::<LEAF_PI_LEN, PARENT_HASH_START>(child_pi_targets, indices.blocks[0][0]);

    for per_block in indices.blocks.iter() {
        let rep = per_block[0];
        let block_ref = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(child_pi_targets, rep);
        for &idx in per_block.iter() {
            let block_i = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(child_pi_targets, idx);
            let ee = bytes_digest_eq(&mut builder, block_i, block_ref);
            builder.connect(ee.target, one);
            // Enforce parent hash linkage
            let ee_parent = bytes_digest_eq(
                &mut builder,
                parent_hash,
                limbs4_at_offset::<LEAF_PI_LEN, PARENT_HASH_START>(child_pi_targets, idx),
            );
            builder.connect(ee_parent.target, one);
        }
        // Update parent_hash for next iteration
        parent_hash = block_ref;
    }
    // Append the last block's hash (which is not a parent of any other block)
    deduped_pis.extend_from_slice(&parent_hash);
    // Append the last block's number
    deduped_pis.push(limb1_at_offset::<LEAF_PI_LEN, BLOCK_NUMBER_START>(
        child_pi_targets,
        indices.blocks.last().unwrap()[0],
    ));

    for per_exit in indices.exit_accounts.iter() {
        let rep = per_exit[0];
        let exit_ref = limbs4_at_offset::<LEAF_PI_LEN, EXIT_START>(child_pi_targets, rep);

        // Sum funding across the group
        let mut acc = [
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
        ];

        for &idx in per_exit.iter() {
            // Enforce all members share same exit
            let exit_i = limbs4_at_offset::<LEAF_PI_LEN, EXIT_START>(child_pi_targets, idx);
            let ee = bytes_digest_eq(&mut builder, exit_i, exit_ref);
            builder.connect(ee.target, one);
            // Sum funding amounts
            let fund_i = limbs4_at_offset::<LEAF_PI_LEN, FUNDING_START>(child_pi_targets, idx);
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
    for i in 0..n_leaf {
        deduped_pis.extend_from_slice(&limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(
            child_pi_targets,
            i,
        ));
    }

    // Pad the rest of the deduped_pis until it is equal to root_pi_len + 1 (for the one count)
    while deduped_pis.len() < root_pi_len + 1 {
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

    use crate::circuits::tree::BTreeMap;
    use plonky2::field::types::PrimeField64;
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

    use zk_circuits_common::circuit::{C, D, F};

    use super::{
        aggregate_to_tree, AggregatedProof, TreeAggregationConfig, BLOCK_HASH_START,
        BLOCK_NUMBER_START, EXIT_START, FUNDING_START, LEAF_PI_LEN, NULLIFIER_START,
        PARENT_HASH_START,
    };

    // ---------------- Circuit ----------------

    /// Dummy wormhole leaf for the *new* aggregator layout:
    ///
    /// PIs per leaf (length = LEAF_PI_LEN = 21):
    ///   [ nullifier(4×felt),
    ///     funding(4×felt, 32-bit limbs, BE),
    ///     exit(4×felt, 32-bit limbs, BE),
    ///     block_hash(4×felt),
    ///     parent_hash(4×felt),
    ///     block_number(1×felt) ]
    ///
    /// We 32-bit range check the 4 funding limbs and 4 exit limbs only.
    fn generate_dummy_wormhole_circuit() -> (CircuitData<F, C, D>, [Target; LEAF_PI_LEN]) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pis_vec = builder.add_virtual_targets(LEAF_PI_LEN);
        let pis: [Target; LEAF_PI_LEN] = pis_vec
            .clone()
            .try_into()
            .expect("exactly LEAF_PI_LEN targets");

        // 32-bit range checks for funding limbs.
        for k in 0..4 {
            builder.range_check(pis[FUNDING_START + k], 32);
        }

        builder.register_public_inputs(&pis_vec);

        let data = builder.build::<C>();
        (data, pis)
    }

    fn prove_dummy_wormhole(pis: [F; LEAF_PI_LEN]) -> AggregatedProof<F, C, D> {
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

    /// Build one leaf PI in the new layout.
    #[inline]
    fn make_pi_from_felts(
        nullifier: [F; 4],   // 4×felt
        funding: [F; 4],     // 4×felt, 32-bit limbs
        exit: [F; 4],        // 4×felt, 32-bit limbs
        block_hash: [F; 4],  // 4×felt
        parent_hash: [F; 4], // 4×felt
        block_number: F,     // 1×felt
    ) -> [F; LEAF_PI_LEN] {
        let mut out = [F::ZERO; LEAF_PI_LEN];
        out[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&nullifier);
        out[FUNDING_START..FUNDING_START + 4].copy_from_slice(&funding);
        out[EXIT_START..EXIT_START + 4].copy_from_slice(&exit);
        out[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&block_hash);
        out[PARENT_HASH_START..PARENT_HASH_START + 4].copy_from_slice(&parent_hash);
        out[BLOCK_NUMBER_START] = block_number;
        out
    }

    /// Helper: generate 8 funding values with total sum < u128::MAX to avoid overflow.
    fn gen_non_overflowing_funding_vals(rng: &mut StdRng) -> [u128; 8] {
        loop {
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
        }
    }

    // ---------------- Hardcoded 64-bit-limb digests ----------------
    // 8 distinct exit accounts, block hashes, nullifiers — each as 4×u64 big-endian limbs.

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

    // Re-use the old ROOT_HASHES constants as *block hashes*.
    const BLOCK_HASHES: [[u64; 4]; 8] = [
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
        let mut rng = StdRng::from_seed([41u8; 32]);

        // Choose number of unique exits in [1..=8].
        let k_exits: usize = rng.gen_range(1..=8);

        // Select the first k indices for exits.
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

        // Convert hardcoded digests to felts.
        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // Build parent hashes forming a simple chain:
        //   parent_hash[0] = 0 (genesis)
        //   parent_hash[i] = block_hash[i-1] for i >= 1
        let mut parent_hashes_felts: [[F; 4]; 8] = [[F::ZERO; 4]; 8];
        parent_hashes_felts[1..8].copy_from_slice(&block_hashes_felts[..(8 - 1)]);

        // Block numbers: 0..8 as field elements.
        let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));

        // Build 8 leaf PI sets:
        // - Nullifiers: all 8 (distinct).
        // - Exits: cycle through the chosen k_exits (different phase to avoid perfect pairing).
        // - Funding: the 8 random u128s (as 4×u32 felts).
        // - Block hashes: BLOCK_HASHES[i].
        // - Parent hashes: parent_hashes_felts[i] (chain).
        // - Block numbers: 0..7.
        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            let nfel = nullifiers_felts[i];
            let efel = exits_felts[exit_idxs[(7 - i) % k_exits]];
            let ffel = funding_felts[i];
            let bhash = block_hashes_felts[i];
            let phash = parent_hashes_felts[i];
            let bnum = block_numbers[i];

            pis_list.push(make_pi_from_felts(nfel, ffel, efel, bhash, phash, bnum));
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

        // ---------------------------
        // Build the reference aggregation OFF-CIRCUIT
        // ---------------------------

        let n_leaf = pis_list.len();
        assert_eq!(n_leaf, 8);

        // 1) Sum funding by exit account (across all blocks), deterministic map (BTreeMap).
        let mut exit_sums: BTreeMap<[F; 4], u128> = BTreeMap::new();

        for (i, pis) in pis_list.iter().enumerate() {
            let exit_f: [F; 4] = [
                pis[EXIT_START],
                pis[EXIT_START + 1],
                pis[EXIT_START + 2],
                pis[EXIT_START + 3],
            ];

            let funding_u128 = funding_vals[i];

            exit_sums
                .entry(exit_f)
                .and_modify(|s| *s = s.checked_add(funding_u128).expect("no u128 overflow"))
                .or_insert(funding_u128);
        }

        let num_exits_ref = exit_sums.len();

        // 2) Determine last block (by max block_number).
        let mut last_block_idx = 0usize;
        let mut last_block_num_u64: u64 = 0;
        for (i, pis) in pis_list.iter().enumerate() {
            let bnum = pis[BLOCK_NUMBER_START].to_canonical_u64();
            if bnum >= last_block_num_u64 {
                last_block_num_u64 = bnum;
                last_block_idx = i;
            }
        }
        let last_block_hash_ref: [F; 4] = [
            pis_list[last_block_idx][BLOCK_HASH_START],
            pis_list[last_block_idx][BLOCK_HASH_START + 1],
            pis_list[last_block_idx][BLOCK_HASH_START + 2],
            pis_list[last_block_idx][BLOCK_HASH_START + 3],
        ];
        let last_block_num_ref = pis_list[last_block_idx][BLOCK_NUMBER_START];

        // 3) Forward all nullifiers in leaf order.
        let mut nullifiers_ref: Vec<[F; 4]> = Vec::with_capacity(n_leaf);
        for pis in pis_list.iter() {
            nullifiers_ref.push([
                pis[NULLIFIER_START],
                pis[NULLIFIER_START + 1],
                pis[NULLIFIER_START + 2],
                pis[NULLIFIER_START + 3],
            ]);
        }

        // ---------------------------
        // Parse the aggregated PIs produced by the circuit
        // ---------------------------
        let pis = &root_proof.proof.public_inputs;
        let root_pi_len = n_leaf * LEAF_PI_LEN;
        assert_eq!(
            pis.len(),
            root_pi_len + 1,
            "aggregated PI length must be root_pi_len + 1"
        );

        // Layout:
        //   [ num_exits(1),
        //     last_block_hash(4),
        //     last_block_number(1),
        //     [funding_sum(4), exit(4)]*,
        //     nullifiers(4)*,
        //     padding... ]
        let num_exits_circuit = pis[0].to_canonical_u64() as usize;
        assert_eq!(
            num_exits_circuit, num_exits_ref,
            "num_exits mismatch between circuit and reference"
        );

        let last_block_hash_circuit: [F; 4] = [pis[1], pis[2], pis[3], pis[4]];
        let last_block_num_circuit = pis[5];

        assert_eq!(
            last_block_hash_circuit, last_block_hash_ref,
            "last_block_hash mismatch between circuit and reference"
        );
        assert_eq!(
            last_block_num_circuit, last_block_num_ref,
            "last_block_number mismatch between circuit and reference"
        );

        // Exit data region starts at index 6.
        let mut idx = 6usize;

        // Reconstruct exit_sums from circuit PIs and compare with exit_sums (BTreeMap).
        let mut exit_sums_from_circuit: BTreeMap<[F; 4], u128> = BTreeMap::new();

        for (exit_key, sum_u128_ref) in exit_sums.iter() {
            // funding_sum(4)
            let f0 = pis[idx];
            let f1 = pis[idx + 1];
            let f2 = pis[idx + 2];
            let f3 = pis[idx + 3];
            idx += 4;

            // exit(4)
            let e0 = pis[idx];
            let e1 = pis[idx + 1];
            let e2 = pis[idx + 2];
            let e3 = pis[idx + 3];
            idx += 4;

            let exit_key_circuit = [e0, e1, e2, e3];

            // Convert funding felts (4×32-bit limbs) back to u128 (BE).
            let limb0 = f0.to_canonical_u64() as u128;
            let limb1 = f1.to_canonical_u64() as u128;
            let limb2 = f2.to_canonical_u64() as u128;
            let limb3 = f3.to_canonical_u64() as u128;

            let sum_u128_circuit = (limb0 << 96) | (limb1 << 64) | (limb2 << 32) | limb3;

            exit_sums_from_circuit.insert(exit_key_circuit, sum_u128_circuit);

            // Also directly compare this pair against the reference map entry.
            assert_eq!(
                exit_key_circuit, *exit_key,
                "exit account key mismatch between circuit and reference"
            );
            assert_eq!(
                sum_u128_circuit, *sum_u128_ref,
                "funding sum mismatch for exit account"
            );
        }

        assert_eq!(
            exit_sums_from_circuit, exit_sums,
            "exit_sums map mismatch between circuit and reference"
        );

        // Now idx points at the start of the forwarded nullifiers.
        for (leaf_idx, nullifier_expected) in nullifiers_ref.iter().enumerate() {
            let n0 = pis[idx];
            let n1 = pis[idx + 1];
            let n2 = pis[idx + 2];
            let n3 = pis[idx + 3];
            idx += 4;

            let nullifier_circuit = [n0, n1, n2, n3];
            assert_eq!(
                nullifier_circuit, *nullifier_expected,
                "nullifier mismatch at leaf {}",
                leaf_idx
            );
        }

        // Remaining entries must be zero padding.
        while idx < pis.len() {
            assert_eq!(
                pis[idx],
                F::ZERO,
                "expected zero padding at index {}, found {:?}",
                idx,
                pis[idx]
            );
            idx += 1;
        }

        // Finally, verify the final root proof.
        root_proof
            .circuit_data
            .verify(root_proof.proof.clone())
            .unwrap();
    }

    // ---------- Negative test 1: broken parent chain --------------------------

    /// Break the parent-hash chain so that the wrapper circuit's parent-hash linkage
    /// constraints are violated. Aggregation should fail.
    #[test]
    fn recursive_aggregation_tree_broken_parent_chain_fails() {
        // Deterministic RNG.
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Choose number of unique exits in [1..=8].
        let k_exits: usize = rng.gen_range(1..=8);
        let exit_idxs: Vec<usize> = (0..k_exits).collect();

        // Generate 8 random funding amounts with sum < u128::MAX.
        let funding_vals = gen_non_overflowing_funding_vals(&mut rng);

        // Convert funding to 4×u32-limb felts (BE).
        let funding_felts: [[F; 4]; 8] =
            funding_vals.map(|v| limbs_u32_to_felts_be(u128_to_be_u32x4(v)));

        // Convert hardcoded digests to felts.
        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // Wrong parent hashes: all zeros (no real chain).
        let parent_hashes_felts: [[F; 4]; 8] = [[F::ZERO; 4]; 8];

        // Block numbers: 0..8 as field elements.
        let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));

        // Build 8 leaf PI sets.
        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            let nfel = nullifiers_felts[i];
            let efel = exits_felts[exit_idxs[(7 - i) % k_exits]];
            let ffel = funding_felts[i];
            let bhash = block_hashes_felts[i];
            let phash = parent_hashes_felts[i];
            let bnum = block_numbers[i];

            pis_list.push(make_pi_from_felts(nfel, ffel, efel, bhash, phash, bnum));
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
        let res = aggregate_to_tree(to_aggregate, common_data, verifier_data, config);

        assert!(
            res.is_err(),
            "expected aggregation to fail due to broken parent hash chain, but it succeeded"
        );
    }

    // ---------- Negative test 2: funding overflow -----------------------------

    /// Create two leaves with the same exit account but funding values that overflow
    /// 128-bit addition in the circuit (base-2^32 limbs). The overflow bit is constrained
    /// to be zero, so aggregation should fail.
    #[test]
    fn recursive_aggregation_tree_funding_overflow_fails() {
        // No RNG needed; deterministic construction.

        // Funding: two very large 128-bit values that will *overflow* when added.
        let big: u128 = 1u128 << 127;
        let mut funding_vals = [0u128; 8];
        funding_vals[0] = big;
        funding_vals[1] = big;
        // Others are zero.

        // Convert funding to 4×u32-limb felts (BE).
        let funding_felts: [[F; 4]; 8] =
            funding_vals.map(|v| limbs_u32_to_felts_be(u128_to_be_u32x4(v)));

        // Convert hardcoded digests to felts.
        let exits_felts_all: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // Parent hashes forming a valid chain.
        let mut parent_hashes_felts: [[F; 4]; 8] = [[F::ZERO; 4]; 8];
        parent_hashes_felts[1..8].copy_from_slice(&block_hashes_felts[..(8 - 1)]);

        // Block numbers: 0..8 as field elements.
        let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));

        // Build 8 leaf PI sets:
        // - Leaves 0 and 1 share the same exit account, so they end up in the same exit group.
        //   Their funding sums to 2 * 2^127 = 2^128, which overflows 128 bits.
        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            let nfel = nullifiers_felts[i];
            let efel = if i < 2 {
                exits_felts_all[0]
            } else {
                exits_felts_all[i]
            };
            let ffel = funding_felts[i];
            let bhash = block_hashes_felts[i];
            let phash = parent_hashes_felts[i];
            let bnum = block_numbers[i];

            pis_list.push(make_pi_from_felts(nfel, ffel, efel, bhash, phash, bnum));
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
        let res = aggregate_to_tree(to_aggregate, common_data, verifier_data, config);

        assert!(
            res.is_err(),
            "expected aggregation to fail due to funding overflow in an exit group, but it succeeded"
        );
    }
}
