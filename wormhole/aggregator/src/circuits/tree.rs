use plonky2::plonk::proof::ProofWithPublicInputs;
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
#[cfg(feature = "multithread")]
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use zk_circuits_common::{
    circuit::{C, D, F},
    gadgets::{bytes_digest_eq, count_unique_4x32_keys, limb1_at_offset, limbs4_at_offset},
};

/// The default branching factor of the proof tree. A higher value means more proofs get aggregated
/// into a single proof at each level.
pub const DEFAULT_TREE_BRANCHING_FACTOR: usize = 2;
/// The default depth of the tree of the aggregated proof, counted as the longest path of edges between the
/// leaf nodes and the root node.
pub const DEFAULT_TREE_DEPTH: u32 = 3;

const LEAF_PI_LEN: usize = 20;
const ASSET_ID_START: usize = 0; // 1 felt
const OUTPUT_AMOUNT_START: usize = 1; // 1 felt (output amount after fee deduction)
const VOLUME_FEE_BPS_START: usize = 2; // 1 felt (volume fee in basis points)
const NULLIFIER_START: usize = 3; // 4 felts
const EXIT_START: usize = 7; // 4 felts
const BLOCK_HASH_START: usize = 11; // 4 felts
#[allow(dead_code)] // Used in tests
const PARENT_HASH_START: usize = 15; // 4 felts
const BLOCK_NUMBER_START: usize = 19; // 1 felt
/// A proof containing both the proof data and the circuit data needed to verify it.
#[derive(Debug)]
pub struct AggregatedProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub circuit_data: CircuitData<F, C, D>,
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
    let n_leaf = leaf_proofs.len();

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

    // Build the final wrapper circuit with fixed structure
    let root_proof = aggregate_dedupe_public_inputs(proofs, n_leaf)?;

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

/// Circuit gadget that takes in a chunk of proofs, verifies each one, and aggregates their public inputs.
///
/// All proofs must be valid proofs from the same circuit (same CommonCircuitData).
/// For padding with dummy proofs, use proofs generated from the same WormholeProver
/// with block_hash = 0 as a sentinel.
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
        // Verify the proof
        let proof_t = builder.add_virtual_proof_with_pis(common_data);
        builder.verify_proof::<C>(&proof_t, &verifier_data_t, common_data);

        // Aggregate public inputs of proof
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

/// Build a wrapper circuit around the root aggregated proof with FIXED STRUCTURE.
///
/// This circuit has a deterministic structure regardless of input data, which is required
/// for on-chain verification where the verifier binaries are pre-built.
///
/// The circuit:
///  - verifies the root proof
///  - enforces all real proofs (non-zero block_hash) reference the same block
///  - enforces asset ID and volume_fee_bps consistency across all proofs
///  - for each of N "slots", computes the sum of amounts for proofs matching that slot's exit account
///  - forwards all nullifiers
///
/// Public inputs layout:
///    [num_exit_accounts(1),
///     asset_id(1),
///     volume_fee_bps(1),
///     block_hash(4),
///     block_number(1),
///     [funding_sum(1), exit(4)] * N,   // N slots, one per proof
///     nullifiers(4) * N,
///     padding...]
///
/// Note: The exit account slots are always N (one per proof slot), even if multiple proofs
/// share the same exit account. The chain can deduplicate by exit account after verification.
fn aggregate_dedupe_public_inputs(
    proofs: Vec<AggregatedProof<F, C, D>>,
    n_leaf: usize,
) -> anyhow::Result<AggregatedProof<F, C, D>> {
    anyhow::ensure!(
        proofs.len() == 1,
        "aggregate_dedupe_public_inputs expects a single root proof"
    );
    let root = &proofs[0];

    let root_pi_len = root.proof.public_inputs.len();
    anyhow::ensure!(
        root_pi_len.is_multiple_of(LEAF_PI_LEN),
        "Root PI length {} is not a multiple of {}",
        root_pi_len,
        LEAF_PI_LEN
    );
    anyhow::ensure!(
        root_pi_len / LEAF_PI_LEN == n_leaf,
        "n_leaf {} must match number of proofs in root PI {} (root_pi_len={})",
        n_leaf,
        root_pi_len / LEAF_PI_LEN,
        root_pi_len
    );

    // Build wrapper circuit
    let child_common = &root.circuit_data.common;
    let child_verifier_only = &root.circuit_data.verifier_only;

    let mut builder = CircuitBuilder::new(child_common.config.clone());
    let vd_t = builder.add_virtual_verifier_data(child_common.fri_params.config.cap_height);

    // Child proof target = the (only) root aggregated proof
    let child_pt = builder.add_virtual_proof_with_pis(child_common);
    builder.verify_proof::<C>(&child_pt, &vd_t, child_common);

    let child_pi_targets = &child_pt.public_inputs;

    // Count unique exit accounts (for informational purposes in public inputs)
    let num_exits_t = count_unique_4x32_keys::<_, _, LEAF_PI_LEN, EXIT_START>(
        &mut builder,
        child_pi_targets,
        n_leaf,
    );

    // Reference values from first proof
    let asset_ref = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(child_pi_targets, 0);
    let volume_fee_bps_ref =
        limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(child_pi_targets, 0);

    let one = builder.one();
    let zero = builder.zero();

    // Build output public inputs
    let mut output_pis: Vec<Target> = Vec::new();

    // 1) Number of unique exit accounts
    output_pis.push(num_exits_t);
    // 2) Asset ID
    output_pis.push(asset_ref);
    // 3) Volume fee bps
    output_pis.push(volume_fee_bps_ref);

    // =========================================================================
    // BLOCK VALIDATION (Fixed Structure)
    // =========================================================================
    // All real proofs (block_hash != 0) must reference the same block.
    // We use the first real proof's block as the reference.
    // Dummies (block_hash == 0) are skipped via conditional constraints.
    //
    // For fixed circuit structure, we always iterate over all N proofs.

    // Get block_hash from proof 0 as reference (might be dummy or real)
    let block_ref = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(child_pi_targets, 0);
    let block_number_ref = limb1_at_offset::<LEAF_PI_LEN, BLOCK_NUMBER_START>(child_pi_targets, 0);

    // Build the dummy sentinel [0,0,0,0] for comparison
    let dummy_sentinel = [zero, zero, zero, zero];

    // For each proof, check: if it's not a dummy, it must match block_ref
    // Constraint: is_dummy OR (block_hash == block_ref)
    // Equivalently: NOT(is_real AND block_hash != block_ref)
    for i in 0..n_leaf {
        let block_i = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(child_pi_targets, i);

        // is_dummy_i = (block_i == [0,0,0,0])
        let is_dummy_i = bytes_digest_eq(&mut builder, block_i, dummy_sentinel);

        // matches_ref = (block_i == block_ref)
        let matches_ref = bytes_digest_eq(&mut builder, block_i, block_ref);

        // Constraint: is_dummy OR matches_ref must be true
        // i.e., is_dummy + matches_ref - is_dummy*matches_ref >= 1
        // Since both are bool, OR = is_dummy + matches_ref - is_dummy*matches_ref
        let or_result = builder.or(is_dummy_i, matches_ref);
        builder.connect(or_result.target, one);

        // Also enforce asset_id and volume_fee_bps consistency
        let asset_i = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(child_pi_targets, i);
        builder.connect(asset_i, asset_ref);
        let volume_fee_bps_i =
            limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(child_pi_targets, i);
        builder.connect(volume_fee_bps_i, volume_fee_bps_ref);
    }

    // Output the reference block hash and number
    // (If all proofs are dummies, this will be [0,0,0,0] and 0, which is fine)
    output_pis.extend_from_slice(&block_ref);
    output_pis.push(block_number_ref);

    // =========================================================================
    // EXIT ACCOUNT GROUPING (Fixed Structure)
    // =========================================================================
    // We output N "slots", one per proof position.
    // For each slot i, we output:
    //   - sum of amounts from all proofs that match proof[i]'s exit account
    //   - the exit account from proof[i]
    //
    // This creates a fixed N×N iteration structure.
    // The chain can deduplicate slots with matching exit accounts after verification.

    for slot in 0..n_leaf {
        let exit_slot = limbs4_at_offset::<LEAF_PI_LEN, EXIT_START>(child_pi_targets, slot);

        // Sum amounts from all proofs that match this slot's exit account
        let mut acc = zero;
        for j in 0..n_leaf {
            let exit_j = limbs4_at_offset::<LEAF_PI_LEN, EXIT_START>(child_pi_targets, j);
            let amount_j = limb1_at_offset::<LEAF_PI_LEN, OUTPUT_AMOUNT_START>(child_pi_targets, j);

            // matches = (exit_j == exit_slot)
            let matches = bytes_digest_eq(&mut builder, exit_j, exit_slot);

            // conditional_amount = matches ? amount_j : 0
            let conditional_amount = builder.select(matches, amount_j, zero);

            acc = builder.add(acc, conditional_amount);
        }

        // Range check the sum
        builder.range_check(acc, 32);

        // Output: [sum, exit_account(4)]
        output_pis.push(acc);
        output_pis.extend_from_slice(&exit_slot);
    }

    // =========================================================================
    // NULLIFIERS
    // =========================================================================
    // Forward all N nullifiers
    for i in 0..n_leaf {
        output_pis.extend_from_slice(&limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(
            child_pi_targets,
            i,
        ));
    }

    // Pad to expected length
    // Expected: root_pi_len + metadata (3 for num_exits, asset_id, volume_fee_bps)
    //           + 5 for block (hash + number)
    //           = root_pi_len + 8
    // But we now output N*(1+4) for exit slots instead of variable
    // So total = 3 + 5 + N*5 + N*4 = 8 + 9*N
    // We pad to a consistent size for the parser
    while output_pis.len() < root_pi_len + 8 {
        output_pis.push(zero);
    }

    // Register public inputs
    builder.register_public_inputs(&output_pis);

    // Build and prove
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
    use std::collections::BTreeMap;

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
        aggregate_to_tree, AggregatedProof, TreeAggregationConfig, ASSET_ID_START,
        BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_START, LEAF_PI_LEN, NULLIFIER_START,
        OUTPUT_AMOUNT_START, PARENT_HASH_START, VOLUME_FEE_BPS_START,
    };

    const TEST_ASSET_ID_U64: u64 = 0;
    const TEST_VOLUME_FEE_BPS: u64 = 10; // 0.1% = 10 basis points

    // ---------------- Circuit ----------------

    /// Dummy wormhole leaf for the *new* aggregator layout:
    ///
    /// PIs per leaf (length = LEAF_PI_LEN = 20):
    ///   [ asset_id(1×felt),
    ///     output_amount(1×felt),
    ///     volume_fee_bps(1×felt),
    ///     nullifier(4×felt),
    ///     exit(4×felt),
    ///     block_hash(4×felt),
    ///     parent_hash(4×felt),
    ///     block_number(1×felt) ]
    ///
    fn generate_dummy_wormhole_circuit() -> (CircuitData<F, C, D>, [Target; LEAF_PI_LEN]) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pis_vec = builder.add_virtual_targets(LEAF_PI_LEN);
        let pis: [Target; LEAF_PI_LEN] = pis_vec
            .clone()
            .try_into()
            .expect("exactly LEAF_PI_LEN targets");

        builder.range_check(pis[OUTPUT_AMOUNT_START], 32);
        builder.range_check(pis[VOLUME_FEE_BPS_START], 32);

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

    /// Build one leaf PI in the new layout (funding is 1 felt).
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn make_pi_from_felts(
        asset_id: F,
        output_amount: F,
        volume_fee_bps: F,
        nullifier: [F; 4],
        exit: [F; 4],
        block_hash: [F; 4],
        parent_hash: [F; 4],
        block_number: F,
    ) -> [F; LEAF_PI_LEN] {
        let mut out = [F::ZERO; LEAF_PI_LEN];
        out[ASSET_ID_START] = asset_id;
        out[OUTPUT_AMOUNT_START] = output_amount;
        out[VOLUME_FEE_BPS_START] = volume_fee_bps;
        out[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&nullifier);
        out[EXIT_START..EXIT_START + 4].copy_from_slice(&exit);
        out[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&block_hash);
        out[PARENT_HASH_START..PARENT_HASH_START + 4].copy_from_slice(&parent_hash);
        out[BLOCK_NUMBER_START] = block_number;
        out
    }

    // ---------------- Hardcoded 64-bit-limb digests ----------------

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
        let mut rng = StdRng::from_seed([41u8; 32]);

        // Choose number of unique exits in [1..=8].
        let k_exits: usize = rng.gen_range(1..=8);
        let exit_idxs: Vec<usize> = (0..k_exits).collect();

        // Funding values as *one felt each*
        // We bit shift by 3 to ensure accumulated sums fit in 32 bits.
        let funding_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 3);

        let funding_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(funding_vals_u32[i] as u64));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // NEW: All proofs must be from the SAME block
        // Use block 0's hash for all proofs
        let common_block_hash = block_hashes_felts[0];
        let common_parent_hash = [F::ZERO; 4]; // First block has no parent
        let common_block_number = F::from_canonical_u64(42); // Arbitrary block number

        let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        // Build leaves - all from the same block
        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            let nfel = nullifiers_felts[i];
            let efel = exits_felts[exit_idxs[(7 - i) % k_exits]];
            let ffel = funding_felts[i];

            pis_list.push(make_pi_from_felts(
                asset_id,
                ffel,
                volume_fee_bps,
                nfel,
                efel,
                common_block_hash, // Same block for all
                common_parent_hash,
                common_block_number,
            ));
        }

        let leaves = pis_list
            .clone()
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();

        let common_data = &leaves[0].circuit_data.common.clone();
        let verifier_data = &leaves[0].circuit_data.verifier_only.clone();
        let to_aggregate = leaves.into_iter().map(|p| p.proof).collect();

        let config = TreeAggregationConfig::default();
        let root_proof =
            aggregate_to_tree(to_aggregate, common_data, verifier_data, config).unwrap();

        // ---------------------------
        // Reference aggregation OFF-CIRCUIT (field sums)
        // ---------------------------
        let n_leaf = pis_list.len();
        assert_eq!(n_leaf, 8);

        // Compute expected sums per exit account
        let mut exit_sums: BTreeMap<[F; 4], F> = BTreeMap::new();
        for (i, pis) in pis_list.iter().enumerate() {
            let exit_f: [F; 4] = [
                pis[EXIT_START],
                pis[EXIT_START + 1],
                pis[EXIT_START + 2],
                pis[EXIT_START + 3],
            ];
            let funding_f = funding_felts[i];
            exit_sums
                .entry(exit_f)
                .and_modify(|s| *s += funding_f)
                .or_insert(funding_f);
        }
        let num_exits_ref = exit_sums.len();

        // Block reference - all proofs use the same block
        let block_hash_ref = common_block_hash;
        let block_num_ref = common_block_number;

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
        // Parse aggregated PIs (NEW FIXED LAYOUT)
        // ---------------------------
        // Layout:
        // [ num_exits(1), asset_id(1), volume_fee_bps(1), block_hash(4), block_number(1),
        //   [funding_sum(1), exit(4)] * N,  (N slots, one per proof)
        //   nullifiers(4) * N,
        //   padding... ]
        let pis = &root_proof.proof.public_inputs;
        let root_pi_len = n_leaf * LEAF_PI_LEN;
        assert_eq!(pis.len(), root_pi_len + 8); // +8 for header (3 + 5)

        let num_exits_circuit = pis[0].to_canonical_u64() as usize;
        assert_eq!(num_exits_circuit, num_exits_ref);

        let asset_id_circuit = pis[1];
        assert_eq!(asset_id_circuit, asset_id);

        let volume_fee_bps_circuit = pis[2];
        assert_eq!(volume_fee_bps_circuit, volume_fee_bps);

        let block_hash_circuit: [F; 4] = [pis[3], pis[4], pis[5], pis[6]];
        let block_num_circuit = pis[7];
        assert_eq!(block_hash_circuit, block_hash_ref);
        assert_eq!(block_num_circuit, block_num_ref);

        let mut idx = 8usize;

        // Exit slots region: N slots, each with [funding_sum(1), exit(4)]
        // Each slot i contains the sum of all amounts with exit_account == exit_account[i]
        // Collect all sums by exit account from circuit output
        let mut exit_sums_from_circuit: BTreeMap<[F; 4], F> = BTreeMap::new();
        for _ in 0..n_leaf {
            let sum_circuit = pis[idx];
            idx += 1;

            let exit_key_circuit = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
            idx += 4;

            // Sum may appear multiple times for same exit (once per slot with that exit)
            // The actual sum is computed by summing all proofs with matching exit
            exit_sums_from_circuit
                .entry(exit_key_circuit)
                .and_modify(|_| {}) // Don't double-count, each slot outputs the full sum
                .or_insert(sum_circuit);
        }

        // Verify sums match expected
        for (exit_key, sum_ref) in exit_sums.iter() {
            let sum_from_circuit = exit_sums_from_circuit.get(exit_key).unwrap();
            assert_eq!(
                *sum_from_circuit, *sum_ref,
                "sum mismatch for exit {:?}",
                exit_key
            );
        }

        // Nullifiers: 4 felts each
        for (leaf_idx, nullifier_expected) in nullifiers_ref.iter().enumerate() {
            let n0 = pis[idx];
            let n1 = pis[idx + 1];
            let n2 = pis[idx + 2];
            let n3 = pis[idx + 3];
            idx += 4;

            assert_eq!(
                [n0, n1, n2, n3],
                *nullifier_expected,
                "nullifier mismatch at leaf {leaf_idx}"
            );
        }

        // Padding must be zeros.
        while idx < pis.len() {
            assert_eq!(pis[idx], F::ZERO, "expected zero padding at index {idx}");
            idx += 1;
        }

        // Verify the final root proof.
        root_proof
            .circuit_data
            .verify(root_proof.proof.clone())
            .unwrap();
    }

    // ---------- Negative test: different blocks should fail --------------------------

    #[test]
    fn recursive_aggregation_tree_different_blocks_fails() {
        let mut rng = StdRng::from_seed([42u8; 32]);

        let k_exits: usize = rng.gen_range(1..=8);
        let exit_idxs: Vec<usize> = (0..k_exits).collect();

        let funding_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 3);
        let funding_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(funding_vals_u32[i] as u64));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        let parent_hashes_felts: [[F; 4]; 8] = [[F::ZERO; 4]; 8];

        // Different block numbers (this is the old behavior that should now fail)
        let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));
        let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            let nfel = nullifiers_felts[i];
            let efel = exits_felts[exit_idxs[(7 - i) % k_exits]];
            let ffel = funding_felts[i];
            // Each proof uses a DIFFERENT block hash - this should fail
            let bhash = block_hashes_felts[i];
            let phash = parent_hashes_felts[i];
            let bnum = block_numbers[i];

            pis_list.push(make_pi_from_felts(
                asset_id,
                ffel,
                volume_fee_bps,
                nfel,
                efel,
                bhash,
                phash,
                bnum,
            ));
        }

        let leaves = pis_list
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();

        let common_data = &leaves[0].circuit_data.common.clone();
        let verifier_data = &leaves[0].circuit_data.verifier_only.clone();
        let to_aggregate = leaves.into_iter().map(|p| p.proof).collect();

        let config = TreeAggregationConfig::default();
        let res = aggregate_to_tree(to_aggregate, common_data, verifier_data, config);

        assert!(
            res.is_err(),
            "expected failure because proofs are from different blocks"
        );
    }

    // ---------- Negative test: mismatched asset ID --------------------------

    #[test]
    fn recursive_aggregation_tree_mismatched_asset_id_fails() {
        let asset_a = F::from_canonical_u64(7);
        let asset_b = F::from_canonical_u64(9);

        let funding_felts: [F; 8] = core::array::from_fn(|_| F::from_canonical_u64(1));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        let mut parent_hashes_felts: [[F; 4]; 8] = [[F::ZERO; 4]; 8];
        parent_hashes_felts[1..8].copy_from_slice(&block_hashes_felts[..7]);

        let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            let asset_id = if i == 3 { asset_b } else { asset_a };
            pis_list.push(make_pi_from_felts(
                asset_id,
                funding_felts[i],
                volume_fee_bps,
                nullifiers_felts[i],
                exits_felts[i],
                block_hashes_felts[i],
                parent_hashes_felts[i],
                block_numbers[i],
            ));
        }

        let leaves = pis_list
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();

        let common_data = &leaves[0].circuit_data.common.clone();
        let verifier_data = &leaves[0].circuit_data.verifier_only.clone();
        let to_aggregate = leaves.into_iter().map(|p| p.proof).collect();

        let config = TreeAggregationConfig::default();
        let res = aggregate_to_tree(to_aggregate, common_data, verifier_data, config);

        assert!(res.is_err(), "expected failure due to mismatched asset IDs");
    }

    // ---------- Test: mixed real proofs + dummy proofs with block_hash=0 sentinel ------

    #[test]
    fn recursive_aggregation_tree_with_dummy_proofs() {
        // Test that we can aggregate 2 real proofs + 6 dummy proofs (block_hash = 0)
        // The dummies should be excluded from block validation but included in exit grouping.

        let mut rng = StdRng::from_seed([99u8; 32]);

        let funding_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 3);
        let funding_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(funding_vals_u32[i] as u64));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // First two proofs are real (all from SAME block)
        // Remaining 6 are dummies (block_hash = 0)
        let num_real_proofs = 2;

        // NEW: All real proofs must be from the same block
        let common_block_hash = block_hashes_felts[0];
        let common_parent_hash = [F::ZERO; 4];
        let common_block_number = F::from_canonical_u64(42);

        let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);

        // Real proofs (indices 0 and 1) - all from same block
        for i in 0..num_real_proofs {
            pis_list.push(make_pi_from_felts(
                asset_id,
                funding_felts[i],
                volume_fee_bps,
                nullifiers_felts[i],
                exits_felts[i],
                common_block_hash,
                common_parent_hash,
                common_block_number,
            ));
        }

        // Dummy proofs (indices 2-7): block_hash = 0, exit_account = 0, output_amount = 0
        let dummy_exit = [F::ZERO; 4];
        let dummy_block_hash = [F::ZERO; 4];
        let dummy_parent_hash = [F::ZERO; 4];
        let dummy_output_amount = F::ZERO;

        for i in num_real_proofs..8 {
            pis_list.push(make_pi_from_felts(
                asset_id,
                dummy_output_amount,
                volume_fee_bps,
                nullifiers_felts[i],
                dummy_exit,
                dummy_block_hash,
                dummy_parent_hash,
                F::ZERO,
            ));
        }

        let leaves = pis_list
            .clone()
            .into_iter()
            .map(prove_dummy_wormhole)
            .collect::<Vec<_>>();

        let common_data = &leaves[0].circuit_data.common.clone();
        let verifier_data = &leaves[0].circuit_data.verifier_only.clone();
        let to_aggregate = leaves.into_iter().map(|p| p.proof).collect();

        let config = TreeAggregationConfig::default();
        let root_proof =
            aggregate_to_tree(to_aggregate, common_data, verifier_data, config).unwrap();

        // Verify the final root proof.
        root_proof
            .circuit_data
            .verify(root_proof.proof.clone())
            .unwrap();

        // Check public inputs structure
        let pis = &root_proof.proof.public_inputs;

        // The block hash should be from the first real proof (proof[0] is the reference)
        let block_hash_circuit: [F; 4] = [pis[3], pis[4], pis[5], pis[6]];
        assert_eq!(
            block_hash_circuit, common_block_hash,
            "block hash should match common block"
        );

        // The block number should match common block number
        let block_num_circuit = pis[7];
        assert_eq!(
            block_num_circuit, common_block_number,
            "block number should match common block"
        );

        println!(
            "Successfully aggregated {} real proofs + {} dummy proofs!",
            num_real_proofs,
            8 - num_real_proofs
        );
    }
}
