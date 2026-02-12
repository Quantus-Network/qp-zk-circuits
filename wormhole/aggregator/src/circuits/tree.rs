use plonky2::field::types::Field;
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
    gadgets::{bytes_digest_eq, limb1_at_offset, limbs4_at_offset},
};

/// Public inputs per leaf proof (Bitcoin-style 2-output layout)
/// Layout: asset_id(1) + output_amount_1(1) + output_amount_2(1) + volume_fee_bps(1) +
///         nullifier(4) + exit_account_1(4) + exit_account_2(4) + block_hash(4) + parent_hash(4) + block_number(1)
/// = 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + 4 + 1 = 25
const LEAF_PI_LEN: usize = 25;
const ASSET_ID_START: usize = 0; // 1 felt
const OUTPUT_AMOUNT_1_START: usize = 1; // 1 felt (spend amount)
const OUTPUT_AMOUNT_2_START: usize = 2; // 1 felt (change amount)
const VOLUME_FEE_BPS_START: usize = 3; // 1 felt (volume fee in basis points)
const NULLIFIER_START: usize = 4; // 4 felts
const EXIT_1_START: usize = 8; // 4 felts (spend destination)
const EXIT_2_START: usize = 12; // 4 felts (change destination)
const BLOCK_HASH_START: usize = 16; // 4 felts
#[allow(dead_code)] // Used in tests
const PARENT_HASH_START: usize = 20; // 4 felts
const BLOCK_NUMBER_START: usize = 24; // 1 felt

// Legacy alias for tests (points to first output)
#[allow(dead_code)]
const OUTPUT_AMOUNT_START: usize = OUTPUT_AMOUNT_1_START;
#[allow(dead_code)]
const EXIT_START: usize = EXIT_1_START;
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
///  - enforces all real proofs (non-zero block_hash) reference the same block for their storage proofs
///    (Note: the underlying transfers can occur in different blocks; this constraint only applies to
///    the block used when generating the storage proof, i.e., when the proof is created)
///  - enforces asset ID and volume_fee_bps consistency across all proofs
///  - for each of 2*N "slots" (2 outputs per proof), computes the sum of amounts for proofs matching that slot's exit account
///  - forwards all nullifiers
///
/// Public inputs layout:
///    [num_exit_accounts(1),
///     asset_id(1),
///     volume_fee_bps(1),
///     block_hash(4),
///     block_number(1),
///     [funding_sum(1), exit(4)] * 2*N,   // 2*N slots (2 outputs per proof)
///     nullifiers(4) * N,
///     padding...]
///
/// Note: The exit account slots are always 2*N (two per proof slot for Bitcoin-style spend+change).
/// The chain can deduplicate by exit account after verification. Slots with exit_account=[0;32]
/// and amount=0 represent unused second outputs.
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

    // Note: With 2 outputs per proof, counting unique exits in-circuit is complex.
    // We output 2*N exit slots and let the chain deduplicate after parsing.
    // The num_exits field is set to 2*n_leaf as an upper bound.
    let num_exit_slots_t = builder.constant(F::from_canonical_u64((n_leaf * 2) as u64));

    // Reference values from first proof
    let asset_ref = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(child_pi_targets, 0);
    let volume_fee_bps_ref =
        limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(child_pi_targets, 0);

    let one = builder.one();
    let zero = builder.zero();

    // Build output public inputs
    let mut output_pis: Vec<Target> = Vec::new();

    // 1) Number of exit slots (2*N for Bitcoin-style 2 outputs per proof)
    output_pis.push(num_exit_slots_t);
    // 2) Asset ID
    output_pis.push(asset_ref);
    // 3) Volume fee bps
    output_pis.push(volume_fee_bps_ref);

    // =========================================================================
    // BLOCK VALIDATION (Fixed Structure)
    // =========================================================================
    // All real proofs (block_hash != 0) must reference the same block for their storage proofs.
    // This means all proofs must be generated against the same chain state snapshot.
    // Note: The underlying transfers can occur in different blocks; this constraint only
    // applies to the block used when generating the storage proof (when the proof is created).
    //
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
    // EXIT ACCOUNT GROUPING (Fixed Structure - 2 outputs per proof)
    // =========================================================================
    // With Bitcoin-style 2-output proofs, each leaf proof has 2 exit accounts:
    //   - exit_account_1 (spend destination) with output_amount_1
    //   - exit_account_2 (change destination) with output_amount_2
    //
    // We output 2*N "slots" (2 outputs per proof).
    // For each slot, we compute the sum of all matching amounts across all 2*N outputs.
    //
    // Slot mapping:
    //   - slot 2*i   -> proof[i]'s exit_account_1, sums all matching output_amount_1 and output_amount_2
    //   - slot 2*i+1 -> proof[i]'s exit_account_2, sums all matching output_amount_1 and output_amount_2
    //
    // The chain can deduplicate slots with matching exit accounts after verification.
    // Unused second outputs have exit_account_2 = [0;32] and output_amount_2 = 0.

    let num_exit_slots = n_leaf * 2;

    // Helper: get exit account and amount for a given (proof_idx, output_idx) pair
    // output_idx: 0 = first output, 1 = second output
    let get_exit_and_amount = |proof_idx: usize, output_idx: usize| -> ([Target; 4], Target) {
        let exit = if output_idx == 0 {
            limbs4_at_offset::<LEAF_PI_LEN, EXIT_1_START>(child_pi_targets, proof_idx)
        } else {
            limbs4_at_offset::<LEAF_PI_LEN, EXIT_2_START>(child_pi_targets, proof_idx)
        };
        let amount = if output_idx == 0 {
            limb1_at_offset::<LEAF_PI_LEN, OUTPUT_AMOUNT_1_START>(child_pi_targets, proof_idx)
        } else {
            limb1_at_offset::<LEAF_PI_LEN, OUTPUT_AMOUNT_2_START>(child_pi_targets, proof_idx)
        };
        (exit, amount)
    };

    for slot in 0..num_exit_slots {
        let proof_idx = slot / 2;
        let output_idx = slot % 2;
        let (exit_slot, _) = get_exit_and_amount(proof_idx, output_idx);

        // Check if this exit account already appeared in an earlier slot (deduplication)
        // If so, we'll output zero for this slot to avoid double-minting
        let mut is_duplicate = builder._false();
        for earlier in 0..slot {
            let earlier_proof_idx = earlier / 2;
            let earlier_output_idx = earlier % 2;
            let (exit_earlier, _) = get_exit_and_amount(earlier_proof_idx, earlier_output_idx);
            let matches_earlier = bytes_digest_eq(&mut builder, exit_earlier, exit_slot);
            is_duplicate = builder.or(is_duplicate, matches_earlier);
        }

        // Sum amounts from all 2*N outputs that match this slot's exit account
        let mut acc = zero;
        for j in 0..num_exit_slots {
            let j_proof_idx = j / 2;
            let j_output_idx = j % 2;
            let (exit_j, amount_j) = get_exit_and_amount(j_proof_idx, j_output_idx);

            // matches = (exit_j == exit_slot)
            let matches = bytes_digest_eq(&mut builder, exit_j, exit_slot);

            // conditional_amount = matches ? amount_j : 0
            let conditional_amount = builder.select(matches, amount_j, zero);

            acc = builder.add(acc, conditional_amount);
        }

        // If this is a duplicate slot, zero out the sum to prevent double-minting
        // The chain will skip slots with zero amount
        let final_sum = builder.select(is_duplicate, zero, acc);

        // Range check the sum (with 2 outputs per proof, max sum could be larger)
        // 32-bit outputs * 2*N proofs, need 32 + log2(2*N) bits
        builder.range_check(final_sum, 40);

        // Output: [sum, exit_account(4)]
        output_pis.push(final_sum);
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
    // Layout: metadata(8) + 2*N exit slots(5 each) + N nullifiers(4 each)
    //       = 8 + 2*N*5 + N*4 = 8 + 14*N
    // Root PI len = N * LEAF_PI_LEN = N * 25
    // We pad to root_pi_len + 8 for consistent sizing
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
        BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START, EXIT_2_START, LEAF_PI_LEN,
        NULLIFIER_START, OUTPUT_AMOUNT_1_START, OUTPUT_AMOUNT_2_START, PARENT_HASH_START,
        VOLUME_FEE_BPS_START,
    };

    const TEST_ASSET_ID_U64: u64 = 0;
    const TEST_VOLUME_FEE_BPS: u64 = 10; // 0.1% = 10 basis points

    /// Test config: branching_factor=8, depth=1 (8 leaf proofs)
    fn test_aggregation_config() -> TreeAggregationConfig {
        TreeAggregationConfig::new(8, 1)
    }

    // ---------------- Circuit ----------------

    /// Dummy wormhole leaf for the Bitcoin-style 2-output layout:
    ///
    /// PIs per leaf (length = LEAF_PI_LEN = 25):
    ///   [ asset_id(1×felt),
    ///     output_amount_1(1×felt),     // spend amount
    ///     output_amount_2(1×felt),     // change amount
    ///     volume_fee_bps(1×felt),
    ///     nullifier(4×felt),
    ///     exit_account_1(4×felt),      // spend destination
    ///     exit_account_2(4×felt),      // change destination
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

        builder.range_check(pis[OUTPUT_AMOUNT_1_START], 32);
        builder.range_check(pis[OUTPUT_AMOUNT_2_START], 32);
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

    /// Build one leaf PI in the Bitcoin-style 2-output layout.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn make_pi_from_felts(
        asset_id: F,
        output_amount_1: F,
        output_amount_2: F,
        volume_fee_bps: F,
        nullifier: [F; 4],
        exit_1: [F; 4],
        exit_2: [F; 4],
        block_hash: [F; 4],
        parent_hash: [F; 4],
        block_number: F,
    ) -> [F; LEAF_PI_LEN] {
        let mut out = [F::ZERO; LEAF_PI_LEN];
        out[ASSET_ID_START] = asset_id;
        out[OUTPUT_AMOUNT_1_START] = output_amount_1;
        out[OUTPUT_AMOUNT_2_START] = output_amount_2;
        out[VOLUME_FEE_BPS_START] = volume_fee_bps;
        out[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&nullifier);
        out[EXIT_1_START..EXIT_1_START + 4].copy_from_slice(&exit_1);
        out[EXIT_2_START..EXIT_2_START + 4].copy_from_slice(&exit_2);
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

        // Generate random funding values (output amounts)
        // Use bit shift to ensure sums fit in 32 bits
        let output1_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
        let output2_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);

        let output1_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(output1_vals_u32[i] as u64));
        let output2_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(output2_vals_u32[i] as u64));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // All proofs must be from the SAME block
        let common_block_hash = block_hashes_felts[0];
        let common_parent_hash = [F::ZERO; 4];
        let common_block_number = F::from_canonical_u64(42);

        let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
        let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);

        // Build leaves - each proof has 2 outputs
        // For simplicity: exit_1 = exits_felts[i], exit_2 = exits_felts[(i+1)%8]
        let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
        for i in 0..8 {
            let nfel = nullifiers_felts[i];
            let exit_1 = exits_felts[i];
            let exit_2 = exits_felts[(i + 1) % 8]; // Change goes to next account

            pis_list.push(make_pi_from_felts(
                asset_id,
                output1_felts[i],
                output2_felts[i],
                volume_fee_bps,
                nfel,
                exit_1,
                exit_2,
                common_block_hash,
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

        let config = test_aggregation_config();
        let root_proof =
            aggregate_to_tree(to_aggregate, common_data, verifier_data, config).unwrap();

        // ---------------------------
        // Reference aggregation OFF-CIRCUIT
        // ---------------------------
        let n_leaf = pis_list.len();
        assert_eq!(n_leaf, 8);

        // Compute expected sums per exit account (across both outputs)
        let mut exit_sums: BTreeMap<[F; 4], F> = BTreeMap::new();
        for (i, pis) in pis_list.iter().enumerate() {
            // First output
            let exit_1: [F; 4] = [
                pis[EXIT_1_START],
                pis[EXIT_1_START + 1],
                pis[EXIT_1_START + 2],
                pis[EXIT_1_START + 3],
            ];
            let amount_1 = output1_felts[i];
            exit_sums
                .entry(exit_1)
                .and_modify(|s| *s += amount_1)
                .or_insert(amount_1);

            // Second output
            let exit_2: [F; 4] = [
                pis[EXIT_2_START],
                pis[EXIT_2_START + 1],
                pis[EXIT_2_START + 2],
                pis[EXIT_2_START + 3],
            ];
            let amount_2 = output2_felts[i];
            exit_sums
                .entry(exit_2)
                .and_modify(|s| *s += amount_2)
                .or_insert(amount_2);
        }

        // Block reference
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
        // Parse aggregated PIs (Bitcoin-style 2-output layout)
        // ---------------------------
        // Layout:
        // [ num_exit_slots(1), asset_id(1), volume_fee_bps(1), block_hash(4), block_number(1),
        //   [funding_sum(1), exit(4)] * 2*N,  (2*N slots, 2 outputs per proof)
        //   nullifiers(4) * N,
        //   padding... ]
        let pis = &root_proof.proof.public_inputs;
        let root_pi_len = n_leaf * LEAF_PI_LEN;
        assert_eq!(pis.len(), root_pi_len + 8); // +8 for header

        let num_exit_slots_circuit = pis[0].to_canonical_u64() as usize;
        assert_eq!(num_exit_slots_circuit, n_leaf * 2); // 2 outputs per proof

        let asset_id_circuit = pis[1];
        assert_eq!(asset_id_circuit, asset_id);

        let volume_fee_bps_circuit = pis[2];
        assert_eq!(volume_fee_bps_circuit, volume_fee_bps);

        let block_hash_circuit: [F; 4] = [pis[3], pis[4], pis[5], pis[6]];
        let block_num_circuit = pis[7];
        assert_eq!(block_hash_circuit, block_hash_ref);
        assert_eq!(block_num_circuit, block_num_ref);

        let mut idx = 8usize;

        // Exit slots region: 2*N slots, each with [funding_sum(1), exit(4)]
        // Duplicate exit accounts have sum=0 (deduplication in circuit)
        // Collect all sums by exit account from circuit output
        let mut exit_sums_from_circuit: BTreeMap<[F; 4], F> = BTreeMap::new();
        for _ in 0..(n_leaf * 2) {
            let sum_circuit = pis[idx];
            idx += 1;

            let exit_key_circuit = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
            idx += 4;

            // Only record non-zero sums (zero means duplicate slot)
            if sum_circuit != F::ZERO {
                exit_sums_from_circuit
                    .entry(exit_key_circuit)
                    .and_modify(|_| {}) // Don't double-count
                    .or_insert(sum_circuit);
            }
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

        let output1_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
        let output1_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(output1_vals_u32[i] as u64));

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
            let exit_1 = exits_felts[i];
            let exit_2 = [F::ZERO; 4]; // No change output
                                       // Each proof uses a DIFFERENT block hash - this should fail
            let bhash = block_hashes_felts[i];
            let phash = parent_hashes_felts[i];
            let bnum = block_numbers[i];

            pis_list.push(make_pi_from_felts(
                asset_id,
                output1_felts[i],
                F::ZERO, // No second output
                volume_fee_bps,
                nfel,
                exit_1,
                exit_2,
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

        let config = test_aggregation_config();
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

        let output_felts: [F; 8] = core::array::from_fn(|_| F::from_canonical_u64(1));

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
                output_felts[i],
                F::ZERO, // No second output
                volume_fee_bps,
                nullifiers_felts[i],
                exits_felts[i],
                [F::ZERO; 4], // No second exit
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

        let config = test_aggregation_config();
        let res = aggregate_to_tree(to_aggregate, common_data, verifier_data, config);

        assert!(res.is_err(), "expected failure due to mismatched asset IDs");
    }

    // ---------- Test: mixed real proofs + dummy proofs with block_hash=0 sentinel ------

    #[test]
    fn recursive_aggregation_tree_with_dummy_proofs() {
        // Test that we can aggregate 2 real proofs + 6 dummy proofs (block_hash = 0)
        // The dummies should be excluded from block validation but included in exit grouping.

        let mut rng = StdRng::from_seed([99u8; 32]);

        let output_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
        let output_felts: [F; 8] =
            core::array::from_fn(|i| F::from_canonical_u64(output_vals_u32[i] as u64));

        let exits_felts: [[F; 4]; 8] = EXIT_ACCOUNTS.map(limbs_u64_to_felts_be);
        let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs_u64_to_felts_be);
        let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs_u64_to_felts_be);

        // First two proofs are real (all from SAME block)
        // Remaining 6 are dummies (block_hash = 0)
        let num_real_proofs = 2;

        // All real proofs must be from the same block
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
                output_felts[i],
                F::ZERO, // No second output for simplicity
                volume_fee_bps,
                nullifiers_felts[i],
                exits_felts[i],
                [F::ZERO; 4], // No second exit
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

        for nullifier in nullifiers_felts.iter().skip(num_real_proofs) {
            pis_list.push(make_pi_from_felts(
                asset_id,
                dummy_output_amount,
                dummy_output_amount, // Both outputs zero
                volume_fee_bps,
                *nullifier,
                dummy_exit,
                dummy_exit, // Both exits zero
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

        let config = test_aggregation_config();
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
