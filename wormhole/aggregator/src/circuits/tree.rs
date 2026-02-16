use plonky2::field::types::Field;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::{
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    },
};
use zk_circuits_common::utils::digest_bytes_to_felts;
use zk_circuits_common::{
    aggregation::{aggregate_with_wrapper, AggregatedProof, AggregationWrapper},
    circuit::{C, D, F},
    gadgets::{bytes_digest_eq, limb1_at_offset, limbs4_at_offset},
};

use crate::dummy_proof::generate_random_nullifier;

/// Public inputs per leaf proof (Bitcoin-style 2-output layout)
/// Layout: asset_id(1) + output_amount_1(1) + output_amount_2(1) + volume_fee_bps(1) +
///         nullifier(4) + exit_account_1(4) + exit_account_2(4) + block_hash(4) + block_number(1)
/// = 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + 1 = 21
const LEAF_PI_LEN: usize = 21;
const ASSET_ID_START: usize = 0; // 1 felt
const OUTPUT_AMOUNT_1_START: usize = 1; // 1 felt (spend amount)
const OUTPUT_AMOUNT_2_START: usize = 2; // 1 felt (change amount)
const VOLUME_FEE_BPS_START: usize = 3; // 1 felt (volume fee in basis points)
const NULLIFIER_START: usize = 4; // 4 felts
const EXIT_1_START: usize = 8; // 4 felts (spend destination)
const EXIT_2_START: usize = 12; // 4 felts (change destination)
const BLOCK_HASH_START: usize = 16; // 4 felts
const BLOCK_NUMBER_START: usize = 20; // 1 felt

/// Layer-0 aggregated proof output layout constants.
///
/// These define the public inputs layout produced by `WormholeAggregationWrapper`.
/// Used by higher layers (e.g., Layer1Wrapper) to parse layer-0 output.
///
/// Layout:
/// ```text
/// [num_exit_slots(1), asset_id(1), volume_fee_bps(1),
///  block_hash(4), block_number(1),
///  [sum(1), exit_account(4)] * 2*N,
///  nullifier(4) * N,
///  padding...]
/// ```
pub mod aggregated_output {
    use qp_wormhole_inputs::PUBLIC_INPUTS_FELTS_LEN;

    /// Offset of `num_exit_slots` in the output PIs.
    pub const NUM_EXIT_SLOTS_OFFSET: usize = 0;
    /// Offset of `asset_id` in the output PIs.
    pub const ASSET_ID_OFFSET: usize = 1;
    /// Offset of `volume_fee_bps` in the output PIs.
    pub const VOLUME_FEE_BPS_OFFSET: usize = 2;
    /// Offset of `block_hash` (4 felts) in the output PIs.
    pub const BLOCK_HASH_OFFSET: usize = 3;
    /// Offset of `block_number` in the output PIs.
    pub const BLOCK_NUMBER_OFFSET: usize = 7;
    /// Length of the fixed header before exit slot data.
    pub const HEADER_LEN: usize = 8;
    /// Each exit slot is [sum(1), exit_account(4)] = 5 felts.
    pub const EXIT_SLOT_LEN: usize = 5;

    /// Compute the number of exit slots for a given number of leaf proofs (2 per leaf).
    pub const fn exit_slots_count(num_leaves: usize) -> usize {
        num_leaves * 2
    }

    /// Compute the offset where exit slot data starts.
    pub const fn exit_slots_start() -> usize {
        HEADER_LEN
    }

    /// Compute the offset where nullifier data starts for a given number of leaf proofs.
    pub const fn nullifiers_start(num_leaves: usize) -> usize {
        HEADER_LEN + exit_slots_count(num_leaves) * EXIT_SLOT_LEN
    }

    /// Compute the total PI length of a layer-0 aggregated proof.
    pub const fn pi_len(num_leaves: usize) -> usize {
        PUBLIC_INPUTS_FELTS_LEN * num_leaves + 8
    }
}

/// Wormhole-specific aggregation wrapper.
///
/// Builds a wrapper circuit around the merged proof that:
/// - Enforces all real proofs reference the same block (block_hash != 0)
/// - Enforces asset_id and volume_fee_bps consistency
/// - Deduplicates exit accounts and sums amounts (2 outputs per proof, Bitcoin-style)
/// - Replaces dummy nullifiers with random values to prevent collisions on-chain
///
/// Dummy proofs are detected by `block_hash == [0,0,0,0]`.
pub struct WormholeAggregationWrapper {
    dummy_nullifiers: Vec<[F; 4]>,
}

impl WormholeAggregationWrapper {
    /// Create a new wrapper with random dummy nullifiers for `n_leaf` proofs.
    pub fn new(n_leaf: usize) -> Self {
        let dummy_nullifiers = (0..n_leaf)
            .map(|_| digest_bytes_to_felts(generate_random_nullifier()))
            .collect();
        Self { dummy_nullifiers }
    }
}

impl AggregationWrapper for WormholeAggregationWrapper {
    fn is_dummy(&self, proof: &ProofWithPublicInputs<F, C, D>) -> bool {
        // Wormhole dummy proofs have block_hash == [0,0,0,0]
        proof.public_inputs[BLOCK_HASH_START..BLOCK_HASH_START + 4]
            .iter()
            .all(|f| f.is_zero())
    }

    fn build_wrapper(
        &self,
        merged: AggregatedProof,
        n_inner: usize,
    ) -> anyhow::Result<AggregatedProof> {
        aggregate_dedupe_public_inputs(merged, n_inner, &self.dummy_nullifiers)
    }
}

/// Aggregate N wormhole leaf proofs into a single aggregated proof.
///
/// Uses [`WormholeAggregationWrapper`] to apply wormhole-specific constraints
/// on top of the generic [`aggregate_with_wrapper`] pipeline.
pub fn aggregate_proofs(
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    common_data: &CommonCircuitData<F, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> anyhow::Result<AggregatedProof> {
    let wrapper = WormholeAggregationWrapper::new(leaf_proofs.len());
    aggregate_with_wrapper(leaf_proofs, common_data, verifier_data, &wrapper)
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
///  - overrides nullifiers from dummy proofs with provided dummy nullifiers.
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
    root: AggregatedProof,
    n_leaf: usize,
    dummy_nullifiers: &[[F; 4]],
) -> anyhow::Result<AggregatedProof> {
    anyhow::ensure!(
        dummy_nullifiers.len() == n_leaf,
        "dummy_nullifiers must have length n_leaf"
    );

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

    // Used later to generate unique nullifiers for dummy proofs
    let mut is_dummy_flags: Vec<BoolTarget> = Vec::with_capacity(n_leaf);

    // For each proof, check: if it's not a dummy, it must match block_ref
    // Constraint: is_dummy OR (block_hash == block_ref)
    // Equivalently: NOT(is_real AND block_hash != block_ref)
    for i in 0..n_leaf {
        let block_i = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(child_pi_targets, i);

        // is_dummy_i = (block_i == [0,0,0,0])
        let is_dummy_i = bytes_digest_eq(&mut builder, block_i, dummy_sentinel);
        is_dummy_flags.push(is_dummy_i);

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

        // If this is a duplicate slot, zero out both the sum AND the exit account.
        // This makes duplicate slots indistinguishable from dummy proofs in the output,
        // hiding which slots were real duplicates vs padding dummies.
        let final_sum = builder.select(is_duplicate, zero, acc);

        // Zero out exit_slot for duplicates to match dummy output format
        let final_exit = [
            builder.select(is_duplicate, zero, exit_slot[0]),
            builder.select(is_duplicate, zero, exit_slot[1]),
            builder.select(is_duplicate, zero, exit_slot[2]),
            builder.select(is_duplicate, zero, exit_slot[3]),
        ];

        // Range check the sum
        // Since max supply is 21m coins, then max quantized amount is 2.1b < 2^32
        builder.range_check(final_sum, 32);

        // Output: [sum, exit_account(4)]
        output_pis.push(final_sum);
        output_pis.extend_from_slice(&final_exit);
    }

    // =========================================================================
    // NULLIFIERS
    // =========================================================================

    // Allocate dummy nullifier targets
    let mut dummy_nullifier_targets: Vec<[Target; 4]> = Vec::with_capacity(n_leaf);
    for _ in 0..n_leaf {
        dummy_nullifier_targets.push([
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ]);
    }

    // Override dummy nullifiers `Forward all N nullifiers
    for i in 0..n_leaf {
        let real_null_i = limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(child_pi_targets, i);

        let dn = dummy_nullifier_targets[i];
        let is_dummy_i = is_dummy_flags[i];

        // limbwise select: output = is_dummy ? dn : real
        output_pis.extend_from_slice(&[
            builder.select(is_dummy_i, dn[0], real_null_i[0]),
            builder.select(is_dummy_i, dn[1], real_null_i[1]),
            builder.select(is_dummy_i, dn[2], real_null_i[2]),
            builder.select(is_dummy_i, dn[3], real_null_i[3]),
        ]);
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
    // Fill dummy nullifier targets with provided dummy nullifiers
    for i in 0..n_leaf {
        let dn = dummy_nullifiers[i];
        let t = dummy_nullifier_targets[i];
        pw.set_target(t[0], dn[0])?;
        pw.set_target(t[1], dn[1])?;
        pw.set_target(t[2], dn[2])?;
        pw.set_target(t[3], dn[3])?;
    }

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
        aggregate_proofs, AggregatedProof, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START,
        EXIT_1_START, EXIT_2_START, LEAF_PI_LEN, NULLIFIER_START, OUTPUT_AMOUNT_1_START,
        OUTPUT_AMOUNT_2_START, VOLUME_FEE_BPS_START,
    };

    const TEST_ASSET_ID_U64: u64 = 0;
    const TEST_VOLUME_FEE_BPS: u64 = 10; // 0.1% = 10 basis points

    /// Test config: branching_factor=8, depth=1 (8 leaf proofs)
    // ---------------- Circuit ----------------

    /// Dummy wormhole leaf for the Bitcoin-style 2-output layout:
    ///
    /// PIs per leaf (length = LEAF_PI_LEN = 21):
    ///   [ asset_id(1×felt),
    ///     output_amount_1(1×felt),     // spend amount
    ///     output_amount_2(1×felt),     // change amount
    ///     volume_fee_bps(1×felt),
    ///     nullifier(4×felt),
    ///     exit_account_1(4×felt),      // spend destination
    ///     exit_account_2(4×felt),      // change destination
    ///     block_hash(4×felt),
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

    fn prove_dummy_wormhole(pis: [F; LEAF_PI_LEN]) -> AggregatedProof {
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

        let root_proof = aggregate_proofs(to_aggregate, common_data, verifier_data).unwrap();

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

        let res = aggregate_proofs(to_aggregate, common_data, verifier_data);

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

        let res = aggregate_proofs(to_aggregate, common_data, verifier_data);

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
                common_block_number,
            ));
        }

        // Dummy proofs (indices 2-7): block_hash = 0, exit_account = 0, output_amount = 0
        let dummy_exit = [F::ZERO; 4];
        let dummy_block_hash = [F::ZERO; 4];
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

        let root_proof = aggregate_proofs(to_aggregate, common_data, verifier_data).unwrap();

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
