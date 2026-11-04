//! Private-batch aggregation prover (prebuilt-circuit proving API).
//!
//! - `new(...)` / `new_from_*` constructors (one expensive circuit build)
//! - `aggregate(...)` to prove a batch; non-consuming, so one prover instance
//!   can prove any number of batches without rebuilding the circuit
//!
//! The leaf verifier key is baked in as constants at circuit build time to prevent
//! verifier key substitution attacks.

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
            VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputs,
    },
};
use rand::seq::SliceRandom;

#[cfg(feature = "std")]
use std::path::Path;

use qp_wormhole_inputs::{BytesDigest, PrivateBatchShape, PublicCircuitInputs, WithdrawalOutput};
use zk_circuits_common::{
    circuit::{wormhole_private_batch_circuit_config, C, D, F},
    utils::bytes_to_digest,
};

#[cfg(feature = "std")]
use crate::common::utils::read_artifact_file;
use crate::{
    common::utils::{
        ensure_proof_public_input_len, leaf_proof_asset_id, load_canonical_leaf_verifier_data,
    },
    dummy_proof::{generate_random_nullifier_preimage, load_dummy_proof},
    private_batch::{
        circuit::{
            circuit_logic::{PrivateBatchCircuit, PrivateBatchCircuitTargets},
            constants::LEAF_PI_LEN,
        },
        prover::witness::fill_private_batch_witness,
    },
};

/// Maximum `volume_fee_bps`: a fee of 100% leaves nothing to pay out.
pub const MAX_VOLUME_FEE_BPS: u32 = 10_000;

/// Everything a client supplies to prove one private batch.
#[derive(Debug, Clone)]
pub struct PrivateBatchInputs {
    /// Leaf (proof-of-burn) proofs to spend; padded with the dummy template up
    /// to the circuit's `num_leaf_proofs`.
    pub leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    /// Requested payouts; padded with zero outputs up to the circuit's
    /// `num_exit_slots`.
    pub outputs: Vec<WithdrawalOutput>,
    /// Volume fee in basis points applied to the whole batch.
    pub volume_fee_bps: u32,
}

#[derive(Debug)]
pub struct PrivateBatchProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    targets: PrivateBatchCircuitTargets,
    shape: PrivateBatchShape,
    dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    /// Leaf verifier data, kept so [`Self::aggregate`] can cheaply verify each
    /// supplied leaf proof before starting the expensive recursive proving run
    /// (mirrors [`crate::public_batch::prover::PublicBatchProver`]'s pinned
    /// inner verifier).
    leaf_verifier: VerifierCircuitData<F, C, D>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateBatchBuildMetrics {
    pub leaf_degree_bits: usize,
    pub unpadded_gates: usize,
    pub degree_bits: usize,
    pub padded_gates: usize,
}

impl PrivateBatchProver {
    /// Build a fresh private-batch aggregation prover from circuit definitions.
    ///
    /// In production, prefer `new_from_binaries_dir(...)` to load prebuilt circuits.
    /// Returns an error when `shape` is outside the supported range,
    /// or when `dummy_proof_template` is not a valid leaf proof carrying the
    /// strong dummy sentinel (zero block hash, zero outputs, and zero asset_id).
    pub fn new(
        agg_circuit_config: CircuitConfig,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        shape: PrivateBatchShape,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self> {
        // Shape bounds are enforced by PrivateBatchCircuit::new.
        let agg_circuit =
            PrivateBatchCircuit::new(agg_circuit_config, &leaf_common, leaf_verifier_only, shape)?;

        let targets = agg_circuit.targets();
        let circuit_data = agg_circuit.build_prover();
        Self::from_fresh_circuit(
            circuit_data,
            targets,
            leaf_common,
            leaf_verifier_only,
            shape,
            dummy_proof_template,
        )
    }

    /// Build a fresh prover and return its finalized circuit dimensions.
    pub fn new_with_metrics(
        agg_circuit_config: CircuitConfig,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        shape: PrivateBatchShape,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Result<(Self, PrivateBatchBuildMetrics)> {
        // Shape bounds are enforced by PrivateBatchCircuit::new.
        let agg_circuit =
            PrivateBatchCircuit::new(agg_circuit_config, &leaf_common, leaf_verifier_only, shape)?;

        let unpadded_gates = agg_circuit.num_gates();
        let targets = agg_circuit.targets();
        let circuit_data = agg_circuit.build_prover();
        let metrics = PrivateBatchBuildMetrics {
            leaf_degree_bits: leaf_common.degree_bits(),
            unpadded_gates,
            degree_bits: circuit_data.common.degree_bits(),
            padded_gates: circuit_data.common.degree(),
        };

        let prover = Self::from_fresh_circuit(
            circuit_data,
            targets,
            leaf_common,
            leaf_verifier_only,
            shape,
            dummy_proof_template,
        )?;
        Ok((prover, metrics))
    }

    fn from_fresh_circuit(
        circuit_data: ProverCircuitData<F, C, D>,
        targets: PrivateBatchCircuitTargets,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        shape: PrivateBatchShape,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self> {
        // Enforce the same template invariant as the byte-loading constructors:
        // `aggregate` clones this template into every padded slot, and the circuit
        // only exempts slots carrying the dummy sentinel — a caller-supplied
        // REAL proof here would replay its payout in every empty slot (#97026).
        let leaf_verifier = VerifierCircuitData {
            verifier_only: leaf_verifier_only.clone(),
            common: leaf_common,
        };
        verify_dummy_leaf_template(&dummy_proof_template, &leaf_verifier)?;

        Ok(Self {
            circuit_data,
            targets,
            shape,
            dummy_proof_template,
            leaf_verifier,
        })
    }

    /// Create a private-batch aggregation prover from serialized bytes.
    ///
    /// The aggregation circuit's prover data is **rebuilt from source**, never
    /// loaded from an artifact. `ProverOnlyCircuitData` carries the witness
    /// generators and the `public_inputs` target list that decides which
    /// witness values are exposed in the returned proof, so a poisoned
    /// `private_batch_prover.bin` could otherwise make the prover emit chosen
    /// witness targets (e.g. dummy-nullifier preimages that reveal padding
    /// slots) in the serialized proof before any downstream verifier rejects
    /// it. Rebuilding is free here because constructing the circuit is required
    /// regardless, and it mirrors the leaf prover, which likewise never trusts a
    /// serialized prover artifact.
    ///
    /// Expected bytes:
    /// - `leaf_common_bytes`: leaf circuit common data (`common.bin`)
    /// - `leaf_verifier_only_bytes`: leaf verifier-only data (`verifier.bin`)
    /// - `dummy_proof_bytes`: serialized dummy leaf proof (`dummy_proof.bin`)
    /// - `shape`: leaf-proof and exit-slot counts of this private-batch prover
    pub fn new_from_bytes(
        leaf_common_bytes: &[u8],
        leaf_verifier_only_bytes: &[u8],
        dummy_proof_bytes: &[u8],
        shape: PrivateBatchShape,
    ) -> Result<Self> {
        // Validate the batch shape at the public byte-loading boundary so a zero
        // or oversized count returns an error instead of panicking inside the
        // circuit builder (#97027, #97070).
        shape.validate()?;

        // 1) Load and pin leaf verifier data to the canonical Wormhole leaf circuit.
        let leaf_verifier_data =
            load_canonical_leaf_verifier_data(leaf_common_bytes, leaf_verifier_only_bytes)?;

        // 2) Rebuild the aggregation circuit from source and take its prover
        // data directly. The leaf verifier key is pinned above and baked in as
        // constants, so this prover is a deterministic function of the compiled
        // circuit code — no serialized prover/common artifact is trusted.
        let circuit = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf_verifier_data.common,
            &leaf_verifier_data.verifier_only,
            shape,
        )?;
        let targets = circuit.targets();
        let circuit_data = circuit.build_prover();

        // 3) Load dummy proof template compatible with the leaf verifier common data
        let dummy_proof_template =
            load_dummy_proof(dummy_proof_bytes.to_vec(), &leaf_verifier_data.common)
                .map_err(|e| anyhow!("failed to deserialize dummy proof: {}", e))?;

        // Verify the template is a valid leaf proof carrying the strong dummy
        // sentinel (zero block hash, zero outputs, AND zero asset_id), so a
        // poisoned padding template cannot inject a real payout into every
        // partial batch or deny partial-batch padding with a nonzero asset.
        // This mirrors the public-batch template check (#97026).
        verify_dummy_leaf_template(&dummy_proof_template, &leaf_verifier_data)?;

        Ok(Self {
            circuit_data,
            targets,
            shape,
            dummy_proof_template,
            leaf_verifier: leaf_verifier_data,
        })
    }

    /// Create a private-batch aggregation prover from explicit file paths.
    #[cfg(feature = "std")]
    pub fn new_from_files(
        leaf_common_path: &Path,
        leaf_verifier_path: &Path,
        dummy_proof_path: &Path,
        shape: PrivateBatchShape,
    ) -> Result<Self> {
        let leaf_common_bytes = read_artifact_file(leaf_common_path)
            .with_context(|| format!("Failed to read leaf common file {:?}", leaf_common_path))?;
        let leaf_verifier_only_bytes =
            read_artifact_file(leaf_verifier_path).with_context(|| {
                format!("Failed to read leaf verifier file {:?}", leaf_verifier_path)
            })?;
        let dummy_proof_bytes = read_artifact_file(dummy_proof_path)
            .with_context(|| format!("Failed to read dummy proof file {:?}", dummy_proof_path))?;

        Self::new_from_bytes(
            &leaf_common_bytes,
            &leaf_verifier_only_bytes,
            &dummy_proof_bytes,
            shape,
        )
    }

    /// Convenience constructor that loads everything from a generated binaries directory.
    ///
    /// The aggregation prover circuit is rebuilt from source, so no
    /// `private_batch_prover.bin` is read.
    ///
    /// Expected files:
    /// - `common.bin`
    /// - `verifier.bin`
    /// - `dummy_proof.bin`
    /// - `config.json`
    ///
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let bins_config = crate::config::CircuitBinsConfig::load(bins_dir)
            .with_context(|| format!("Failed to load config.json from {}", bins_dir.display()))?;

        Self::new_from_files(
            &bins_dir.join("common.bin"),
            &bins_dir.join("verifier.bin"),
            &bins_dir.join("dummy_proof.bin"),
            bins_config.private_batch_shape(),
        )
    }

    // -------------------------------------------------------------------------
    // Proving API
    // -------------------------------------------------------------------------

    /// Leaf-proof and exit-slot counts of this private-batch prover.
    pub fn shape(&self) -> PrivateBatchShape {
        self.shape
    }

    /// Number of leaf proofs aggregated by this private-batch prover.
    pub fn num_leaf_proofs(&self) -> usize {
        self.shape.num_leaf_proofs
    }

    /// Number of exit slots exposed by this private-batch prover.
    pub fn num_exit_slots(&self) -> usize {
        self.shape.num_exit_slots
    }

    /// Fill a fresh witness for one private batch.
    ///
    /// Fails fast (milliseconds, before the recursive proving run) on inputs
    /// the private-batch circuit could never prove: each supplied leaf is
    /// cryptographically verified against the pinned leaf verifier, batches
    /// that would fail the circuit's cross-slot constraints (mixed block
    /// hashes or asset ids) are rejected, an all-dummy batch is refused, and
    /// the requested outputs are checked against the fee-adjusted burned
    /// total. Then pads with the dummy template / zero outputs, shuffles the
    /// leaves, and fills the witness.
    fn build_witness(&self, inputs: PrivateBatchInputs) -> Result<PartialWitness<F>> {
        let PrivateBatchInputs {
            leaf_proofs: mut proofs,
            mut outputs,
            volume_fee_bps,
        } = inputs;

        // An empty batch would be padded into an all-dummy proof that settles
        // nothing; a client asking for that is a caller bug. (The intentional
        // all-dummy padding template is built on the circuit-build path, which
        // fills the witness with explicit dummy leaves and never calls here.)
        if proofs.is_empty() {
            bail!("no leaf proofs to aggregate");
        }
        if proofs.len() > self.shape.num_leaf_proofs {
            bail!(
                "too many proofs: got {}, expected at most {}",
                proofs.len(),
                self.shape.num_leaf_proofs
            );
        }
        if outputs.len() > self.shape.num_exit_slots {
            bail!(
                "too many outputs: got {}, expected at most {}",
                outputs.len(),
                self.shape.num_exit_slots
            );
        }

        // If we're going to pad with dummy proofs (asset_id = 0), real proofs must
        // also use asset_id = 0 because the private-batch circuit enforces asset_id
        // equality across all proofs.
        let num_dummies_needed = self.shape.num_leaf_proofs.saturating_sub(proofs.len());

        // Validate shape and cryptography up front so a malformed or invalid
        // leaf is rejected at the API boundary instead of panicking inside
        // witness assignment (#97073) or failing only after a full recursive
        // prove (audit finding: leaf validity deferred to the expensive path).
        for (idx, proof) in proofs.iter().enumerate() {
            ensure_proof_public_input_len(proof, LEAF_PI_LEN, "leaf proof")?;
            self.leaf_verifier.verify(proof.clone()).map_err(|e| {
                anyhow!(
                    "leaf proof {} failed verification against the pinned leaf verifier: {}",
                    idx,
                    e
                )
            })?;
            if num_dummies_needed > 0 {
                let real_asset_id =
                    leaf_proof_asset_id(proof).map_err(|e| anyhow!("leaf proof {}: {}", idx, e))?;
                if real_asset_id != 0 {
                    bail!(
                        "real proof {} has asset_id={}, but dummy proofs use asset_id=0. \
                         All proofs must have the same asset_id for aggregation when padding is required.",
                        idx,
                        real_asset_id
                    );
                }
            }
        }

        ensure_leaf_batch_compatible(&proofs)?;
        ensure_outputs_covered_by_burns(&proofs, &outputs, volume_fee_bps)?;

        // Pad with dummy proofs and zero outputs.
        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_proof_template.clone());
        }
        outputs.resize(self.shape.num_exit_slots, WithdrawalOutput::default());

        let mut rng = rand::thread_rng();

        // Uniformly shuffle proofs to hide dummy positions. The circuit selects its block
        // reference from the first non-dummy slot in-circuit, so no position is special.
        // Nullifiers are emitted in slot order, so this shuffle also randomises the
        // public nullifier order.
        if proofs.len() > 1 {
            proofs.shuffle(&mut rng);
        }

        // Generate one dummy nullifier preimage per slot.
        // In-circuit hashes these only for dummy proofs.
        let dummy_nullifier_pre_images =
            generate_dummy_nullifier_pre_images_for_slots(proofs.len());

        let mut partial_witness = PartialWitness::new();
        fill_private_batch_witness(
            &mut partial_witness,
            &self.targets,
            &proofs,
            &outputs,
            volume_fee_bps,
            &dummy_nullifier_pre_images,
        )?;

        Ok(partial_witness)
    }

    /// Aggregate a full leaf-proof set and its requested payouts into one
    /// private-batch proof.
    ///
    /// This is the intended client (CLI / mobile) entry point: a client knows
    /// its complete leaf set and payouts up front, so there is no queue — pass
    /// everything at once. Leaf verification, cross-proof compatibility and
    /// the fee-adjusted output total are checked fail-fast before the
    /// recursive proving run.
    ///
    /// Non-consuming: each call fills a fresh witness against the circuit
    /// built at construction, so one prover instance can aggregate any number
    /// of batches without paying the circuit build again.
    pub fn aggregate(&self, inputs: PrivateBatchInputs) -> Result<ProofWithPublicInputs<F, C, D>> {
        let partial_witness = self.build_witness(inputs)?;
        self.circuit_data
            .prove(partial_witness)
            .map_err(|e| anyhow!("Failed to prove private-batch aggregation circuit: {}", e))
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Check that a set of leaf proofs is mutually compatible under the
/// private-batch circuit's cross-slot constraints, so an incompatible batch is
/// rejected at commit time instead of failing after a full proving run
/// (potentially minutes on the phone-class hardware clients prove on):
///
/// - `asset_id` must match across ALL proofs (dummies included),
/// - `block_hash` must match between non-dummy proofs (`block_hash == 0`
///   slots are exempt),
/// - non-dummy nullifiers must be pairwise DISTINCT, mirroring the circuit's
///   real-nullifier uniqueness constraint (dummy slots are exempt: the circuit
///   replaces their nullifiers with hashes of fresh random preimages). Without
///   this, replaying the same valid leaf proof twice passes per-proof
///   verification and only fails inside the recursive proving run,
/// - at least one proof must be non-dummy: an all-dummy batch settles nothing,
///   so proving it only burns the proving window. The intentional all-dummy
///   padding template is built on the circuit-build path, which fills the
///   witness directly and never calls this. Mirrors
///   `ensure_private_batch_compatible` at the public-batch layer.
///
/// NOTE: keep in lockstep with the circuit's cross-slot constraints
/// (`private_batch::circuit::circuit_logic`). The circuit remains the enforcer;
/// this only improves failure latency and error quality.
fn ensure_leaf_batch_compatible(proofs: &[ProofWithPublicInputs<F, C, D>]) -> Result<()> {
    use crate::private_batch::circuit::constants::{
        ASSET_ID_START, BLOCK_HASH_START, NULLIFIER_START,
    };
    use std::collections::HashMap;

    struct LeafMeta {
        asset_id: u64,
        block_hash: [u64; 4],
        nullifier: [u64; 4],
    }
    // PI lengths were validated by the caller.
    let metas: Vec<LeafMeta> = proofs
        .iter()
        .map(|proof| LeafMeta {
            asset_id: proof.public_inputs[ASSET_ID_START].to_canonical_u64(),
            block_hash: core::array::from_fn(|i| {
                proof.public_inputs[BLOCK_HASH_START + i].to_canonical_u64()
            }),
            nullifier: core::array::from_fn(|i| {
                proof.public_inputs[NULLIFIER_START + i].to_canonical_u64()
            }),
        })
        .collect();

    if let Some(first) = metas.first() {
        for (idx, meta) in metas.iter().enumerate().skip(1) {
            if meta.asset_id != first.asset_id {
                bail!(
                    "leaf proof {} has asset_id={}, but proof 0 has asset_id={}; \
                     the private-batch circuit enforces asset consistency across all slots",
                    idx,
                    meta.asset_id,
                    first.asset_id
                );
            }
        }
    }

    let mut reference: Option<(usize, &LeafMeta)> = None;
    let mut seen_nullifiers: HashMap<[u64; 4], usize> = HashMap::new();
    for (idx, meta) in metas.iter().enumerate() {
        if meta.block_hash == [0u64; 4] {
            continue; // dummy sentinel: exempt from block/nullifier consistency
        }
        match reference {
            None => reference = Some((idx, meta)),
            Some((ref_idx, reference)) => {
                if meta.block_hash != reference.block_hash {
                    bail!(
                        "leaf proof {} is for a different block than proof {}; \
                         all non-dummy proofs in a private batch must share one block hash",
                        idx,
                        ref_idx
                    );
                }
            }
        }
        if let Some(prev_idx) = seen_nullifiers.insert(meta.nullifier, idx) {
            bail!(
                "leaf proof {} carries the same nullifier as proof {}; the private-batch \
                 circuit enforces pairwise-distinct real nullifiers, so this batch (e.g. \
                 the same leaf proof supplied twice) would only fail after the expensive \
                 recursive proving run",
                idx,
                prev_idx
            );
        }
    }
    if reference.is_none() {
        bail!(
            "every supplied leaf proof is all-dummy (block_hash == 0): such a batch \
             settles nothing; supply at least one real leaf proof"
        );
    }
    Ok(())
}

/// Mirror of the circuit's fee constraint,
/// `sum(outputs) * 10_000 <= sum(real inputs) * (10_000 - volume_fee_bps)`,
/// so an over-spending batch is rejected before the proving run. Dummy slots
/// (`block_hash == 0`) contribute no input, exactly as in-circuit.
fn ensure_outputs_covered_by_burns(
    proofs: &[ProofWithPublicInputs<F, C, D>],
    outputs: &[WithdrawalOutput],
    volume_fee_bps: u32,
) -> Result<()> {
    use crate::private_batch::circuit::constants::{BLOCK_HASH_START, INPUT_AMOUNT_START};

    if volume_fee_bps > MAX_VOLUME_FEE_BPS {
        bail!(
            "volume_fee_bps {} exceeds the maximum {}",
            volume_fee_bps,
            MAX_VOLUME_FEE_BPS
        );
    }
    let total_input: u128 = proofs
        .iter()
        .filter(|proof| {
            proof.public_inputs[BLOCK_HASH_START..BLOCK_HASH_START + 4]
                .iter()
                .any(|f| !f.is_zero())
        })
        .map(|proof| u128::from(proof.public_inputs[INPUT_AMOUNT_START].to_canonical_u64()))
        .sum();
    let total_output: u128 = outputs.iter().map(|o| u128::from(o.amount)).sum();
    let max_output_scaled = total_input * u128::from(MAX_VOLUME_FEE_BPS - volume_fee_bps);
    if total_output * u128::from(MAX_VOLUME_FEE_BPS) > max_output_scaled {
        bail!(
            "requested outputs total {} but the burned inputs total {} only cover {} after \
             a {} bps fee",
            total_output,
            total_input,
            max_output_scaled / u128::from(MAX_VOLUME_FEE_BPS),
            volume_fee_bps
        );
    }
    Ok(())
}

/// Verify that the dummy leaf proof template is a valid leaf proof carrying the
/// dummy sentinel: `block_hash == 0`, `input_amount == 0` and `asset_id == 0`.
///
/// The private-batch circuit only treats `block_hash == 0` slots as dummies. If a
/// poisoned `dummy_proof.bin` contained a *real* proof (non-zero block hash or
/// burn), every empty slot in a partial batch would count that burn towards the
/// fee check. This mirrors `verify_dummy_private_batch_template` at the
/// public-batch layer (#97026).
///
/// `asset_id` must be zero because `commit` pads native-asset (`asset_id = 0`)
/// batches with this template and the circuit enforces asset_id equality across
/// ALL slots, dummies included. A nonzero-asset template would pass loading but
/// make every padded batch unprovable: partial native-asset batches fail the
/// in-circuit asset-equality constraint, and nonzero-asset batches are already
/// rejected by the padding preflight — denying the partial-batch path entirely.
pub(crate) fn verify_dummy_leaf_template(
    template: &ProofWithPublicInputs<F, C, D>,
    leaf_verifier: &VerifierCircuitData<F, C, D>,
) -> Result<()> {
    // Check the sentinel first (cheap, and independently testable); a template
    // is only acceptable if BOTH the sentinel and cryptographic verification pass.
    let u64s: Vec<u64> = template
        .public_inputs
        .iter()
        .map(|f| f.to_canonical_u64())
        .collect();
    let pis = PublicCircuitInputs::try_from_u64_slice(&u64s)
        .context("failed to parse dummy leaf proof template public inputs")?;

    if pis.block_hash != BytesDigest::default() {
        bail!(
            "dummy leaf proof template has non-zero block_hash {:?}; \
             padding templates must carry the all-zero block-hash sentinel",
            pis.block_hash
        );
    }
    if pis.input_amount != 0 {
        bail!(
            "dummy leaf proof template has non-zero input_amount {}; padding templates \
             must authenticate no value (the leaf circuit forces this for the zero \
             block-hash sentinel, and the wrapper masks dummy inputs as defense in depth)",
            pis.input_amount
        );
    }
    if pis.asset_id != 0 {
        bail!(
            "dummy leaf proof template has non-zero asset_id {}; padding templates \
             must use the native asset (asset_id = 0) because the circuit enforces \
             asset_id equality across all slots, dummies included",
            pis.asset_id
        );
    }

    leaf_verifier
        .verify(template.clone())
        .map_err(|e| anyhow!("dummy leaf proof template failed verification: {}", e))?;

    Ok(())
}

/// Generate a dummy nullifier preimage for every slot.
///
/// The private-batch circuit hashes these for dummy slots (`block_hash == 0`) and ignores them
/// for real slots via conditional select.
fn generate_dummy_nullifier_pre_images_for_slots(n_slots: usize) -> Vec<[F; 4]> {
    (0..n_slots)
        .map(|_| bytes_to_digest(generate_random_nullifier_preimage()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_batch::circuit::constants::{
        ASSET_ID_START, BLOCK_HASH_START, INPUT_AMOUNT_START,
        NULLIFIER_START as LEAF_NULLIFIER_START,
    };
    use plonky2::field::types::Field;
    use qp_wormhole_inputs::{
        BLOCK_HASH_START_INDEX, INPUT_AMOUNT_INDEX, NULLIFIER_START_INDEX, PUBLIC_INPUTS_FELTS_LEN,
    };
    use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};

    fn inputs(
        leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
        outputs: Vec<WithdrawalOutput>,
    ) -> PrivateBatchInputs {
        PrivateBatchInputs {
            leaf_proofs,
            outputs,
            volume_fee_bps: 10,
        }
    }

    fn output(amount: u32) -> WithdrawalOutput {
        WithdrawalOutput {
            exit_account: BytesDigest::try_from([4u8; 32]).unwrap(),
            amount,
        }
    }

    #[test]
    fn dummy_template_with_zero_sentinel_is_accepted() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let template = prove_fake_leaf(&leaf, &targets, [F::ZERO; PUBLIC_INPUTS_FELTS_LEN]);
        verify_dummy_leaf_template(&template, &leaf.verifier_data())
            .expect("all-zero sentinel template must be accepted");
    }

    #[test]
    fn build_metrics_match_finalized_circuit_data() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let template = prove_fake_leaf(&leaf, &targets, [F::ZERO; PUBLIC_INPUTS_FELTS_LEN]);
        let leaf_degree_bits = leaf.common.degree_bits();
        let (prover, metrics) = PrivateBatchProver::new_with_metrics(
            wormhole_private_batch_circuit_config(),
            leaf.common,
            &leaf.verifier_only,
            PrivateBatchShape::new(1, 2),
            template,
        )
        .unwrap();

        assert_eq!(metrics.leaf_degree_bits, leaf_degree_bits);
        assert_eq!(
            metrics.degree_bits,
            prover.circuit_data.common.degree_bits()
        );
        assert_eq!(metrics.padded_gates, prover.circuit_data.common.degree());
        assert!(metrics.unpadded_gates <= metrics.padded_gates);
    }

    #[test]
    fn dummy_template_with_nonzero_block_hash_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let mut pis = [F::ZERO; PUBLIC_INPUTS_FELTS_LEN];
        pis[BLOCK_HASH_START_INDEX] = F::ONE;
        let template = prove_fake_leaf(&leaf, &targets, pis);
        let err = verify_dummy_leaf_template(&template, &leaf.verifier_data()).unwrap_err();
        assert!(
            err.to_string().contains("non-zero block_hash"),
            "got: {err}"
        );
    }

    #[test]
    fn dummy_template_with_nonzero_asset_id_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let mut pis = [F::ZERO; PUBLIC_INPUTS_FELTS_LEN];
        pis[ASSET_ID_START] = F::from_canonical_u32(7);
        let template = prove_fake_leaf(&leaf, &targets, pis);
        let err = verify_dummy_leaf_template(&template, &leaf.verifier_data()).unwrap_err();
        assert!(err.to_string().contains("non-zero asset_id"), "got: {err}");
    }

    /// The leaf circuit forces a zero-block-hash leaf to burn nothing; a
    /// template claiming otherwise could only come from a different circuit
    /// and must be rejected before the cryptographic check.
    #[test]
    fn dummy_template_with_nonzero_input_amount_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let mut pis = [F::ZERO; PUBLIC_INPUTS_FELTS_LEN];
        pis[INPUT_AMOUNT_INDEX] = F::from_canonical_u32(5);
        let template = prove_fake_leaf(&leaf, &targets, pis);
        let err = verify_dummy_leaf_template(&template, &leaf.verifier_data()).unwrap_err();
        assert!(
            err.to_string().contains("non-zero input_amount"),
            "got: {err}"
        );
    }

    #[test]
    fn dummy_template_failing_cryptographic_verification_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let mut template = prove_fake_leaf(&leaf, &targets, [F::ZERO; PUBLIC_INPUTS_FELTS_LEN]);
        // Sentinel-neutral mutation (nullifier felt): the sentinel checks pass but
        // the proof no longer verifies against its mutated public inputs.
        template.public_inputs[NULLIFIER_START_INDEX] = F::ONE;
        let err = verify_dummy_leaf_template(&template, &leaf.verifier_data()).unwrap_err();
        assert!(
            err.to_string().contains("failed verification"),
            "got: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Cross-proof batch-compatibility preflight
    // -------------------------------------------------------------------------

    fn leaf_pis(asset_id: u64, input_amount: u64, block: u64) -> [F; PUBLIC_INPUTS_FELTS_LEN] {
        let mut pis = [F::ZERO; PUBLIC_INPUTS_FELTS_LEN];
        pis[ASSET_ID_START] = F::from_canonical_u64(asset_id);
        pis[INPUT_AMOUNT_START] = F::from_canonical_u64(input_amount);
        pis[BLOCK_HASH_START] = F::from_canonical_u64(block);
        pis
    }

    fn with_nullifier(
        mut pis: [F; PUBLIC_INPUTS_FELTS_LEN],
        nullifier: u64,
    ) -> [F; PUBLIC_INPUTS_FELTS_LEN] {
        pis[LEAF_NULLIFIER_START] = F::from_canonical_u64(nullifier);
        pis
    }

    /// Cryptographically invalid (tampered) leaf proofs must be rejected at
    /// commit time, before the expensive recursive proving run starts — the
    /// same fail-fast guard PublicBatchProver applies to its inner proofs.
    #[test]
    fn commit_rejects_tampered_leaf_proof_before_proving() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let dummy = prove_fake_leaf(&leaf, &targets, [F::ZERO; PUBLIC_INPUTS_FELTS_LEN]);
        let mut real = prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 1));
        // Right shape, wrong cryptography: mutate one public input so the
        // proof no longer verifies against the pinned leaf verifier.
        real.public_inputs[NULLIFIER_START_INDEX] = F::ONE;

        let prover = PrivateBatchProver::new(
            wormhole_private_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            PrivateBatchShape::new(1, 1),
            dummy,
        )
        .unwrap();

        let err = prover
            .build_witness(inputs(vec![real], vec![]))
            .expect_err("tampered leaf proof must be rejected at the witness boundary");
        assert!(
            err.to_string().contains("failed verification"),
            "got: {err}"
        );
    }

    #[test]
    fn compatible_leaf_batch_is_accepted() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let proofs = vec![
            prove_fake_leaf(&leaf, &targets, with_nullifier(leaf_pis(0, 10, 1), 1)),
            prove_fake_leaf(&leaf, &targets, with_nullifier(leaf_pis(0, 10, 1), 2)),
            // Dummy slot: exempt from block/fee consistency.
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 99, 0)),
        ];
        ensure_leaf_batch_compatible(&proofs).expect("compatible batch must be accepted");
    }

    /// The circuit rejects pairwise-equal real nullifiers (two real slots
    /// sharing a nullifier would merge into one inflated exit while the chain
    /// marks the shared nullifier spent once). The commit-boundary preflight
    /// must mirror that rule, otherwise replaying the same valid leaf proof
    /// twice passes per-proof verification and only fails after entering the
    /// expensive recursive proving path — violating commit's fail-fast
    /// contract.
    #[test]
    fn duplicate_real_nullifier_leaf_batch_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        // The same valid leaf proof supplied twice: identical nullifiers.
        let replayed = prove_fake_leaf(&leaf, &targets, with_nullifier(leaf_pis(0, 10, 1), 7));
        let proofs = vec![replayed.clone(), replayed];
        let err = ensure_leaf_batch_compatible(&proofs).unwrap_err();
        assert!(err.to_string().contains("same nullifier"), "got: {err}");
    }

    /// Dummy slots are exempt from nullifier uniqueness: the circuit replaces
    /// their nullifiers with hashes of fresh random preimages, so equal
    /// nullifier fields in supplied dummy proofs never collide on-chain.
    #[test]
    fn duplicate_dummy_nullifiers_are_exempt() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let proofs = vec![
            prove_fake_leaf(&leaf, &targets, with_nullifier(leaf_pis(0, 10, 1), 7)),
            // Two dummy slots (block 0) sharing nullifier 7 with each other
            // AND with the real proof above.
            prove_fake_leaf(&leaf, &targets, with_nullifier(leaf_pis(0, 10, 0), 7)),
            prove_fake_leaf(&leaf, &targets, with_nullifier(leaf_pis(0, 10, 0), 7)),
        ];
        ensure_leaf_batch_compatible(&proofs)
            .expect("dummy slots must be exempt from nullifier uniqueness");
    }

    /// End-to-end guard at the commit boundary: the same valid leaf proof
    /// supplied twice must be rejected by `commit` (fail-fast, milliseconds),
    /// not by the recursive proving run it precedes.
    #[test]
    fn commit_rejects_duplicate_real_nullifiers_before_proving() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let dummy = prove_fake_leaf(&leaf, &targets, [F::ZERO; PUBLIC_INPUTS_FELTS_LEN]);
        let replayed = prove_fake_leaf(&leaf, &targets, with_nullifier(leaf_pis(0, 10, 1), 7));

        let prover = PrivateBatchProver::new(
            wormhole_private_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            PrivateBatchShape::new(2, 1),
            dummy,
        )
        .unwrap();

        let err = prover
            .build_witness(inputs(vec![replayed.clone(), replayed], vec![]))
            .expect_err("replayed leaf proof must be rejected at the witness boundary");
        assert!(err.to_string().contains("same nullifier"), "got: {err}");
    }

    #[test]
    fn mixed_block_leaf_batch_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let proofs = vec![
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 1)),
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 2)),
        ];
        let err = ensure_leaf_batch_compatible(&proofs).unwrap_err();
        assert!(err.to_string().contains("different block"), "got: {err}");
    }

    /// Mirror of the in-circuit fee constraint at the commit boundary: outputs
    /// may claim at most the fee-adjusted burned total; dummy slots burn nothing.
    #[test]
    fn outputs_exceeding_fee_adjusted_burns_are_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let proofs = vec![
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 1_000, 1)),
            // Dummy slot carrying a nonzero input_amount must not count.
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 1_000, 0)),
        ];

        ensure_outputs_covered_by_burns(&proofs, &[output(500), output(499)], 10)
            .expect("999 <= 1000 * 0.999");
        let err =
            ensure_outputs_covered_by_burns(&proofs, &[output(500), output(500)], 10).unwrap_err();
        assert!(err.to_string().contains("only cover 999"), "got: {err}");

        let err =
            ensure_outputs_covered_by_burns(&proofs, &[], MAX_VOLUME_FEE_BPS + 1).unwrap_err();
        assert!(
            err.to_string().contains("exceeds the maximum"),
            "got: {err}"
        );
    }

    #[test]
    fn too_many_outputs_are_rejected_before_proving() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let dummy = prove_fake_leaf(&leaf, &targets, [F::ZERO; PUBLIC_INPUTS_FELTS_LEN]);
        let real = prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 1));
        let prover = PrivateBatchProver::new(
            wormhole_private_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            PrivateBatchShape::new(1, 1),
            dummy,
        )
        .unwrap();

        let err = prover
            .build_witness(inputs(vec![real], vec![output(1), output(1)]))
            .expect_err("more outputs than exit slots must be rejected");
        assert!(err.to_string().contains("too many outputs"), "got: {err}");
    }

    /// A non-empty batch of only dummy leaf proofs (block_hash == 0) settles
    /// nothing; proving it burns a full private-batch prove. The intentional
    /// all-dummy padding template is built on the circuit-build path, which
    /// fills the witness directly and never calls commit, so this can only be
    /// a caller bug — reject it at the API boundary, mirroring
    /// `ensure_private_batch_compatible` at the public-batch layer (audit
    /// finding: leaf layer skips all-dummy rejection).
    #[test]
    fn all_dummy_leaf_batch_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let proofs = vec![
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 0)),
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 0)),
        ];
        let err = ensure_leaf_batch_compatible(&proofs).unwrap_err();
        assert!(err.to_string().contains("all-dummy"), "got: {err}");
    }

    #[test]
    fn mixed_asset_leaf_batch_is_rejected_even_for_dummies() {
        let (leaf, targets) = build_fake_leaf_circuit();
        // Second proof is a dummy (block 0) with a different asset: the circuit
        // enforces asset equality across ALL slots, dummies included.
        let proofs = vec![
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 1)),
            prove_fake_leaf(&leaf, &targets, leaf_pis(5, 10, 0)),
        ];
        let err = ensure_leaf_batch_compatible(&proofs).unwrap_err();
        assert!(err.to_string().contains("asset"), "got: {err}");
    }
}
