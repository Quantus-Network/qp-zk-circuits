//! Private-batch aggregation prover (prebuilt-circuit proving API).
//!
//! - `new(...)` / `new_from_*` constructors
//! - `commit(...)` to fill the witness
//! - `prove()` to generate the aggregated proof
//!
//! The leaf verifier key is baked in as constants at circuit build time to prevent
//! verifier key substitution attacks.

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    field::types::PrimeField64,
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData,
            VerifierCircuitData, VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use rand::seq::SliceRandom;

#[cfg(feature = "std")]
use std::{fs, path::Path};

use qp_wormhole_inputs::{validate_proof_count, BytesDigest, PublicCircuitInputs};
use zk_circuits_common::{
    circuit::{wormhole_private_batch_circuit_config, C, D, F},
    utils::bytes_to_digest,
};

use crate::{
    common::utils::{
        ensure_common_matches_canonical, ensure_proof_public_input_len, leaf_proof_asset_id,
        load_canonical_leaf_verifier_data,
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

#[derive(Debug)]
pub struct PrivateBatchProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<PrivateBatchCircuitTargets>,
    num_leaf_proofs: usize,
    dummy_proof_template: ProofWithPublicInputs<F, C, D>,
}

impl PrivateBatchProver {
    /// Build a fresh private-batch aggregation prover from circuit definitions.
    ///
    /// In production, prefer `new_from_binaries_dir(...)` to load prebuilt circuits.
    /// Returns an error when `num_leaf_proofs` is outside the supported range.
    pub fn new(
        agg_circuit_config: CircuitConfig,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_leaf_proofs: usize,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self> {
        // Proof-count bounds are enforced by PrivateBatchCircuit::new.
        let agg_circuit = PrivateBatchCircuit::new(
            agg_circuit_config,
            &leaf_common,
            leaf_verifier_only,
            num_leaf_proofs,
        )?;

        let targets = Some(agg_circuit.targets());
        let circuit_data = agg_circuit.build_prover();

        Ok(Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
            num_leaf_proofs,
            dummy_proof_template,
        })
    }

    /// Create a private-batch aggregation prover from serialized bytes.
    ///
    /// Expected bytes:
    /// - `aggregated_prover_only_bytes`: private-batch aggregated prover-only circuit data
    /// - `aggregated_common_bytes`: private-batch aggregated common circuit data
    /// - `leaf_common_bytes`: leaf circuit common data (`common.bin`)
    /// - `leaf_verifier_only_bytes`: leaf verifier-only data (`verifier.bin`)
    /// - `dummy_proof_bytes`: serialized dummy leaf proof (`dummy_proof.bin`)
    /// - `num_leaf_proofs`: number of leaf proofs aggregated by this private-batch prover
    pub fn new_from_bytes(
        aggregated_prover_only_bytes: &[u8],
        aggregated_common_bytes: &[u8],
        leaf_common_bytes: &[u8],
        leaf_verifier_only_bytes: &[u8],
        dummy_proof_bytes: &[u8],
        num_leaf_proofs: usize,
    ) -> Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: Default::default(),
        };

        // Validate the batch count at the public byte-loading boundary so a zero
        // or oversized count returns an error instead of panicking inside the
        // circuit builder (#97027, #97070).
        validate_proof_count(num_leaf_proofs, "num_leaf_proofs")?;

        // 1) Load and pin leaf verifier data to the canonical Wormhole leaf circuit.
        let leaf_verifier_data =
            load_canonical_leaf_verifier_data(leaf_common_bytes, leaf_verifier_only_bytes)?;

        // 2) Reconstruct the canonical aggregation circuit once: it provides both the
        // witness targets and the canonical common data used to pin the prebuilt artifacts.
        let circuit = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf_verifier_data.common,
            &leaf_verifier_data.verifier_only,
            num_leaf_proofs,
        )?;
        let targets = Some(circuit.targets());
        let canonical_agg = circuit.build_verifier();

        // 3) Load prebuilt aggregation circuit prover data and pin common data.
        let agg_common =
            CommonCircuitData::from_bytes(aggregated_common_bytes.to_vec(), &gate_serializer)
                .map_err(|e| anyhow!("failed to deserialize aggregated common data: {}", e))?;
        ensure_common_matches_canonical(&agg_common, &canonical_agg.common, "private_batch")?;

        let agg_prover_only = ProverOnlyCircuitData::from_bytes(
            aggregated_prover_only_bytes,
            &generator_serializer,
            &agg_common,
        )
        .map_err(|e| anyhow!("failed to deserialize aggregated prover data: {}", e))?;

        // 4) Load dummy proof template compatible with the leaf verifier common data
        let dummy_proof_template =
            load_dummy_proof(dummy_proof_bytes.to_vec(), &leaf_verifier_data.common)
                .map_err(|e| anyhow!("failed to deserialize dummy proof: {}", e))?;

        // Verify the template is a valid leaf proof carrying the strong dummy
        // sentinel (zero block hash AND zero outputs), so a poisoned padding
        // template cannot inject a real payout into every partial batch. This
        // mirrors the public-batch template check (#97026).
        verify_dummy_leaf_template(&dummy_proof_template, &leaf_verifier_data)?;

        Ok(Self {
            circuit_data: ProverCircuitData {
                prover_only: agg_prover_only,
                common: agg_common,
            },
            partial_witness: PartialWitness::new(),
            targets,
            num_leaf_proofs,
            dummy_proof_template,
        })
    }

    /// Create a private-batch aggregation prover from explicit file paths.
    #[cfg(feature = "std")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_files(
        aggregated_prover_path: &Path,
        aggregated_common_path: &Path,
        leaf_common_path: &Path,
        leaf_verifier_path: &Path,
        dummy_proof_path: &Path,
        num_leaf_proofs: usize,
    ) -> Result<Self> {
        let aggregated_prover_only_bytes = fs::read(aggregated_prover_path).with_context(|| {
            format!(
                "Failed to read aggregated prover file {:?}",
                aggregated_prover_path
            )
        })?;
        let aggregated_common_bytes = fs::read(aggregated_common_path).with_context(|| {
            format!(
                "Failed to read aggregated common file {:?}",
                aggregated_common_path
            )
        })?;
        let leaf_common_bytes = fs::read(leaf_common_path)
            .with_context(|| format!("Failed to read leaf common file {:?}", leaf_common_path))?;
        let leaf_verifier_only_bytes = fs::read(leaf_verifier_path).with_context(|| {
            format!("Failed to read leaf verifier file {:?}", leaf_verifier_path)
        })?;
        let dummy_proof_bytes = fs::read(dummy_proof_path)
            .with_context(|| format!("Failed to read dummy proof file {:?}", dummy_proof_path))?;

        Self::new_from_bytes(
            &aggregated_prover_only_bytes,
            &aggregated_common_bytes,
            &leaf_common_bytes,
            &leaf_verifier_only_bytes,
            &dummy_proof_bytes,
            num_leaf_proofs,
        )
    }

    /// Convenience constructor that loads everything from a generated binaries directory.
    ///
    /// Expected files:
    /// - `private_batch_prover.bin`
    /// - `private_batch_common.bin`
    /// - `common.bin`
    /// - `verifier.bin`
    /// - `dummy_proof.bin`
    /// - `config.json`
    ///
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let bins_config = crate::config::CircuitBinsConfig::load(bins_dir)
            .with_context(|| format!("Failed to load config.json from {}", bins_dir.display()))?;
        let num_leaf_proofs = bins_config.num_leaf_proofs;

        Self::new_from_files(
            &bins_dir.join("private_batch_prover.bin"),
            &bins_dir.join("private_batch_common.bin"),
            &bins_dir.join("common.bin"),
            &bins_dir.join("verifier.bin"),
            &bins_dir.join("dummy_proof.bin"),
            num_leaf_proofs,
        )
    }

    // -------------------------------------------------------------------------
    // Proving API
    // -------------------------------------------------------------------------

    /// Number of leaf proofs aggregated by this private-batch prover.
    pub fn num_leaf_proofs(&self) -> usize {
        self.num_leaf_proofs
    }

    /// Commit leaf proofs to the aggregation circuit witness.
    ///
    /// Performs padding with dummy proofs, shuffling, and witness filling.
    /// Rejects batches the private-batch circuit's cross-slot constraints would
    /// fail (mixed block hashes, asset ids, or fee rates) up front, so callers
    /// get a precise error in milliseconds instead of a proving failure.
    pub fn commit(mut self, mut proofs: Vec<ProofWithPublicInputs<F, C, D>>) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("private-batch aggregation prover has already committed to inputs");
        };

        if proofs.len() > self.num_leaf_proofs {
            bail!(
                "too many proofs: got {}, expected at most {}",
                proofs.len(),
                self.num_leaf_proofs
            );
        }

        // If we're going to pad with dummy proofs (asset_id = 0), real proofs must
        // also use asset_id = 0 because the private-batch circuit enforces asset_id
        // equality across all proofs.
        let num_dummies_needed = self.num_leaf_proofs.saturating_sub(proofs.len());

        // Validate every real proof's public-input length up front, regardless of
        // whether padding is needed, so a malformed full batch is rejected at the
        // API boundary instead of panicking inside witness assignment (#97073).
        for (idx, proof) in proofs.iter().enumerate() {
            ensure_proof_public_input_len(proof, LEAF_PI_LEN, "leaf proof")?;
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

        // Pad with dummy proofs
        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_proof_template.clone());
        }

        // Uniformly shuffle proofs to hide dummy positions. The circuit selects its block
        // reference from the first non-dummy slot in-circuit, so no position is special.
        if proofs.len() > 1 {
            let mut rng = rand::thread_rng();
            proofs.shuffle(&mut rng);
        }

        // Generate one dummy nullifier preimage per slot.
        // In-circuit hashes these only for dummy proofs.
        let dummy_nullifier_pre_images =
            generate_dummy_nullifier_pre_images_for_slots(proofs.len());

        fill_private_batch_witness(
            &mut self.partial_witness,
            &targets,
            &proofs,
            &dummy_nullifier_pre_images,
        )?;

        Ok(self)
    }

    /// Generate the aggregated private-batch proof after `commit(...)`.
    pub fn prove(self) -> Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove private-batch aggregation circuit: {}", e))
    }

    /// One-shot client aggregation: commit the full leaf-proof set and prove.
    ///
    /// This is the intended client (CLI / mobile) entry point: a client knows
    /// its complete leaf set up front, so there is no queue — pass everything
    /// at once. Cross-proof compatibility is checked fail-fast in `commit`.
    pub fn aggregate(
        self,
        proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        self.commit(proofs)?.prove()
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Check that a set of leaf proofs is mutually compatible under the
/// private-batch circuit's cross-slot constraints, so an incompatible batch is
/// rejected at commit time instead of failing after minutes of proving:
///
/// - `asset_id` must match across ALL proofs (dummies included),
/// - `block_hash` and `volume_fee_bps` must match between non-dummy proofs
///   (`block_hash == 0` slots are exempt).
///
/// NOTE: keep in lockstep with the circuit's cross-slot constraints
/// (`private_batch::circuit::circuit_logic`). The circuit remains the enforcer;
/// this only improves failure latency and error quality.
fn ensure_leaf_batch_compatible(proofs: &[ProofWithPublicInputs<F, C, D>]) -> Result<()> {
    use crate::private_batch::circuit::constants::{
        ASSET_ID_START, BLOCK_HASH_START, VOLUME_FEE_BPS_START,
    };

    struct LeafMeta {
        asset_id: u64,
        volume_fee_bps: u64,
        block_hash: [u64; 4],
    }
    // PI lengths were validated by the caller.
    let metas: Vec<LeafMeta> = proofs
        .iter()
        .map(|proof| LeafMeta {
            asset_id: proof.public_inputs[ASSET_ID_START].to_canonical_u64(),
            volume_fee_bps: proof.public_inputs[VOLUME_FEE_BPS_START].to_canonical_u64(),
            block_hash: core::array::from_fn(|i| {
                proof.public_inputs[BLOCK_HASH_START + i].to_canonical_u64()
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
    for (idx, meta) in metas.iter().enumerate() {
        if meta.block_hash == [0u64; 4] {
            continue; // dummy sentinel: exempt from block/fee consistency
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
                if meta.volume_fee_bps != reference.volume_fee_bps {
                    bail!(
                        "leaf proof {} has volume_fee_bps={}, but proof {} has volume_fee_bps={}; \
                         all non-dummy proofs in a private batch must share one fee rate",
                        idx,
                        meta.volume_fee_bps,
                        ref_idx,
                        reference.volume_fee_bps
                    );
                }
            }
        }
    }
    Ok(())
}

/// Verify that the dummy leaf proof template is a valid leaf proof carrying the
/// strong dummy sentinel: `block_hash == 0` AND both output amounts zero.
///
/// The private-batch circuit only treats `block_hash == 0` slots as dummies, and
/// its exit-dedup gadget sums output amounts across matching exit accounts. If a
/// poisoned `dummy_proof.bin` contained a *real* proof (non-zero block hash or
/// outputs), every empty slot in a partial batch would replay that payout. This
/// mirrors `verify_dummy_private_batch_template` at the public-batch layer (#97026).
fn verify_dummy_leaf_template(
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
    if pis.output_amount_1 != 0 || pis.output_amount_2 != 0 {
        bail!(
            "dummy leaf proof template has non-zero output amounts ({}, {}); \
             padding templates must contribute zero to every exit slot",
            pis.output_amount_1,
            pis.output_amount_2
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
        ASSET_ID_START, BLOCK_HASH_START, VOLUME_FEE_BPS_START,
    };
    use plonky2::field::types::Field;
    use qp_wormhole_inputs::{
        BLOCK_HASH_START_INDEX, NULLIFIER_START_INDEX, OUTPUT_AMOUNT_1_INDEX,
        PUBLIC_INPUTS_FELTS_LEN,
    };
    use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};

    #[test]
    fn dummy_template_with_zero_sentinel_is_accepted() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let template = prove_fake_leaf(&leaf, &targets, [F::ZERO; PUBLIC_INPUTS_FELTS_LEN]);
        verify_dummy_leaf_template(&template, &leaf.verifier_data())
            .expect("all-zero sentinel template must be accepted");
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
    fn dummy_template_with_nonzero_payout_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let mut pis = [F::ZERO; PUBLIC_INPUTS_FELTS_LEN];
        pis[OUTPUT_AMOUNT_1_INDEX] = F::from_canonical_u32(5);
        let template = prove_fake_leaf(&leaf, &targets, pis);
        let err = verify_dummy_leaf_template(&template, &leaf.verifier_data()).unwrap_err();
        assert!(
            err.to_string().contains("non-zero output amounts"),
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

    fn leaf_pis(asset_id: u64, volume_fee_bps: u64, block: u64) -> [F; PUBLIC_INPUTS_FELTS_LEN] {
        let mut pis = [F::ZERO; PUBLIC_INPUTS_FELTS_LEN];
        pis[ASSET_ID_START] = F::from_canonical_u64(asset_id);
        pis[VOLUME_FEE_BPS_START] = F::from_canonical_u64(volume_fee_bps);
        pis[BLOCK_HASH_START] = F::from_canonical_u64(block);
        pis
    }

    #[test]
    fn compatible_leaf_batch_is_accepted() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let proofs = vec![
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 1)),
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 1)),
            // Dummy slot: exempt from block/fee consistency.
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 99, 0)),
        ];
        ensure_leaf_batch_compatible(&proofs).expect("compatible batch must be accepted");
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

    #[test]
    fn mixed_fee_leaf_batch_is_rejected() {
        let (leaf, targets) = build_fake_leaf_circuit();
        let proofs = vec![
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 10, 1)),
            prove_fake_leaf(&leaf, &targets, leaf_pis(0, 20, 1)),
        ];
        let err = ensure_leaf_batch_compatible(&proofs).unwrap_err();
        assert!(err.to_string().contains("volume_fee_bps"), "got: {err}");
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
