//! Public-batch aggregation prover.
//!
//! The private-batch verifier key is baked in as constants at circuit build time to prevent
//! verifier key substitution attacks. The public-batch circuit (and its prover-only data)
//! is always rebuilt from source rather than loaded from a serialized artifact; see
//! [`PublicBatchProver::new_from_bytes`].

use anyhow::{anyhow, bail, Context, Result};
use plonky2::field::types::PrimeField64;
#[cfg(feature = "std")]
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
            VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputs,
    },
};
use qp_wormhole_inputs::{validate_proof_count, BytesDigest, PrivateBatchPublicInputs};

#[cfg(feature = "std")]
use std::path::Path;

use zk_circuits_common::{
    circuit::{wormhole_public_batch_circuit_config, C, D, F},
    utils::bytes_to_digest,
};

#[cfg(feature = "std")]
use crate::common::utils::read_artifact_file;
use crate::{
    common::utils::{
        canonical_leaf_verifier_data, ensure_proof_public_input_len,
        load_canonical_private_batch_verifier_data,
    },
    public_batch::{
        circuit::{
            circuit_logic::{PublicBatchCircuit, PublicBatchCircuitTargets},
            constants::private_batch_pi_len,
        },
        prover::witness::fill_public_batch_witness,
    },
};

#[derive(Debug)]
pub struct PublicBatchInputs {
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub aggregator_address: BytesDigest,
}

#[derive(Debug)]
pub struct PublicBatchProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<PublicBatchCircuitTargets>,
    num_private_batch_proofs: usize,
    /// Dummy private-batch proof (over all-dummy leaves, `block_hash == 0`) used to
    /// pad partial public batches. The circuit zeroes dummy inners' exit slots and
    /// nullifiers, so one template can fill several slots without collisions.
    dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    /// Private-batch verifier data, kept so `commit` can cheaply verify each
    /// supplied inner proof before starting the minutes-long proving run.
    private_batch_verifier: VerifierCircuitData<F, C, D>,
}

impl PublicBatchProver {
    /// Build a fresh public-batch aggregation prover from circuit definitions.
    ///
    /// In production, prefer `new_from_binaries_dir(...)` to load prebuilt circuits.
    /// Returns an error when either proof count is outside the supported range,
    /// or when `dummy_proof_template` is not a valid all-dummy private-batch
    /// proof (zero block-hash sentinel and zero payouts).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        public_batch_circuit_config: CircuitConfig,
        private_batch_common: CommonCircuitData<F, D>,
        private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_private_batch_proofs: usize,
        private_batch_num_leaves: usize,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self> {
        let private_batch_verifier_data = VerifierCircuitData {
            verifier_only: private_batch_verifier_only.clone(),
            common: private_batch_common.clone(),
        };

        // Proof-count bounds are enforced by PublicBatchCircuit::new.
        let public_batch_circuit = PublicBatchCircuit::new(
            public_batch_circuit_config,
            private_batch_common,
            private_batch_verifier_only,
            num_private_batch_proofs,
            private_batch_num_leaves,
        )?;

        let targets = Some(public_batch_circuit.targets());
        let circuit_data = public_batch_circuit.build_prover();

        // Enforce the same template invariant as the byte-loading constructors:
        // `commit` clones this template into every padded slot, and the circuit
        // only zeroes a slot's exits/nullifiers when its block_hash is the zero
        // sentinel — a caller-supplied REAL proof here would be forwarded as a
        // legitimate batch member (#97026).
        verify_dummy_private_batch_template(&dummy_proof_template, &private_batch_verifier_data)?;

        Ok(Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
            num_private_batch_proofs,
            dummy_proof_template,
            private_batch_verifier: private_batch_verifier_data,
        })
    }

    /// Create a public-batch prover from serialized bytes.
    ///
    /// The public-batch circuit itself (including its `ProverOnlyCircuitData`)
    /// is always rebuilt from source rather than deserialized: prover-only data
    /// decides which witness wires are exposed as public inputs, so a poisoned
    /// prover artifact could exfiltrate witness data through the proof's
    /// public-input list. The full circuit build was already required here to
    /// pin the loaded artifacts, so rebuilding adds no extra cost.
    pub fn new_from_bytes(
        private_batch_common_bytes: &[u8],
        private_batch_verifier_only_bytes: &[u8],
        dummy_private_batch_proof_bytes: &[u8],
        config: (usize, usize), // (num_leaf_proofs, num_private_batch_proofs)
    ) -> Result<Self> {
        let (num_leaf_proofs, num_private_batch_proofs) = config;

        // Validate batch counts at the public byte-loading boundary so a zero or
        // oversized config returns an error instead of panicking inside the
        // circuit builder (#97027, #97070).
        validate_proof_count(num_leaf_proofs, "num_leaf_proofs")?;
        validate_proof_count(num_private_batch_proofs, "num_private_batch_proofs")?;

        // 1) Load and pin private-batch verifier data to the canonical circuit.
        let private_batch_verifier_data = load_canonical_private_batch_verifier_data(
            private_batch_common_bytes,
            private_batch_verifier_only_bytes,
            &canonical_leaf_verifier_data(),
            num_leaf_proofs,
        )?;

        // Ensure the loaded private-batch artifact's public-input shape matches the
        // caller-supplied leaf count before building the public-batch circuit, which
        // indexes fixed offsets derived from that count (#97071).
        let expected_l0_pi_len = private_batch_pi_len(num_leaf_proofs);
        if private_batch_verifier_data.common.num_public_inputs != expected_l0_pi_len {
            bail!(
                "private-batch common data has {} public inputs, expected {} for num_leaf_proofs={}; \
                 refusing to build a public-batch circuit over an inconsistent private-batch artifact",
                private_batch_verifier_data.common.num_public_inputs,
                expected_l0_pi_len,
                num_leaf_proofs,
            );
        }

        // 2) Rebuild the canonical public-batch circuit from source. Its prover
        // data is used directly instead of loading a serialized prover artifact.
        let circuit = PublicBatchCircuit::new(
            wormhole_public_batch_circuit_config(),
            private_batch_verifier_data.common.clone(),
            &private_batch_verifier_data.verifier_only,
            num_private_batch_proofs,
            num_leaf_proofs,
        )?;
        let targets = Some(circuit.targets());
        let circuit_data = circuit.build_prover();

        // 3) Load the dummy private-batch proof template used to pad partial batches
        let dummy_proof_template = ProofWithPublicInputs::<F, C, D>::from_bytes(
            dummy_private_batch_proof_bytes.to_vec(),
            &private_batch_verifier_data.common,
        )
        .map_err(|e| anyhow!("failed to deserialize dummy private-batch proof: {}", e))?;

        // Verify the template is a valid all-dummy private-batch proof (zero
        // block-hash sentinel and zero forwarded payouts) so a poisoned padding
        // template cannot inject real exits into partial public batches (#97026).
        verify_dummy_private_batch_template(&dummy_proof_template, &private_batch_verifier_data)?;

        Ok(Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
            num_private_batch_proofs,
            dummy_proof_template,
            private_batch_verifier: private_batch_verifier_data,
        })
    }

    #[cfg(feature = "std")]
    pub fn new_from_files(
        private_batch_common_path: &Path,
        private_batch_verifier_path: &Path,
        dummy_private_batch_proof_path: &Path,
        config: (usize, usize),
    ) -> Result<Self> {
        let private_batch_common_bytes = read_artifact_file(private_batch_common_path)
            .with_context(|| format!("Failed to read {:?}", private_batch_common_path))?;
        let private_batch_verifier_only_bytes = read_artifact_file(private_batch_verifier_path)
            .with_context(|| format!("Failed to read {:?}", private_batch_verifier_path))?;
        let dummy_private_batch_proof_bytes = read_artifact_file(dummy_private_batch_proof_path)
            .with_context(|| format!("Failed to read {:?}", dummy_private_batch_proof_path))?;

        Self::new_from_bytes(
            &private_batch_common_bytes,
            &private_batch_verifier_only_bytes,
            &dummy_private_batch_proof_bytes,
            config,
        )
    }

    /// Convenience constructor from a generated binaries directory.
    ///
    /// Expected files:
    /// - `private_batch_common.bin`             (private-batch common)
    /// - `private_batch_verifier.bin`           (private-batch verifier-only)
    /// - `dummy_private_batch_proof.bin`        (padding template)
    /// - `config.json`
    ///
    /// The public-batch circuit itself is rebuilt from source (see
    /// [`Self::new_from_bytes`]); no `public_batch_prover.bin` or
    /// `public_batch_common.bin` is read.
    #[cfg(feature = "std")]
    pub fn new_from_binaries_dir(bins_dir: &Path) -> Result<Self> {
        let bins_config = crate::config::CircuitBinsConfig::load(bins_dir)?;

        let num_private_batch_proofs = bins_config.num_private_batch_proofs.ok_or_else(|| {
            anyhow!(
                "config is missing num_private_batch_proofs. Regenerate binaries with num_private_batch_proofs set."
            )
        })?;
        let config = (bins_config.num_leaf_proofs, num_private_batch_proofs);

        Self::new_from_files(
            &bins_dir.join("private_batch_common.bin"),
            &bins_dir.join("private_batch_verifier.bin"),
            &bins_dir.join("dummy_private_batch_proof.bin"),
            config,
        )
    }

    pub fn num_private_batch_proofs(&self) -> usize {
        self.num_private_batch_proofs
    }

    /// Commit private-batch aggregated proofs into the public-batch circuit witness.
    ///
    /// Partial batches are padded with the dummy private-batch proof template.
    /// The circuit exempts dummies (`block_hash == 0`) from metadata consistency
    /// and zeroes their forwarded exit slots and nullifiers.
    ///
    /// Fails fast (milliseconds, before the minutes-long proving run) on inputs
    /// the public-batch circuit could never prove: each supplied proof is
    /// cryptographically verified against the pinned private-batch verifier,
    /// and non-dummy proofs must share one (block hash, asset id, fee) triple —
    /// the cross-proof consistency the circuit enforces. Proofs arriving via
    /// [`crate::pool::ProofPool`] already satisfy both by construction; this
    /// protects services that feed untrusted proof vectors to the prover
    /// directly.
    pub fn commit(mut self, inputs: PublicBatchInputs) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("public-batch aggregation prover has already committed to inputs");
        };

        let mut proofs = inputs.proofs;
        let aggregator_address = inputs.aggregator_address;

        let aggregator_address_felts = bytes_to_digest(aggregator_address);

        if proofs.is_empty() {
            bail!("no private-batch proofs to aggregate");
        }
        if proofs.len() > self.num_private_batch_proofs {
            bail!(
                "Expected at most {} private-batch proofs, but got {}",
                self.num_private_batch_proofs,
                proofs.len()
            );
        }

        let expected_pi_len = targets
            .private_batch_proofs
            .first()
            .map(|proof| proof.public_inputs.len())
            .ok_or_else(|| anyhow!("public-batch circuit has no private-batch proof targets"))?;
        for (index, proof) in proofs.iter().enumerate() {
            ensure_proof_public_input_len(proof, expected_pi_len, "private-batch proof")
                .with_context(|| format!("private-batch proof {} is malformed", index))?;
            self.private_batch_verifier
                .verify(proof.clone())
                .map_err(|e| {
                    anyhow!(
                        "private-batch proof {} failed verification against the pinned \
                         private-batch verifier: {}",
                        index,
                        e
                    )
                })?;
        }

        ensure_private_batch_compatible(&proofs)?;

        // Pad partial batches with the dummy template. No shuffle: forwarding is
        // order-preserving by design (per-segment attribution on-chain).
        let num_dummies_needed = self.num_private_batch_proofs - proofs.len();
        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_proof_template.clone());
        }

        fill_public_batch_witness(
            &mut self.partial_witness,
            &targets,
            &proofs,
            aggregator_address_felts,
        )?;

        Ok(self)
    }

    pub fn prove(self) -> Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove public-batch aggregation circuit: {}", e))
    }
}

/// Check that a set of private-batch proofs is mutually compatible under the
/// public-batch circuit's cross-proof constraints, so an incompatible batch is
/// rejected at commit time instead of failing after minutes of proving:
/// non-dummy proofs (`block_hash != 0`) must share one block hash, asset id,
/// and volume fee; dummy proofs are exempt.
///
/// NOTE: keep in lockstep with the circuit's cross-proof constraints
/// (`public_batch::circuit::circuit_logic`). The circuit remains the enforcer;
/// this only improves failure latency and error quality. Mirrors
/// `ensure_leaf_batch_compatible` one layer down.
fn ensure_private_batch_compatible(proofs: &[ProofWithPublicInputs<F, C, D>]) -> Result<()> {
    use crate::public_batch::circuit::constants::{
        PRIVATE_BATCH_ASSET_ID_OFFSET, PRIVATE_BATCH_BLOCK_HASH_OFFSET,
        PRIVATE_BATCH_VOLUME_FEE_BPS_OFFSET,
    };

    struct InnerMeta {
        asset_id: u64,
        volume_fee_bps: u64,
        block_hash: [u64; 4],
    }
    // PI lengths were validated by the caller.
    let metas: Vec<InnerMeta> = proofs
        .iter()
        .map(|proof| InnerMeta {
            asset_id: proof.public_inputs[PRIVATE_BATCH_ASSET_ID_OFFSET].to_canonical_u64(),
            volume_fee_bps: proof.public_inputs[PRIVATE_BATCH_VOLUME_FEE_BPS_OFFSET]
                .to_canonical_u64(),
            block_hash: core::array::from_fn(|i| {
                proof.public_inputs[PRIVATE_BATCH_BLOCK_HASH_OFFSET + i].to_canonical_u64()
            }),
        })
        .collect();

    let mut reference: Option<(usize, &InnerMeta)> = None;
    for (idx, meta) in metas.iter().enumerate() {
        if meta.block_hash == [0u64; 4] {
            continue; // all-dummy sentinel: exempt from consistency checks
        }
        match reference {
            None => reference = Some((idx, meta)),
            Some((ref_idx, reference)) => {
                if meta.block_hash != reference.block_hash {
                    bail!(
                        "private-batch proof {} is for a different block than proof {}; \
                         all non-dummy proofs in a public batch must share one block hash",
                        idx,
                        ref_idx
                    );
                }
                if meta.asset_id != reference.asset_id {
                    bail!(
                        "private-batch proof {} has asset_id={}, but proof {} has asset_id={}; \
                         all non-dummy proofs in a public batch must share one asset",
                        idx,
                        meta.asset_id,
                        ref_idx,
                        reference.asset_id
                    );
                }
                if meta.volume_fee_bps != reference.volume_fee_bps {
                    bail!(
                        "private-batch proof {} has volume_fee_bps={}, but proof {} has volume_fee_bps={}; \
                         all non-dummy proofs in a public batch must share one fee rate",
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

/// Verify that the dummy private-batch proof template is a valid all-dummy
/// private-batch proof carrying the zero block-hash sentinel and zero forwarded
/// payouts, so poisoned padding cannot inject real exits into partial public
/// batches (#97026).
fn verify_dummy_private_batch_template(
    template: &ProofWithPublicInputs<F, C, D>,
    private_batch_verifier: &VerifierCircuitData<F, C, D>,
) -> Result<()> {
    private_batch_verifier
        .verify(template.clone())
        .map_err(|e| {
            anyhow!(
                "dummy private-batch proof template failed verification: {}",
                e
            )
        })?;

    let u64s: Vec<u64> = template
        .public_inputs
        .iter()
        .map(|f| f.to_canonical_u64())
        .collect();
    let pis = PrivateBatchPublicInputs::try_from_u64_slice(&u64s)
        .context("failed to parse dummy private-batch proof public inputs")?;

    if pis.block_data.block_hash != BytesDigest::default() {
        bail!(
            "dummy private-batch proof template has non-zero block_hash {:?}; \
             padding templates must carry the all-zero block-hash sentinel",
            pis.block_data.block_hash
        );
    }
    for (i, slot) in pis.account_data.iter().enumerate() {
        if slot.summed_output_amount != 0 {
            bail!(
                "dummy private-batch proof template forwards non-zero payout at slot {} ({}); \
                 padding templates must contribute zero to every exit slot",
                i,
                slot.summed_output_amount
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_batch::circuit::circuit_logic::PrivateBatchCircuit;
    use crate::private_batch::prover::PrivateBatchProver;
    use plonky2::field::types::Field;
    use qp_wormhole_inputs::MAX_PROOF_COUNT;
    use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};
    use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, F};

    #[test]
    fn direct_constructors_reject_oversized_counts() {
        let (leaf, leaf_targets) = build_fake_leaf_circuit();
        let fake_proof = prove_fake_leaf(&leaf, &leaf_targets, [F::ZERO; 21]);

        let err = PrivateBatchProver::new(
            wormhole_private_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            MAX_PROOF_COUNT + 1,
            fake_proof.clone(),
        )
        .expect_err("oversized direct private-batch prover count must be rejected");
        assert!(err.to_string().contains("exceeds maximum"));

        let err = PublicBatchProver::new(
            wormhole_public_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            MAX_PROOF_COUNT + 1,
            1,
            fake_proof,
        )
        .expect_err("oversized direct public-batch prover count must be rejected");
        assert!(err.to_string().contains("exceeds maximum"));

        let err = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf.common,
            &leaf.verifier_only,
            MAX_PROOF_COUNT + 1,
        )
        .err()
        .expect("oversized private-batch count must be rejected");
        assert!(err.to_string().contains("exceeds maximum"));

        let err = PublicBatchCircuit::new(
            wormhole_public_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            MAX_PROOF_COUNT + 1,
            1,
        )
        .err()
        .expect("oversized public-batch count must be rejected");
        assert!(err.to_string().contains("exceeds maximum"));
    }

    /// A genuine all-dummy private-batch proof over the fake leaf circuit:
    /// the only template the (now-validating) direct constructor accepts.
    fn make_all_dummy_private_batch_template(
        leaf: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
        fake_leaf_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        PrivateBatchProver::new(
            wormhole_private_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            1,
            fake_leaf_proof.clone(),
        )
        .unwrap()
        .commit(vec![fake_leaf_proof.clone()])
        .unwrap()
        .prove()
        .unwrap()
    }

    #[test]
    fn commit_rejects_malformed_private_batch_pi_without_panicking() {
        let (leaf, leaf_targets) = build_fake_leaf_circuit();
        let fake_proof = prove_fake_leaf(&leaf, &leaf_targets, [F::ZERO; 21]);
        let private_batch = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf.common,
            &leaf.verifier_only,
            1,
        )
        .unwrap()
        .build_verifier();

        let template = make_all_dummy_private_batch_template(&leaf, &fake_proof);
        let prover = PublicBatchProver::new(
            wormhole_public_batch_circuit_config(),
            private_batch.common.clone(),
            &private_batch.verifier_only,
            1,
            1,
            template,
        )
        .unwrap();

        let mut malformed = fake_proof;
        malformed.public_inputs.pop();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.commit(PublicBatchInputs {
                proofs: vec![malformed],
                aggregator_address: BytesDigest::default(),
            })
        }));
        assert!(
            result.is_ok(),
            "commit must not panic on malformed PI length"
        );
        let err = result.unwrap().unwrap_err();
        assert!(err
            .to_string()
            .contains("private-batch proof 0 is malformed"));
    }

    /// A genuine private-batch proof (over the fake leaf circuit) aggregating a
    /// single leaf with the given public inputs.
    fn make_private_batch_proof(
        leaf: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
        dummy_leaf: &ProofWithPublicInputs<F, C, D>,
        leaf_pis: [F; 21],
        leaf_targets: &[plonky2::iop::target::Target; 21],
    ) -> ProofWithPublicInputs<F, C, D> {
        let real_leaf = prove_fake_leaf(leaf, leaf_targets, leaf_pis);
        PrivateBatchProver::new(
            wormhole_private_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            1,
            dummy_leaf.clone(),
        )
        .unwrap()
        .commit(vec![real_leaf])
        .unwrap()
        .prove()
        .unwrap()
    }

    /// Cryptographically invalid (tampered) inner proofs must be rejected at
    /// commit time, before the expensive proving run starts.
    #[test]
    fn commit_rejects_tampered_private_batch_proof_before_proving() {
        let (leaf, leaf_targets) = build_fake_leaf_circuit();
        let dummy_leaf = prove_fake_leaf(&leaf, &leaf_targets, [F::ZERO; 21]);
        let private_batch = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf.common,
            &leaf.verifier_only,
            1,
        )
        .unwrap()
        .build_verifier();

        let template = make_all_dummy_private_batch_template(&leaf, &dummy_leaf);
        let prover = PublicBatchProver::new(
            wormhole_public_batch_circuit_config(),
            private_batch.common.clone(),
            &private_batch.verifier_only,
            1,
            1,
            template.clone(),
        )
        .unwrap();

        // Right shape, wrong cryptography: mutate one public input so the proof
        // no longer verifies.
        let mut tampered = template;
        tampered.public_inputs
            [crate::private_batch::circuit::constants::aggregated_output::ASSET_ID_OFFSET] =
            F::from_canonical_u64(9);

        let err = prover
            .commit(PublicBatchInputs {
                proofs: vec![tampered],
                aggregator_address: BytesDigest::default(),
            })
            .expect_err("tampered private-batch proof must be rejected at commit");
        assert!(
            err.to_string().contains("failed verification"),
            "got: {err}"
        );
    }

    /// Individually valid inner proofs with incompatible batch metadata (here:
    /// different block hashes) can never satisfy the circuit's cross-proof
    /// constraints; commit must reject them fail-fast instead of letting prove
    /// burn minutes of CPU.
    #[test]
    fn commit_rejects_batch_incompatible_private_batch_proofs() {
        let (leaf, leaf_targets) = build_fake_leaf_circuit();
        let dummy_leaf = prove_fake_leaf(&leaf, &leaf_targets, [F::ZERO; 21]);
        let private_batch = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf.common,
            &leaf.verifier_only,
            1,
        )
        .unwrap()
        .build_verifier();

        let block_pis = |block: u64| {
            let mut pis = [F::ZERO; 21];
            pis[crate::private_batch::circuit::constants::BLOCK_HASH_START] =
                F::from_canonical_u64(block);
            pis
        };
        let inner_a = make_private_batch_proof(&leaf, &dummy_leaf, block_pis(1), &leaf_targets);
        let inner_b = make_private_batch_proof(&leaf, &dummy_leaf, block_pis(2), &leaf_targets);

        let template = make_all_dummy_private_batch_template(&leaf, &dummy_leaf);
        let prover = PublicBatchProver::new(
            wormhole_public_batch_circuit_config(),
            private_batch.common.clone(),
            &private_batch.verifier_only,
            2,
            1,
            template,
        )
        .unwrap();

        let err = prover
            .commit(PublicBatchInputs {
                proofs: vec![inner_a, inner_b],
                aggregator_address: BytesDigest::default(),
            })
            .expect_err("cross-block private-batch proofs must be rejected at commit");
        assert!(err.to_string().contains("different block"), "got: {err}");
    }

    #[test]
    fn direct_constructors_reject_non_dummy_padding_templates() {
        let (leaf, leaf_targets) = build_fake_leaf_circuit();
        let dummy_leaf = prove_fake_leaf(&leaf, &leaf_targets, [F::ZERO; 21]);

        // A valid leaf proof with a non-zero block hash: real work, not padding.
        let mut real_pis = [F::ZERO; 21];
        real_pis[crate::private_batch::circuit::constants::BLOCK_HASH_START] = F::ONE;
        let real_leaf = prove_fake_leaf(&leaf, &leaf_targets, real_pis);

        // Private-batch direct constructor: template must carry the sentinel.
        let err = PrivateBatchProver::new(
            wormhole_private_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            1,
            real_leaf,
        )
        .expect_err("non-dummy leaf template must be rejected by the direct constructor");
        assert!(
            err.to_string().contains("non-zero block_hash"),
            "got: {err}"
        );

        // Public-batch direct constructor: a leaf proof is not even a valid
        // private-batch proof, let alone an all-dummy one.
        let private_batch = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf.common,
            &leaf.verifier_only,
            1,
        )
        .unwrap()
        .build_verifier();
        let err = PublicBatchProver::new(
            wormhole_public_batch_circuit_config(),
            private_batch.common.clone(),
            &private_batch.verifier_only,
            1,
            1,
            dummy_leaf,
        )
        .expect_err("leaf proof as public-batch padding template must be rejected");
        assert!(
            err.to_string().contains("failed verification")
                || err.to_string().contains("failed to parse"),
            "got: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Witness-fill proof-shape preflight
    //
    // A proof with the expected public-input length can still carry internally
    // inconsistent proof vectors. The pinned qp-plonky2 witness writer assigns
    // those through zip_eq / debug-only length checks, so without a full shape
    // preflight a malformed proof panics inside fill_public_batch_witness
    // (or silently leaves targets unset) instead of returning Err. Mirrors the
    // private-batch witness-fill preflight one layer down.
    // -------------------------------------------------------------------------

    /// Prove one valid all-dummy private-batch proof and build matching
    /// 1-slot public-batch targets.
    fn valid_private_batch_proof_and_targets() -> (
        ProofWithPublicInputs<F, C, D>,
        PublicBatchCircuitTargets,
    ) {
        let (leaf, leaf_targets) = build_fake_leaf_circuit();
        let dummy_leaf = prove_fake_leaf(&leaf, &leaf_targets, [F::ZERO; 21]);
        let proof = make_all_dummy_private_batch_template(&leaf, &dummy_leaf);

        let private_batch = PrivateBatchCircuit::new(
            wormhole_private_batch_circuit_config(),
            &leaf.common,
            &leaf.verifier_only,
            1,
        )
        .unwrap()
        .build_verifier();

        let targets = PublicBatchCircuit::new(
            wormhole_public_batch_circuit_config(),
            private_batch.common,
            &private_batch.verifier_only,
            1,
            1,
        )
        .unwrap()
        .targets();

        (proof, targets)
    }

    fn fill_witness_with_proof(
        targets: &PublicBatchCircuitTargets,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<()> {
        let mut pw = PartialWitness::new();
        fill_public_batch_witness(
            &mut pw,
            targets,
            &[proof],
            bytes_to_digest(BytesDigest::default()),
        )
    }

    /// Control: an untampered proof must still pass the shape preflight.
    #[test]
    fn witness_fill_accepts_well_shaped_proof() {
        let (proof, targets) = valid_private_batch_proof_and_targets();
        fill_witness_with_proof(&targets, proof)
            .expect("a valid, well-shaped proof must fill the witness");
    }

    /// A shortened FRI query-round list panics in plonky2's zip_eq without a
    /// shape preflight; it must instead be rejected with an error.
    #[test]
    fn witness_fill_rejects_truncated_fri_query_rounds() {
        let (mut proof, targets) = valid_private_batch_proof_and_targets();
        proof.proof.opening_proof.query_round_proofs.pop();

        let err = fill_witness_with_proof(&targets, proof)
            .expect_err("proof with truncated FRI query rounds must be rejected");
        assert!(err.to_string().contains("query_round_proofs"), "got: {err}");
    }

    /// A truncated opening set trips a debug-only length check in plonky2's
    /// witness writer (silent partial assignment in release); it must instead
    /// be rejected with an error.
    #[test]
    fn witness_fill_rejects_truncated_openings() {
        let (mut proof, targets) = valid_private_batch_proof_and_targets();
        proof.proof.openings.wires.pop();

        let err = fill_witness_with_proof(&targets, proof)
            .expect_err("proof with truncated openings must be rejected");
        assert!(err.to_string().contains("openings.wires"), "got: {err}");
    }

    /// A shortened wires Merkle cap is assigned through a plain zip, silently
    /// leaving trailing cap targets unset and deferring failure to prove time;
    /// it must instead be rejected with an error.
    #[test]
    fn witness_fill_rejects_truncated_wires_cap() {
        let (mut proof, targets) = valid_private_batch_proof_and_targets();
        proof.proof.wires_cap.0.pop();

        let err = fill_witness_with_proof(&targets, proof)
            .expect_err("proof with truncated wires_cap must be rejected");
        assert!(err.to_string().contains("wires_cap"), "got: {err}");
    }
}
