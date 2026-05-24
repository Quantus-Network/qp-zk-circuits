//! Single-gadget circuit harness.
//!
//! `prove_gadget` builds a fresh `CircuitBuilder`, lets the caller wire up a
//! gadget under test, fills the witness, and runs the actual Plonky2 prover.
//! This is the "soundness/completeness oracle": the prover succeeds iff every
//! gate (and every range-check gate the gadget emits) is satisfied by the
//! assigned witness.
//!
//! Usage pattern (matching the Clean `FormalCircuit` decomposition):
//!
//! ```ignore
//! let result = prove_gadget(|builder| {
//!     // build gadget with virtual targets, return them
//! }, |pw, targets| {
//!     // assign witness values, return Ok(())
//! });
//! ```
//!
//! `result.is_ok()` represents the verifier's accept/reject for the assignment.

use std::panic::{catch_unwind, AssertUnwindSafe};

use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::{
    circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
    proof::ProofWithPublicInputs,
};
use zk_circuits_common::circuit::{C, D, F};

/// Outcome of attempting to prove a gadget circuit. Owning the proof on success
/// keeps the door open for follow-up assertions on public inputs.
pub type GadgetResult = anyhow::Result<ProofWithPublicInputs<F, C, D>>;

/// Build a one-shot circuit containing a single gadget and run the prover.
///
/// `setup` registers the gadget's targets in the builder and returns whatever
/// handle the caller needs to fill the witness. `fill` assigns concrete values.
///
/// Returns `Ok(proof)` if the prover accepts and `Err(_)` otherwise. Plonky2
/// can `panic!` during witness generation when a witness violates a range
/// check (e.g. `split_le`); we demote such panics to `Err` so adversarial /
/// completeness properties can simply assert `is_err()` without crashing the
/// proptest runner.
pub fn prove_gadget<T, S, FW>(setup: S, fill: FW) -> GadgetResult
where
    S: FnOnce(&mut CircuitBuilder<F, D>) -> T,
    FW: FnOnce(&mut PartialWitness<F>, &T) -> anyhow::Result<()>,
{
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // Leaf-style (non-ZK) config: smallest, fastest config that covers the
        // gadgets in `common/`. ZK is irrelevant for soundness/completeness.
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = setup(&mut builder);

        let mut pw = PartialWitness::new();
        fill(&mut pw, &targets)?;

        let data = builder.build::<C>();
        data.prove(pw)
    }));

    match outcome {
        Ok(res) => res,
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            Err(anyhow::anyhow!("circuit panicked during build/prove: {msg}"))
        }
    }
}
