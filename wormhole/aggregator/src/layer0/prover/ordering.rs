//! Deterministic leaf-proof ordering for compact-child layer-0 aggregation.
//!
//! The emitted aggregate proof is deterministic for the same set of leaf proofs. It is not a
//! stable-user-input-order contract; downstream consumers should parse semantic exit/nullifier data.

use std::cmp::Ordering;

use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use zk_circuits_common::circuit::{C, D, F};

use crate::common::utils::is_dummy_leaf_proof;

type Proof = ProofWithPublicInputs<F, C, D>;

pub(crate) fn canonicalize_leaf_proofs(proofs: &mut [Proof]) {
    proofs.sort_by(compare_leaf_proofs_canonically);
}

pub(crate) fn compare_leaf_proofs_canonically(left: &Proof, right: &Proof) -> Ordering {
    match (
        is_dummy_leaf_proof(left).unwrap_or(false),
        is_dummy_leaf_proof(right).unwrap_or(false),
    ) {
        (false, true) => Ordering::Less,
        (true, false) => Ordering::Greater,
        _ => left
            .public_inputs
            .iter()
            .map(PrimeField64::to_canonical_u64)
            .cmp(
                right
                    .public_inputs
                    .iter()
                    .map(PrimeField64::to_canonical_u64),
            ),
    }
}
