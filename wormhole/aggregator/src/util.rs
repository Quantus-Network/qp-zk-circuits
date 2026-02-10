use anyhow::bail;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};

use crate::dummy_proof::get_dummy_proof;

pub fn pad_with_dummy_proofs(
    mut proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    proof_len: usize,
    common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<Vec<ProofWithPublicInputs<F, C, D>>> {
    let num_proofs = proofs.len();

    if num_proofs > proof_len {
        bail!("proofs to aggregate was more than the maximum allowed")
    }

    // Get dummy proof based on whether ZK mode is enabled in the circuit config.
    // The proof is lazily generated on first access and cached for subsequent use.
    let zk = common_data.config.zero_knowledge;
    let dummy_proof = get_dummy_proof(zk).clone();

    for _ in 0..(proof_len - num_proofs) {
        proofs.push(dummy_proof.clone());
    }

    Ok(proofs)
}
