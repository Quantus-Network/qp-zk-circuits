use anyhow::{bail, Context};
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};

#[cfg(not(feature = "no_zk"))]
const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../data/dummy_proof_zk.bin");
#[cfg(feature = "no_zk")]
const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../data/dummy_proof.bin");

pub fn pad_with_dummy_proofs(
    mut proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    proof_len: usize,
    common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<Vec<ProofWithPublicInputs<F, C, D>>> {
    let num_proofs = proofs.len();

    if num_proofs > proof_len {
        bail!("proofs to aggregate was more than the maximum allowed")
    }

    let dummy_proof = ProofWithPublicInputs::from_bytes(DUMMY_PROOF_BYTES.to_vec(), common_data)
        .context("failed to deserialize dummy proof")?;
    for _ in 0..(proof_len - num_proofs) {
        proofs.push(dummy_proof.clone());
    }

    Ok(proofs)
}
