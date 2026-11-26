use ownership_circuit::circuit::circuit_logic::OwnershipCircuit;
use ownership_circuit::inputs::CircuitInputs;
use ownership_circuit::PUBLIC_INPUTS_FELTS_LEN;
use ownership_prover::OwnershipProver;
use ownership_verifier::{OwnershipVerifier, ProofWithPublicInputs};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::util::serialization::DefaultGateSerializer;
use tiny_keccak::{Hasher, Keccak};
use wormhole_circuit::sensitive::Secret;
use zk_circuits_common::circuit::ownership_circuit_config;
use zk_circuits_common::utils::BytesDigest;

fn sample_inputs() -> CircuitInputs {
    let secret = Secret::try_from([0x11; 32]).unwrap();
    let claim = BytesDigest::try_from([0x22; 32].as_slice()).unwrap();
    CircuitInputs::from_secret(secret, claim)
}

fn build_verifier_bytes() -> (Vec<u8>, Vec<u8>) {
    let verifier_data = OwnershipCircuit::new(ownership_circuit_config())
        .unwrap()
        .build_verifier();
    let common_bytes = verifier_data
        .common
        .to_bytes(&DefaultGateSerializer)
        .unwrap();
    let verifier_bytes = verifier_data.verifier_only.to_bytes().unwrap();
    (verifier_bytes, common_bytes)
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

#[test]
fn verify_simple_proof() {
    let config = CircuitConfig::standard_recursion_config();
    let prover = OwnershipProver::new(config.clone()).unwrap();
    let proof = prover.commit(&sample_inputs()).unwrap().prove().unwrap();

    let verifier_data = OwnershipCircuit::new(config).unwrap().build_verifier();
    verifier_data.verify(proof).unwrap();
}

#[test]
fn loaded_verifier_accepts_fresh_proof() {
    let prover = OwnershipProver::new(ownership_circuit_config()).unwrap();
    let proof = prover.commit(&sample_inputs()).unwrap().prove().unwrap();

    let (verifier_bytes, common_bytes) = build_verifier_bytes();
    let verifier = OwnershipVerifier::new_from_bytes(&verifier_bytes, &common_bytes).unwrap();
    let verifier_proof =
        ProofWithPublicInputs::from_bytes(proof.to_bytes(), &verifier.circuit_data.common).unwrap();
    verifier.verify(verifier_proof).unwrap();
    assert_eq!(proof.public_inputs.len(), PUBLIC_INPUTS_FELTS_LEN);
}

#[test]
fn loader_rejects_non_canonical_bytes() {
    let err = OwnershipVerifier::new_from_bytes(b"not-a-circuit", b"also-not").unwrap_err();
    assert!(
        format!("{err:#}").contains("does not match the canonical"),
        "got: {err:#}"
    );
}

/// Prints the keccak256 of the canonical artifacts so the verifier pin can
/// be updated after a deliberate circuit change.
#[test]
fn canonical_artifact_hashes_match_pinned_values() {
    let (verifier_bytes, common_bytes) = build_verifier_bytes();
    let verifier_hash = keccak256(&verifier_bytes);
    let common_hash = keccak256(&common_bytes);
    eprintln!("ownership verifier keccak256: {verifier_hash:02x?}");
    eprintln!("ownership common keccak256:   {common_hash:02x?}");

    let loaded = OwnershipVerifier::new_from_bytes(&verifier_bytes, &common_bytes);
    assert!(
        loaded.is_ok(),
        "freshly built artifacts must match the pinned keccak256; \
         update CANONICAL_*_KECCAK256 in qp-ownership-verifier. \
         verifier={verifier_hash:02x?} common={common_hash:02x?}: {loaded:?}"
    );
}
