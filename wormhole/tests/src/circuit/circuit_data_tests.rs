use anyhow::Result;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::util::serialization::DefaultGateSerializer;
use std::fs;
use std::path::Path;
use test_helpers::TestInputs;
use wormhole_circuit::circuit::circuit_logic::WormholeCircuit;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_verifier::WormholeVerifier;

/// The circuit crate must not expose a deserializer for the full leaf
/// `CircuitData`. A full `CircuitData` carries prover-only data (witness
/// generators plus the target list that decides which witness values become
/// `public_inputs`), so loading one from untrusted bytes could exfiltrate
/// private witness material such as the Wormhole `secret` through a proof's
/// public inputs. The leaf circuit builds from source in ~40 ms (release), so
/// there is no need for serialized full-circuit artifacts; provers always
/// construct `WormholeCircuit` directly and verifiers load pinned artifacts
/// through `WormholeVerifier::new_from_bytes`.
///
/// This is a compile-time guarantee: if `circuit_data_from_bytes` (or a
/// similar unauthenticated full-circuit loader) is ever reintroduced, this
/// test file is where its fail-closed behavior must be covered again.
#[test]
fn full_circuit_data_loader_is_not_exposed() {
    // `wormhole_circuit::circuit` intentionally only exposes `circuit_logic`.
    // Building from source is the only way to obtain leaf CircuitData.
    let config = CircuitConfig::standard_recursion_config();
    let circuit_data = WormholeCircuit::new(config).build_circuit();
    assert_eq!(circuit_data.common.num_public_inputs, 21);
}

#[test]
fn test_prover_and_verifier_from_file_e2e() -> Result<()> {
    // Create a temp directory for the test files
    let temp_dir = "temp_test_bins_e2e";
    fs::create_dir_all(temp_dir)?;

    // Generate circuit and write component files to the temporary directory.
    let config = CircuitConfig::standard_recursion_config();
    let circuit_data = WormholeCircuit::new(config).build_circuit();

    let gate_serializer = DefaultGateSerializer;

    let verifier_data = circuit_data.verifier_data();
    let common_data = &verifier_data.common;

    // Serialize and write common data
    let common_bytes = common_data
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let common_path = Path::new(temp_dir).join("common.bin");
    fs::write(&common_path, &common_bytes)?;

    // Serialize and write verifier only data
    let verifier_only_bytes = verifier_data
        .verifier_only
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let verifier_path = Path::new(temp_dir).join("verifier.bin");
    fs::write(&verifier_path, &verifier_only_bytes)?;

    // The prover is always built from source (no prover.bin artifact exists anymore);
    // a fresh build must be compatible with verifier artifacts loaded from files.
    let prover = wormhole_prover::build_fresh();
    let verifier = WormholeVerifier::new_from_files(&verifier_path, &common_path)?;

    // Create inputs
    let inputs = CircuitInputs::test_inputs_0();

    // Generate a proof using the prover
    let prover_next = prover.commit(&inputs)?;
    let proof = prover_next.prove()?;

    // Convert the proof from plonky2 types to verifier types via serialization
    // This is necessary because the verifier uses qp-plonky2-verifier which has
    // separate type definitions from the full qp-plonky2 used by the prover.
    let proof_bytes = proof.to_bytes();
    let verifier_proof = wormhole_verifier::ProofWithPublicInputs::from_bytes(
        proof_bytes,
        &verifier.circuit_data.common,
    )?;

    verifier.verify(verifier_proof)?;

    // Clean up the temporary directory
    fs::remove_dir_all(temp_dir)?;

    Ok(())
}
