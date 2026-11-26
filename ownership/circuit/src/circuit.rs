//! Wormhole-address ownership circuit.
//!
//! Proves knowledge of the secret `s` such that
//! `wormhole_address = H(H("wormhole" || s))`, and binds the proof to a
//! public `claim_account`. There is no inclusion proof, block header, or
//! nullifier — eligibility and single-claim enforcement are on-chain.
//!
//! Full `CircuitData` is never serialized: a poisoned artifact could
//! exfiltrate the secret through `public_inputs`. Always construct
//! [`circuit_logic::OwnershipCircuit`] from source. Verifier-side artifacts
//! are loaded through the pinned loader in `qp-ownership-verifier`.

#[cfg(feature = "std")]
pub mod circuit_logic {
    use anyhow::Result;
    use plonky2::{
        hash::hash_types::HashOutTarget,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData},
        },
    };
    use wormhole_circuit::substrate_account::{ExitAccountTargets, SubstrateAccount};
    use wormhole_circuit::unspendable_account::{UnspendableAccount, UnspendableAccountTargets};
    use zk_circuits_common::circuit::{
        ownership_circuit_config, validate_circuit_config, CircuitFragment, C, D, F,
    };

    #[derive(Debug, Clone)]
    pub struct CircuitTargets {
        pub unspendable_account: UnspendableAccountTargets,
        pub claim_account: ExitAccountTargets,
    }

    impl CircuitTargets {
        pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
            let account_id = HashOutTarget {
                elements: core::array::from_fn(|_| builder.add_virtual_public_input()),
            };
            let secret = builder.add_virtual_hash();
            Self {
                unspendable_account: UnspendableAccountTargets { account_id, secret },
                claim_account: ExitAccountTargets::new(builder),
            }
        }
    }

    pub struct OwnershipCircuit {
        builder: CircuitBuilder<F, D>,
        targets: CircuitTargets,
    }

    impl Default for OwnershipCircuit {
        fn default() -> Self {
            let config = ownership_circuit_config();
            Self::new(config).expect("canonical ownership circuit config is valid")
        }
    }

    impl OwnershipCircuit {
        /// Build the ownership circuit from a caller-supplied config.
        ///
        /// The config is checked against the shared structural policy
        /// ([`validate_circuit_config`]) before any builder work.
        pub fn new(config: CircuitConfig) -> Result<Self> {
            validate_circuit_config(&config)?;

            let mut builder = CircuitBuilder::<F, D>::new(config);
            let targets = CircuitTargets::new(&mut builder);

            UnspendableAccount::circuit(&targets.unspendable_account, &mut builder);
            SubstrateAccount::circuit(&targets.claim_account, &mut builder);

            Ok(Self { builder, targets })
        }

        pub fn targets(&self) -> CircuitTargets {
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

        pub fn num_gates(&self) -> usize {
            self.builder.num_gates()
        }
    }
}
