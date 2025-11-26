//! Wormhole Circuit.
//!
//! This module defines the zero-knowledge circuit for the Wormhole protocol.
use alloc::vec::Vec;
use plonky2::{
    plonk::circuit_data::CircuitData,
    plonk::config::PoseidonGoldilocksConfig,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use zk_circuits_common::circuit::{C, D, F};

pub fn circuit_data_to_bytes(
    data: &CircuitData<F, C, D>,
) -> Result<Vec<u8>, plonky2::util::serialization::IoError> {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };
    data.to_bytes(&gate_serializer, &generator_serializer)
}

pub fn circuit_data_from_bytes(
    bytes: &[u8],
) -> Result<CircuitData<F, C, D>, plonky2::util::serialization::IoError> {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
        _phantom: Default::default(),
    };
    CircuitData::from_bytes(bytes, &gate_serializer, &generator_serializer)
}

#[cfg(feature = "std")]
pub mod circuit_logic {
    use crate::block_header::BlockHeaderTargets;
    use crate::nullifier::{Nullifier, NullifierTargets};
    use crate::storage_proof::{StorageProof, StorageProofTargets};
    use crate::substrate_account::{ExitAccountTargets, SubstrateAccount};
    use crate::unspendable_account::{UnspendableAccount, UnspendableAccountTargets};
    use plonky2::{
        plonk::circuit_data::{CircuitData, ProverCircuitData, VerifierCircuitData},
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    };
    use zk_circuits_common::circuit::{CircuitFragment, C, D, F};

    #[derive(Debug, Clone)]
    pub struct CircuitTargets {
        pub nullifier: NullifierTargets,
        pub unspendable_account: UnspendableAccountTargets,
        pub storage_proof: StorageProofTargets,
        pub exit_account: ExitAccountTargets,
        pub block_header: BlockHeaderTargets,
    }

    impl CircuitTargets {
        pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
            Self {
                nullifier: NullifierTargets::new(builder),
                unspendable_account: UnspendableAccountTargets::new(builder),
                storage_proof: StorageProofTargets::new(builder),
                exit_account: ExitAccountTargets::new(builder),
                block_header: BlockHeaderTargets::new(builder),
            }
        }
    }

    pub struct WormholeCircuit {
        builder: CircuitBuilder<F, D>,
        targets: CircuitTargets,
    }

    impl Default for WormholeCircuit {
        fn default() -> Self {
            let config = CircuitConfig::standard_recursion_zk_config();
            Self::new(config)
        }
    }

    impl WormholeCircuit {
        pub fn new(config: CircuitConfig) -> Self {
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup targets
            let targets = CircuitTargets::new(&mut builder);

            // Setup circuits.
            use crate::block_header::BlockHeader;
            Nullifier::circuit(&targets.nullifier, &mut builder);
            UnspendableAccount::circuit(&targets.unspendable_account, &mut builder);
            StorageProof::circuit(&targets.storage_proof, &mut builder);
            SubstrateAccount::circuit(&targets.exit_account, &mut builder);
            BlockHeader::circuit(&targets.block_header, &mut builder);

            // Ensure that shared inputs to each fragment are the same.
            connect_shared_targets(&targets, &mut builder);

            Self { builder, targets }
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
    }

    fn connect_shared_targets(targets: &CircuitTargets, builder: &mut CircuitBuilder<F, D>) {
        // Secret.
        builder.connect_hashes(targets.unspendable_account.secret, targets.nullifier.secret);
        // Transfer count.
        for (&a, &b) in targets
            .nullifier
            .transfer_count
            .iter()
            .zip(&targets.storage_proof.leaf_inputs.transfer_count)
        {
            builder.connect(a, b);
        }

        // to_account and unspendable_account must be the same
        builder.connect_hashes(
            targets.unspendable_account.account_id,
            targets.storage_proof.leaf_inputs.to_account,
        );

        // The state_root from the block_header must be the same as the root_hash for the storage_proof
        builder.connect_hashes(
            targets.block_header.header.state_root,
            targets.storage_proof.root_hash,
        );
    }
}
