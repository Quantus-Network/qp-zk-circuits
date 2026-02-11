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
    use crate::substrate_account::{DualExitAccount, DualExitAccountTargets};
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
        pub exit_accounts: DualExitAccountTargets,
        pub block_header: BlockHeaderTargets,
    }

    impl CircuitTargets {
        pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
            // storage_proof must be created first so asset_id is registered as public input at index 0
            let storage_proof = StorageProofTargets::new(builder);

            Self {
                nullifier: NullifierTargets::new(builder),
                unspendable_account: UnspendableAccountTargets::new(builder),
                storage_proof,
                exit_accounts: DualExitAccountTargets::new(builder),
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
            DualExitAccount::circuit(&targets.exit_accounts, &mut builder);
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
        use crate::nullifier::NULLIFIER_SALT;
        use plonky2::hash::poseidon2::Poseidon2Hash;
        use zk_circuits_common::utils::injective_string_to_felt;

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

        // Connect block_hash_sentinel in storage_proof to the actual block_hash from block_header.
        // This allows the storage proof circuit to detect dummy proofs (block_hash == 0).
        builder.connect_hashes(
            targets.storage_proof.block_hash_sentinel,
            targets.block_header.block_hash,
        );

        // Dummy proof detection: block_hash == 0 (all four limbs are zero)
        // This sentinel allows dummy proofs to skip validation while preserving
        // the ability to use output_amount == 0 for privacy in real proofs.
        let zero = builder.zero();
        let one = builder.one();

        // Check if all four limbs of block_hash are zero
        let bh = &targets.block_header.block_hash.elements;
        let bh0_is_zero = builder.is_equal(bh[0], zero);
        let bh1_is_zero = builder.is_equal(bh[1], zero);
        let bh2_is_zero = builder.is_equal(bh[2], zero);
        let bh3_is_zero = builder.is_equal(bh[3], zero);

        // is_dummy = bh0_is_zero AND bh1_is_zero AND bh2_is_zero AND bh3_is_zero
        let bh01_zero = builder.and(bh0_is_zero, bh1_is_zero);
        let bh23_zero = builder.and(bh2_is_zero, bh3_is_zero);
        let is_dummy = builder.and(bh01_zero, bh23_zero);
        let is_not_dummy = builder.sub(one, is_dummy.target);

        // Nullifier validation: nullifier == H(H(salt + secret + transfer_count))
        // Skip this validation for dummy proofs (block_hash == 0).
        // This allows dummy proofs to use random nullifiers for better privacy.
        let salt_felts = injective_string_to_felt(NULLIFIER_SALT);
        let mut nullifier_preimage = Vec::new();
        for &f in salt_felts.iter() {
            nullifier_preimage.push(builder.constant(f));
        }
        nullifier_preimage.extend(targets.nullifier.secret.elements.iter());
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

        // Block hash validation: block_hash == hash(header contents)
        // Skip this validation for dummy proofs (block_hash == 0).
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

        // The state_root from the block_header must be the same as the root_hash for the storage_proof.
        // Skip this validation for dummy proofs (block_hash == 0).
        for i in 0..4 {
            let diff = builder.sub(
                targets.block_header.header.state_root.elements[i],
                targets.storage_proof.root_hash.elements[i],
            );
            let result = builder.mul(diff, is_not_dummy);
            builder.connect(result, zero);
        }
    }
}
