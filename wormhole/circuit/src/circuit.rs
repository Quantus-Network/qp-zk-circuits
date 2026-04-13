//! Wormhole Circuit.
//!
//! This module defines the zero-knowledge circuit for the Wormhole protocol.
use alloc::vec::Vec;
use plonky2::{
    plonk::circuit_data::CircuitData,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use zk_circuits_common::circuit::{C, D, F};

pub fn circuit_data_to_bytes(
    data: &CircuitData<F, C, D>,
) -> Result<Vec<u8>, plonky2::util::serialization::IoError> {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };
    data.to_bytes(&gate_serializer, &generator_serializer)
}

pub fn circuit_data_from_bytes(
    bytes: &[u8],
) -> Result<CircuitData<F, C, D>, plonky2::util::serialization::IoError> {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D> {
        _phantom: Default::default(),
    };
    CircuitData::from_bytes(bytes, &gate_serializer, &generator_serializer)
}

#[cfg(feature = "std")]
pub mod circuit_logic {
    use crate::block_header::BlockHeaderTargets;
    use crate::nullifier::{Nullifier, NullifierTargets};
    use crate::substrate_account::{DualExitAccount, DualExitAccountTargets};
    use crate::unspendable_account::{UnspendableAccount, UnspendableAccountTargets};
    use crate::zk_merkle_proof::{ZkMerkleProofData, ZkMerkleProofTargets};
    use plonky2::{
        plonk::circuit_data::{CircuitData, ProverCircuitData, VerifierCircuitData},
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    };
    use zk_circuits_common::circuit::{wormhole_leaf_circuit_config, CircuitFragment, C, D, F};

    #[derive(Debug, Clone)]
    pub struct CircuitTargets {
        pub nullifier: NullifierTargets,
        pub unspendable_account: UnspendableAccountTargets,
        pub zk_merkle_proof: ZkMerkleProofTargets,
        pub exit_accounts: DualExitAccountTargets,
        pub block_header: BlockHeaderTargets,
    }

    impl CircuitTargets {
        pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
            // zk_merkle_proof must be created first so asset_id is registered as public input at index 0
            let zk_merkle_proof = ZkMerkleProofTargets::new(builder);

            Self {
                nullifier: NullifierTargets::new(builder),
                unspendable_account: UnspendableAccountTargets::new(builder),
                zk_merkle_proof,
                exit_accounts: DualExitAccountTargets::new(builder),
                block_header: BlockHeaderTargets::new(builder),
            }
        }

        #[cfg(feature = "profile")]
        pub fn new_profiled(builder: &mut CircuitBuilder<F, D>) -> Self {
            use crate::profile::GateProfiler;
            let mut profiler = GateProfiler::new();

            println!("\n=== Target Creation Gates ===");

            let zk_merkle_proof = ZkMerkleProofTargets::new(builder);
            profiler.checkpoint("ZkMerkleProofTargets::new", builder.num_gates());

            let nullifier = NullifierTargets::new(builder);
            profiler.checkpoint("NullifierTargets::new", builder.num_gates());

            let unspendable_account = UnspendableAccountTargets::new(builder);
            profiler.checkpoint("UnspendableAccountTargets::new", builder.num_gates());

            let exit_accounts = DualExitAccountTargets::new(builder);
            profiler.checkpoint("DualExitAccountTargets::new", builder.num_gates());

            let block_header = BlockHeaderTargets::new(builder);
            profiler.checkpoint("BlockHeaderTargets::new", builder.num_gates());

            Self {
                nullifier,
                unspendable_account,
                zk_merkle_proof,
                exit_accounts,
                block_header,
            }
        }
    }

    pub struct WormholeCircuit {
        builder: CircuitBuilder<F, D>,
        targets: CircuitTargets,
    }

    impl Default for WormholeCircuit {
        /// Creates a WormholeCircuit with the default leaf circuit config (non-ZK).
        ///
        /// Leaf proofs don't need ZK because they're only verified by the aggregator (which runs
        /// in a trusted environment), not on-chain. Disabling ZK improves proving performance.
        fn default() -> Self {
            let config = wormhole_leaf_circuit_config();
            Self::new(config)
        }
    }

    impl WormholeCircuit {
        pub fn new(config: CircuitConfig) -> Self {
            #[cfg(feature = "profile")]
            return Self::new_profiled(config);

            #[cfg(not(feature = "profile"))]
            Self::new_internal(config)
        }

        #[cfg(not(feature = "profile"))]
        fn new_internal(config: CircuitConfig) -> Self {
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup targets
            let targets = CircuitTargets::new(&mut builder);

            // Setup circuits.
            use crate::block_header::BlockHeader;
            Nullifier::circuit(&targets.nullifier, &mut builder);
            UnspendableAccount::circuit(&targets.unspendable_account, &mut builder);
            ZkMerkleProofData::circuit(&targets.zk_merkle_proof, &mut builder);
            DualExitAccount::circuit(&targets.exit_accounts, &mut builder);
            BlockHeader::circuit(&targets.block_header, &mut builder);

            // Ensure that shared inputs to each fragment are the same.
            connect_shared_targets(&targets, &mut builder);

            Self { builder, targets }
        }

        #[cfg(feature = "profile")]
        fn new_profiled(config: CircuitConfig) -> Self {
            use crate::profile::GateProfiler;
            let mut profiler = GateProfiler::new();

            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Setup targets with profiling
            let targets = CircuitTargets::new_profiled(&mut builder);

            println!("\n=== Circuit Fragment Gates ===");
            let gates_after_targets = builder.num_gates();

            // Setup circuits with profiling
            use crate::block_header::BlockHeader;

            Nullifier::circuit(&targets.nullifier, &mut builder);
            profiler.checkpoint("Nullifier::circuit", builder.num_gates());

            UnspendableAccount::circuit(&targets.unspendable_account, &mut builder);
            profiler.checkpoint("UnspendableAccount::circuit", builder.num_gates());

            ZkMerkleProofData::circuit(&targets.zk_merkle_proof, &mut builder);
            profiler.checkpoint("ZkMerkleProofData::circuit", builder.num_gates());

            DualExitAccount::circuit(&targets.exit_accounts, &mut builder);
            profiler.checkpoint("DualExitAccount::circuit", builder.num_gates());

            BlockHeader::circuit(&targets.block_header, &mut builder);
            profiler.checkpoint("BlockHeader::circuit", builder.num_gates());

            // Ensure that shared inputs to each fragment are the same.
            connect_shared_targets(&targets, &mut builder);
            profiler.checkpoint("connect_shared_targets", builder.num_gates());

            profiler.print_summary();

            println!(
                "\nTotal gates before build: {} (targets: {}, fragments: {})",
                builder.num_gates(),
                gates_after_targets,
                builder.num_gates() - gates_after_targets
            );

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

        /// Build circuit with profiling output. Prints gate instance counts before building.
        /// Requires RUST_LOG=debug to see per-gate-type counts.
        #[cfg(feature = "profile")]
        pub fn build_circuit_profiled(self) -> CircuitData<F, C, D> {
            println!("\n=== Gate Instance Counts ===");
            self.builder.print_gate_counts(0);
            self.builder.build()
        }

        /// Returns the current number of gates in the circuit (before building).
        pub fn num_gates(&self) -> usize {
            self.builder.num_gates()
        }
    }

    fn connect_shared_targets(targets: &CircuitTargets, builder: &mut CircuitBuilder<F, D>) {
        use crate::nullifier::NULLIFIER_SALT;
        use plonky2::hash::poseidon2::Poseidon2Hash;
        use zk_circuits_common::utils::string_to_felts;

        builder.connect_hashes(targets.nullifier.secret, targets.unspendable_account.secret);

        // Transfer count: connect nullifier's transfer_count to zk_merkle_proof's
        for (&a, &b) in targets
            .nullifier
            .transfer_count
            .iter()
            .zip(&targets.zk_merkle_proof.leaf.transfer_count)
        {
            builder.connect(a, b);
        }

        // to_account and unspendable_account must be the same (both are 4 felts)
        for (&a, &b) in targets
            .unspendable_account
            .account_id
            .elements
            .iter()
            .zip(&targets.zk_merkle_proof.leaf.to_account.elements)
        {
            builder.connect(a, b);
        }

        // Dummy proof detection: requires BOTH block_hash == 0 AND output_amounts == 0.
        // This prevents an attacker from slipping funds through with a zero block hash
        // but positive output amounts.
        let zero = builder.zero();
        let one = builder.one();

        // Check if all four limbs of block_hash are zero
        let bh = &targets.block_header.block_hash.elements;
        let bh0_is_zero = builder.is_equal(bh[0], zero);
        let bh1_is_zero = builder.is_equal(bh[1], zero);
        let bh2_is_zero = builder.is_equal(bh[2], zero);
        let bh3_is_zero = builder.is_equal(bh[3], zero);

        let bh01_zero = builder.and(bh0_is_zero, bh1_is_zero);
        let bh23_zero = builder.and(bh2_is_zero, bh3_is_zero);
        let block_hash_is_zero = builder.and(bh01_zero, bh23_zero);

        // Check if both output amounts are individually zero
        let leaf = &targets.zk_merkle_proof.leaf;
        let output_1_is_zero = builder.is_equal(leaf.output_amount_1, zero);
        let output_2_is_zero = builder.is_equal(leaf.output_amount_2, zero);
        let both_outputs_zero = builder.and(output_1_is_zero, output_2_is_zero);

        // is_dummy = block_hash_is_zero AND both_outputs_zero
        let is_dummy = builder.and(block_hash_is_zero, both_outputs_zero);
        let is_not_dummy = builder.sub(one, is_dummy.target);

        // Connect is_not_dummy in zk_merkle_proof.
        // This allows the ZK Merkle proof circuit to detect dummy proofs (block_hash == 0).
        builder.connect(targets.zk_merkle_proof.is_not_dummy.target, is_not_dummy);

        // Nullifier validation: nullifier == H(H(salt + secret + transfer_count))
        // Skip this validation for dummy proofs (block_hash == 0 AND outputs == 0).
        // This allows dummy proofs to use random nullifiers for better privacy.
        let salt_felts = string_to_felts(NULLIFIER_SALT);
        let mut nullifier_preimage = Vec::new();
        for &f in salt_felts.iter() {
            nullifier_preimage.push(builder.constant(f));
        }
        nullifier_preimage.extend(targets.nullifier.secret.elements.iter().copied());
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
        // Skip this validation for dummy proofs (block_hash == 0 AND outputs == 0).
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

        // ZK trie root validation: header.zk_trie_root == zk_merkle_proof.root_hash
        // This is the CRITICAL constraint that binds the Merkle proof to the block header.
        // Without this, a malicious prover could supply any valid Merkle proof unrelated
        // to the claimed block header.
        //
        // The security chain is:
        // 1. block_hash commits to zk_trie_root (via header preimage)
        // 2. zk_trie_root == zk_merkle_proof.root_hash (this constraint)
        // 3. zk_merkle_proof.root_hash == computed merkle root (in ZkMerkleProofData::circuit)
        // 4. computed merkle root is derived from leaf data
        //
        // Skip this validation for dummy proofs (block_hash == 0 AND outputs == 0).
        for i in 0..4 {
            let diff = builder.sub(
                targets.block_header.header.zk_trie_root[i],
                targets.zk_merkle_proof.root_hash.elements[i],
            );
            let result = builder.mul(diff, is_not_dummy);
            builder.connect(result, zero);
        }
    }
}
