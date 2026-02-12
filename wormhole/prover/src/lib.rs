//! Prover logic for the Wormhole circuit.
//!
//! This module provides the [`WormholeProver`] type, which allows committing inputs to the circuit
//! and generating a zero-knowledge proof using those inputs.
//!
//! The typical usage flow involves:
//! 1. Initializing the prover (e.g., via [`WormholeProver::default`] or [`WormholeProver::new`]).
//! 2. Creating user inputs with [`CircuitInputs`].
//! 3. Committing user inputs using [`WormholeProver::commit`].
//! 4. Generating a proof using [`WormholeProver::prove`].
//!
//! # Example
//!
//! ```no_run
//! use qp_wormhole_inputs::PublicCircuitInputs;
//! use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs};
//! use wormhole_circuit::nullifier::Nullifier;
//! use wormhole_circuit::storage_proof::ProcessedStorageProof;
//! use wormhole_circuit::substrate_account::SubstrateAccount;
//! use wormhole_circuit::unspendable_account::UnspendableAccount;
//! use qp_wormhole_prover::WormholeProver;
//! use plonky2::plonk::circuit_data::CircuitConfig;
//!
//! # fn main() -> anyhow::Result<()> {
//! // Create inputs. In practice, each input would be gathered from the real node.
//! let inputs = CircuitInputs {
//!     private: PrivateCircuitInputs {
//!         secret: [1u8; 32].try_into().unwrap(),
//!         transfer_count: 0,
//!         funding_account: [2u8; 32].try_into().unwrap(),
//!         storage_proof: ProcessedStorageProof::new(vec![], vec![]).unwrap(),
//!         unspendable_account: [1u8; 32].try_into().unwrap(),
//!         state_root: [3u8; 32].try_into().unwrap(),
//!         extrinsics_root: [4u8; 32].try_into().unwrap(),
//!         digest: [0u8; 110],
//!         input_amount: 1000,
//!     },
//!     public: PublicCircuitInputs {
//!         asset_id: 0_u32,
//!         output_amount_1: 900,  // Spend amount after fee
//!         output_amount_2: 99,   // Change amount (1000 - 900 - fee)
//!         volume_fee_bps: 10,    // 0.1% = 10 basis points
//!         nullifier: [1u8; 32].try_into().unwrap(),
//!         block_hash: [0u8; 32].try_into().unwrap(),
//!         parent_hash: [5u8; 32].try_into().unwrap(),
//!         exit_account_1: [2u8; 32].try_into().unwrap(),  // Spend destination
//!         exit_account_2: [3u8; 32].try_into().unwrap(),  // Change destination
//!         block_number: 1,
//!     },
//! };
//!
//! let config = CircuitConfig::standard_recursion_config();
//! let prover = WormholeProver::new(config);
//! let prover_next = prover.commit(&inputs)?;
//! let _proof = prover_next.prove()?;
//! # Ok(())
//! # }
//! ```
#[cfg(not(feature = "std"))]
extern crate alloc;

use anyhow::{anyhow, bail};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{
            CircuitConfig, CommonCircuitData, ProverCircuitData, ProverOnlyCircuitData,
        },
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
#[cfg(feature = "std")]
use std::{fs, path::Path};

use wormhole_circuit::nullifier::Nullifier;
use wormhole_circuit::ByteCodec;
use wormhole_circuit::{
    block_header::BlockHeader,
    circuit::circuit_logic::{CircuitTargets, WormholeCircuit},
};
use wormhole_circuit::{
    inputs::CircuitInputs,
    substrate_account::{DualExitAccount, SubstrateAccount},
};
use wormhole_circuit::{storage_proof::StorageProof, unspendable_account::UnspendableAccount};
use zk_circuits_common::circuit::{CircuitFragment, C, D, F};

#[derive(Debug)]
pub struct WormholeProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<CircuitTargets>,
}

#[cfg(feature = "std")]
impl Default for WormholeProver {
    fn default() -> Self {
        Self::new_from_files(
            Path::new("generated-bins/prover.bin"),
            Path::new("generated-bins/common.bin"),
        )
        .unwrap_or_else(|_| {
            let wormhole_circuit = WormholeCircuit::default();
            let partial_witness = PartialWitness::new();

            let targets = Some(wormhole_circuit.targets());
            let circuit_data = wormhole_circuit.build_prover();

            Self {
                circuit_data,
                partial_witness,
                targets,
            }
        })
    }
}

impl WormholeProver {
    /// Creates a new [`WormholeProver`] from prover and common data bytes.
    pub fn new_from_bytes(
        prover_only_bytes: &[u8],
        common_bytes: &[u8],
    ) -> Result<Self, &'static str> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
            _phantom: Default::default(),
        };

        let common_data = CommonCircuitData::from_bytes(common_bytes.to_vec(), &gate_serializer)
            .map_err(|_| "Failed to deserialize common circuit data")?;

        let prover_only_data = ProverOnlyCircuitData::from_bytes(
            prover_only_bytes,
            &generator_serializer,
            &common_data,
        )
        .map_err(|e| anyhow!("Failed to deserialize prover only data: {}", e));

        let wormhole_circuit = WormholeCircuit::new(common_data.config.clone());
        let targets = Some(wormhole_circuit.targets());

        let circuit_data = ProverCircuitData {
            prover_only: prover_only_data.unwrap(),
            common: common_data,
        };

        Ok(Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
        })
    }

    /// Creates a new [`WormholeProver`] from a prover and common data files.
    #[cfg(feature = "std")]
    pub fn new_from_files(
        prover_data_path: &Path,
        common_data_path: &Path,
    ) -> anyhow::Result<Self> {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<PoseidonGoldilocksConfig, D> {
            _phantom: Default::default(),
        };

        let common_bytes = fs::read(common_data_path)?;
        let common_data =
            CommonCircuitData::from_bytes(common_bytes, &gate_serializer).map_err(|e| {
                anyhow!(
                    "Failed to deserialize common circuit data from {:?}: {}",
                    common_data_path,
                    e
                )
            })?;

        let prover_only_bytes = fs::read(prover_data_path)?;
        let prover_only_data = ProverOnlyCircuitData::from_bytes(
            &prover_only_bytes,
            &generator_serializer,
            &common_data,
        )
        .map_err(|e| {
            anyhow!(
                "Failed to deserialize prover only data from {:?}: {}",
                prover_data_path,
                e
            )
        })?;

        let wormhole_circuit = WormholeCircuit::new(common_data.config.clone());
        let targets = Some(wormhole_circuit.targets());

        let circuit_data = ProverCircuitData {
            prover_only: prover_only_data,
            common: common_data,
        };

        Ok(Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
        })
    }

    /// Creates a new [`WormholeProver`].
    pub fn new(config: CircuitConfig) -> Self {
        let wormhole_circuit = WormholeCircuit::new(config);
        let partial_witness = PartialWitness::new();

        let targets = Some(wormhole_circuit.targets());
        let circuit_data = wormhole_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness,
            targets,
        }
    }

    /// Commits the provided [`CircuitInputs`] to the circuit by filling relevant targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has already commited to inputs previously.
    pub fn commit(mut self, circuit_inputs: &CircuitInputs) -> anyhow::Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("prover has already commited to inputs");
        };

        fill_witness(&mut self.partial_witness, circuit_inputs, &targets)?;
        Ok(self)
    }

    /// Prove the circuit with commited values. It's necessary to call [`WormholeProver::commit`]
    /// before running this function.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has not commited to any inputs.
    pub fn prove(self) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove: {}", e))
    }
}

/// Fill a partial witness with circuit inputs.
///
/// This is the single source of truth for witness filling logic, used by both
/// `WormholeProver::commit` and the aggregator's dummy proof generation.
///
/// # Arguments
/// * `pw` - The partial witness to fill
/// * `circuit_inputs` - The circuit inputs containing both public and private data
/// * `targets` - The circuit targets to fill
pub fn fill_witness(
    pw: &mut PartialWitness<F>,
    circuit_inputs: &CircuitInputs,
    targets: &CircuitTargets,
) -> anyhow::Result<()> {
    let nullifier = Nullifier::from(circuit_inputs);
    let storage_proof = StorageProof::try_from(circuit_inputs)?;
    let unspendable_account = UnspendableAccount::from(circuit_inputs);
    let exit_accounts = DualExitAccount {
        exit_account_1: SubstrateAccount::from_bytes(
            circuit_inputs.public.exit_account_1.as_slice(),
        )?,
        exit_account_2: SubstrateAccount::from_bytes(
            circuit_inputs.public.exit_account_2.as_slice(),
        )?,
    };
    let block_header = BlockHeader::try_from(circuit_inputs)?;

    nullifier.fill_targets(pw, targets.nullifier.clone())?;
    unspendable_account.fill_targets(pw, targets.unspendable_account.clone())?;
    storage_proof.fill_targets(pw, targets.storage_proof.clone())?;
    exit_accounts.fill_targets(pw, targets.exit_accounts)?;
    block_header.fill_targets(pw, targets.block_header.clone())?;

    Ok(())
}
