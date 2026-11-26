//! Prover logic for the wormhole-address ownership circuit.
//!
//! The circuit is small and builds from source; no `prover.bin` is loaded.
//! `ProverOnlyCircuitData` contains the witness generators and the target
//! list that decides which values become `public_inputs`, so a poisoned
//! artifact could exfiltrate the secret through the serialized proof.

use anyhow::{anyhow, bail};
use ownership_circuit::circuit::circuit_logic::{CircuitTargets, OwnershipCircuit};
use ownership_circuit::inputs::CircuitInputs;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{CircuitConfig, ProverCircuitData},
        proof::ProofWithPublicInputs,
    },
};
use wormhole_circuit::substrate_account::SubstrateAccount;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::circuit::{CircuitFragment, C, D, F};

pub struct OwnershipProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<CircuitTargets>,
}

impl core::fmt::Debug for OwnershipProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnershipProver")
            .field("circuit_data", &"[ProverCircuitData]")
            .field("partial_witness", &"[REDACTED]")
            .field("committed", &self.targets.is_none())
            .finish()
    }
}

/// Build a fresh [`OwnershipProver`] with the canonical ZK ownership config.
pub fn build_fresh() -> OwnershipProver {
    OwnershipProver::new(zk_circuits_common::circuit::ownership_circuit_config())
        .expect("canonical ownership circuit config is valid")
}

impl OwnershipProver {
    /// Creates a new [`OwnershipProver`].
    ///
    /// # Errors
    ///
    /// Returns an error when `config` fails
    /// [`validate_circuit_config`](zk_circuits_common::circuit::validate_circuit_config).
    pub fn new(config: CircuitConfig) -> anyhow::Result<Self> {
        let circuit = OwnershipCircuit::new(config)?;
        let targets = Some(circuit.targets());
        let circuit_data = circuit.build_prover();

        Ok(Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
        })
    }

    /// Commits [`CircuitInputs`] by filling the circuit targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has already committed to inputs.
    pub fn commit(mut self, circuit_inputs: &CircuitInputs) -> anyhow::Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("prover has already commited to inputs");
        };

        fill_witness(&mut self.partial_witness, circuit_inputs, &targets)?;
        Ok(self)
    }

    /// Prove the circuit with committed values. Call [`OwnershipProver::commit`]
    /// first.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has not committed to any inputs.
    pub fn prove(self) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|e| anyhow!("Failed to prove: {}", e))
    }
}

/// Fill a partial witness with ownership-circuit inputs.
pub fn fill_witness(
    pw: &mut PartialWitness<F>,
    circuit_inputs: &CircuitInputs,
    targets: &CircuitTargets,
) -> anyhow::Result<()> {
    let unspendable_account = UnspendableAccount::new(
        circuit_inputs.public.wormhole_address,
        circuit_inputs.private.secret.expose_digest(),
    );
    let claim_account = SubstrateAccount::new(circuit_inputs.public.claim_account.as_slice())?;

    unspendable_account.fill_targets(pw, targets.unspendable_account.clone())?;
    claim_account.fill_targets(pw, targets.claim_account)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_circuit::sensitive::Secret;
    use zk_circuits_common::utils::BytesDigest;

    #[test]
    fn committed_prover_debug_does_not_leak_secret() {
        let secret = Secret::try_from([0xAB; 32]).unwrap();
        let claim = BytesDigest::try_from([0xCD; 32].as_slice()).unwrap();
        let inputs = CircuitInputs::from_secret(secret, claim);

        let prover = build_fresh().commit(&inputs).unwrap();
        let dump = format!("{:?}", prover);
        assert!(
            !dump.contains("12370169555311111083"),
            "raw secret leaked from committed prover Debug output"
        );
    }
}
