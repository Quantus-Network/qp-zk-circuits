use anyhow::{bail, Context};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_circuit::sensitive::Secret;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{digest_to_bytes, try_4_felts_to_bytes, BytesDigest};

pub use qp_ownership_inputs::PublicCircuitInputs;
use qp_ownership_inputs::{
    CLAIM_ACCOUNT_END_INDEX, CLAIM_ACCOUNT_START_INDEX, PUBLIC_INPUTS_FELTS_LEN,
    WORMHOLE_ADDRESS_END_INDEX, WORMHOLE_ADDRESS_START_INDEX,
};

/// Inputs required to commit to the ownership circuit.
///
/// Deliberately not `Clone`: `private.secret` is a zeroize-on-drop
/// [`Secret`], so the credential cannot be silently duplicated.
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

impl core::fmt::Debug for CircuitInputs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CircuitInputs")
            .field("public", &self.public)
            .field("private", &self.private)
            .finish()
    }
}

impl CircuitInputs {
    /// Derive the wormhole address from `secret` and bind the proof to
    /// `claim_account`.
    pub fn from_secret(secret: Secret, claim_account: BytesDigest) -> Self {
        let account = UnspendableAccount::from_secret(secret.expose_digest());
        Self {
            public: PublicCircuitInputs {
                wormhole_address: digest_to_bytes(account.account_id),
                claim_account,
            },
            private: PrivateCircuitInputs { secret },
        }
    }
}

/// Private witness for the ownership circuit.
///
/// Deliberately not `Clone`: `secret` is a zeroize-on-drop [`Secret`].
pub struct PrivateCircuitInputs {
    /// The wormhole spend secret. Zeroized on drop; duplication requires an
    /// explicit [`Secret::expose_digest`] (or `expose_felts`) call.
    pub secret: Secret,
}

impl core::fmt::Debug for PrivateCircuitInputs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateCircuitInputs")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Parse `PublicCircuitInputs` from Plonky2 field-element slices.
pub trait ParsePublicInputs {
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PublicCircuitInputs>;

    fn try_from_proof(
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<PublicCircuitInputs>;
}

impl ParsePublicInputs for PublicCircuitInputs {
    fn try_from_felts(pis: &[GoldilocksField]) -> anyhow::Result<PublicCircuitInputs> {
        if pis.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain: {} field elements, got: {}",
                PUBLIC_INPUTS_FELTS_LEN,
                pis.len()
            )
        }

        let wormhole_address =
            try_4_felts_to_bytes(&pis[WORMHOLE_ADDRESS_START_INDEX..WORMHOLE_ADDRESS_END_INDEX])
                .context("failed to deserialize wormhole_address")?;
        let claim_account =
            try_4_felts_to_bytes(&pis[CLAIM_ACCOUNT_START_INDEX..CLAIM_ACCOUNT_END_INDEX])
                .context("failed to deserialize claim_account")?;

        Ok(PublicCircuitInputs {
            wormhole_address,
            claim_account,
        })
    }

    fn try_from_proof(
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<PublicCircuitInputs> {
        Self::try_from_felts(&proof.public_inputs)
            .context("failed to deserialize public inputs from proof")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_inputs_debug_redacts_secret() {
        let secret = Secret::try_from([0xab; 32]).unwrap();
        let inputs = PrivateCircuitInputs { secret };
        let dump = alloc::format!("{:?}", inputs);
        assert!(dump.contains("[REDACTED]"));
        assert!(!dump.contains("abababab"));
    }

    #[test]
    fn from_secret_derives_matching_address() {
        let secret = Secret::try_from([0x11; 32]).unwrap();
        let claim = BytesDigest::try_from([0x22; 32].as_slice()).unwrap();
        let inputs = CircuitInputs::from_secret(secret, claim);
        let derived = UnspendableAccount::from_secret(inputs.private.secret.expose_digest());
        assert_eq!(
            inputs.public.wormhole_address,
            digest_to_bytes(derived.account_id)
        );
        assert_eq!(inputs.public.claim_account, claim);
    }
}
