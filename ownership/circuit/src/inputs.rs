use alloc::vec::Vec;
use anyhow::Context;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_circuit::sensitive::Secret;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::circuit::{C, D, F};
use zk_circuits_common::utils::{digest_to_bytes, BytesDigest};

pub use qp_ownership_inputs::PublicCircuitInputs;

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
    /// `claim_account` and `context`.
    pub fn from_secret(secret: Secret, claim_account: BytesDigest, context: BytesDigest) -> Self {
        let account = UnspendableAccount::from_secret(secret.expose_digest());
        Self {
            public: PublicCircuitInputs {
                wormhole_address: digest_to_bytes(account.account_id),
                claim_account,
                context,
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
        let pis: Vec<u64> = pis.iter().map(|f| f.to_canonical_u64()).collect();
        Self::try_from_u64_slice(&pis)
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
        let context = BytesDigest::try_from([0x66; 32].as_slice()).unwrap();
        let inputs = CircuitInputs::from_secret(secret, claim, context);
        let derived = UnspendableAccount::from_secret(inputs.private.secret.expose_digest());
        assert_eq!(
            inputs.public.wormhole_address,
            digest_to_bytes(derived.account_id)
        );
        assert_eq!(inputs.public.claim_account, claim);
        assert_eq!(inputs.public.context, context);
    }
}
