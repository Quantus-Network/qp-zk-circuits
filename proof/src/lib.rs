#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(any(feature = "prover", feature = "verifier"))]
macro_rules! decoder {
    ($module:ident, $backend:ident) => {
        pub mod $module {
            use alloc::vec::Vec;
            use anyhow::{anyhow, ensure, Context, Result};
            use $backend::{
                field::extension::Extendable,
                hash::hash_types::RichField,
                plonk::{
                    circuit_data::{CommonCircuitData, VerifierCircuitData},
                    config::GenericConfig,
                    proof::ProofWithPublicInputs,
                },
                util::serialization::{Buffer, Read, Remaining},
            };

            /// Decode an uncompressed proof using trusted circuit data.
            /// The caller must cryptographically verify the returned proof.
            pub fn decode_proof<F, C, const D: usize>(
                bytes: &[u8],
                common: &CommonCircuitData<F, D>,
            ) -> Result<ProofWithPublicInputs<F, C, D>>
            where
                F: RichField + Extendable<D>,
                C: GenericConfig<D, F = F>,
            {
                let mut buffer = Buffer::new(bytes);
                let proof = buffer
                    .read_proof(common)
                    .map_err(anyhow::Error::msg)
                    .context("failed to decode proof body")?;
                let count = read_u64(&mut buffer)?;
                ensure!(
                    count == common.num_public_inputs as u64,
                    "proof public-input count does not match circuit"
                );
                let expected_bytes = common
                    .num_public_inputs
                    .checked_mul(8)
                    .context("proof public-input size overflow")?;
                ensure!(
                    buffer.remaining() == expected_bytes,
                    "proof public-input bytes are truncated or have trailing data"
                );
                let mut public_inputs = Vec::new();
                public_inputs
                    .try_reserve_exact(common.num_public_inputs)
                    .map_err(|_| anyhow!("failed to allocate proof public inputs"))?;
                for _ in 0..common.num_public_inputs {
                    let value = read_u64(&mut buffer)?;
                    ensure!(value < F::ORDER, "noncanonical proof public input");
                    public_inputs.push(F::from_canonical_u64(value));
                }
                Ok(ProofWithPublicInputs {
                    proof,
                    public_inputs,
                })
            }

            /// Decode and verify a proof against trusted circuit data.
            pub fn verify_proof_bytes<F, C, const D: usize>(
                bytes: &[u8],
                verifier: &VerifierCircuitData<F, C, D>,
            ) -> Result<ProofWithPublicInputs<F, C, D>>
            where
                F: RichField + Extendable<D>,
                C: GenericConfig<D, F = F>,
            {
                let proof = decode_proof(bytes, &verifier.common)?;
                verifier
                    .verify(proof.clone())
                    .context("proof verification failed")?;
                Ok(proof)
            }

            fn read_u64(buffer: &mut Buffer<'_>) -> Result<u64> {
                let mut bytes = [0u8; 8];
                buffer
                    .read_exact(&mut bytes)
                    .map_err(anyhow::Error::msg)
                    .context("truncated proof integer")?;
                Ok(u64::from_le_bytes(bytes))
            }
        }
    };
}

#[cfg(feature = "prover")]
decoder!(prover, plonky2);
#[cfg(feature = "verifier")]
decoder!(verifier, qp_plonky2_verifier);
