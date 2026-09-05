//! Public input types for wormhole-address ownership circuit proofs.
//!
//! Lightweight and `no_std`, so an on-chain pallet can parse public inputs
//! without pulling in the circuit or prover.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use anyhow::{bail, Context};
use core::fmt;

pub use qp_wormhole_inputs::{BytesDigest, DigestError, DIGEST_BYTES_LEN};

/// Public inputs: wormhole_address(4) + claim_account(4) = 8.
pub const PUBLIC_INPUTS_FELTS_LEN: usize = 8;

/// Minimum acceptable security level (bits) for the ownership circuit config.
pub const MIN_OWNERSHIP_SECURITY_BITS: usize = 100;

pub const WORMHOLE_ADDRESS_START_INDEX: usize = 0;
pub const WORMHOLE_ADDRESS_END_INDEX: usize = 4;
pub const CLAIM_ACCOUNT_START_INDEX: usize = 4;
pub const CLAIM_ACCOUNT_END_INDEX: usize = 8;

/// Public inputs for a wormhole-address ownership proof.
///
/// The circuit proves knowledge of the secret `s` such that
/// `wormhole_address = H(H("wormhole" || s))`. `claim_account` is bound as a
/// public input so a stolen proof cannot be submitted to a different
/// destination. Eligibility and single-claim enforcement are on-chain.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicCircuitInputs {
    /// The wormhole address whose secret the prover claims to know.
    pub wormhole_address: BytesDigest,
    /// The account that receives the airdrop if the proof verifies.
    pub claim_account: BytesDigest,
}

impl fmt::Debug for PublicCircuitInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicCircuitInputs")
            .field("wormhole_address", &self.wormhole_address)
            .field("claim_account", &self.claim_account)
            .finish()
    }
}

fn hash_u64s_to_bytes_digest(vals: &[u64]) -> anyhow::Result<BytesDigest> {
    if vals.len() != 4 {
        bail!(
            "Expected 4 field elements for hash digest, got {}",
            vals.len()
        );
    }
    let mut bytes = [0u8; DIGEST_BYTES_LEN];
    for (i, &val) in vals.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
    BytesDigest::try_from(bytes).map_err(|e| anyhow::anyhow!("{}", e))
}

impl PublicCircuitInputs {
    /// Parse public inputs from a slice of u64 values (canonical field elements).
    pub fn try_from_u64_slice(pis: &[u64]) -> anyhow::Result<Self> {
        if pis.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain {} field elements, got {}",
                PUBLIC_INPUTS_FELTS_LEN,
                pis.len()
            );
        }

        let wormhole_address = hash_u64s_to_bytes_digest(
            &pis[WORMHOLE_ADDRESS_START_INDEX..WORMHOLE_ADDRESS_END_INDEX],
        )
        .context("failed to parse wormhole_address")?;
        let claim_account =
            hash_u64s_to_bytes_digest(&pis[CLAIM_ACCOUNT_START_INDEX..CLAIM_ACCOUNT_END_INDEX])
                .context("failed to parse claim_account")?;

        Ok(PublicCircuitInputs {
            wormhole_address,
            claim_account,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_wrong_length() {
        let err = PublicCircuitInputs::try_from_u64_slice(&[0u64; 4]).unwrap_err();
        assert!(err.to_string().contains("field elements"), "got: {err}");
    }

    #[test]
    fn parse_round_trip_zero_digests() {
        let pis = [0u64; PUBLIC_INPUTS_FELTS_LEN];
        let parsed = PublicCircuitInputs::try_from_u64_slice(&pis).unwrap();
        assert_eq!(*parsed.wormhole_address, [0u8; 32]);
        assert_eq!(*parsed.claim_account, [0u8; 32]);
    }

    #[test]
    fn parse_preserves_limb_bytes() {
        let mut pis = [0u64; PUBLIC_INPUTS_FELTS_LEN];
        pis[0] = 1;
        pis[4] = 2;
        let parsed = PublicCircuitInputs::try_from_u64_slice(&pis).unwrap();
        assert_eq!(&parsed.wormhole_address[..8], &1u64.to_le_bytes());
        assert_eq!(&parsed.claim_account[..8], &2u64.to_le_bytes());
    }
}
