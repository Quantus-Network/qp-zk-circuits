//! Phase-1 differential safety net for the formal spec (`formal/`).
//!
//! These property tests pin the *native* reference implementations
//! (`UnspendableAccount::from_secret`, `Nullifier::from_preimage`) to the hash
//! structure asserted by the Lean spec (`WormholeSpec.Hash`): both `WA` and
//! `Null` are the double hash `H(H(salt ‖ …))` with the documented preimage
//! orderings. Re-deriving the digest independently here catches drift between
//! the spec relation and the implementation before any heavy formal proof.
//!
//! The independent recomputation mirrors:
//!   * `RandomOracle.WA   s   = hh (wormholeSalt ++ s)`
//!   * `RandomOracle.Null s c = hh (nullifierSalt ++ s ++ c)`
//! from `formal/WormholeSpec/Hash.lean`.

use plonky2::field::types::Field;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::plonk::config::Hasher;
use proptest::prelude::*;
use wormhole_circuit::nullifier::{Nullifier, NULLIFIER_SALT};
use wormhole_circuit::unspendable_account::{UnspendableAccount, UNSPENDABLE_SALT};
use wormhole_circuit::zk_merkle_proof::ZkLeafData;
use zk_circuits_common::circuit::F;
use zk_circuits_common::serialization::bytes_to_digest as ser_bytes_to_digest;
use zk_circuits_common::utils::{bytes_to_digest, string_to_felts, u64_to_felts, BytesDigest};

/// Goldilocks field order; canonical felt limbs must be strictly below it.
const GOLDILOCKS: u64 = 0xFFFF_FFFF_0000_0001;

/// The spec's double hash `hh p = H((H p).toList)`.
fn hh(preimage: &[F]) -> [F; 4] {
    let inner = Poseidon2Hash::hash_no_pad(preimage).elements;
    Poseidon2Hash::hash_no_pad(&inner).elements
}

/// Pack four canonical Goldilocks limbs into 32 bytes (8 bytes/felt, little-endian).
fn bytes32_from_limbs(limbs: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

/// Build a valid 32-byte secret from four canonical Goldilocks limbs.
fn secret_from_limbs(limbs: [u64; 4]) -> BytesDigest {
    BytesDigest::try_from(bytes32_from_limbs(limbs)).expect("canonical limbs encode a valid digest")
}

proptest! {
    /// C2: `WA(s) = H(H(salt_wh ‖ s))`.
    #[test]
    fn wa_matches_double_hash(
        a in 0u64..GOLDILOCKS,
        b in 0u64..GOLDILOCKS,
        c in 0u64..GOLDILOCKS,
        d in 0u64..GOLDILOCKS,
    ) {
        let secret = secret_from_limbs([a, b, c, d]);

        let mut preimage: Vec<F> = string_to_felts(UNSPENDABLE_SALT).to_vec();
        preimage.extend_from_slice(&bytes_to_digest(secret));
        let expected = hh(&preimage);

        let actual = UnspendableAccount::from_secret(secret).account_id;
        prop_assert_eq!(actual, expected);
    }

    /// C1: `Null(s, c) = H(H(salt_null ‖ s ‖ c))`.
    #[test]
    fn nullifier_matches_double_hash(
        a in 0u64..GOLDILOCKS,
        b in 0u64..GOLDILOCKS,
        c in 0u64..GOLDILOCKS,
        d in 0u64..GOLDILOCKS,
        transfer_count in any::<u64>(),
    ) {
        let secret = secret_from_limbs([a, b, c, d]);

        let mut preimage: Vec<F> = string_to_felts(NULLIFIER_SALT).to_vec();
        preimage.extend_from_slice(&bytes_to_digest(secret));
        preimage.extend(u64_to_felts(transfer_count));
        let expected = hh(&preimage);

        let actual = Nullifier::from_preimage(secret, transfer_count).hash;
        prop_assert_eq!(actual, expected);
    }

    /// Determinism: the derivations are pure functions of their inputs.
    #[test]
    fn derivations_are_deterministic(
        a in 0u64..GOLDILOCKS,
        b in 0u64..GOLDILOCKS,
        c in 0u64..GOLDILOCKS,
        d in 0u64..GOLDILOCKS,
        transfer_count in any::<u64>(),
    ) {
        let secret = secret_from_limbs([a, b, c, d]);
        prop_assert_eq!(
            UnspendableAccount::from_secret(secret).account_id,
            UnspendableAccount::from_secret(secret).account_id
        );
        prop_assert_eq!(
                Nullifier::from_preimage(secret, transfer_count).hash,
                    Nullifier::from_preimage(secret, transfer_count).hash
                );
        }

        /// C3: the ZK-tree leaf hash preimage is ordered
        /// `to_account(4) ‖ transfer_count(2) ‖ asset_id(1) ‖ input_amount(1)`,
        /// matching the spec's `leafHash` (`WormholeSpec.Hash`).
        #[test]
        fn leaf_hash_preimage_order(
            a in 0u64..GOLDILOCKS,
            b in 0u64..GOLDILOCKS,
            c in 0u64..GOLDILOCKS,
            d in 0u64..GOLDILOCKS,
            transfer_count in any::<u64>(),
            asset_id in any::<u32>(),
            input_amount in any::<u32>(),
            output_amount_1 in any::<u32>(),
            output_amount_2 in any::<u32>(),
            volume_fee_bps in any::<u32>(),
        ) {
            let to_account = bytes32_from_limbs([a, b, c, d]);

            let leaf = ZkLeafData::new(
                to_account,
                transfer_count,
                asset_id,
                input_amount,
                output_amount_1,
                output_amount_2,
                volume_fee_bps,
            );
            let actual = Poseidon2Hash::hash_no_pad(&leaf.collect_for_hash()).elements;

            // Independently reconstruct the spec-documented preimage order.
            let mut preimage: Vec<F> = ser_bytes_to_digest(&to_account).to_vec();
            preimage.extend(u64_to_felts(transfer_count));
            preimage.push(F::from_canonical_u32(asset_id));
            preimage.push(F::from_canonical_u32(input_amount));
            let expected = Poseidon2Hash::hash_no_pad(&preimage).elements;

            prop_assert_eq!(actual, expected);
        }
    }
