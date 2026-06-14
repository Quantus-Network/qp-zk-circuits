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

use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::plonk::config::Hasher;
use proptest::prelude::*;
use wormhole_circuit::nullifier::{Nullifier, NULLIFIER_SALT};
use wormhole_circuit::unspendable_account::{UnspendableAccount, UNSPENDABLE_SALT};
use zk_circuits_common::circuit::F;
use zk_circuits_common::utils::{bytes_to_digest, string_to_felts, u64_to_felts, BytesDigest};

/// Goldilocks field order; canonical felt limbs must be strictly below it.
const GOLDILOCKS: u64 = 0xFFFF_FFFF_0000_0001;

/// The spec's double hash `hh p = H((H p).toList)`.
fn hh(preimage: &[F]) -> [F; 4] {
    let inner = Poseidon2Hash::hash_no_pad(preimage).elements;
    Poseidon2Hash::hash_no_pad(&inner).elements
}

/// Build a valid 32-byte secret from four canonical Goldilocks limbs
/// (8 bytes/felt, little-endian — the encoding `bytes_to_digest` expects).
fn secret_from_limbs(limbs: [u64; 4]) -> BytesDigest {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    BytesDigest::try_from(bytes).expect("canonical limbs encode a valid digest")
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
}
