//! Differential checks for the byte↔felt encoding safety argument formalized in
//! `formal/WormholeSpec/Encoding.lean`.
//!
//! The wormhole code uses two encodings (`qp-zk-circuits-common::serialization`):
//!   * 4 bytes/felt + terminator (`bytes_to_felts`) at *edges* — injective,
//!     every limb < 2^32 ≤ p so no field reduction ever occurs;
//!   * 8 bytes/felt (`bytes_to_digest`) for *hash outputs* — injective only on
//!     canonical limbs (< p), because `from_noncanonical_u64` reduces mod p.
//!
//! These tests pin both halves: the edge encoding is lossless/injective
//! unconditionally, the digest encoding round-trips on canonical inputs, and we
//! *exhibit* the `{w, w+p}` collision that proves the digest encoding is unsafe
//! off the canonical range (so the canonical-input precondition is load-bearing,
//! not cosmetic).

use plonky2::field::types::{Field, PrimeField64};
use proptest::prelude::*;
use zk_circuits_common::circuit::F;
use zk_circuits_common::serialization::{
    bytes_to_digest, bytes_to_felts, digest_to_bytes, felts_to_bytes,
};

/// Goldilocks prime `p = 2^64 - 2^32 + 1`.
const GOLDILOCKS: u64 = 0xFFFF_FFFF_0000_0001;

/// Pack four canonical `u64` limbs little-endian into a 32-byte digest.
fn bytes32_from_limbs(limbs: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

// ── Witnessed facts (no randomness): the heart of the security argument ──────

/// The 8-byte digest decode is NOT injective off the canonical range: the limb
/// `p` (a valid `u64`) and the limb `0` are distinct byte strings that decode to
/// the same field element, because `from_noncanonical_u64(p) = 0`.
#[test]
fn digest_decode_collides_off_canonical() {
    let canonical = bytes32_from_limbs([0, 0, 0, 0]);
    let non_canonical = bytes32_from_limbs([GOLDILOCKS, 0, 0, 0]);

    assert_ne!(
        canonical, non_canonical,
        "the two byte strings must be distinct"
    );
    assert_eq!(
        bytes_to_digest(&canonical),
        bytes_to_digest(&non_canonical),
        "limbs 0 and p must decode to the same field digest (mod-p reduction)"
    );
}

/// Corollary: the digest round-trip FAILS on a non-canonical limb (it gets
/// folded back to its canonical representative). This is exactly why the input
/// to `bytes_to_digest` must be a genuine (canonical) hash output.
#[test]
fn digest_round_trip_fails_off_canonical() {
    let non_canonical = bytes32_from_limbs([GOLDILOCKS, 0, 0, 0]);
    let recovered = digest_to_bytes(&bytes_to_digest(&non_canonical));
    assert_ne!(
        recovered, non_canonical,
        "non-canonical bytes cannot survive an 8-byte decode/encode round trip"
    );
    // It folds to the canonical representative (limb 0).
    assert_eq!(recovered, bytes32_from_limbs([0, 0, 0, 0]));
}

proptest! {
    // ── 4-byte edge encoding: injective + lossless, unconditionally ──────────

    /// Round trip: `felts_to_bytes ∘ bytes_to_felts = id` for arbitrary bytes.
    #[test]
    fn edge_encoding_round_trips(input in prop::collection::vec(any::<u8>(), 0..96)) {
        let felts = bytes_to_felts(&input).unwrap();
        let recovered = felts_to_bytes(&felts).expect("valid terminator");
        prop_assert_eq!(recovered, input);
    }

    /// Injectivity: distinct byte strings map to distinct felt sequences.
    #[test]
    fn edge_encoding_injective(
        x in prop::collection::vec(any::<u8>(), 0..96),
        y in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        prop_assume!(x != y);
        prop_assert_ne!(bytes_to_felts(&x).unwrap(), bytes_to_felts(&y).unwrap());
    }

    /// No field reduction at the edges: every limb is a 32-bit value (< 2^32),
    /// hence canonical (`feltOf_id_of_lt_2pow32` in the Lean spec).
    #[test]
    fn edge_encoding_limbs_are_32_bit(input in prop::collection::vec(any::<u8>(), 0..96)) {
        for f in bytes_to_felts(&input).unwrap() {
            prop_assert!(f.to_canonical_u64() < (1u64 << 32));
        }
    }

    // ── 8-byte digest encoding: injective ON canonical inputs ────────────────

    /// Round trip on canonical limbs: `digest_to_bytes ∘ bytes_to_digest = id`.
    #[test]
    fn digest_round_trips_on_canonical(
        a in 0u64..GOLDILOCKS,
        b in 0u64..GOLDILOCKS,
        c in 0u64..GOLDILOCKS,
        d in 0u64..GOLDILOCKS,
    ) {
        let bytes = bytes32_from_limbs([a, b, c, d]);
        prop_assert_eq!(digest_to_bytes(&bytes_to_digest(&bytes)), bytes);
    }

    /// Genuine hash outputs (any 4 field elements) always survive
    /// `bytes_to_digest ∘ digest_to_bytes = id`, since field elements are
    /// canonical by construction.
    #[test]
    fn hash_output_digest_round_trips(
        a in 0u64..GOLDILOCKS,
        b in 0u64..GOLDILOCKS,
        c in 0u64..GOLDILOCKS,
        d in 0u64..GOLDILOCKS,
    ) {
        let felts = [
            F::from_canonical_u64(a),
            F::from_canonical_u64(b),
            F::from_canonical_u64(c),
            F::from_canonical_u64(d),
        ];
        prop_assert_eq!(bytes_to_digest(&digest_to_bytes(&felts)), felts);
    }

    /// Injectivity on canonical inputs: distinct canonical digests decode to
    /// distinct field digests (`bytesToDigest_inj_canonical` in the Lean spec).
    #[test]
    fn digest_decode_injective_on_canonical(
        x in (0u64..GOLDILOCKS, 0u64..GOLDILOCKS, 0u64..GOLDILOCKS, 0u64..GOLDILOCKS),
        y in (0u64..GOLDILOCKS, 0u64..GOLDILOCKS, 0u64..GOLDILOCKS, 0u64..GOLDILOCKS),
    ) {
        let bx = bytes32_from_limbs([x.0, x.1, x.2, x.3]);
        let by = bytes32_from_limbs([y.0, y.1, y.2, y.3]);
        prop_assume!(bx != by);
        prop_assert_ne!(bytes_to_digest(&bx), bytes_to_digest(&by));
    }
}
