//! Move-only, zeroize-on-drop wrappers for the Wormhole spend secret.
//!
//! This imitates `SensitiveBytes32` from `qp-rusty-crystals` (see
//! `WormholePair` in the hdwallet crate, which already keeps the secret in
//! such a wrapper). The protection was previously lost at the hand-off into
//! this repository, where the secret degraded into a `Copy` [`BytesDigest`]
//! inside a `Clone`-able `PrivateCircuitInputs`: any move or field access
//! could silently duplicate the spend credential into stack frames, logs, or
//! crash dumps that no drop-time scrub can reach.
//!
//! Two wrappers cover the secret's two encodings:
//!
//! - [`SensitiveDigest`]: the 32-byte form held by `PrivateCircuitInputs`.
//! - [`Secret`]: the felt-encoded form (4 felts, 8 bytes/felt) held by
//!   `Nullifier` and `UnspendableAccount` for witness filling.
//!
//! Shared properties:
//!
//! - **Zeroized on drop** via the [`zeroize`] crate, whose writes the
//!   optimizer cannot elide. This crate is `#![forbid(unsafe_code)]`, so the
//!   volatile scrubbing lives in that vetted dependency.
//! - **No `Debug`**: a container that derives `Debug` over these fields fails
//!   to compile, forcing a redacting manual impl instead.
//! - Duplication out of a wrapper requires an explicitly named `expose_*`
//!   call, making every copy searchable and visible in review.
//!   [`SensitiveDigest`] is additionally move-only (no `Clone`).
//!
//! # Scope
//!
//! These wrappers cover the copies *we* own. Transient stack copies made
//! while encoding the secret into field elements, and the copies plonky2
//! keeps inside `PartialWitness`/`ProverCircuitData` during proving, are out
//! of scope here (the latter requires upstream support to scrub).

use plonky2::field::types::{Field, PrimeField64};
use zeroize::Zeroize;
use zk_circuits_common::circuit::F;
use zk_circuits_common::utils::{
    BytesDigest, Digest, DigestError, DIGEST_BYTES_LEN, POSEIDON2_OUTPUT,
};

/// The Wormhole spend secret: a validated 32-byte digest that is move-only
/// and zeroized on drop.
///
/// Construction validates the same invariant as [`BytesDigest`] (every 8-byte
/// limb is a canonical Goldilocks element), so [`SensitiveDigest::expose_digest`]
/// can rebuild a `BytesDigest` without re-validation.
pub struct SensitiveDigest([u8; DIGEST_BYTES_LEN]);

impl SensitiveDigest {
    /// Takes practical ownership of the secret: validates it, moves it into
    /// the wrapper, and zeroizes the source bytes so no copy remains at the
    /// call site (also on validation failure — an invalid secret is useless
    /// to the caller anyway).
    pub fn new(bytes: &mut [u8; DIGEST_BYTES_LEN]) -> Result<Self, DigestError> {
        let validated = BytesDigest::try_from(*bytes);
        let result = validated.map(|digest| Self(*digest));
        bytes.zeroize();
        result
    }

    /// Borrow the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES_LEN] {
        &self.0
    }

    /// Explicitly duplicate the secret as a `Copy` [`BytesDigest`].
    ///
    /// The returned value escapes this wrapper's zeroization, so keep it
    /// transient: encode it and let it go out of scope. The deliberate name
    /// makes every such duplication searchable and visible in review.
    pub fn expose_digest(&self) -> BytesDigest {
        // Validated at construction, so unchecked reconstruction is sound.
        BytesDigest::new_unchecked(self.0)
    }
}

/// Convenience for call sites that already hold a validated digest (tests,
/// dummy proofs). Note `BytesDigest` is `Copy`: this cannot scrub the
/// caller's original, so real secrets should enter via
/// [`SensitiveDigest::new`] instead.
impl From<BytesDigest> for SensitiveDigest {
    fn from(digest: BytesDigest) -> Self {
        Self(*digest)
    }
}

/// Convenience for literals in tests and docs. Does not scrub the source
/// array; real secrets should enter via [`SensitiveDigest::new`].
impl TryFrom<[u8; DIGEST_BYTES_LEN]> for SensitiveDigest {
    type Error = DigestError;

    fn try_from(bytes: [u8; DIGEST_BYTES_LEN]) -> Result<Self, Self::Error> {
        BytesDigest::try_from(bytes).map(Self::from)
    }
}

impl Drop for SensitiveDigest {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The felt-encoded spend secret (4 felts, 8 bytes/felt), zeroized on drop.
///
/// This is the in-circuit encoding counterpart of [`SensitiveDigest`]: the
/// same 32-byte secret after `bytes_to_digest`, as held by `Nullifier` and
/// `UnspendableAccount` for witness filling. It replaces the two identical
/// `type Secret = [F; 4]` aliases those modules used to declare.
///
/// The limbs are stored as canonical `u64`s rather than `GoldilocksField`
/// values because the field type is foreign and has no [`Zeroize`] impl;
/// storing plain integers lets the vetted `zeroize` crate do the drop-time
/// scrub without local `unsafe` (which this crate forbids). Conversion is
/// lossless: the felts are
/// canonicalized on the way in and rebuilt with `from_canonical_u64` on the
/// way out.
///
/// Unlike [`SensitiveDigest`] this is `Clone`: the containing types need
/// value semantics for their codecs, and every clone scrubs itself on drop,
/// so duplication never escapes the zeroization invariant. Reading the felts
/// out requires the explicitly named [`Secret::expose_felts`], and there is
/// no `Debug` impl, so containers must redact it manually.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret([u64; POSEIDON2_OUTPUT]);

impl Secret {
    /// Explicitly duplicate the secret as plain `Copy` felts.
    ///
    /// The returned array escapes this wrapper's zeroization, so keep it
    /// transient: encode it and let it go out of scope. The deliberate name
    /// makes every such duplication searchable and visible in review.
    pub fn expose_felts(&self) -> Digest {
        self.0.map(F::from_canonical_u64)
    }
}

/// Note the source `Digest` is `Copy`, so this cannot scrub the caller's
/// original; the felts should be transient at the call site.
impl From<Digest> for Secret {
    fn from(felts: Digest) -> Self {
        Self(felts.map(|f| f.to_canonical_u64()))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_validates_and_zeroizes_source() {
        let mut source = [0x11u8; 32];
        let sensitive = SensitiveDigest::new(&mut source).unwrap();
        assert_eq!(source, [0u8; 32], "source must be scrubbed");
        assert_eq!(sensitive.as_bytes(), &[0x11u8; 32]);
        assert_eq!(*sensitive.expose_digest(), [0x11u8; 32]);
    }

    #[test]
    fn new_zeroizes_source_even_on_invalid_digest() {
        // All-0xFF limbs are >= the Goldilocks modulus, so validation fails.
        let mut source = [0xFFu8; 32];
        assert!(SensitiveDigest::new(&mut source).is_err());
        assert_eq!(source, [0u8; 32], "source must be scrubbed on failure too");
    }

    /// Guards against the `Drop` impls (the zeroization hook) being removed:
    /// a plain byte/int array needs no drop glue, so `needs_drop` is `true`
    /// for these types only while their scrubbing destructors exist.
    #[test]
    fn wrappers_have_drop_glue() {
        assert!(core::mem::needs_drop::<SensitiveDigest>());
        assert!(core::mem::needs_drop::<Secret>());
    }

    #[test]
    fn secret_felts_round_trip() {
        let felts: Digest = [1u64, 2, 3, u32::MAX as u64].map(F::from_canonical_u64);
        let secret = Secret::from(felts);
        assert_eq!(secret.expose_felts(), felts);
    }
}
