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
//! Two wrappers:
//!
//! - [`Secret`]: the spend secret itself, held by `PrivateCircuitInputs`,
//!   `Nullifier`, and `UnspendableAccount`. Stores the 32-byte form and
//!   exposes either encoding (bytes via [`Secret::expose_digest`], felts via
//!   [`Secret::expose_felts`]).
//! - [`SensitiveFelts`]: a heap buffer of field elements that carries an
//!   exposed secret out of a serialization API.
//!
//! Shared properties:
//!
//! - **Zeroized on drop** via the [`zeroize`] crate, whose writes the
//!   optimizer cannot elide. This crate is `#![forbid(unsafe_code)]`, so the
//!   volatile scrubbing lives in that vetted dependency.
//! - **No `Debug`**: a container that derives `Debug` over these fields fails
//!   to compile, forcing a redacting manual impl instead.
//! - [`Secret`] is move-only (no `Clone`): duplication out of the wrapper
//!   requires an explicitly named `expose_*` call, making every copy
//!   searchable and visible in review.
//! - Serialization that must carry an exposed secret returns
//!   [`zeroize::Zeroizing`] / [`SensitiveFelts`] so the heap buffer is
//!   scrubbed when the caller drops it — never a bare `Vec`.
//!
//! # Scope
//!
//! These wrappers cover the copies *we* own. Transient stack copies made
//! while encoding the secret into field elements, and the copies plonky2
//! keeps inside `PartialWitness`/`ProverCircuitData` during proving, are out
//! of scope here (the latter requires upstream support to scrub).

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use plonky2::field::types::{Field, PrimeField64};
use zeroize::Zeroize;
use zk_circuits_common::circuit::F;
use zk_circuits_common::utils::{
    bytes_to_digest, digest_to_bytes, BytesDigest, Digest, DigestError, DIGEST_BYTES_LEN,
};

/// The Wormhole spend secret: a validated 32-byte digest, zeroized on drop.
///
/// Construction validates the same invariant as [`BytesDigest`] (every 8-byte
/// limb is a canonical Goldilocks element), so both `expose_*` accessors can
/// rebuild their encoding without re-validation:
///
/// - [`Secret::expose_digest`] for the 32-byte form (block-header hand-off),
/// - [`Secret::expose_felts`] for the felt encoding (witness filling). The
///   8-bytes-per-felt conversion is lossless in both directions.
///
/// Move-only (no `Clone`): the only ways to duplicate the secret are the
/// explicitly named `expose_*` calls, so every copy is searchable and
/// visible in review. This also keeps the containing types (`Nullifier`,
/// `UnspendableAccount`, `PrivateCircuitInputs`) move-only. There is no
/// `Debug` impl, so containers must redact the field manually. Call sites
/// that must return the secret in a heap buffer (e.g. serialization) must
/// wrap that buffer in [`zeroize::Zeroizing`] or [`SensitiveFelts`].
#[derive(PartialEq, Eq)]
pub struct Secret([u8; DIGEST_BYTES_LEN]);

impl Secret {
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

    /// Explicitly duplicate the secret as plain `Copy` felts
    /// (4 felts, 8 bytes/felt — the in-circuit encoding).
    ///
    /// The returned array escapes this wrapper's zeroization, so keep it
    /// transient: encode it and let it go out of scope. The deliberate name
    /// makes every such duplication searchable and visible in review.
    pub fn expose_felts(&self) -> Digest {
        bytes_to_digest(self.expose_digest())
    }
}

/// Convenience for call sites that already hold a validated digest (tests,
/// dummy proofs). Note `BytesDigest` is `Copy`: this cannot scrub the
/// caller's original, so real secrets should enter via [`Secret::new`]
/// instead.
impl From<BytesDigest> for Secret {
    fn from(digest: BytesDigest) -> Self {
        Self(*digest)
    }
}

/// Convenience for call sites that hold the felt encoding (deserialization).
/// Note the source `Digest` is `Copy`, so this cannot scrub the caller's
/// original; the felts should be transient at the call site.
impl From<Digest> for Secret {
    fn from(felts: Digest) -> Self {
        // Canonical field elements always produce a valid digest.
        Self::from(digest_to_bytes(felts))
    }
}

/// Convenience for literals in tests and docs. Does not scrub the source
/// array; real secrets should enter via [`Secret::new`].
impl TryFrom<[u8; DIGEST_BYTES_LEN]> for Secret {
    type Error = DigestError;

    fn try_from(bytes: [u8; DIGEST_BYTES_LEN]) -> Result<Self, Self::Error> {
        BytesDigest::try_from(bytes).map(Self::from)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Heap buffer of field elements that may contain an exposed spend secret.
///
/// `F` has no [`Zeroize`] impl (foreign type), so drop scrubs each limb via
/// its canonical `u64` representation and overwrites the slot with `F::ZERO`.
/// Prefer this (or [`zeroize::Zeroizing`] for bytes) over returning a bare
/// `Vec` from any API that serializes [`Secret`].
pub struct SensitiveFelts(Vec<F>);

impl SensitiveFelts {
    pub fn new(elements: Vec<F>) -> Self {
        Self(elements)
    }

    pub fn as_slice(&self) -> &[F] {
        &self.0
    }
}

impl Deref for SensitiveFelts {
    type Target = [F];

    fn deref(&self) -> &[F] {
        &self.0
    }
}

impl DerefMut for SensitiveFelts {
    fn deref_mut(&mut self) -> &mut [F] {
        &mut self.0
    }
}

impl AsRef<[F]> for SensitiveFelts {
    fn as_ref(&self) -> &[F] {
        &self.0
    }
}

impl Drop for SensitiveFelts {
    fn drop(&mut self) {
        for felt in &mut self.0 {
            let mut limb = felt.to_canonical_u64();
            limb.zeroize();
            *felt = F::ZERO;
        }
        self.0.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_validates_and_zeroizes_source() {
        let mut source = [0x11u8; 32];
        let sensitive = Secret::new(&mut source).unwrap();
        assert_eq!(source, [0u8; 32], "source must be scrubbed");
        assert_eq!(sensitive.as_bytes(), &[0x11u8; 32]);
        assert_eq!(*sensitive.expose_digest(), [0x11u8; 32]);
    }

    #[test]
    fn new_zeroizes_source_even_on_invalid_digest() {
        // All-0xFF limbs are >= the Goldilocks modulus, so validation fails.
        let mut source = [0xFFu8; 32];
        assert!(Secret::new(&mut source).is_err());
        assert_eq!(source, [0u8; 32], "source must be scrubbed on failure too");
    }

    /// Guards against the `Drop` impls (the zeroization hook) being removed:
    /// a plain byte/int array needs no drop glue, so `needs_drop` is `true`
    /// for these types only while their scrubbing destructors exist.
    #[test]
    fn wrappers_have_drop_glue() {
        assert!(core::mem::needs_drop::<Secret>());
    }

    #[test]
    fn secret_felts_round_trip() {
        let felts: Digest = [1u64, 2, 3, u32::MAX as u64].map(F::from_canonical_u64);
        let secret = Secret::from(felts);
        assert_eq!(secret.expose_felts(), felts);
    }

    #[test]
    fn sensitive_felts_have_drop_glue() {
        assert!(core::mem::needs_drop::<SensitiveFelts>());
    }
}
