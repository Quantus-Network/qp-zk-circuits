//! Nullifier circuit fragment.
//!
//! Proves the public nullifier is *well-formed*:
//! `hash == H(H(salt || secret || transfer_count))`, binding it to the same
//! `secret` that derives the unspendable deposit account and the same
//! `transfer_count` that appears in the deposit's storage-proof leaf. One
//! funded deposit event therefore yields exactly one valid nullifier.
//!
//! # Scope: well-formedness only, no uniqueness
//!
//! Neither this fragment nor any other circuit in this repository checks that a
//! nullifier is *unused* (i.e. detects collisions/double spends). Uniqueness is
//! a statement about global chain state and is enforced on-chain by the
//! wormhole pallet, which maintains the persistent set of settled nullifiers
//! and settles each nullifier at most once. See "Nullifiers and Double-Spend
//! Prevention" in `wormhole/README.md` for the full layering.

use alloc::vec::Vec;
use core::array;
use core::mem::size_of;
use zk_circuits_common::utils::bytes_to_digest;
use zk_circuits_common::utils::digest_to_bytes;
use zk_circuits_common::utils::felts_to_u64;
use zk_circuits_common::utils::DIGEST_BYTES_LEN;
use zk_circuits_common::utils::FELTS_PER_U128;
use zk_circuits_common::utils::FELTS_PER_U64;
use zk_circuits_common::utils::POSEIDON2_OUTPUT;

use crate::inputs::CircuitInputs;
use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon2::Poseidon2Hash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
use zk_circuits_common::utils::{string_to_felts, u64_to_felts, BytesDigest, Digest};

pub const SALT_BYTES_LEN: usize = 8;
pub const NULLIFIER_SALT: &str = "~nullif~";

// Compile-time check: require NULLIFIER_SALT to have exactly SALT_BYTES_LEN bytes
const _: () = {
    assert!(
        NULLIFIER_SALT.len() == SALT_BYTES_LEN,
        "invalid NULLIFIER_SALT length"
    );
};
pub const SECRET_BYTES_LEN: usize = 32;
/// Number of field elements for the secret (32 bytes with 8 bytes/felt encoding)
pub const SECRET_NUM_TARGETS: usize = POSEIDON2_OUTPUT; // 4
pub const SALT_NUM_TARGETS: usize = 3;
pub const FUNDING_ACCOUNT_NUM_TARGETS: usize = FELTS_PER_U128;
pub const TRANSFER_COUNT_NUM_TARGETS: usize = FELTS_PER_U64;
pub const PREIMAGE_NUM_TARGETS: usize =
    SECRET_NUM_TARGETS + SALT_NUM_TARGETS + FUNDING_ACCOUNT_NUM_TARGETS;
pub const NULLIFIER_SIZE_FELTS: usize =
    POSEIDON2_OUTPUT + SECRET_NUM_TARGETS + TRANSFER_COUNT_NUM_TARGETS;

/// Type alias for the secret as a fixed-size array (4 field elements for 32 bytes)
pub type Secret = Digest;

#[derive(PartialEq, Eq, Clone)]
pub struct Nullifier {
    pub hash: Digest,
    /// Secret encoded with 8 bytes/felt (4 field elements for 32 bytes)
    pub secret: Secret,
    transfer_count: [F; TRANSFER_COUNT_NUM_TARGETS],
}

impl core::fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Nullifier")
            .field("hash", &self.hash)
            .field("secret", &"[REDACTED]")
            .field("transfer_count", &"[REDACTED]")
            .finish()
    }
}

impl Nullifier {
    pub fn new(digest: BytesDigest, secret: BytesDigest, transfer_count: u64) -> Self {
        let hash = bytes_to_digest(digest);
        // Use 8 bytes/felt encoding.
        let secret = bytes_to_digest(secret);
        let transfer_count = u64_to_felts(transfer_count);

        Self {
            hash,
            secret,
            transfer_count,
        }
    }

    pub fn from_preimage(secret: BytesDigest, transfer_count: u64) -> Self {
        let mut preimage = Vec::new();

        let salt =
            string_to_felts(NULLIFIER_SALT).expect("NULLIFIER_SALT within serialization cap");
        let secret_felts = bytes_to_digest(secret);
        let transfer_count_felts = u64_to_felts(transfer_count);

        preimage.extend(salt);
        preimage.extend(secret_felts);
        preimage.extend(transfer_count_felts);

        let inner_hash = Poseidon2Hash::hash_no_pad(&preimage).elements;
        let outer_hash = Poseidon2Hash::hash_no_pad(&inner_hash).elements;
        let hash = Digest::from(outer_hash);

        Self {
            hash,
            secret: secret_felts,
            transfer_count: transfer_count_felts,
        }
    }
}

impl ByteCodec for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(*digest_to_bytes(self.hash));
        bytes.extend(*digest_to_bytes(self.secret));
        let transfer_count_uint = felts_to_u64(self.transfer_count).unwrap();
        bytes.extend(transfer_count_uint.to_le_bytes());
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let hash_size = DIGEST_BYTES_LEN;
        let secret_size = SECRET_BYTES_LEN;
        let transfer_count_size = size_of::<u64>();
        let total_size = hash_size + secret_size + transfer_count_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for Nullifier, got: {}",
                total_size,
                slice.len()
            ));
        }

        let mut offset = 0;
        // Deserialize hash
        let digest = slice[offset..offset + hash_size].try_into().map_err(|e| {
            anyhow::anyhow!("Failed to deserialize nullifier hash with error: {:?}", e)
        })?;
        let hash = bytes_to_digest(digest);
        offset += hash_size;

        // Deserialize secret (32 bytes -> 4 field elements)
        let secret_bytes: BytesDigest =
            slice[offset..offset + secret_size]
                .try_into()
                .map_err(|e| {
                    anyhow::anyhow!("Failed to deserialize nullifier secret with error: {:?}", e)
                })?;
        let secret = bytes_to_digest(secret_bytes);
        offset += secret_size;

        // Deserialize transfer_count
        // Read as u64 and then convert to felts to ensure proper encoding
        let transfer_count_u64 = u64::from_le_bytes(
            slice[offset..offset + transfer_count_size]
                .try_into()
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to deserialize nullifier transfer_count with error: {:?}",
                        e
                    )
                })?,
        );
        let transfer_count = u64_to_felts(transfer_count_u64);

        Ok(Self {
            hash,
            secret,
            transfer_count,
        })
    }
}

impl FieldElementCodec for Nullifier {
    fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        elements.extend(self.hash.to_vec());
        elements.extend(self.secret);
        elements.extend(self.transfer_count);
        elements
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != NULLIFIER_SIZE_FELTS {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for Nullifier, got: {}",
                NULLIFIER_SIZE_FELTS,
                elements.len()
            ));
        }

        let mut offset = 0;
        // Deserialize hash
        let hash: Digest = elements[offset..offset + POSEIDON2_OUTPUT]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier hash"))?;
        offset += POSEIDON2_OUTPUT;

        // Deserialize secret (4 field elements)
        let secret: Secret = elements[offset..offset + SECRET_NUM_TARGETS]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier secret"))?;
        offset += SECRET_NUM_TARGETS;

        // Deserialize transfer_count, enforcing the 32-bit limb invariant so a
        // later `to_bytes` cannot panic on attacker-supplied oversized limbs (#97064).
        let transfer_count = elements[offset..offset + TRANSFER_COUNT_NUM_TARGETS]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier transfer_count"))?;
        felts_to_u64(transfer_count)
            .map_err(|e| anyhow::anyhow!("invalid nullifier transfer_count felts: {}", e))?;

        Ok(Self {
            hash,
            secret,
            transfer_count,
        })
    }
}

impl From<&CircuitInputs> for Nullifier {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(
            inputs.public.nullifier,
            inputs.private.secret,
            inputs.private.transfer_count,
        )
    }
}

#[derive(Debug, Clone)]
pub struct NullifierTargets {
    pub hash: HashOutTarget,
    /// Secret targets
    pub secret: HashOutTarget,
    pub transfer_count: [Target; TRANSFER_COUNT_NUM_TARGETS],
}

impl NullifierTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            hash: builder.add_virtual_hash_public_input(),
            secret: builder.add_virtual_hash(),
            transfer_count: array::from_fn(|_| builder.add_virtual_target()),
        }
    }
}

impl Nullifier {
    /// Computes `H(H(salt + secret + transfer_count))` in-circuit.
    fn computed_nullifier(
        targets: &NullifierTargets,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let salt_felts =
            string_to_felts(NULLIFIER_SALT).expect("NULLIFIER_SALT within serialization cap");
        let mut nullifier_preimage = Vec::new();
        for &f in salt_felts.iter() {
            nullifier_preimage.push(builder.constant(f));
        }
        nullifier_preimage.extend(targets.secret.elements.iter().copied());
        nullifier_preimage.extend(targets.transfer_count.iter());

        let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(nullifier_preimage);
        builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec())
    }

    /// Enforces `hash == H(H(salt + secret + transfer_count))` whenever
    /// `is_not_dummy` is 1, i.e. `(hash[i] - computed[i]) * is_not_dummy == 0`
    /// for each limb.
    ///
    /// This is an escape hatch for the full Wormhole circuit, which skips the
    /// binding for dummy proofs so they can use random nullifiers for better
    /// privacy. `is_not_dummy` MUST itself be constrained by the caller (the
    /// full Wormhole circuit derives it in-circuit from
    /// `block_hash == 0 AND outputs == 0`); otherwise a malicious prover can
    /// simply witness it to 0 and skip the check. Every other caller should use
    /// [`CircuitFragment::circuit`], which enforces the binding unconditionally.
    pub fn conditional_hash_binding(
        targets: &NullifierTargets,
        builder: &mut CircuitBuilder<F, D>,
        is_not_dummy: Target,
    ) {
        let computed_nullifier = Self::computed_nullifier(targets, builder);
        let zero = builder.zero();
        for i in 0..4 {
            let diff = builder.sub(
                targets.hash.elements[i],
                computed_nullifier.elements[i],
            );
            let result = builder.mul(diff, is_not_dummy);
            builder.connect(result, zero);
        }
    }
}

impl CircuitFragment for Nullifier {
    type Targets = NullifierTargets;

    /// Builds the nullifier circuit, unconditionally enforcing
    /// `hash == H(H(salt + secret + transfer_count))`.
    ///
    /// This is the safe-by-default entry point: any circuit composed from this
    /// fragment inherits the hash binding that gives the public nullifier
    /// `hash` input its meaning. The full Wormhole circuit is the one
    /// exception; it does NOT call this and instead uses
    /// [`Nullifier::conditional_hash_binding`] so dummy proofs can use random
    /// nullifiers for better privacy.
    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>) {
        let computed_nullifier = Self::computed_nullifier(targets, builder);
        builder.connect_hashes(targets.hash, computed_nullifier);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.hash, self.hash.into())?;
        pw.set_hash_target(targets.secret, self.secret.into())?;
        pw.set_target_arr(&targets.transfer_count, &self.transfer_count)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::Nullifier;
    use plonky2::field::types::Field;
    use qp_wormhole_inputs::BytesDigest;
    use zk_circuits_common::{circuit::F, codec::FieldElementCodec};

    #[test]
    fn from_field_elements_rejects_oversized_transfer_count_limbs() {
        // `to_bytes` treats transfer_count as 32-bit limbs, so `from_field_elements`
        // must reject oversized limbs up front instead of letting a later
        // `to_bytes` panic (#97064).
        let valid = Nullifier::from_preimage(BytesDigest::new_unchecked([7u8; 32]), 42);
        let mut felts = valid.to_field_elements();
        let last = felts.len() - 1;
        felts[last] = F::from_noncanonical_u64(0x1_0000_0000);

        let err = Nullifier::from_field_elements(&felts)
            .expect_err("oversized transfer_count limb must be rejected");
        assert!(
            err.to_string()
                .contains("invalid nullifier transfer_count felts"),
            "got: {err}"
        );
    }
}
