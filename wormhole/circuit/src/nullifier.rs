use alloc::vec::Vec;
use core::array;
use core::mem::size_of;
use zk_circuits_common::utils::digest_bytes_to_felts;
use zk_circuits_common::utils::digest_felts_to_bytes;
use zk_circuits_common::utils::felts_to_u64;
use zk_circuits_common::utils::DIGEST_BYTES_LEN;
use zk_circuits_common::utils::DIGEST_NUM_FIELD_ELEMENTS;
use zk_circuits_common::utils::FELTS_PER_U128;
use zk_circuits_common::utils::FELTS_PER_U64;
use zk_circuits_common::utils::INJECTIVE_BYTES_LIMB;

use crate::codec::ByteCodec;
use crate::codec::FieldElementCodec;
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
use zk_circuits_common::utils::{injective_string_to_felt, u64_to_felts, BytesDigest, Digest};

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
pub const SECRET_NUM_TARGETS: usize = DIGEST_NUM_FIELD_ELEMENTS;
pub const SALT_NUM_TARGETS: usize = 3;
pub const FUNDING_ACCOUNT_NUM_TARGETS: usize = FELTS_PER_U128;
pub const TRANSFER_COUNT_NUM_TARGETS: usize = FELTS_PER_U64;
pub const PREIMAGE_NUM_TARGETS: usize =
    SECRET_NUM_TARGETS + SALT_NUM_TARGETS + FUNDING_ACCOUNT_NUM_TARGETS;
pub const NULLIFIER_SIZE_FELTS: usize =
    DIGEST_NUM_FIELD_ELEMENTS + SECRET_NUM_TARGETS + TRANSFER_COUNT_NUM_TARGETS;
pub const NULLIFIER_SIZE_BYTES: usize = NULLIFIER_SIZE_FELTS * INJECTIVE_BYTES_LIMB; // 4 + 8 + 2 = 14 field elements
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nullifier {
    pub hash: Digest,
    pub secret: Digest,
    transfer_count: [F; TRANSFER_COUNT_NUM_TARGETS],
}

impl Nullifier {
    pub fn new(digest: BytesDigest, secret: BytesDigest, transfer_count: u64) -> Self {
        let hash = digest_bytes_to_felts(digest);
        let secret = digest_bytes_to_felts(secret);
        let transfer_count = u64_to_felts(transfer_count);

        Self {
            hash,
            secret,
            transfer_count,
        }
    }

    pub fn from_preimage(secret: BytesDigest, transfer_count: u64) -> Self {
        let mut preimage = Vec::new();

        let salt = injective_string_to_felt(NULLIFIER_SALT);
        let secret = digest_bytes_to_felts(secret);
        let transfer_count = u64_to_felts(transfer_count);

        preimage.extend(salt);
        preimage.extend(secret);
        preimage.extend(transfer_count);

        let inner_hash = Poseidon2Hash::hash_no_pad(&preimage).elements;
        let outer_hash = Poseidon2Hash::hash_no_pad(&inner_hash).elements;
        let hash = Digest::from(outer_hash);

        Self {
            hash,
            secret,
            transfer_count,
        }
    }
}

impl ByteCodec for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(*digest_felts_to_bytes(self.hash));
        bytes.extend(*digest_felts_to_bytes(self.secret));
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
        let hash = digest_bytes_to_felts(digest);
        offset += hash_size;

        // Deserialize secret
        let secret = slice[offset..offset + secret_size]
            .try_into()
            .map_err(|e| {
                anyhow::anyhow!("Failed to deserialize nullifier secret with error: {:?}", e)
            })?;
        let secret = digest_bytes_to_felts(secret);
        if secret.len() != SECRET_NUM_TARGETS {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for secret, got: {}",
                SECRET_NUM_TARGETS,
                secret.len()
            ));
        }

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
        let hash = elements[offset..offset + DIGEST_NUM_FIELD_ELEMENTS]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier hash"))?;
        offset += DIGEST_NUM_FIELD_ELEMENTS;

        // Deserialize secret
        let secret = elements[offset..offset + SECRET_NUM_TARGETS]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier secret"))?;
        offset += SECRET_NUM_TARGETS;

        // Deserialize funding_nonce
        let transfer_count = elements[offset..offset + TRANSFER_COUNT_NUM_TARGETS]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier transfer_count"))?;

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

impl CircuitFragment for Nullifier {
    type Targets = NullifierTargets;

    /// Builds a circuit that assert that nullifier was computed with `H(H(nullifier +
    /// extrinsic_index + secret))`
    fn circuit(
        &Self::Targets {
            hash,
            ref secret,
            ref transfer_count,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let mut preimage = Vec::new();
        let salt_felts = injective_string_to_felt(NULLIFIER_SALT);
        for &f in salt_felts.iter() {
            preimage.push(builder.constant(f));
        }
        preimage.extend(secret.elements.iter());
        preimage.extend(transfer_count);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(preimage);
        let computed_hash =
            builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(computed_hash, hash);
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
