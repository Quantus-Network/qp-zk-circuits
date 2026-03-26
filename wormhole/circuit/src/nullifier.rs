use alloc::vec::Vec;
use core::array;
use core::mem::size_of;
use zk_circuits_common::utils::bytes_to_digest;
use zk_circuits_common::utils::digest_to_bytes;
use zk_circuits_common::utils::digest_to_felts;
use zk_circuits_common::utils::felts_to_digest;
use zk_circuits_common::utils::felts_to_u64;
use zk_circuits_common::utils::DIGEST_BYTES_LEN;
use zk_circuits_common::utils::FELTS_PER_U128;
use zk_circuits_common::utils::FELTS_PER_U64;
use zk_circuits_common::utils::INJECTIVE_DIGEST_NUM_FELTS;
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
/// Number of field elements for the secret (32 bytes with 4 bytes/felt encoding)
pub const SECRET_NUM_TARGETS: usize = INJECTIVE_DIGEST_NUM_FELTS; // 8
pub const SALT_NUM_TARGETS: usize = 3;
pub const FUNDING_ACCOUNT_NUM_TARGETS: usize = FELTS_PER_U128;
pub const TRANSFER_COUNT_NUM_TARGETS: usize = FELTS_PER_U64;
pub const PREIMAGE_NUM_TARGETS: usize =
    SECRET_NUM_TARGETS + SALT_NUM_TARGETS + FUNDING_ACCOUNT_NUM_TARGETS;
pub const NULLIFIER_SIZE_FELTS: usize =
    POSEIDON2_OUTPUT + SECRET_NUM_TARGETS + TRANSFER_COUNT_NUM_TARGETS;

/// Type alias for the secret as a fixed-size array (8 field elements for 32 bytes)
pub type Secret = [F; SECRET_NUM_TARGETS];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nullifier {
    pub hash: Digest,
    /// Secret encoded with 4 bytes/felt (8 field elements for 32 bytes)
    pub secret: Secret,
    transfer_count: [F; TRANSFER_COUNT_NUM_TARGETS],
}

impl Nullifier {
    pub fn new(digest: BytesDigest, secret: BytesDigest, transfer_count: u64) -> Self {
        let hash = bytes_to_digest(digest);
        // Use 4 bytes/felt encoding for collision resistance
        let secret = digest_to_felts(secret);
        let transfer_count = u64_to_felts(transfer_count);

        Self {
            hash,
            secret,
            transfer_count,
        }
    }

    pub fn from_preimage(secret: BytesDigest, transfer_count: u64) -> Self {
        let mut preimage = Vec::new();

        let salt = string_to_felts(NULLIFIER_SALT);
        // Use 4 bytes/felt encoding for collision resistance
        let secret_felts = digest_to_felts(secret);
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
        bytes.extend(*felts_to_digest(self.secret));
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

        // Deserialize secret (32 bytes -> 8 field elements)
        let secret_bytes: BytesDigest =
            slice[offset..offset + secret_size]
                .try_into()
                .map_err(|e| {
                    anyhow::anyhow!("Failed to deserialize nullifier secret with error: {:?}", e)
                })?;
        let secret = digest_to_felts(secret_bytes);
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

        // Deserialize secret (8 field elements)
        let secret: Secret = elements[offset..offset + SECRET_NUM_TARGETS]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize nullifier secret"))?;
        offset += SECRET_NUM_TARGETS;

        // Deserialize transfer_count
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
    /// Secret targets (8 field elements with 4 bytes/felt encoding)
    pub secret: [Target; SECRET_NUM_TARGETS],
    pub transfer_count: [Target; TRANSFER_COUNT_NUM_TARGETS],
}

impl NullifierTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            hash: builder.add_virtual_hash_public_input(),
            secret: builder
                .add_virtual_targets(SECRET_NUM_TARGETS)
                .try_into()
                .unwrap(),
            transfer_count: array::from_fn(|_| builder.add_virtual_target()),
        }
    }
}

impl CircuitFragment for Nullifier {
    type Targets = NullifierTargets;

    /// Builds nullifier targets but does NOT enforce hash validation here.
    /// The nullifier hash validation is made conditional on block_hash != 0
    /// in `connect_shared_targets()` to allow dummy proofs to use random nullifiers.
    fn circuit(
        &Self::Targets {
            hash: _,
            secret: _,
            transfer_count: _,
        }: &Self::Targets,
        _builder: &mut CircuitBuilder<F, D>,
    ) {
        // NOTE: Nullifier hash validation (nullifier == H(H(salt + secret + transfer_count)))
        // is enforced conditionally in connect_shared_targets() based on block_hash != 0.
        // This allows dummy proofs to use random nullifiers for better privacy.
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(targets.hash, self.hash.into())?;
        for (target, value) in targets.secret.iter().zip(self.secret.iter()) {
            pw.set_target(*target, *value)?;
        }
        pw.set_target_arr(&targets.transfer_count, &self.transfer_count)?;
        Ok(())
    }
}

/// Adds unconditional nullifier hash validation: hash == H(H(salt + secret + transfer_count)).
/// Use this for isolated testing of Nullifier. The full WormholeCircuit uses
/// a conditional version in connect_shared_targets() to support dummy proofs.
pub fn add_nullifier_validation(targets: &NullifierTargets, builder: &mut CircuitBuilder<F, D>) {
    use plonky2::hash::poseidon2::Poseidon2Hash;
    use zk_circuits_common::utils::string_to_felts;

    let salt_felts = string_to_felts(NULLIFIER_SALT);
    let mut nullifier_preimage = Vec::new();
    for &f in salt_felts.iter() {
        nullifier_preimage.push(builder.constant(f));
    }
    nullifier_preimage.extend(targets.secret.iter().copied());
    nullifier_preimage.extend(targets.transfer_count.iter());

    let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(nullifier_preimage);
    let computed_nullifier =
        builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec());

    builder.connect_hashes(targets.hash, computed_nullifier);
}
