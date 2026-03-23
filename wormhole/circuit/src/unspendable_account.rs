use alloc::vec::Vec;

use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon2::Poseidon2Hash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::inputs::CircuitInputs;
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
use zk_circuits_common::serialization::SAFE_DIGEST_NUM_FELTS;
use zk_circuits_common::utils::{
    digest_bytes_to_felts, digest_felts_to_bytes, injective_string_to_felt,
    safe_digest_bytes_to_felts, safe_digest_felts_to_bytes, BytesDigest, Digest,
};

/// Number of field elements for the secret (32 bytes with safe 4-bytes/felt encoding)
pub const SECRET_NUM_TARGETS: usize = SAFE_DIGEST_NUM_FELTS; // 8
/// Number of field elements for the preimage (salt 3 + secret 8)
pub const PREIMAGE_NUM_TARGETS: usize = 11;
pub const UNSPENDABLE_SALT: &str = "wormhole";

/// Type alias for the secret as a fixed-size array
pub type Secret = [F; SECRET_NUM_TARGETS];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnspendableAccount {
    pub account_id: Digest,
    /// Secret encoded with safe 4-bytes/felt encoding (8 field elements for 32 bytes)
    pub secret: Secret,
}

impl UnspendableAccount {
    pub fn new(account_id: BytesDigest, secret: BytesDigest) -> Self {
        let account_id = digest_bytes_to_felts(account_id);
        // Use safe encoding (4 bytes/felt) for collision resistance
        let secret = safe_digest_bytes_to_felts(secret);
        Self { account_id, secret }
    }

    pub fn from_secret(secret: BytesDigest) -> Self {
        // Use safe encoding (4 bytes/felt) for collision resistance
        let secret_felts = safe_digest_bytes_to_felts(secret);

        // Build preimage: salt + secret
        let mut preimage = Vec::new();
        preimage.extend(injective_string_to_felt(UNSPENDABLE_SALT));
        preimage.extend(&secret_felts);

        if preimage.len() != PREIMAGE_NUM_TARGETS {
            panic!(
                "Expected preimage to be {} field elements, got {}",
                PREIMAGE_NUM_TARGETS,
                preimage.len()
            );
        }

        // Hash twice to get the account id.
        let inner_hash = Poseidon2Hash::hash_no_pad(&preimage).elements;
        let outer_hash = Poseidon2Hash::hash_no_pad(&inner_hash).elements;
        let account_id = Digest::from(outer_hash);

        Self {
            account_id,
            secret: secret_felts,
        }
    }
}

impl ByteCodec for UnspendableAccount {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(*digest_felts_to_bytes(self.account_id));
        bytes.extend(*safe_digest_felts_to_bytes(self.secret));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let account_id_size = 32; // 4 field elements * 8 bytes
        let secret_size = 32; // 32 bytes for secret
        let total_size = account_id_size + secret_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for UnspendableAccount, got: {}",
                total_size,
                slice.len()
            ));
        }

        // Deserialize account_id
        let account_id_bytes: BytesDigest = slice[..account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        let account_id = digest_bytes_to_felts(account_id_bytes);

        // Deserialize secret (32 bytes -> 8 field elements)
        let secret_bytes: BytesDigest = slice[account_id_size..total_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account secret"))?;
        let secret = safe_digest_bytes_to_felts(secret_bytes);

        Ok(Self { account_id, secret })
    }
}

impl FieldElementCodec for UnspendableAccount {
    fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        elements.extend(self.account_id.to_vec());
        elements.extend(self.secret);
        elements
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        // Expected sizes
        let account_id_size = 4;
        let secret_size = SECRET_NUM_TARGETS; // 8
        let total_size = account_id_size + secret_size;

        if elements.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for UnspendableAccount, got: {}",
                total_size,
                elements.len()
            ));
        }

        // Deserialize account_id
        let account_id = elements[..account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;

        // Deserialize secret
        let secret: Secret = elements[account_id_size..total_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account secret"))?;

        Ok(Self { account_id, secret })
    }
}

impl From<&CircuitInputs> for UnspendableAccount {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(inputs.private.unspendable_account, inputs.private.secret)
    }
}

#[derive(Debug, Clone)]
pub struct UnspendableAccountTargets {
    pub account_id: HashOutTarget,
    /// Secret targets (8 field elements with safe 4-bytes/felt encoding)
    pub secret: [Target; SECRET_NUM_TARGETS],
}

impl UnspendableAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            account_id: builder.add_virtual_hash(),
            secret: builder
                .add_virtual_targets(SECRET_NUM_TARGETS)
                .try_into()
                .unwrap(),
        }
    }
}

impl CircuitFragment for UnspendableAccount {
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(
        &Self::Targets {
            account_id,
            ref secret,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let salt = injective_string_to_felt(UNSPENDABLE_SALT);
        let mut preimage = Vec::new();
        for felt in salt {
            preimage.push(builder.constant(felt));
        }
        preimage.extend(secret.iter().copied());

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(preimage.clone());
        let generated_account =
            builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(generated_account, account_id);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        // Unspendable account circuit values.
        pw.set_hash_target(targets.account_id, self.account_id.into())?;
        for (target, value) in targets.secret.iter().zip(self.secret.iter()) {
            pw.set_target(*target, *value)?;
        }

        Ok(())
    }
}

impl Default for UnspendableAccount {
    fn default() -> Self {
        let preimage =
            hex::decode("cd94df2e3c38a87f3e429b62af022dbe4363143811219d80037e8798b2ec9229")
                .unwrap();
        let preimage = preimage[..32]
            .try_into()
            .expect("Expected 32 bytes for preimage");
        Self::from_secret(preimage)
    }
}
