use alloc::vec::Vec;

use plonky2::{
    hash::poseidon2::Poseidon2Hash,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::inputs::CircuitInputs;
use crate::substrate_account::AccountTargets;
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
use zk_circuits_common::utils::{
    bytes_to_digest, digest_to_bytes, digest_to_felts, felts_to_digest, string_to_felts,
    BytesDigest, Digest, INJECTIVE_DIGEST_NUM_FELTS, POSEIDON2_OUTPUT,
};

/// Number of field elements for the secret (32 bytes with 4 bytes/felt encoding)
pub const SECRET_NUM_TARGETS: usize = INJECTIVE_DIGEST_NUM_FELTS; // 8
/// Number of field elements for the account ID (4 felts, 8 bytes/felt for hash output)
pub const ACCOUNT_ID_NUM_TARGETS: usize = POSEIDON2_OUTPUT; // 4
/// Number of field elements for the preimage (salt 3 + secret 8)
pub const PREIMAGE_NUM_TARGETS: usize = 11;
pub const UNSPENDABLE_SALT: &str = "wormhole";

/// Type alias for the secret as a fixed-size array (8 felts, 4 bytes/felt)
pub type Secret = [F; SECRET_NUM_TARGETS];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnspendableAccount {
    /// Account ID as 4 field elements (8 bytes/felt for hash output)
    pub account_id: Digest,
    /// Secret encoded with 4 bytes/felt (8 field elements for 32 bytes)
    pub secret: Secret,
}

impl UnspendableAccount {
    pub fn new(account_id: BytesDigest, secret: BytesDigest) -> Self {
        // Account ID uses 8 bytes/felt encoding (hash output)
        let account_id = bytes_to_digest(account_id);
        // Secret uses 4 bytes/felt encoding for collision resistance
        let secret = digest_to_felts(secret);
        Self { account_id, secret }
    }

    pub fn from_secret(secret: BytesDigest) -> Self {
        // Use 4 bytes/felt encoding for collision resistance on secrets
        let secret_felts = digest_to_felts(secret);

        // Build preimage: salt + secret
        let mut preimage = Vec::new();
        preimage.extend(string_to_felts(UNSPENDABLE_SALT));
        preimage.extend(&secret_felts);

        if preimage.len() != PREIMAGE_NUM_TARGETS {
            panic!(
                "Expected preimage to be {} field elements, got {}",
                PREIMAGE_NUM_TARGETS,
                preimage.len()
            );
        }

        // Hash twice to get the account id hash (4 felts).
        let inner_hash = Poseidon2Hash::hash_no_pad(&preimage).elements;
        let outer_hash = Poseidon2Hash::hash_no_pad(&inner_hash).elements;

        Self {
            account_id: outer_hash,
            secret: secret_felts,
        }
    }
}

impl ByteCodec for UnspendableAccount {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(*digest_to_bytes(self.account_id));
        bytes.extend(*felts_to_digest(self.secret));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let account_id_size = 32; // 32 bytes for account ID
        let secret_size = 32; // 32 bytes for secret
        let total_size = account_id_size + secret_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for UnspendableAccount, got: {}",
                total_size,
                slice.len()
            ));
        }

        // Deserialize account_id (32 bytes -> 4 field elements, 8 bytes/felt)
        let account_id_bytes: BytesDigest = slice[..account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        let account_id = bytes_to_digest(account_id_bytes);

        // Deserialize secret (32 bytes -> 8 field elements, 4 bytes/felt)
        // Use new_unchecked because 4-bytes-per-felt encoding doesn't need 8-byte validation
        let secret_bytes: [u8; 32] = slice[account_id_size..total_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account secret"))?;
        let secret = digest_to_felts(BytesDigest::new_unchecked(secret_bytes));

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
        let account_id_size = ACCOUNT_ID_NUM_TARGETS; // 4
        let secret_size = SECRET_NUM_TARGETS; // 8
        let total_size = account_id_size + secret_size;

        if elements.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for UnspendableAccount, got: {}",
                total_size,
                elements.len()
            ));
        }

        // Deserialize account_id (4 field elements)
        let account_id: Digest = elements[..account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;

        // Deserialize secret (8 field elements)
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
    /// Account ID as 4 targets (8 bytes/felt for hash output)
    pub account_id: AccountTargets,
    /// Secret targets (8 field elements with 4 bytes/felt encoding)
    pub secret: [Target; SECRET_NUM_TARGETS],
}

impl UnspendableAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            account_id: AccountTargets::new(builder),
            secret: builder
                .add_virtual_targets(SECRET_NUM_TARGETS)
                .try_into()
                .unwrap(),
        }
    }
}

impl CircuitFragment for UnspendableAccount {
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `account_id` was generated from `H(H(salt+secret))`.
    ///
    /// The circuit computes the hash (4 felts) and directly compares with account_id (also 4 felts).
    fn circuit(
        &Self::Targets {
            ref account_id,
            ref secret,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let salt = string_to_felts(UNSPENDABLE_SALT);
        let mut preimage = Vec::new();
        for felt in salt {
            preimage.push(builder.constant(felt));
        }
        preimage.extend(secret.iter().copied());

        // Compute the hash by double-hashing the preimage (salt + secret).
        // Result is 4 field elements (HashOut).
        let inner_hash = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(preimage.clone());
        let outer_hash =
            builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(inner_hash.elements.to_vec());

        // Assert that the computed hash matches the provided account_id (both are 4 felts)
        for i in 0..4 {
            builder.connect(outer_hash.elements[i], account_id.elements[i]);
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        // Set account_id targets (4 field elements)
        pw.set_target_arr(&targets.account_id.elements, &self.account_id)?;

        // Set secret targets
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
