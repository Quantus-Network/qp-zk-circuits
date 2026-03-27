use alloc::vec::Vec;

use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon2::Poseidon2Hash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::inputs::CircuitInputs;
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::codec::{ByteCodec, FieldElementCodec};
use zk_circuits_common::utils::{
    bytes_to_digest, digest_to_bytes, string_to_felts, BytesDigest, Digest, POSEIDON2_OUTPUT,
};

/// Number of field elements for the secret (32 bytes with 8 bytes/felt encoding)
pub const SECRET_NUM_TARGETS: usize = POSEIDON2_OUTPUT; // 4
/// Number of field elements for the account ID (4 felts, 8 bytes/felt for hash output)
pub const ACCOUNT_ID_NUM_TARGETS: usize = POSEIDON2_OUTPUT; // 4
/// Number of field elements for the preimage (salt 3 + secret 4)
pub const PREIMAGE_NUM_TARGETS: usize = 7;
pub const UNSPENDABLE_SALT: &str = "wormhole";

/// Type alias for the secret as a fixed-size array (4 felts, 8 bytes/felt)
pub type Secret = [F; SECRET_NUM_TARGETS];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnspendableAccount {
    /// Account ID as 4 field elements (8 bytes/felt for hash output)
    pub account_id: Digest,
    /// Secret encoded as 4 field elements (8 bytes/felt for 32 bytes)
    pub secret: Secret,
}

impl UnspendableAccount {
    pub fn new(account_id: BytesDigest, secret: BytesDigest) -> Self {
        // Account ID uses 8 bytes/felt encoding (hash output)
        let account_id = bytes_to_digest(account_id);
        // Secret uses 8 bytes/felt encoding.
        let secret = bytes_to_digest(secret);
        Self { account_id, secret }
    }

    pub fn from_secret(secret: BytesDigest) -> Self {
        // Use 8 bytes/felt encoding for secrets.
        let secret_felts = bytes_to_digest(secret);

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
        bytes.extend(*digest_to_bytes(self.secret));
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

        // Deserialize secret (32 bytes -> 4 field elements, 8 bytes/felt)
        let secret_bytes: BytesDigest = slice[account_id_size..total_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account secret"))?;
        let secret = bytes_to_digest(secret_bytes);

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
        let secret_size = SECRET_NUM_TARGETS; // 4
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

        // Deserialize secret (4 field elements)
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
    pub account_id: HashOutTarget,
    /// Secret targets (4 field elements with 8 bytes/felt encoding)
    pub secret: HashOutTarget,
}

impl UnspendableAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            account_id: builder.add_virtual_hash(),
            secret: builder.add_virtual_hash(),
        }
    }
}

impl CircuitFragment for UnspendableAccount {
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `account_id` was generated from `H(H(salt+secret))`.
    ///
    /// The circuit computes the hash (4 felts) and directly compares with account_id (also 4 felts).
    fn circuit(
        Self::Targets { account_id, secret }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let salt = string_to_felts(UNSPENDABLE_SALT);
        let mut preimage = Vec::new();
        for felt in salt {
            preimage.push(builder.constant(felt));
        }
        preimage.extend(secret.elements.iter());

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
        pw.set_hash_target(targets.account_id, self.account_id.into())?;
        pw.set_hash_target(targets.secret, self.secret.into())?;

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
