use alloc::vec::Vec;

use plonky2::{
    field::types::Field,
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
    digest_to_bytes, digest_to_felts, felts_to_digest, string_to_felts, AccountId, BytesDigest,
    Digest, DIGEST_NUM_FELTS,
};

/// Number of field elements for the secret (32 bytes with 4 bytes/felt encoding)
pub const SECRET_NUM_TARGETS: usize = DIGEST_NUM_FELTS; // 8
/// Number of field elements for the account ID (32 bytes with 4 bytes/felt encoding)
pub const ACCOUNT_ID_NUM_TARGETS: usize = DIGEST_NUM_FELTS; // 8
/// Number of field elements for the preimage (salt 3 + secret 8)
pub const PREIMAGE_NUM_TARGETS: usize = 11;
pub const UNSPENDABLE_SALT: &str = "wormhole";

/// Type alias for the secret as a fixed-size array
pub type Secret = [F; SECRET_NUM_TARGETS];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnspendableAccount {
    /// Account ID as 8 field elements (4 bytes/felt for 32 bytes total)
    pub account_id: AccountId,
    /// Secret encoded with 4 bytes/felt (8 field elements for 32 bytes)
    pub secret: Secret,
}

impl UnspendableAccount {
    pub fn new(account_id: BytesDigest, secret: BytesDigest) -> Self {
        // Account ID uses 4 bytes/felt encoding for collision resistance
        let account_id = digest_to_felts(account_id);
        // Secret also uses 4 bytes/felt encoding
        let secret = digest_to_felts(secret);
        Self { account_id, secret }
    }

    pub fn from_secret(secret: BytesDigest) -> Self {
        // Use 4 bytes/felt encoding for collision resistance
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
        let hash_digest = Digest::from(outer_hash);

        // Convert the 4-felt hash to bytes, then to 8-felt AccountId
        let account_bytes = digest_to_bytes(hash_digest);
        let account_id = digest_to_felts(account_bytes);

        Self {
            account_id,
            secret: secret_felts,
        }
    }
}

impl ByteCodec for UnspendableAccount {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(*felts_to_digest(self.account_id));
        bytes.extend(*felts_to_digest(self.secret));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let account_id_size = 32; // 8 field elements * 4 bytes
        let secret_size = 32; // 32 bytes for secret
        let total_size = account_id_size + secret_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for UnspendableAccount, got: {}",
                total_size,
                slice.len()
            ));
        }

        // Deserialize account_id (32 bytes -> 8 field elements)
        let account_id_bytes: BytesDigest = slice[..account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        let account_id = digest_to_felts(account_id_bytes);

        // Deserialize secret (32 bytes -> 8 field elements)
        let secret_bytes: BytesDigest = slice[account_id_size..total_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account secret"))?;
        let secret = digest_to_felts(secret_bytes);

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
        let account_id_size = ACCOUNT_ID_NUM_TARGETS; // 8
        let secret_size = SECRET_NUM_TARGETS; // 8
        let total_size = account_id_size + secret_size;

        if elements.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for UnspendableAccount, got: {}",
                total_size,
                elements.len()
            ));
        }

        // Deserialize account_id (8 field elements)
        let account_id: AccountId = elements[..account_id_size]
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
    /// Account ID as 8 targets (4 bytes/felt for 32 bytes total)
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
    /// The circuit computes the hash (4 felts), converts it to bytes, then to 8 felts for comparison.
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

        // Convert 4-felt hash to 8-felt account representation.
        // Each hash felt is up to 64 bits. We split it into two 32-bit felts.
        // For felt f: low = f & 0xFFFFFFFF, high = f >> 32
        let shift_32 = builder.constant(F::from_canonical_u64(1u64 << 32));

        let mut generated_account = Vec::with_capacity(8);
        for hash_felt in outer_hash.elements.iter() {
            // Split each 64-bit felt into two 32-bit felts
            // We use the split_low_high gadget pattern
            let low = builder.add_virtual_target();
            let high = builder.add_virtual_target();

            // Constrain: hash_felt = low + high * 2^32
            let reconstructed = builder.mul_add(high, shift_32, low);
            builder.connect(*hash_felt, reconstructed);

            // Range check both parts to 32 bits
            builder.range_check(low, 32);
            builder.range_check(high, 32);

            generated_account.push(low);
            generated_account.push(high);
        }

        // Assert that the generated account matches the provided account_id
        for (i, &gen) in generated_account.iter().enumerate() {
            builder.connect(gen, account_id.elements[i]);
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        // Set account_id targets (8 field elements)
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
