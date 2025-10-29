use alloc::vec::Vec;
use core::mem::size_of;

use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::codec::FieldElementCodec;
use crate::{codec::ByteCodec, inputs::CircuitInputs};
use zk_circuits_common::circuit::{CircuitFragment, D, F};
use zk_circuits_common::utils::{
    digest_bytes_to_felts, digest_felts_to_bytes, injective_string_to_felt, BytesDigest, Digest,
};

pub const SECRET_NUM_TARGETS: usize = 8;
pub const PREIMAGE_NUM_TARGETS: usize = 10;
pub const UNSPENDABLE_SALT: &str = "wormhole";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnspendableAccount {
    pub account_id: Digest,
    pub secret: Digest,
}

impl UnspendableAccount {
    pub fn new(account_id: BytesDigest, secret: BytesDigest) -> Self {
        let account_id = digest_bytes_to_felts(account_id);
        let secret = digest_bytes_to_felts(secret);
        Self { account_id, secret }
    }

    pub fn from_secret(secret: BytesDigest) -> Self {
        // First, convert the preimage to its representation as field elements.
        let mut preimage = Vec::new();
        let secret_felts: Digest = digest_bytes_to_felts(secret);
        preimage.extend(injective_string_to_felt(UNSPENDABLE_SALT));
        preimage.extend(secret_felts);

        if preimage.len() != PREIMAGE_NUM_TARGETS {
            panic!(
                "Expected preimage to be 80 bytes (10 field elements), got {} field elements",
                preimage.len()
            );
        }

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        // println!("inner_hash: {:?}", hex::encode(felts_to_bytes(&inner_hash)));
        let outer_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
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
        bytes.extend(*digest_felts_to_bytes(self.secret));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let f_size = size_of::<F>(); // 8 bytes
        let account_id_size = 4 * f_size; // 4 field elements
        let secret_size = 4 * f_size; // 4 field elements
        let total_size = account_id_size + secret_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for UnspendableAccount, got: {}",
                total_size,
                slice.len()
            ));
        }

        let mut offset = 0;
        // Deserialize account_id
        let account_id_bytes: BytesDigest = slice[offset..offset + account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        let account_id = digest_bytes_to_felts(account_id_bytes);
        offset += account_id_size;

        // Deserialize secret
        let secret_bytes: BytesDigest = slice[offset..offset + secret_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account secret"))?;
        let secret = digest_bytes_to_felts(secret_bytes);

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
        let secret_size = 4;
        let total_size = account_id_size + secret_size;

        if elements.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for UnspendableAccount, got: {}",
                total_size,
                elements.len()
            ));
        }

        let mut offset = 0;
        // Deserialize account_id
        let account_id = elements[offset..offset + account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        offset += account_id_size;

        // Deserialize secret
        let secret = elements[offset..offset + secret_size]
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!(
                    "Failed to deserialize unspendable account secret, expected {} field elements",
                    SECRET_NUM_TARGETS
                )
            })?;

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
        preimage.push(builder.constant(salt[0]));
        preimage.push(builder.constant(salt[1]));
        preimage.extend(secret.elements.iter());

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let generated_account =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

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
