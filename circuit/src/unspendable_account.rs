use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::{codec::ByteCodec, inputs::CircuitInputs};
use crate::{
    circuit::{CircuitFragment, Digest, D, F},
    codec::FieldElementCodec,
};
use crate::utils::{field_elements_to_bytes, slice_to_field_elements};

// FIXME: Adjust as needed.
pub const PREIMAGE_NUM_TARGETS: usize = 5;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UnspendableAccount {
    account_id: Digest,
}

impl UnspendableAccount {
    pub fn new(preimage: &[u8]) -> Self {
        // First, convert the preimage to its representation as field elements.
        let preimage = slice_to_field_elements(preimage);

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let account_id = PoseidonHash::hash_no_pad(&inner_hash).elements;

        Self { account_id }
    }
}

impl ByteCodec for UnspendableAccount {
    fn to_bytes(&self) -> Vec<u8> {
        field_elements_to_bytes(&self.account_id)
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let account_id = slice_to_field_elements(slice).try_into().map_err(|_| {
            anyhow::anyhow!("failed to deserialize bytes into unspendable account hash")
        })?;
        Ok(Self { account_id })
    }
}

impl FieldElementCodec for UnspendableAccount {
    fn to_field_elements(&self) -> Vec<F> {
        self.account_id.to_vec()
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        if elements.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 field elements for Unspendable Account, got: {}",
                elements.len()
            ));
        }

        let account_id = elements.try_into()?;
        Ok(Self { account_id })
    }
}

impl From<&CircuitInputs> for UnspendableAccount {
    fn from(inputs: &CircuitInputs) -> Self {
        inputs.private.unspendable_account
    }
}

#[derive(Debug, Clone)]
pub struct UnspendableAccountTargets {
    account_id: HashOutTarget,
    preimage: Vec<Target>,
}

impl UnspendableAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            account_id: builder.add_virtual_hash_public_input(),
            preimage: builder.add_virtual_targets(PREIMAGE_NUM_TARGETS),
        }
    }
}

#[derive(Debug)]
pub struct UnspendableAccountInputs {
    preimage: Vec<F>,
}

impl UnspendableAccountInputs {
    pub fn new(preimage: &[u8]) -> Self {
        let preimage = slice_to_field_elements(preimage);
        Self { preimage }
    }
}

impl CircuitFragment for UnspendableAccount {
    type PrivateInputs = UnspendableAccountInputs;
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(
        &Self::Targets {
            account_id,
            ref preimage,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
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
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        // Unspendable account circuit values.
        pw.set_hash_target(targets.account_id, self.account_id.into())?;
        for (i, element) in inputs.preimage.into_iter().enumerate() {
            pw.set_target(targets.preimage[i], element)?;
        }

        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use super::{UnspendableAccount, UnspendableAccountInputs};

    /// An array of preimages generated from the Resoncance Node with `./resonance-node key resonance --scheme wormhole`.
    pub const PREIMAGES: [&str; 5] = [
        "776f726d686f6c650908804f8983b91253f3b2e4d49b71afc8e2c707608d9ae456990fb21591037f",
        "776f726d686f6c65dc907058e510a6b2994569eead6bd4f91ad8b3b6052409a7bdddd9e704ba3192",
        "776f726d686f6c6563c2f38d8f60300633eb0322ce9638e4a3019d43bae1d5fd49da7270893d2c54",
        "776f726d686f6c6514f29ed6fa954a9fb82155cfb89d4531a8abc7b5dff92e98e1f1979a8a376bc8",
        "776f726d686f6c65858cfd1777d7e0374eb846e106df95d3d53f17c6e6db83674d2545d21fef4e11",
    ];

    /// An array of addresses generated from the Resoncance Node with `./resonance-node key resonance --scheme wormhole`.
    #[allow(dead_code)]
    pub const ADRESSES: [&str; 5] = [
        "7b434935e653afd2b20726488d155cd183114a3cc70fed3c120ef885a0e2145c",
        "c5ed765c4039d6e48fcf26c79165ee1d14d7bfcfa6e4ce6ac4352ab62e6f9cd5",
        "1e233db6f8797d35b34fcf5c419f77720a859492131803345f60f94ac3cd0964",
        "3842abc3876d47de27b2b0acb4da50ff13a3b24a08a5813afcb5135efaa5025a",
        "ecf980dda3fb801e29300dc86eece519f345b8e56edc0a9ae8c5598c82626ffa",
    ];

    impl Default for UnspendableAccount {
        fn default() -> Self {
            let preimage = hex::decode(PREIMAGES[0]).unwrap();
            Self::new(&preimage)
        }
    }

    impl Default for UnspendableAccountInputs {
        fn default() -> Self {
            let preimage = hex::decode(PREIMAGES[0]).unwrap();
            Self::new(&preimage)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};

    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };

    use super::{
        test_helpers::{ADRESSES, PREIMAGES},
        *,
    };

    fn run_test(
        unspendable_account: &UnspendableAccount,
        inputs: UnspendableAccountInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = UnspendableAccountTargets::new(&mut builder);
        UnspendableAccount::circuit(&targets, &mut builder);

        unspendable_account
            .fill_targets(&mut pw, targets, inputs)
            .unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_proof() {
        let unspendable_account = UnspendableAccount::default();
        let inputs = UnspendableAccountInputs::default();
        run_test(&unspendable_account, inputs).unwrap();
    }

    #[test]
    fn preimage_matches_right_address() {
        for (preimage, address) in PREIMAGES.iter().zip(ADRESSES) {
            let decoded_preimage = hex::decode(preimage).unwrap();
            let unspendable_account = UnspendableAccount::new(&decoded_preimage);
            let inputs = UnspendableAccountInputs::new(&decoded_preimage);

            let address = slice_to_field_elements(&hex::decode(address).unwrap());
            assert_eq!(unspendable_account.account_id.to_vec(), address);

            run_test(&unspendable_account, inputs).unwrap();
        }
    }

    #[test]
    fn preimage_does_not_match_wrong_address() {
        let (preimage, wrong_address) = (PREIMAGES[0], ADRESSES[1]);
        let decoded_preimage = hex::decode(preimage).unwrap();
        let mut unspendable_account = UnspendableAccount::new(&decoded_preimage);

        // Override the correct hash with the wrong one.
        let wrong_hash = slice_to_field_elements(&hex::decode(wrong_address).unwrap());
        unspendable_account.account_id = wrong_hash.try_into().unwrap();

        let inputs = UnspendableAccountInputs::new(&decoded_preimage);

        let result = run_test(&unspendable_account, inputs);
        assert!(result.is_err());
    }

    #[test]
    fn all_zero_preimage_is_valid_and_hashes() {
        let preimage_bytes = vec![0u8; 64];
        let account = UnspendableAccount::new(&preimage_bytes);
        assert!(!account.account_id.to_vec().iter().all(Field::is_zero));
    }

    #[test]
    fn unspendable_account_codec() {
        let account = UnspendableAccount {
            account_id: [
                F::from_noncanonical_u64(1),
                F::from_noncanonical_u64(2),
                F::from_noncanonical_u64(3),
                F::from_noncanonical_u64(4),
            ],
        };

        // Encode the account as field elements and compare.
        let field_elements = account.to_field_elements();
        assert_eq!(field_elements.len(), 4);
        assert_eq!(field_elements[0], F::from_noncanonical_u64(1));
        assert_eq!(field_elements[1], F::from_noncanonical_u64(2));
        assert_eq!(field_elements[2], F::from_noncanonical_u64(3));
        assert_eq!(field_elements[3], F::from_noncanonical_u64(4));

        // Decode the field elements back into an UnspendableAccount
        let recovered_account = UnspendableAccount::from_field_elements(&field_elements).unwrap();
        assert_eq!(account, recovered_account);
    }

    #[test]
    fn codec_invalid_length() {
        let invalid_elements = vec![F::from_noncanonical_u64(1), F::from_noncanonical_u64(2)];
        let recovered_account_result = UnspendableAccount::from_field_elements(&invalid_elements);

        assert!(recovered_account_result.is_err());
        assert_eq!(
            recovered_account_result.unwrap_err().to_string(),
            "Expected 4 field elements for Unspendable Account, got: 2"
        );
    }

    #[test]
    fn codec_empty_elements() {
        let empty_elements: Vec<F> = vec![];
        let recovered_account_result = UnspendableAccount::from_field_elements(&empty_elements);

        assert!(recovered_account_result.is_err());
        assert_eq!(
            recovered_account_result.unwrap_err().to_string(),
            "Expected 4 field elements for Unspendable Account, got: 0"
        );
    }
}
