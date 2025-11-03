use crate::storage_proof::{TestInputs, DEFAULT_ROOT_HASH};
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
    nullifier::Nullifier,
    storage_proof::ProcessedStorageProof,
    unspendable_account::UnspendableAccount,
};
use zk_circuits_common::utils::BytesDigest;

pub const DEFAULT_SECRET: &str = "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05";
pub const DEFAULT_TRANSFER_COUNT: u64 = 4;
pub const DEFAULT_FUNDING_ACCOUNT: [u8; 32] = [
    226, 124, 203, 9, 80, 60, 124, 205, 165, 5, 178, 216, 195, 15, 149, 38, 116, 1, 238, 133, 181,
    154, 106, 17, 41, 228, 118, 179, 82, 141, 225, 76,
];
pub const DEFAULT_FUNDING_AMOUNT: u128 =
    u128::from_le_bytes([0, 16, 165, 212, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
pub const DEFAULT_TO_ACCOUNT: [u8; 32] = [
    162, 77, 187, 9, 249, 178, 185, 87, 194, 50, 198, 98, 179, 134, 179, 126, 123, 21, 247, 44, 50,
    216, 140, 243, 97, 177, 13, 94, 26, 255, 19, 170,
];
pub const DEFAULT_BLOCK_HASH: [u8; 32] = [
    162, 77, 187, 9, 249, 178, 185, 87, 194, 50, 198, 98, 179, 134, 179, 126, 123, 21, 247, 44, 50,
    216, 140, 243, 97, 177, 13, 94, 26, 255, 19, 170,
];

pub const DEFAULT_EXIT_ACCOUNT: [u8; 32] = [4u8; 32];

impl TestInputs for CircuitInputs {
    fn test_inputs() -> Self {
        let secret = hex::decode(DEFAULT_SECRET.trim()).unwrap();
        let root_hash: [u8; 32] = hex::decode(DEFAULT_ROOT_HASH.trim())
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
        let nullifier = Nullifier::from_preimage(&secret, DEFAULT_TRANSFER_COUNT)
            .hash
            .into();
        let secret: [u8; 32] = secret.try_into().expect("Expected 32 bytes for secret");
        let unspendable_account = UnspendableAccount::from_secret(&secret).account_id.into();
        let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();

        let storage_proof = ProcessedStorageProof::test_inputs();
        Self {
            public: PublicCircuitInputs {
                funding_amount: DEFAULT_FUNDING_AMOUNT,
                nullifier,
                exit_account,
                block_hash: BytesDigest::try_from(DEFAULT_BLOCK_HASH).unwrap(),
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                transfer_count: DEFAULT_TRANSFER_COUNT,
                funding_account,
                unspendable_account,
                block_header: wormhole_circuit::inputs::BlockHeaderInputs {
                    block_hash: BytesDigest::try_from(DEFAULT_BLOCK_HASH).unwrap(),
                    parent_hash: BytesDigest::try_from(DEFAULT_BLOCK_HASH).unwrap(), // TODO: use more sensible value
                    block_number: 1,
                    state_root: BytesDigest::try_from(root_hash).unwrap(),
                    extrinsics_root: BytesDigest::try_from(root_hash).unwrap(), // TODO: use more sensible value
                    digest_logs: [0u8; 72],
                },
            },
        }
    }
}

pub mod storage_proof {
    use crate::{
        DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_AMOUNT, DEFAULT_TO_ACCOUNT, DEFAULT_TRANSFER_COUNT,
    };
    use wormhole_circuit::storage_proof::{leaf::LeafInputs, ProcessedStorageProof, StorageProof};
    use zk_circuits_common::utils::BytesDigest;

    pub const DEFAULT_ROOT_HASH: &str =
        "5ffa2ab5b0db9883b22b1e5810932ea9d9eab1840730fd39ace71c26bb8d082d";

    pub const DEFAULT_STORAGE_PROOF: [&str; 7] = [
        "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000545576a55a3f69e109b776d252064d3c9bf2fd3a0cd0447c8d82ec12b0343f3a20000000000000000f3ed746dd90e0e2a0d3f8faf0b8a41d5fafd9edcbc88630e389f2db76dd44b7200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000e6f538f42cbc6e72d6a302a648da34c475bcfa104e7cb80625fcf3219bd12172200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb2000000000000000805a0b660043743ecac1396810e2c3664e5f6bd54890cfc4eb04d914a38a32ba2000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000003687179c5ce1cb12b50e50d421bcbdceb82ec583de7585fb7898e167108168b5",
        "000000000000002004100000000000002000000000000000508b02bea5f6ec0560cb2cbfda44d44ee4ea671f5f3cbb5d27b90e6afcafa1f32000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f003280000000000000200000000000000036eed7029a2181549ea0a84a554dd682b0184a06f1c56a53ebf70c127123252920000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b2000000000000000b5e25bb2727a369c7a991e657eb15e8a578a30b89088ba5cf5c588deaee3a9f5200000000000000016b14e363d6ed03d0f13adc683dab364d051a8394db2f605adfe69d0ef5dd78a",
        "000000000000002084000000000000002000000000000000c58635f106880ea6ac74b554a030a74e08587a15fe9cca1117415c1f086613e62000000000000000abf9dfa05f2adc8c6b9447a6dae41d898ac8d77d683c8fe8c9a563a0cd05e0d7",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc20085eb00000000000020000000000000007f6a20004a9e9c8534de8e4a017e3795c9d8a30e036108eb593d2ac31f6a34e42000000000000000baf5a768ed92d1ac1cead4bcee891151641cfb6b109c9b6075952a36e5808dfc20000000000000006e19211b4ff0a3feb43b34373129676d22378dfe1303191a96b34012713b65832000000000000000f6885f81a0d9ee08a3a67c4f2ef71a2ec725c8a9c79599eb975c2319e4aae5e920000000000000008d4b3c32ff1324fe3b7a05467e88e9f69b0df523bc3b6fbfdc888f06401bc9e72000000000000000ea72cebf4e99ec5a02713c47fa3198ea718fabce8eaf27707c3ec03eafa34174200000000000000077c5198a04b75c9795fe20a45d68df141ef53182a243c6102607da94ee03a9a82000000000000000ee55785e535fe32542b8b7f8537d8f921df34012c8f8dfd97087159ac05b99d1200000000000000013da88523a40420379a2776f484740dd9e78e858b11c7f43d5db16dc923b5e71",
        "0000000000000020a0000000000000002000000000000000439f73a9fe5a17162de32efd7abca06f0c880dc966613afdcf1ab350e1619c4a2000000000000000797b157cc18a8d60054cf9e008630ef8642b335fe0869a9796b5feb0f464ff4b",
        "3e0000000000003000e339aa4f999f6414fef6d1a1eae663e1cbc7ba7fe5fd365ea504b46241cddf0000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_INDICIES: [usize; 7] = [768, 48, 240, 48, 160, 128, 16];

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for ProcessedStorageProof {
        fn test_inputs() -> Self {
            let proof = DEFAULT_STORAGE_PROOF
                .map(|node| hex::decode(node).unwrap())
                .to_vec();
            let indices = DEFAULT_STORAGE_PROOF_INDICIES.to_vec();
            Self::new(proof, indices).unwrap()
        }
    }

    impl TestInputs for LeafInputs {
        fn test_inputs() -> Self {
            let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
            let to_account = BytesDigest::try_from(DEFAULT_TO_ACCOUNT).unwrap();
            LeafInputs::new(
                DEFAULT_TRANSFER_COUNT,
                funding_account,
                to_account,
                DEFAULT_FUNDING_AMOUNT,
            )
            .unwrap()
        }
    }

    impl TestInputs for StorageProof {
        fn test_inputs() -> Self {
            StorageProof::new(
                &ProcessedStorageProof::test_inputs(),
                default_root_hash(),
                LeafInputs::test_inputs(),
            )
        }
    }

    pub fn default_root_hash() -> [u8; 32] {
        hex::decode(DEFAULT_ROOT_HASH).unwrap().try_into().unwrap()
    }
}

pub mod nullifier {
    use crate::DEFAULT_TRANSFER_COUNT;

    use super::DEFAULT_SECRET;
    use wormhole_circuit::nullifier::Nullifier;

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for Nullifier {
        fn test_inputs() -> Self {
            let secret = hex::decode(DEFAULT_SECRET).unwrap();
            Self::from_preimage(secret.as_slice(), DEFAULT_TRANSFER_COUNT)
        }
    }
}
