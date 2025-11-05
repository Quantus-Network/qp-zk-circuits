use crate::storage_proof::{TestAggrInputs, TestInputs, DEFAULT_ROOT_HASHES};
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
    nullifier::Nullifier,
    storage_proof::ProcessedStorageProof,
    unspendable_account::UnspendableAccount,
};
use zk_circuits_common::utils::BytesDigest;

pub const DEFAULT_SECRETS: [&str; 2] = [
    "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05",
    "c6034553e5556630d24a593d2c92de9f1ede81d48f0fb3371764462cc3594b3f",
];
pub const DEFAULT_TRANSFER_COUNTS: [u64; 2] = [4, 98];
pub const DEFAULT_FUNDING_ACCOUNT: [u8; 32] = [
    226, 124, 203, 9, 80, 60, 124, 205, 165, 5, 178, 216, 195, 15, 149, 38, 116, 1, 238, 133, 181,
    154, 106, 17, 41, 228, 118, 179, 82, 141, 225, 76,
];
pub const DEFAULT_FUNDING_AMOUNTS: [u128; 2] = [
    u128::from_le_bytes([0, 16, 165, 212, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    3_000_000_000_000,
];
pub const DEFAULT_TO_ACCOUNTS: [[u8; 32]; 2] = [
    [
        77, 56, 171, 201, 89, 235, 126, 17, 82, 111, 214, 50, 199, 61, 71, 232, 148, 89, 114, 250,
        61, 156, 227, 214, 37, 50, 213, 243, 134, 53, 57, 147,
    ],
    [
        130, 19, 214, 46, 1, 4, 171, 227, 100, 130, 239, 38, 52, 110, 13, 92, 209, 215, 81, 27, 34,
        228, 176, 60, 119, 12, 162, 198, 135, 176, 237, 4,
    ],
];

pub const DEFAULT_EXIT_ACCOUNT: [u8; 32] = [4u8; 32];

impl TestInputs for CircuitInputs {
    fn test_inputs_0() -> Self {
        let secret = hex::decode(DEFAULT_SECRETS[0].trim()).unwrap()[..32]
            .try_into()
            .unwrap();
        let root_hash = hex::decode(DEFAULT_ROOT_HASHES[0].trim())
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
        let nullifier = Nullifier::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[0])
            .hash
            .into();
        let unspendable_account = UnspendableAccount::from_secret(secret).account_id.into();
        let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();

        let storage_proof = ProcessedStorageProof::test_inputs_0();
        Self {
            public: PublicCircuitInputs {
                funding_amount: DEFAULT_FUNDING_AMOUNTS[0],
                nullifier,
                root_hash,
                exit_account,
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                transfer_count: DEFAULT_TRANSFER_COUNTS[0],
                funding_account,
                unspendable_account,
            },
        }
    }
    fn test_inputs_1() -> Self {
        let secret = hex::decode(DEFAULT_SECRETS[1].trim()).unwrap()[..32]
            .try_into()
            .unwrap();
        let root_hash = hex::decode(DEFAULT_ROOT_HASHES[1].trim())
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
        let nullifier = Nullifier::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[1])
            .hash
            .into();
        let unspendable_account = UnspendableAccount::from_secret(secret).account_id.into();
        let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();

        let storage_proof = ProcessedStorageProof::test_inputs_1();
        Self {
            public: PublicCircuitInputs {
                funding_amount: DEFAULT_FUNDING_AMOUNTS[1],
                nullifier,
                root_hash,
                exit_account,
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                transfer_count: DEFAULT_TRANSFER_COUNTS[1],
                funding_account,
                unspendable_account,
            },
        }
    }
}

impl TestAggrInputs for CircuitInputs {
    fn test_aggr_inputs() -> Vec<Self> {
        vec![Self::test_inputs_0(), Self::test_inputs_1()]
    }
}

pub mod storage_proof {
    use crate::{
        DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_AMOUNTS, DEFAULT_TO_ACCOUNTS,
        DEFAULT_TRANSFER_COUNTS,
    };
    use wormhole_circuit::storage_proof::{leaf::LeafInputs, ProcessedStorageProof, StorageProof};
    use zk_circuits_common::utils::BytesDigest;

    pub const DEFAULT_ROOT_HASHES: [&str; 2] = [
        "24d6a3e3877cf86a5e17a32e3f269b70963fbaf4b050e04911cf11afa3b48350",
        "4d72d40b239bd3189d0b1b80b7271a7561e4944712709be94e43aaab31107ab3",
    ];

    pub const DEFAULT_STORAGE_PROOF_A: [&str; 7] = [
        "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000545576a55a3f69e109b776d252064d3c9bf2fd3a0cd0447c8d82ec12b0343f3a20000000000000000f3ed746dd90e0e2a0d3f8faf0b8a41d5fafd9edcbc88630e389f2db76dd44b7200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000e6f538f42cbc6e72d6a302a648da34c475bcfa104e7cb80625fcf3219bd12172200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb2000000000000000d549afac7285d8e774c1ae9fc95e7348bf41355780363b8fae5f9419d102ac862000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000003687179c5ce1cb12b50e50d421bcbdceb82ec583de7585fb7898e167108168b5",
        "0000000000000020041000000000000020000000000000002a16f39fcd5165bf697d302569b1e838cef46a64e15f811f947c2a6b047aeeef2000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f003280000000000000200000000000000036eed7029a2181549ea0a84a554dd682b0184a06f1c56a53ebf70c127123252920000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b2000000000000000d2638934a8676f8b13994c29d78ce6cc809564e9ba5ac5a4a5f634adb0b4e423200000000000000016b14e363d6ed03d0f13adc683dab364d051a8394db2f605adfe69d0ef5dd78a",
        "00000000000000208400000000000000200000000000000000beae231b99c3bca09ee083b2bf4093244a3067fd4b239066d34ab6bfd3e9d82000000000000000abf9dfa05f2adc8c6b9447a6dae41d898ac8d77d683c8fe8c9a563a0cd05e0d7",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc20085eb00000000000020000000000000007f6a20004a9e9c8534de8e4a017e3795c9d8a30e036108eb593d2ac31f6a34e42000000000000000712de6a897691616c2b9cc4c8a6e66aca771c611b2b987b0a8168ddd4fe0ac4520000000000000006e19211b4ff0a3feb43b34373129676d22378dfe1303191a96b34012713b65832000000000000000f6885f81a0d9ee08a3a67c4f2ef71a2ec725c8a9c79599eb975c2319e4aae5e920000000000000008d4b3c32ff1324fe3b7a05467e88e9f69b0df523bc3b6fbfdc888f06401bc9e72000000000000000ea72cebf4e99ec5a02713c47fa3198ea718fabce8eaf27707c3ec03eafa34174200000000000000077c5198a04b75c9795fe20a45d68df141ef53182a243c6102607da94ee03a9a82000000000000000ee55785e535fe32542b8b7f8537d8f921df34012c8f8dfd97087159ac05b99d1200000000000000013da88523a40420379a2776f484740dd9e78e858b11c7f43d5db16dc923b5e71",
        "0000000000000020a0000000000000002000000000000000439f73a9fe5a17162de32efd7abca06f0c880dc966613afdcf1ab350e1619c4a200000000000000061de6d1fa656bd270f0db73db8b31477b7a4b501cdcd7c406f478d722fc81178",
        "3e000000000000303c50f9414cfc1b9c306bb216b2d36e4b985fe968d1a2388979ead6583540b8780000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_B: [&str; 8] = [
        "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000ac6a84a91bbac6f4032f313867bad3934278d0a48577048b8d518449b523f6e42000000000000000a5d2b1dbcb9f9ff1ff5a45098e12a9df809321f01ead6a080bc4d964261ea2da200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000ce0ca8addb19134bcb10e995fdb9cc7bddf31d369b99e2d0c0a6f7a9ea8743f8200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb2000000000000000fde8143374b5dd076db014f535953955493b544303dfcd59c08738f9c4481eca2000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000009e15f4976458fbee3d53572af38975d14d8fcddfe85eaf1331f32eafc186dbad",
        "0000000000000020041000000000000020000000000000001e60dbb365bf4ece9ba5bb8d82c51a2a617a54a49072f52deb5894689bd4f0dd2000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f0032800000000000002000000000000000d39670f2339789b1a1e5181d4b84088f1ad8aaf6d246f395205e9558d0d3229720000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b200000000000000012577c7c42302b6478676f65e1559492fbbd8b42073254ec87d1c9910c4107ff2000000000000000450156a96af132f41fc3d7b50fc98bd68f02c3979ea5b71fe103a393550b69b4",
        "000000000000002084000000000000002000000000000000399b900bca37a7a593159a32404177eb6e9570f0d4c814af8bd2ccb68c69790d200000000000000028eebda41303bbdd9f64f5a36e1ce338b6bacdaee99fb13ee344c067365459b3",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc200ffff00000000000020000000000000004b88ce02ac1faba5b2fd624470a1c203c067f62de849f246e5039ce075e96cf22000000000000000e032dabc0f09448816726abb7f43ec45ec58f25599f5c2ba2e0dd5c49f12e2122000000000000000bd851a33bca19404ae47af9d6bcfb2189df8b56cc4e684f64820c9fae630f64f20000000000000009a56ffb735efe652461b349f58fb68e7792f20ff317ef50b9546c54750d4afe220000000000000007bca02ac7ad442b52521659481cb71150937d3a1b373812d93c42ba6f61d08b620000000000000001bb0a9f1463b2c4bd4f5fd931ff8b60582c2292e13b3bd6bf7137b747c4d047a2000000000000000214da76aa1acd14dfc7ac65578fbf91976a5a8cbcbaa11dcb9f5f7f00cfaf77e200000000000000040040912f654e112126648d3e4a84493366462f4c09ddc74a9ef015a23ca51f32000000000000000a82f374f0d22ae10918a4e6e25c25ccc4cf48afef9bf9d3e5d6a6426dc1b497220000000000000002ae11224ba1283fdf9cbe452ae96a8ad0d11a1548d1ab78c6280dd352f78340120000000000000009ced4f70bb27fa9a3139877096890c18564cc07c898c8df1e642e8a26bf6b17d20000000000000009a55e008e99a91d3c46127b8eb8a20b8f5ba929d77609123f8c34d5c01bad5f220000000000000002eb7037b85ebc0785d624f6ea715873e5660cda1952be86e1e8bb7d4fa64895620000000000000007ca0c44a771641ec63db9247b1da22c8f71e85ed2c9ceefd62586b0c3d0324bf20000000000000008acbdc0d2caaf91c1b7e4c9b4a3622e67b567635dca84c45ec8f3b8affeae15a2000000000000000215d046226927d7e48fdbdbecdb8d7a6f40ac25b40c1b60cf42e340452a2ad30",
        "0000000000000020aa300000000000002000000000000000a32275e334089f36b9250a40fd7669e84ae704ad376a6dc5829790756632398320000000000000000ac8aa5f0b702b72f3a5bb23828d8ea8aa9534ce4a93e116e12f3a7ee53c979e2000000000000000cd491ea089d3fc273f536ed0444ee448a2e5a844c620953b7dae0a977be1da4f2000000000000000531fc4cbb1e5ac724a6ac6e94f8cc2fd51b91d155cdb249ffdc70e9d1f7d9e73200000000000000094eb14a0f08d4705e1d0c647cef48a3abe9ca205d6e6dfbdd172220b2cef3e8c20000000000000005dad1fc1252b3886d4e118576149a3446db182ea07106d3f32633549f8b1fe6e",
        "00000000000000204080000000000000200000000000000030553150f5771378a7364e5780eef6c6a8cdb75474d4e9c66db6e05bb285c12620000000000000007ef6c95f5ccf1ee1834e5c7123ee918d619b05e1f26e53d50f6cc5d34ca7c06b",
        "3d00000000000030681ef17773d20b8078898e81a26afa017a66ef404081e25081667ec3d65452550000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_INDICIES_A: [usize; 7] = [768, 48, 240, 48, 160, 128, 16];
    pub const DEFAULT_STORAGE_PROOF_INDICIES_B: [usize; 8] = [768, 48, 240, 48, 720, 288, 48, 16];

    pub trait TestInputs {
        fn test_inputs_0() -> Self;
        fn test_inputs_1() -> Self;
    }

    pub trait TestAggrInputs {
        fn test_aggr_inputs() -> Vec<Self>
        where
            Self: Sized;
    }

    impl TestInputs for ProcessedStorageProof {
        fn test_inputs_0() -> Self {
            let proof = DEFAULT_STORAGE_PROOF_A
                .map(|node| hex::decode(node).unwrap())
                .to_vec();
            let indices = DEFAULT_STORAGE_PROOF_INDICIES_A.to_vec();
            Self::new(proof, indices).unwrap()
        }
        fn test_inputs_1() -> Self {
            let proof = DEFAULT_STORAGE_PROOF_B
                .map(|node| hex::decode(node).unwrap())
                .to_vec();
            let indices = DEFAULT_STORAGE_PROOF_INDICIES_B.to_vec();
            Self::new(proof, indices).unwrap()
        }
    }

    impl TestInputs for LeafInputs {
        fn test_inputs_0() -> Self {
            let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
            let to_account = BytesDigest::try_from(DEFAULT_TO_ACCOUNTS[0]).unwrap();
            LeafInputs::new(
                DEFAULT_TRANSFER_COUNTS[0],
                funding_account,
                to_account,
                DEFAULT_FUNDING_AMOUNTS[0],
            )
            .unwrap()
        }
        fn test_inputs_1() -> Self {
            let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
            let to_account = BytesDigest::try_from(DEFAULT_TO_ACCOUNTS[1]).unwrap();
            LeafInputs::new(
                DEFAULT_TRANSFER_COUNTS[1],
                funding_account,
                to_account,
                DEFAULT_FUNDING_AMOUNTS[1],
            )
            .unwrap()
        }
    }

    impl TestInputs for StorageProof {
        fn test_inputs_0() -> Self {
            StorageProof::new(
                &ProcessedStorageProof::test_inputs_0(),
                default_root_hash(),
                LeafInputs::test_inputs_0(),
            )
        }
        fn test_inputs_1() -> Self {
            StorageProof::new(
                &ProcessedStorageProof::test_inputs_1(),
                hex::decode(DEFAULT_ROOT_HASHES[1])
                    .unwrap()
                    .try_into()
                    .unwrap(),
                LeafInputs::test_inputs_1(),
            )
        }
    }

    pub fn default_root_hash() -> [u8; 32] {
        hex::decode(DEFAULT_ROOT_HASHES[0])
            .unwrap()
            .try_into()
            .unwrap()
    }
}

pub mod nullifier {
    use crate::DEFAULT_TRANSFER_COUNTS;

    use super::DEFAULT_SECRETS;
    use wormhole_circuit::nullifier::Nullifier;

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for Nullifier {
        fn test_inputs() -> Self {
            let secret = hex::decode(DEFAULT_SECRETS[0]).unwrap()[..32]
                .try_into()
                .unwrap();
            Self::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[0])
        }
    }
}
