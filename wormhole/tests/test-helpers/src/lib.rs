use crate::{
    block_header::{
        DEFAULT_BLOCK_HASHES, DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS,
        DEFAULT_PARENT_HASHES,
    },
    storage_proof::DEFAULT_ROOT_HASHES,
};
use qp_wormhole_inputs::PublicCircuitInputs;
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs},
    nullifier::Nullifier,
    storage_proof::ProcessedStorageProof,
    unspendable_account::UnspendableAccount,
};
use zk_circuits_common::utils::{digest_to_bytes, felts_to_digest, BytesDigest};

pub const DEFAULT_SECRETS: [&str; 2] = [
    "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05",
    "c6034553e5556630d24a593d2c92de9f1ede81d48f0fb3371764462cc3594b3f",
];
pub const DEFAULT_TRANSFER_COUNTS: [u64; 2] = [4, 98];
pub const DEFAULT_FUNDING_ACCOUNT: [u8; 32] = [
    226, 124, 203, 9, 80, 60, 124, 205, 165, 5, 178, 216, 195, 15, 149, 38, 116, 1, 238, 133, 181,
    154, 106, 17, 41, 228, 118, 179, 82, 141, 225, 76,
];
pub const DEFAULT_INPUT_AMOUNTS: [u32; 2] = [100, 300];
/// Output amounts after 10 bps (0.1%) fee deduction: input - (input * 10 / 10000)
/// 100 - (100 * 10 / 10000) = 100 - 0 = 100 (due to integer division)
/// 300 - (300 * 10 / 10000) = 300 - 0 = 300 (due to integer division)
/// For test purposes, we use slightly lower values to ensure the constraint passes
pub const DEFAULT_OUTPUT_AMOUNTS: [u32; 2] = [99, 297];
pub const DEFAULT_VOLUME_FEE_BPS: u32 = 10; // 0.1% = 10 basis points
pub const DEFAULT_TO_ACCOUNTS: [[u8; 32]; 2] = [
    [
        132, 190, 89, 179, 137, 243, 32, 198, 43, 124, 242, 224, 64, 29, 243, 15, 153, 81, 175,
        132, 48, 22, 200, 111, 46, 63, 6, 143, 249, 158, 3, 141,
    ],
    [
        12, 135, 49, 71, 129, 117, 203, 171, 74, 78, 253, 177, 166, 11, 134, 215, 146, 242, 85,
        246, 153, 82, 43, 96, 143, 66, 238, 231, 188, 227, 66, 119,
    ],
];

pub const DEFAULT_EXIT_ACCOUNT: [u8; 32] = [4u8; 32];

pub trait TestInputs {
    fn test_inputs_0() -> Self;
    fn test_inputs_1() -> Self;
}

pub trait TestAggrInputs {
    fn test_aggr_inputs() -> Vec<Self>
    where
        Self: Sized;
}

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
        let nullifier =
            digest_to_bytes(Nullifier::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[0]).hash);
        let unspendable_account =
            felts_to_digest(UnspendableAccount::from_secret(secret).account_id);
        let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();

        let storage_proof = ProcessedStorageProof::test_inputs_0();
        Self {
            public: PublicCircuitInputs {
                asset_id: 0u32,
                output_amount_1: DEFAULT_OUTPUT_AMOUNTS[0],
                output_amount_2: 0u32, // No second output for tests
                volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
                nullifier,
                exit_account_1: exit_account,
                exit_account_2: BytesDigest::default(), // No second exit account
                block_hash: BytesDigest::try_from(DEFAULT_BLOCK_HASHES[0]).unwrap(),
                block_number: DEFAULT_BLOCK_NUMBERS[0],
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                transfer_count: DEFAULT_TRANSFER_COUNTS[0],
                funding_account,
                unspendable_account,
                parent_hash: BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).unwrap(),
                state_root: root_hash,
                extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
                digest: DEFAULT_DIGESTS[0],
                input_amount: DEFAULT_INPUT_AMOUNTS[0],
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
        let nullifier =
            digest_to_bytes(Nullifier::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[1]).hash);
        let unspendable_account =
            felts_to_digest(UnspendableAccount::from_secret(secret).account_id);
        let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();

        let storage_proof = ProcessedStorageProof::test_inputs_1();
        Self {
            public: PublicCircuitInputs {
                asset_id: 0u32,
                output_amount_1: DEFAULT_OUTPUT_AMOUNTS[1],
                output_amount_2: 0u32, // No second output for tests
                volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
                nullifier,
                exit_account_1: exit_account,
                exit_account_2: BytesDigest::default(), // No second exit account
                block_hash: BytesDigest::try_from(DEFAULT_BLOCK_HASHES[1]).unwrap(),
                block_number: DEFAULT_BLOCK_NUMBERS[1],
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                transfer_count: DEFAULT_TRANSFER_COUNTS[1],
                funding_account,
                unspendable_account,
                parent_hash: BytesDigest::try_from(DEFAULT_PARENT_HASHES[1]).unwrap(),
                state_root: root_hash,
                extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[1].try_into().unwrap(),
                digest: DEFAULT_DIGESTS[1],
                input_amount: DEFAULT_INPUT_AMOUNTS[1],
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
        TestInputs, DEFAULT_FUNDING_ACCOUNT, DEFAULT_INPUT_AMOUNTS, DEFAULT_OUTPUT_AMOUNTS,
        DEFAULT_TO_ACCOUNTS, DEFAULT_TRANSFER_COUNTS, DEFAULT_VOLUME_FEE_BPS,
    };
    use wormhole_circuit::storage_proof::{leaf::LeafInputs, ProcessedStorageProof, StorageProof};
    use zk_circuits_common::utils::BytesDigest;

    pub const DEFAULT_ROOT_HASHES: [&str; 2] = [
        "6e2ebcaa45aaf6620ad75507385e1ecf215e6169302508030dca8541ad438fce",
        "26b4f1f2ee982816f66fe6bbd433f17183f095ee36f906f93276f022baca85c4",
    ];

    pub const DEFAULT_STORAGE_PROOF_A: [&str; 8] = [
    "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000545576a55a3f69e109b776d252064d3c9bf2fd3a0cd0447c8d82ec12b0343f3a20000000000000000f3ed746dd90e0e2a0d3f8faf0b8a41d5fafd9edcbc88630e389f2db76dd44b7200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000e6f538f42cbc6e72d6a302a648da34c475bcfa104e7cb80625fcf3219bd12172200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb20000000000000003f508b9b27e3018ee7ed66d2eb6a93cf40d15be850fed046292dfbaadb8ca9a32000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000003687179c5ce1cb12b50e50d421bcbdceb82ec583de7585fb7898e167108168b5",
    "0000000000000020041000000000000020000000000000002df0551ab4f710eb94f378870fb84fc418702453f37f0f14abbb6e90a9682ff42000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
    "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f003280000000000000200000000000000036eed7029a2181549ea0a84a554dd682b0184a06f1c56a53ebf70c127123252920000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b2000000000000000188d5e69e1721141f7a9c6ccad3e60110dd1447238ac9635397668e061f2a6f2200000000000000016b14e363d6ed03d0f13adc683dab364d051a8394db2f605adfe69d0ef5dd78a",
    "0000000000000020840000000000000020000000000000004e8c8e37a72a686981005fa425f427b66369f7dbbb2a1fff265c2b52780e43752000000000000000abf9dfa05f2adc8c6b9447a6dae41d898ac8d77d683c8fe8c9a563a0cd05e0d7",
    "1e00000000000020857e7ea49e785c4e3e1f77a710cfc20085eb00000000000020000000000000007f6a20004a9e9c8534de8e4a017e3795c9d8a30e036108eb593d2ac31f6a34e420000000000000006d929b460a8e8b2b2b38b7ed45a745d2da0445e940dc24123e9d0dd4f0572fd720000000000000006e19211b4ff0a3feb43b34373129676d22378dfe1303191a96b34012713b65832000000000000000f6885f81a0d9ee08a3a67c4f2ef71a2ec725c8a9c79599eb975c2319e4aae5e920000000000000008d4b3c32ff1324fe3b7a05467e88e9f69b0df523bc3b6fbfdc888f06401bc9e72000000000000000ea72cebf4e99ec5a02713c47fa3198ea718fabce8eaf27707c3ec03eafa34174200000000000000077c5198a04b75c9795fe20a45d68df141ef53182a243c6102607da94ee03a9a82000000000000000ee55785e535fe32542b8b7f8537d8f921df34012c8f8dfd97087159ac05b99d1200000000000000013da88523a40420379a2776f484740dd9e78e858b11c7f43d5db16dc923b5e71",
    "0000000000000020a0000000000000002000000000000000439f73a9fe5a17162de32efd7abca06f0c880dc966613afdcf1ab350e1619c4a2000000000000000866d47a6d43d7bfec4663b06da94836aedcc2db1705fdaf5e31e39152b9f4d5f",
    "3e000000000000508b3a02b44f5f6e050e50cf82f9c25f3f30ad6504cc8adb1894b10d83d529cc340000000000000000",
    "23013e6c628286e65002f9dcef33e34306b73b17e1ee95e1f8a9b75c5baa0215",
];
    pub const DEFAULT_STORAGE_PROOF_B: [&str; 9] = [
    "0000000000000020bfb500000000000020000000000000005d7c4eb0b2a8bb01872f88950f8c736fc72a250c32b4bdad9a50e7b5163a27aa20000000000000008f6440ed6cd23d75bfdd64b70ec7b0c969bd03e53f9fc1df688f8538dad89f402000000000000000ac6a84a91bbac6f4032f313867bad3934278d0a48577048b8d518449b523f6e42000000000000000a5d2b1dbcb9f9ff1ff5a45098e12a9df809321f01ead6a080bc4d964261ea2da200000000000000091c3eead5530405e48b8df6453a60be878eb1fa46c2a95638cdec8c8d722b46020000000000000008475575039b5b19da2901935792d5b1d5f9a09e08065e4d27a438329710120002000000000000000ce0ca8addb19134bcb10e995fdb9cc7bddf31d369b99e2d0c0a6f7a9ea8743f8200000000000000056c6d22ef15fbb6005782db4c357b38cb53f5d39e5d8abdb3efffaec0537381420000000000000007f7b9a72037f9305f49bb2c25aa2f2c0108753ae606e1f094e887071e2596cfb2000000000000000f5e3ed0d91f32c34c27c213426ce9156599f160e43b4f57a50a0749405afad1b2000000000000000a22c86fb54dbd5c704fc4d849c715109d7cb3167b0eb2ed270ca658bd9dcca2a20000000000000009e15f4976458fbee3d53572af38975d14d8fcddfe85eaf1331f32eafc186dbad",
    "00000000000000200410000000000000200000000000000019d8790e28c101b4e72cfde2ac4ff28abf6da98d62864bfba08043ecada1471d2000000000000000b7361080961b2d3b348d96affbf10c7ee2d6416efa14b524289e264863a270b6",
    "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f0032800000000000002000000000000000d39670f2339789b1a1e5181d4b84088f1ad8aaf6d246f395205e9558d0d3229720000000000000001961560d112cfd667e09610793793d3fc2ee32eb87171773c2e4c6e1473f400b20000000000000002f15ad660053b0c58300bd2b8d91841398797ea2ee03469e69d517fe0b46fbf32000000000000000450156a96af132f41fc3d7b50fc98bd68f02c3979ea5b71fe103a393550b69b4",
    "000000000000002084000000000000002000000000000000662965c9d81e69638d292573ed293e9229362fa8443efd3c5b1e91e74376a947200000000000000028eebda41303bbdd9f64f5a36e1ce338b6bacdaee99fb13ee344c067365459b3",
    "1e00000000000020857e7ea49e785c4e3e1f77a710cfc200ffff00000000000020000000000000004b88ce02ac1faba5b2fd624470a1c203c067f62de849f246e5039ce075e96cf22000000000000000e032dabc0f09448816726abb7f43ec45ec58f25599f5c2ba2e0dd5c49f12e2122000000000000000bd851a33bca19404ae47af9d6bcfb2189df8b56cc4e684f64820c9fae630f64f20000000000000009a56ffb735efe652461b349f58fb68e7792f20ff317ef50b9546c54750d4afe220000000000000007bca02ac7ad442b52521659481cb71150937d3a1b373812d93c42ba6f61d08b620000000000000001bb0a9f1463b2c4bd4f5fd931ff8b60582c2292e13b3bd6bf7137b747c4d047a2000000000000000214da76aa1acd14dfc7ac65578fbf91976a5a8cbcbaa11dcb9f5f7f00cfaf77e200000000000000040040912f654e112126648d3e4a84493366462f4c09ddc74a9ef015a23ca51f3200000000000000092b00cd6b7f1071eabb65d76df0cb805bd250a0fde5904093d3ce974c9d712a120000000000000002ae11224ba1283fdf9cbe452ae96a8ad0d11a1548d1ab78c6280dd352f78340120000000000000009ced4f70bb27fa9a3139877096890c18564cc07c898c8df1e642e8a26bf6b17d20000000000000009a55e008e99a91d3c46127b8eb8a20b8f5ba929d77609123f8c34d5c01bad5f220000000000000002eb7037b85ebc0785d624f6ea715873e5660cda1952be86e1e8bb7d4fa64895620000000000000007ca0c44a771641ec63db9247b1da22c8f71e85ed2c9ceefd62586b0c3d0324bf20000000000000008acbdc0d2caaf91c1b7e4c9b4a3622e67b567635dca84c45ec8f3b8affeae15a2000000000000000215d046226927d7e48fdbdbecdb8d7a6f40ac25b40c1b60cf42e340452a2ad30",
    "0000000000000020aa300000000000002000000000000000a32275e334089f36b9250a40fd7669e84ae704ad376a6dc5829790756632398320000000000000000ac8aa5f0b702b72f3a5bb23828d8ea8aa9534ce4a93e116e12f3a7ee53c979e2000000000000000cd491ea089d3fc273f536ed0444ee448a2e5a844c620953b7dae0a977be1da4f20000000000000000f3da473555a11a97462c1bcec9064c14123de8a4cf7db8ba02bc0d50219922c200000000000000094eb14a0f08d4705e1d0c647cef48a3abe9ca205d6e6dfbdd172220b2cef3e8c20000000000000005dad1fc1252b3886d4e118576149a3446db182ea07106d3f32633549f8b1fe6e",
    "000000000000002040800000000000002000000000000000422de3e2aec1d9c58493b030ed810e2f7351afadefdfb662010487d04f37fdb720000000000000007ef6c95f5ccf1ee1834e5c7123ee918d619b05e1f26e53d50f6cc5d34ca7c06b",
    "3d00000000000050270fe7d11983c9e9c72c5c50179a0e695464335d8cc3ee02d0309c2a5b20c0fb0000000000000000",
    "7ce9b029e6261f279a910b83ae0584a3f6a95c7c6344cc8ec49f259e07acbfb2",
];
    pub const DEFAULT_STORAGE_PROOF_INDICIES_A: [usize; 7] = [768, 48, 240, 48, 160, 128, 16];
    pub const DEFAULT_STORAGE_PROOF_INDICIES_B: [usize; 8] = [768, 48, 240, 48, 720, 288, 48, 16];

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
                0u32,
                DEFAULT_TRANSFER_COUNTS[0],
                funding_account,
                to_account,
                DEFAULT_INPUT_AMOUNTS[0],
                DEFAULT_OUTPUT_AMOUNTS[0],
                0u32, // No second output for tests
                DEFAULT_VOLUME_FEE_BPS,
            )
            .unwrap()
        }
        fn test_inputs_1() -> Self {
            let funding_account = BytesDigest::try_from(DEFAULT_FUNDING_ACCOUNT).unwrap();
            let to_account = BytesDigest::try_from(DEFAULT_TO_ACCOUNTS[1]).unwrap();
            LeafInputs::new(
                0u32,
                DEFAULT_TRANSFER_COUNTS[1],
                funding_account,
                to_account,
                DEFAULT_INPUT_AMOUNTS[1],
                DEFAULT_OUTPUT_AMOUNTS[1],
                0u32, // No second output for tests
                DEFAULT_VOLUME_FEE_BPS,
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
                true,
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
                true,
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

pub mod block_header {
    use crate::TestInputs;
    use wormhole_circuit::block_header::{header::HeaderInputs, BlockHeader};
    use zk_circuits_common::utils::BytesDigest;

    use crate::storage_proof::{default_root_hash, DEFAULT_ROOT_HASHES};

    pub const DEFAULT_BLOCK_HASHES: [[u8; 32]; 2] = [
        [
            131, 173, 118, 20, 198, 40, 184, 35, 226, 208, 246, 118, 127, 37, 122, 13, 183, 16, 20,
            42, 25, 124, 143, 197, 162, 176, 220, 94, 220, 131, 1, 205,
        ],
        [
            94, 144, 71, 251, 246, 146, 143, 44, 104, 181, 162, 85, 50, 118, 180, 14, 246, 96, 248,
            165, 62, 28, 221, 143, 211, 205, 174, 11, 233, 83, 25, 113,
        ],
    ];

    pub const DEFAULT_PARENT_HASHES: [[u8; 32]; 2] = [
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            160, 247, 232, 22, 150, 117, 245, 140, 3, 70, 175, 175, 22, 247, 90, 37, 231, 80, 170,
            11, 27, 183, 40, 51, 5, 19, 164, 19, 188, 192, 229, 212,
        ],
    ];
    pub const DEFAULT_EXTRINSICS_ROOTS: [[u8; 32]; 2] = [
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
    ];
    pub const DEFAULT_DIGESTS: [[u8; 110]; 2] = [
        [
            8, 6, 112, 111, 119, 95, 128, 233, 182, 183, 107, 158, 1, 115, 19, 219, 126, 253, 86,
            30, 208, 176, 70, 21, 45, 180, 229, 9, 62, 91, 4, 6, 53, 245, 52, 48, 38, 123, 225, 5,
            112, 111, 119, 95, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 79, 226,
        ],
        [
            8, 6, 112, 111, 119, 95, 128, 233, 182, 183, 107, 158, 1, 115, 19, 219, 126, 253, 86,
            30, 208, 176, 70, 21, 45, 180, 229, 9, 62, 91, 4, 6, 53, 245, 52, 48, 38, 123, 225, 5,
            112, 111, 119, 95, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 79, 226,
        ],
    ];

    pub const DEFAULT_BLOCK_NUMBERS: [u32; 2] = [1, 2];

    impl TestInputs for HeaderInputs {
        fn test_inputs_0() -> Self {
            let parent_hash = BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).unwrap();
            HeaderInputs::new(
                parent_hash,
                DEFAULT_BLOCK_NUMBERS[0],
                default_root_hash().try_into().unwrap(),
                DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
                &DEFAULT_DIGESTS[0],
            )
            .unwrap()
        }
        fn test_inputs_1() -> Self {
            let parent_hash = BytesDigest::try_from(DEFAULT_PARENT_HASHES[1]).unwrap();
            HeaderInputs::new(
                parent_hash,
                DEFAULT_BLOCK_NUMBERS[1],
                hex::decode(DEFAULT_ROOT_HASHES[1])
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .unwrap(),
                DEFAULT_EXTRINSICS_ROOTS[1].try_into().unwrap(),
                &DEFAULT_DIGESTS[1],
            )
            .unwrap()
        }
    }

    impl TestInputs for BlockHeader {
        fn test_inputs_0() -> Self {
            let block_hash = BytesDigest::try_from(DEFAULT_BLOCK_HASHES[0]).unwrap();
            BlockHeader::new(block_hash, HeaderInputs::test_inputs_0()).unwrap()
        }
        fn test_inputs_1() -> Self {
            let block_hash = BytesDigest::try_from(DEFAULT_BLOCK_HASHES[1]).unwrap();
            BlockHeader::new(block_hash, HeaderInputs::test_inputs_1()).unwrap()
        }
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
#[cfg(test)]
mod fixture_updates {
    use anyhow::{anyhow, bail, Context, Result};
    use hex::{decode, encode};
    use wormhole_circuit::{block_header::header::HeaderInputs, storage_proof::leaf::LeafInputs};
    use zk_circuits_common::{storage_proof::hash_node_with_poseidon_padded, utils::BytesDigest};

    fn decode_hex_bytes(s: &str) -> Result<Vec<u8>> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if !s.len().is_multiple_of(2) {
            return Err(anyhow!("hex string has odd length: {}", s.len()));
        }
        Ok(decode(s).unwrap())
    }

    fn encode_hex_bytes(bytes: &[u8]) -> String {
        encode(bytes)
    }

    fn replace_digest_at_index(buf: &mut [u8], idx: usize, digest: &[u8]) -> Result<()> {
        let off = idx / 2; // We assume the index is a byte offset, but it might be a nibble offset.
        let end = off
            .checked_add(digest.len())
            .ok_or_else(|| anyhow!("index overflow"))?;
        if end > buf.len() {
            return Err(anyhow!(
                "digest write out of bounds: off={} len={} buf_len={}",
                off,
                digest.len(),
                buf.len()
            ));
        }
        buf[off..end].copy_from_slice(digest);
        Ok(())
    }

    fn rewrite_leaf_as_hashed_value_leaf(node: &mut [u8]) -> Result<()> {
        if node.len() < 8 {
            bail!("leaf node too short to contain a header");
        }

        let mut header = u64::from_le_bytes(node[0..8].try_into().unwrap());
        header &= !(0xFu64 << 60);
        header |= 5u64 << 60;
        node[0..8].copy_from_slice(&header.to_le_bytes());
        Ok(())
    }

    fn leaf_hash_for(leaf: &LeafInputs) -> BytesDigest {
        leaf.leaf_hash().try_into().unwrap()
    }

    fn process_proof(
        nodes_hex: &[&str],
        indices: &[usize],
        leaf_hash: &BytesDigest,
    ) -> Result<(Vec<String>, String)> {
        if nodes_hex.len() != indices.len() && nodes_hex.len() != indices.len() + 1 {
            bail!(
                "nodes/indices length mismatch: {} vs {}",
                nodes_hex.len(),
                indices.len()
            );
        }

        // Decode once
        let mut nodes_bytes: Vec<Vec<u8>> = nodes_hex
            .iter()
            .map(|s| decode_hex_bytes(s))
            .collect::<Result<_>>()?;

        let leaf_idx = indices
            .len()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("storage proof must contain at least one index"))?;
        let value_node = leaf_hash.as_ref().to_vec();
        let value_node_hash = hash_node_with_poseidon_padded(&value_node);

        // 1) Ensure the proof ends with a terminal 32-byte value node and that the leaf points to
        //    its hash.
        rewrite_leaf_as_hashed_value_leaf(&mut nodes_bytes[leaf_idx])
            .context("while converting leaf to hashed value leaf")?;
        replace_digest_at_index(
            &mut nodes_bytes[leaf_idx],
            indices[leaf_idx],
            value_node_hash.as_ref(),
        )
        .context("while patching value-node hash into leaf")?;

        if nodes_bytes.len() == indices.len() {
            nodes_bytes.push(value_node);
        } else {
            *nodes_bytes.last_mut().unwrap() = value_node;
        }

        // 2) Walk upward: hash(child_node) and patch that digest into the parent node.
        for i in (1..=leaf_idx).rev() {
            let child_digest = hash_node_with_poseidon_padded(&nodes_bytes[i]);
            replace_digest_at_index(
                &mut nodes_bytes[i - 1],
                indices[i - 1],
                child_digest.as_ref(),
            )
            .with_context(|| format!("while updating parent node {}", i - 1))?;
        }

        // 3) Root = hash(node[0])
        let root_digest = hash_node_with_poseidon_padded(&nodes_bytes[0]);
        let root_hex = encode_hex_bytes(root_digest.as_ref());

        // Re-encode all nodes to hex
        let updated_nodes_hex: Vec<String> =
            nodes_bytes.iter().map(|b| encode_hex_bytes(b)).collect();

        Ok((updated_nodes_hex, root_hex))
    }

    fn print_const_array(name: &str, items: &[String]) {
        println!("pub const {}: [&str; {}] = [", name, items.len());
        for s in items {
            println!("    \"{}\",", s);
        }
        println!("];\n");
    }

    #[test]
    fn regen_storage_proof_sample_data_and_roots_from_leaf_hash_update() -> Result<()> {
        use crate::block_header::{
            DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_PARENT_HASHES,
        };
        use crate::storage_proof::{
            DEFAULT_STORAGE_PROOF_A, DEFAULT_STORAGE_PROOF_B, DEFAULT_STORAGE_PROOF_INDICIES_A,
            DEFAULT_STORAGE_PROOF_INDICIES_B,
        };
        use crate::TestInputs;

        let leaf_a = LeafInputs::test_inputs_0();
        let leaf_b = LeafInputs::test_inputs_1();
        let leaf_hash_a = leaf_hash_for(&leaf_a);
        let leaf_hash_b = leaf_hash_for(&leaf_b);

        let (updated_a, root_a) = process_proof(
            &DEFAULT_STORAGE_PROOF_A,
            &DEFAULT_STORAGE_PROOF_INDICIES_A,
            &leaf_hash_a,
        )
        .context("processing proof A")?;

        let (updated_b, root_b) = process_proof(
            &DEFAULT_STORAGE_PROOF_B,
            &DEFAULT_STORAGE_PROOF_INDICIES_B,
            &leaf_hash_b,
        )
        .context("processing proof B")?;

        // Compute block hashes using the NEW root hashes
        let root_bytes_a: [u8; 32] = hex::decode(&root_a).unwrap().try_into().unwrap();
        let root_bytes_b: [u8; 32] = hex::decode(&root_b).unwrap().try_into().unwrap();

        let header_a = HeaderInputs::new(
            BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).unwrap(),
            DEFAULT_BLOCK_NUMBERS[0],
            BytesDigest::try_from(root_bytes_a).unwrap(),
            DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
            &DEFAULT_DIGESTS[0],
        )
        .unwrap();

        let header_b = HeaderInputs::new(
            BytesDigest::try_from(DEFAULT_PARENT_HASHES[1]).unwrap(),
            DEFAULT_BLOCK_NUMBERS[1],
            BytesDigest::try_from(root_bytes_b).unwrap(),
            DEFAULT_EXTRINSICS_ROOTS[1].try_into().unwrap(),
            &DEFAULT_DIGESTS[1],
        )
        .unwrap();

        let block_hash_a = header_a.block_hash();
        let block_hash_b = header_b.block_hash();

        // print the updated block hashes
        println!(
            "pub const DEFAULT_BLOCK_HASHES: [[u8; 32]; 2] = [\n    {:?},\n    {:?},\n];\n",
            block_hash_a.as_ref(),
            block_hash_b.as_ref()
        );

        print_const_array("DEFAULT_STORAGE_PROOF_A", &updated_a);
        print_const_array("DEFAULT_STORAGE_PROOF_B", &updated_b);

        println!(
            "pub const DEFAULT_ROOT_HASHES: [&str; 2] = [\"{}\", \"{}\"];",
            root_a, root_b
        );

        Ok(())
    }
}
