use crate::block_header::{
    DEFAULT_BLOCK_NUMBERS, DEFAULT_DIGESTS, DEFAULT_EXTRINSICS_ROOTS, DEFAULT_STATE_ROOTS,
};
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::plonk::config::Hasher;
use qp_wormhole_inputs::PublicCircuitInputs;
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs},
    nullifier::Nullifier,
    unspendable_account::UnspendableAccount,
};
use zk_circuits_common::serialization::{bytes_to_digest, digest_to_bytes as serialize_digest};
use zk_circuits_common::utils::{digest_to_bytes, u64_to_felts, BytesDigest};
use zk_circuits_common::zk_merkle::SIBLINGS_PER_LEVEL;

pub const DEFAULT_SECRETS: [&str; 2] = [
    "4c8587bd422e01d961acdc75e7d66f6761b7af7c9b1864a492f369c9d6724f05",
    "c6034553e5556630d24a593d2c92de9f1ede81d48f0fb3371764462cc3594b3f",
];
pub const DEFAULT_TRANSFER_COUNTS: [u64; 2] = [4, 98];
pub const DEFAULT_INPUT_AMOUNTS: [u32; 2] = [100, 300];
/// Output amounts after 10 bps (0.1%) fee deduction: input - (input * 10 / 10000)
/// 100 - (100 * 10 / 10000) = 100 - 0 = 100 (due to integer division)
/// 300 - (300 * 10 / 10000) = 300 - 0 = 300 (due to integer division)
/// For test purposes, we use slightly lower values to ensure the constraint passes
pub const DEFAULT_OUTPUT_AMOUNTS: [u32; 2] = [99, 297];
pub const DEFAULT_VOLUME_FEE_BPS: u32 = 10; // 0.1% = 10 basis points

pub const DEFAULT_EXIT_ACCOUNT: [u8; 32] = [4u8; 32];

/// Compute the ZK leaf hash for a given set of leaf data.
///
/// The leaf preimage is: (to_account, transfer_count, asset_id, input_amount)
/// where:
/// - to_account: 4 felts (8 bytes/felt) from the unspendable account
/// - transfer_count: 2 felts (32-bit limbs of u64)
/// - asset_id: 1 felt
/// - input_amount: 1 felt
///
/// This must match the circuit's leaf hash computation.
pub fn compute_zk_leaf_hash(
    to_account: &[u8; 32],
    transfer_count: u64,
    asset_id: u32,
    input_amount: u32,
) -> [u8; 32] {
    use plonky2::field::types::Field;
    use zk_circuits_common::circuit::F;

    // Convert to_account to 4 felts (8 bytes/felt)
    let to_account_felts = bytes_to_digest(to_account);

    // Convert transfer_count to 2 felts
    let transfer_count_felts = u64_to_felts(transfer_count);

    // Build the preimage
    let mut preimage = Vec::new();
    preimage.extend(to_account_felts);
    preimage.extend(transfer_count_felts);
    preimage.push(F::from_canonical_u32(asset_id));
    preimage.push(F::from_canonical_u32(input_amount));

    // Hash with Poseidon2
    let hash = Poseidon2Hash::hash_no_pad(&preimage);

    // Convert back to bytes
    serialize_digest(&hash.elements)
}

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
    /// Creates test inputs with a valid single-leaf ZK Merkle proof (depth 0).
    ///
    /// For a depth-0 tree, the leaf hash IS the root (no siblings needed).
    /// The circuit computes: leaf_hash = H(to_account || transfer_count || asset_id || input_amount)
    /// and verifies it matches the provided root.
    ///
    /// Uses dummy proof mode (block_hash=0, outputs=0) to bypass block header and
    /// nullifier hash validation, but the ZK Merkle proof and unspendable account
    /// constraints are still verified.
    fn test_inputs_0() -> Self {
        let secret: BytesDigest = hex::decode(DEFAULT_SECRETS[0].trim()).unwrap()[..32]
            .try_into()
            .unwrap();

        let nullifier =
            digest_to_bytes(Nullifier::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[0]).hash);
        let unspendable_account_digest = UnspendableAccount::from_secret(secret).account_id;
        let unspendable_account = digest_to_bytes(unspendable_account_digest);
        let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();

        // Compute the ZK leaf hash for a single-leaf tree (depth 0)
        // For depth 0, the leaf hash IS the root
        let zk_tree_root = compute_zk_leaf_hash(
            &unspendable_account,
            DEFAULT_TRANSFER_COUNTS[0],
            0u32, // asset_id
            DEFAULT_INPUT_AMOUNTS[0],
        );
        let zk_merkle_siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]> = vec![]; // Empty for depth 0
        let zk_merkle_positions: Vec<u8> = vec![]; // Empty for depth 0

        Self {
            public: PublicCircuitInputs {
                asset_id: 0u32,
                // DUMMY: output amounts = 0 (part of dummy sentinel to skip block hash validation)
                output_amount_1: 0u32,
                output_amount_2: 0u32,
                volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
                nullifier,
                exit_account_1: exit_account,
                exit_account_2: BytesDigest::default(),
                // DUMMY: block_hash = 0 (part of dummy sentinel)
                block_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                block_number: DEFAULT_BLOCK_NUMBERS[0],
            },
            private: PrivateCircuitInputs {
                secret,
                transfer_count: DEFAULT_TRANSFER_COUNTS[0],
                unspendable_account,
                // These values are not validated for dummy proofs but needed for witness
                parent_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                state_root: BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
                extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
                digest: DEFAULT_DIGESTS[0],
                input_amount: DEFAULT_INPUT_AMOUNTS[0],
                zk_tree_root,
                zk_merkle_siblings,
                zk_merkle_positions,
            },
        }
    }

    /// Creates a second set of test inputs with a valid single-leaf ZK Merkle proof.
    fn test_inputs_1() -> Self {
        let secret: BytesDigest = hex::decode(DEFAULT_SECRETS[1].trim()).unwrap()[..32]
            .try_into()
            .unwrap();

        let nullifier =
            digest_to_bytes(Nullifier::from_preimage(secret, DEFAULT_TRANSFER_COUNTS[1]).hash);
        let unspendable_account_digest = UnspendableAccount::from_secret(secret).account_id;
        let unspendable_account = digest_to_bytes(unspendable_account_digest);
        let exit_account = BytesDigest::try_from(DEFAULT_EXIT_ACCOUNT).unwrap();

        // Compute the ZK leaf hash for a single-leaf tree (depth 0)
        let zk_tree_root = compute_zk_leaf_hash(
            &unspendable_account,
            DEFAULT_TRANSFER_COUNTS[1],
            0u32, // asset_id
            DEFAULT_INPUT_AMOUNTS[1],
        );
        let zk_merkle_siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]> = vec![];
        let zk_merkle_positions: Vec<u8> = vec![];

        Self {
            public: PublicCircuitInputs {
                asset_id: 0u32,
                output_amount_1: 0u32,
                output_amount_2: 0u32,
                volume_fee_bps: DEFAULT_VOLUME_FEE_BPS,
                nullifier,
                exit_account_1: exit_account,
                exit_account_2: BytesDigest::default(),
                block_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                block_number: DEFAULT_BLOCK_NUMBERS[1],
            },
            private: PrivateCircuitInputs {
                secret,
                transfer_count: DEFAULT_TRANSFER_COUNTS[1],
                unspendable_account,
                parent_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
                state_root: BytesDigest::try_from(DEFAULT_STATE_ROOTS[1]).unwrap(),
                extrinsics_root: DEFAULT_EXTRINSICS_ROOTS[1].try_into().unwrap(),
                digest: DEFAULT_DIGESTS[1],
                input_amount: DEFAULT_INPUT_AMOUNTS[1],
                zk_tree_root,
                zk_merkle_siblings,
                zk_merkle_positions,
            },
        }
    }
}

impl TestAggrInputs for CircuitInputs {
    fn test_aggr_inputs() -> Vec<Self> {
        vec![Self::test_inputs_0(), Self::test_inputs_1()]
    }
}

pub mod block_header {
    use crate::TestInputs;
    use wormhole_circuit::block_header::{header::HeaderInputs, BlockHeader};
    use zk_circuits_common::utils::BytesDigest;

    pub const DEFAULT_BLOCK_HASHES: [[u8; 32]; 2] = [
        [
            235, 49, 203, 25, 8, 72, 136, 122, 45, 22, 127, 70, 234, 35, 28, 89, 136, 121, 149, 38,
            96, 98, 213, 3, 110, 94, 216, 104, 36, 15, 130, 72,
        ],
        [
            2, 183, 100, 99, 168, 110, 130, 191, 150, 131, 245, 43, 33, 13, 226, 140, 126, 3, 170,
            145, 203, 11, 147, 179, 80, 25, 24, 207, 73, 209, 191, 116,
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

    /// State roots for the MPT storage trie (still needed for block hash computation).
    /// Note: The ZK trie root is separate and embedded in the digest.
    pub const DEFAULT_STATE_ROOTS: [[u8; 32]; 2] = [
        [
            0x7d, 0x5f, 0x04, 0x3e, 0x06, 0x8b, 0xe9, 0x69, 0x1e, 0xfb, 0xc3, 0xc1, 0xd4, 0x98,
            0x78, 0x8b, 0x5d, 0xc5, 0xc7, 0xd6, 0x5f, 0x41, 0xc0, 0xe2, 0x4e, 0x22, 0x11, 0xc3,
            0x99, 0x7c, 0x08, 0x11,
        ],
        [
            0xd8, 0x97, 0x23, 0x1a, 0xa7, 0x00, 0xe1, 0x5b, 0x49, 0x6a, 0xf8, 0xa4, 0x3d, 0xa1,
            0x56, 0xcf, 0xaf, 0xed, 0x9c, 0x64, 0x49, 0x82, 0xe0, 0xde, 0x72, 0xa1, 0x9b, 0xdb,
            0xe8, 0xf8, 0x73, 0xf5,
        ],
    ];

    impl TestInputs for HeaderInputs {
        fn test_inputs_0() -> Self {
            let parent_hash = BytesDigest::try_from(DEFAULT_PARENT_HASHES[0]).unwrap();
            // Use zero ZK tree root for standalone header tests (dummy proof scenario)
            let zk_tree_root = BytesDigest::try_from([0u8; 32]).unwrap();
            HeaderInputs::new(
                parent_hash,
                DEFAULT_BLOCK_NUMBERS[0],
                BytesDigest::try_from(DEFAULT_STATE_ROOTS[0]).unwrap(),
                DEFAULT_EXTRINSICS_ROOTS[0].try_into().unwrap(),
                zk_tree_root,
                &DEFAULT_DIGESTS[0],
            )
            .unwrap()
        }
        fn test_inputs_1() -> Self {
            let parent_hash = BytesDigest::try_from(DEFAULT_PARENT_HASHES[1]).unwrap();
            // Use zero ZK tree root for standalone header tests (dummy proof scenario)
            let zk_tree_root = BytesDigest::try_from([0u8; 32]).unwrap();
            HeaderInputs::new(
                parent_hash,
                DEFAULT_BLOCK_NUMBERS[1],
                BytesDigest::try_from(DEFAULT_STATE_ROOTS[1]).unwrap(),
                DEFAULT_EXTRINSICS_ROOTS[1].try_into().unwrap(),
                zk_tree_root,
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
