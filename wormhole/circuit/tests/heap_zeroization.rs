//! Regression test (security review): serializing or hashing the spend
//! secret must never free heap memory that still contains it.
//!
//! Two past bugs motivate this:
//!
//! 1. `SensitiveFelts::drop` zeroized a stack temporary from
//!    `to_canonical_u64` and wrote `F::ZERO` back with a plain store the
//!    optimizer may elide as dead, leaving the heap limbs intact in the
//!    freed buffer. The fix scrubs each limb in place through the public
//!    inner `u64` with `zeroize`'s volatile writes.
//! 2. The serialization and hash-preimage buffers grew from `Vec::new()`,
//!    so an `extend` after the secret was written reallocated and freed the
//!    old block unscrubbed — invisible to any drop-time scrub. The fix
//!    reserves full capacity up front.
//!
//! Mirroring `keygen_zeroization.rs` in qp-rusty-crystals, the test installs
//! a global allocator that scans every block for the secret pattern at
//! `dealloc` time (the block is still valid inside the hook, so the scan is
//! sound) and asserts no secret-bearing block is ever freed uncleared.
//! This file contains exactly one test so unrelated concurrent allocations
//! cannot race the scanner.
//!
//! # Coverage
//!
//! Every function the spend secret flows through (the `expose_*` naming
//! makes this surface greppable):
//!
//! - `Secret`: `new`, `From<BytesDigest>`, `From<Digest>`,
//!   `TryFrom<[u8; 32]>`, `expose_digest`, `expose_felts`, drop.
//! - `Nullifier`: `new`, `from_preimage` (Poseidon2 preimage hashing),
//!   `From<&CircuitInputs>`, `to_bytes`, `from_bytes`, `to_field_elements`,
//!   `from_field_elements`, drop.
//! - `UnspendableAccount`: `new`, `from_secret` (hashing),
//!   `From<&CircuitInputs>`, `to_bytes`, `from_bytes`, `to_field_elements`,
//!   `from_field_elements`, drop.
//! - `PrivateCircuitInputs` / `CircuitInputs`: holding and dropping the
//!   secret.
//!
//! Deliberately excluded:
//!
//! - `fill_targets` (both types): copies the secret into plonky2's
//!   `PartialWitness`, which is upstream-owned memory the `sensitive.rs`
//!   scope note already carves out; upstream support is needed to scrub it.
//! - Prover/aggregator entry points: they delegate to the functions above
//!   plus plonky2 proving (same carve-out).
//! - `Debug` impls: redaction is asserted by unit tests; formatting renders
//!   decimal text, which a byte-pattern scanner cannot see.
//!
//! # Known upstream exemption
//!
//! qp-plonky2's `hash_no_pad` (`pad10_to_rate` in `qp-plonky2-core`) copies
//! its input — salt, secret, and terminator — into a rate-aligned heap
//! `Vec<F>` and frees it unscrubbed; only upstream can fix that. The
//! scanner exempts blocks that byte-for-byte equal the two expected pad
//! buffers (one per constructor) and nothing else, so a leak of any of the
//! buffers this crate owns — with different sizes/layouts — still fails.
//! This is the "copies plonky2 keeps" carve-out documented in
//! `sensitive.rs`.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::OnceLock;

use plonky2::field::types::{Field, PrimeField64};
use qp_wormhole_circuit::block_header::header::DIGEST_LOGS_SIZE;
use qp_wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use qp_wormhole_circuit::nullifier::{Nullifier, NULLIFIER_SALT};
use qp_wormhole_circuit::sensitive::Secret;
use qp_wormhole_circuit::unspendable_account::{UnspendableAccount, UNSPENDABLE_SALT};
use zk_circuits_common::circuit::F;
use zk_circuits_common::utils::{
    bytes_to_digest, digest_to_bytes, string_to_felts, u64_to_felts, BytesDigest,
};

/// Distinctive 32-byte pattern; a repeated single byte could false-positive
/// against unrelated allocator noise. Every byte is ASCII (< 0x80), so each
/// 8-byte limb stays below the Goldilocks modulus and the pattern is a valid
/// `BytesDigest`. On the little-endian hosts we test on, the felt encoding
/// (one canonical `u64` per 8-byte limb) has the same in-memory bytes, so a
/// single scan covers both the byte and felt buffers.
const SECRET_PATTERN: [u8; 32] = *b"wormhole-zeroize-regression-pat!";

static SCANNING: AtomicBool = AtomicBool::new(false);
static SECRET_FREED_UNCLEARED: AtomicBool = AtomicBool::new(false);
static LEAKED_BLOCK_SIZE: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicUsize = AtomicUsize::new(0);
static LEAKED_PHASE: AtomicUsize = AtomicUsize::new(0);

/// Byte images of qp-plonky2's internal `pad10_to_rate` buffers for the two
/// constructor hashes (see "Known upstream exemption" above). Populated
/// before scanning starts; only an exact whole-block match is exempted.
static UPSTREAM_PAD_BLOCKS: OnceLock<[Vec<u8>; 2]> = OnceLock::new();

fn felts_to_le_bytes(felts: &[F]) -> Vec<u8> {
    felts
        .iter()
        .flat_map(|f| f.to_canonical_u64().to_le_bytes())
        .collect()
}

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if SCANNING.load(Ordering::SeqCst) && layout.size() >= SECRET_PATTERN.len() {
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            if block
                .windows(SECRET_PATTERN.len())
                .any(|w| w == SECRET_PATTERN)
            {
                let known_upstream = UPSTREAM_PAD_BLOCKS
                    .get()
                    .is_some_and(|pads| pads.iter().any(|pad| pad.as_slice() == block));
                if !known_upstream {
                    SECRET_FREED_UNCLEARED.store(true, Ordering::SeqCst);
                    LEAKED_BLOCK_SIZE.store(layout.size(), Ordering::SeqCst);
                    LEAKED_PHASE.store(PHASE.load(Ordering::SeqCst), Ordering::SeqCst);
                }
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: SecretScanningAllocator = SecretScanningAllocator;

const TRANSFER_COUNT: u64 = 42;
/// Poseidon2 sponge rate (`SPONGE_RATE` in qp-poseidon-core); `pad10_to_rate`
/// pads to a multiple of this.
const RATE: usize = 8;

/// Reconstruct the two `pad10_to_rate` buffers the constructor hashes create
/// inside qp-plonky2: `input || F::ONE`, zero-filled to a `RATE` multiple.
fn expected_upstream_pad_blocks(secret: BytesDigest) -> [Vec<u8>; 2] {
    let secret_felts = bytes_to_digest(secret);

    let mut nullifier_pad: Vec<F> =
        string_to_felts(NULLIFIER_SALT).expect("salt within serialization cap");
    nullifier_pad.extend(secret_felts);
    nullifier_pad.extend(u64_to_felts(TRANSFER_COUNT));
    nullifier_pad.push(F::ONE);
    nullifier_pad.resize(2 * RATE, F::ZERO);

    let mut account_pad: Vec<F> =
        string_to_felts(UNSPENDABLE_SALT).expect("salt within serialization cap");
    account_pad.extend(secret_felts);
    account_pad.push(F::ONE);
    assert_eq!(
        account_pad.len(),
        RATE,
        "account preimage pads to one block"
    );

    [
        felts_to_le_bytes(&nullifier_pad),
        felts_to_le_bytes(&account_pad),
    ]
}

#[test]
fn serialization_never_frees_heap_memory_containing_the_secret() {
    let secret = BytesDigest::try_from(SECRET_PATTERN).unwrap();
    UPSTREAM_PAD_BLOCKS
        .set(expected_upstream_pad_blocks(secret))
        .expect("set once");

    SECRET_FREED_UNCLEARED.store(false, Ordering::SeqCst);
    SCANNING.store(true, Ordering::SeqCst);

    PHASE.store(1, Ordering::SeqCst);
    let nullifier = Nullifier::from_preimage(secret, TRANSFER_COUNT);
    PHASE.store(2, Ordering::SeqCst);
    let bytes = nullifier.to_bytes();
    let round_trip = Nullifier::from_bytes(bytes.as_ref()).expect("byte round trip");
    assert_eq!(round_trip, nullifier);
    drop(bytes);
    PHASE.store(3, Ordering::SeqCst);
    let felts = nullifier.to_field_elements();
    let round_trip = Nullifier::from_field_elements(felts.as_slice()).expect("felt round trip");
    assert_eq!(round_trip, nullifier);
    drop(felts);
    drop(round_trip);
    drop(nullifier);

    PHASE.store(4, Ordering::SeqCst);
    let direct = Nullifier::new(
        BytesDigest::try_from([0x11u8; 32]).unwrap(),
        secret,
        TRANSFER_COUNT,
    );
    drop(direct);

    PHASE.store(5, Ordering::SeqCst);
    let account = UnspendableAccount::from_secret(secret);
    PHASE.store(6, Ordering::SeqCst);
    let bytes = account.to_bytes();
    let round_trip = UnspendableAccount::from_bytes(bytes.as_ref()).expect("byte round trip");
    assert_eq!(round_trip, account);
    drop(bytes);
    PHASE.store(7, Ordering::SeqCst);
    let felts = account.to_field_elements();
    let round_trip =
        UnspendableAccount::from_field_elements(felts.as_slice()).expect("felt round trip");
    assert_eq!(round_trip, account);
    drop(felts);
    drop(round_trip);

    PHASE.store(8, Ordering::SeqCst);
    let direct = UnspendableAccount::new(BytesDigest::try_from([0x11u8; 32]).unwrap(), secret);
    drop(direct);

    // `From<&CircuitInputs>` conversions plus holding/dropping the secret
    // inside `PrivateCircuitInputs`.
    PHASE.store(9, Ordering::SeqCst);
    let inputs = CircuitInputs {
        private: PrivateCircuitInputs {
            secret: Secret::from(secret),
            transfer_count: TRANSFER_COUNT,
            unspendable_account: digest_to_bytes(account.account_id),
            parent_hash: BytesDigest::try_from([5u8; 32]).unwrap(),
            state_root: BytesDigest::try_from([3u8; 32]).unwrap(),
            extrinsics_root: BytesDigest::try_from([4u8; 32]).unwrap(),
            digest: [0xEE; DIGEST_LOGS_SIZE],
            input_amount: 1000,
            zk_tree_root: [0u8; 32],
            zk_merkle_siblings: vec![],
            zk_merkle_positions: vec![],
        },
        public: PublicCircuitInputs {
            asset_id: 0,
            output_amount_1: 900,
            output_amount_2: 99,
            volume_fee_bps: 10,
            nullifier: BytesDigest::try_from([1u8; 32]).unwrap(),
            block_hash: BytesDigest::try_from([0u8; 32]).unwrap(),
            exit_account_1: BytesDigest::try_from([2u8; 32]).unwrap(),
            exit_account_2: BytesDigest::try_from([3u8; 32]).unwrap(),
            block_number: 1,
        },
    };
    let from_inputs = Nullifier::from(&inputs);
    assert_eq!(from_inputs.secret.expose_felts(), bytes_to_digest(secret));
    drop(from_inputs);
    let from_inputs = UnspendableAccount::from(&inputs);
    assert_eq!(from_inputs.secret.expose_felts(), bytes_to_digest(secret));
    drop(from_inputs);
    drop(inputs);
    drop(account);

    // `Secret` entry points and explicit `expose_*` duplication.
    PHASE.store(10, Ordering::SeqCst);
    let mut source = SECRET_PATTERN;
    let owned = Secret::new(&mut source).expect("valid digest");
    assert_eq!(source, [0u8; 32], "Secret::new must scrub its source");
    let via_digest = Secret::from(owned.expose_digest());
    let via_felts = Secret::from(owned.expose_felts());
    let via_array = Secret::try_from(SECRET_PATTERN).expect("valid digest");
    assert!(owned == via_digest && via_digest == via_felts && via_felts == via_array);
    drop(owned);
    drop(via_digest);
    drop(via_felts);
    drop(via_array);

    SCANNING.store(false, Ordering::SeqCst);

    assert!(
        !SECRET_FREED_UNCLEARED.load(Ordering::SeqCst),
        "a heap block of {} bytes still containing the spend secret was freed \
         unscrubbed during phase {}; check SensitiveFelts::drop and the \
         with_capacity pre-sizing of the serialization/preimage buffers",
        LEAKED_BLOCK_SIZE.load(Ordering::SeqCst),
        LEAKED_PHASE.load(Ordering::SeqCst)
    );
}
