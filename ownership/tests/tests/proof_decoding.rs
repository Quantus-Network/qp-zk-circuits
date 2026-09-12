use ownership_circuit::{circuit::circuit_logic::OwnershipCircuit, inputs::CircuitInputs};
use ownership_prover::OwnershipProver;
use ownership_verifier::OwnershipVerifier;
use plonky2::field::types::Field64;
use plonky2::util::serialization::DefaultGateSerializer;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wormhole_circuit::sensitive::Secret;
use zk_circuits_common::circuit::{ownership_circuit_config, C, D, F};
use zk_circuits_common::utils::BytesDigest;

struct TrackingAllocator;
static TRACK: AtomicBool = AtomicBool::new(false);
static MAX_ALLOCATION: AtomicUsize = AtomicUsize::new(0);

fn track(size: usize) {
    if TRACK.load(Ordering::Relaxed) {
        MAX_ALLOCATION.fetch_max(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        track(layout.size());
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        track(layout.size());
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        track(size);
        System.realloc(ptr, layout, size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[test]
fn bounded_decoding_preserves_valid_proofs_and_rejects_malformed_inputs() {
    let config = ownership_circuit_config();
    let data = OwnershipCircuit::new(config.clone())
        .unwrap()
        .build_verifier();
    let verifier = OwnershipVerifier::new_from_bytes(
        &data.verifier_only.to_bytes().unwrap(),
        &data.common.to_bytes(&DefaultGateSerializer).unwrap(),
    )
    .unwrap();
    let inputs = CircuitInputs::from_secret(
        Secret::try_from([0x11; 32]).unwrap(),
        BytesDigest::try_from([0x22; 32].as_slice()).unwrap(),
    );
    let proof = OwnershipProver::new(config)
        .unwrap()
        .commit(&inputs)
        .unwrap()
        .prove()
        .unwrap();
    let bytes = proof.to_bytes();
    let count_offset = bytes.len() - 8 * (proof.public_inputs.len() + 1);
    assert_eq!(verifier.verify_bytes(&bytes).unwrap().to_bytes(), bytes);
    let decoded = zk_circuits_common::decode_proof::<F, C, D>(&bytes, &data.common).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    data.verify(decoded).unwrap();

    let assert_rejected = |malformed: &[u8]| {
        MAX_ALLOCATION.store(0, Ordering::Relaxed);
        TRACK.store(true, Ordering::Relaxed);
        let verifier_result =
            ownership_verifier::decode_proof::<F, C, D>(malformed, &verifier.circuit_data.common);
        let prover_result = zk_circuits_common::decode_proof::<F, C, D>(malformed, &data.common);
        TRACK.store(false, Ordering::Relaxed);
        assert!(verifier_result.is_err());
        assert!(prover_result.is_err());
        assert!(
            MAX_ALLOCATION.load(Ordering::Relaxed) < 1024 * 1024,
            "malformed proof requested an allocation of at least 1 MiB"
        );
    };

    for count in [0, 7, 9, 4 * 1024 * 1024, (1u64 << 32) + 8, u64::MAX] {
        let mut malformed = bytes.clone();
        malformed[count_offset..count_offset + 8].copy_from_slice(&count.to_le_bytes());
        assert_rejected(&malformed);
    }
    for end in [
        0,
        bytes.len() / 2,
        count_offset,
        count_offset + 7,
        bytes.len() - 1,
    ] {
        assert_rejected(&bytes[..end]);
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_rejected(&trailing);
    let mut noncanonical = bytes.clone();
    noncanonical[count_offset + 8..count_offset + 16].copy_from_slice(&F::ORDER.to_le_bytes());
    assert_rejected(&noncanonical);

    let mut tampered = bytes.clone();
    tampered[count_offset + 8] ^= 1;
    assert!(verifier.verify_bytes(&tampered).is_err());
}
