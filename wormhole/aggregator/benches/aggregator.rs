//! Aggregator benchmarks using pre-built circuit artifacts.
//!
//! Before running these benchmarks, generate the circuit artifacts:
//! ```bash
//! cargo run --release -p qp-wormhole-aggregator --bin generate_bench_circuits
//! ```
//!
//! Then run benchmarks:
//! ```bash
//! cargo bench -p qp-wormhole-aggregator
//! ```

use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::DefaultGateSerializer;
use qp_wormhole_aggregator::aggregator::{AggregationBackend, Layer0Aggregator, Layer1Aggregator};
use qp_wormhole_aggregator::dummy_proof::load_dummy_proof;
use qp_wormhole_inputs::BytesDigest;
use zk_circuits_common::circuit::{C, D, F};

/// Main generated-bins directory (with existing layer0-N directories)
const MAIN_BINS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../generated-bins");

const LAYER1_AGGREGATOR_ADDRESS: [u8; 32] = [42u8; 32];

type Proof = ProofWithPublicInputs<F, C, D>;

fn load_dummy_leaf_proof(bins_dir: &str) -> Proof {
    let gate_serializer = DefaultGateSerializer;
    let proof_bytes = std::fs::read(format!("{}/dummy_proof.bin", bins_dir))
        .expect("Failed to read dummy proof bytes. Did you run generate_bench_circuits?");
    let common_circuit_data = std::fs::read(format!("{}/common.bin", bins_dir))
        .expect("Failed to read common circuit data bytes");
    let common = CommonCircuitData::from_bytes(common_circuit_data.to_vec(), &gate_serializer)
        .expect("Failed to deserialize common circuit data");
    load_dummy_proof(proof_bytes, &common).expect("Failed to load dummy proof from bytes")
}

/// Generate a dummy layer-0 proof for layer-1 benchmarks
/// Uses the layer0-{num_leaves} directory to create the aggregation proof
fn generate_dummy_layer0_proof(num_leaves: usize) -> Proof {
    let layer0_dir = format!("{}/layer0-{}", MAIN_BINS_DIR, num_leaves);
    let dummy_leaf_proof = load_dummy_leaf_proof(&layer0_dir);
    let mut aggregator = Layer0Aggregator::new(&layer0_dir).unwrap();
    for _ in 0..num_leaves {
        aggregator.push_proof(dummy_leaf_proof.clone()).unwrap();
    }
    aggregator.aggregate().unwrap()
}

// =============================================================================
// First-layer (layer0) benchmarks
// =============================================================================

macro_rules! layer0_prove_benchmark {
    ($fn_name:ident, $num_leaves:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            // Use existing layer0-N directories (note: hyphen not underscore)
            let bins_dir = format!("{}/layer0-{}", MAIN_BINS_DIR, $num_leaves);
            let proof = load_dummy_leaf_proof(&bins_dir);

            // Pre-create aggregator with proofs loaded (setup cost not measured)
            c.bench_function(&format!("layer0_prove_{}", $num_leaves), |b| {
                b.iter_batched(
                    || {
                        let mut aggregator = Layer0Aggregator::new(&bins_dir).unwrap();
                        for _ in 0..$num_leaves {
                            aggregator.push_proof(proof.clone()).unwrap();
                        }
                        aggregator
                    },
                    |mut aggregator| {
                        aggregator.aggregate().unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    };
}

macro_rules! layer0_verify_benchmark {
    ($fn_name:ident, $num_leaves:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            // Use existing layer0-N directories (note: hyphen not underscore)
            let bins_dir = format!("{}/layer0-{}", MAIN_BINS_DIR, $num_leaves);
            let proof = load_dummy_leaf_proof(&bins_dir);

            // Pre-generate the proof to verify (not measured)
            let mut aggregator = Layer0Aggregator::new(&bins_dir).unwrap();
            for _ in 0..$num_leaves {
                aggregator.push_proof(proof.clone()).unwrap();
            }
            let aggregated_proof = aggregator.aggregate().unwrap();

            c.bench_function(&format!("layer0_verify_{}", $num_leaves), |b| {
                b.iter(|| {
                    aggregator.verify(aggregated_proof.clone()).unwrap();
                });
            });
        }
    };
}

// First-layer benchmarks: N = 2, 4, 8, 16, 32
// Uses existing layer0-N directories in generated-bins/
layer0_prove_benchmark!(bench_layer0_prove_2, 2);
layer0_prove_benchmark!(bench_layer0_prove_4, 4);
layer0_prove_benchmark!(bench_layer0_prove_8, 8);
layer0_prove_benchmark!(bench_layer0_prove_16, 16);
layer0_prove_benchmark!(bench_layer0_prove_32, 32);

layer0_verify_benchmark!(bench_layer0_verify_2, 2);
layer0_verify_benchmark!(bench_layer0_verify_4, 4);
layer0_verify_benchmark!(bench_layer0_verify_8, 8);
layer0_verify_benchmark!(bench_layer0_verify_16, 16);
layer0_verify_benchmark!(bench_layer0_verify_32, 32);

// =============================================================================
// Second-layer (layer1) benchmarks
// =============================================================================

macro_rules! layer1_prove_benchmark {
    ($fn_name:ident, $num_l0_proofs:expr, $leaves_per_l0:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            // Use existing layer1 directories with naming: layer1-M-l0leaves-N
            let bins_dir = format!(
                "{}/layer1-{}-l0leaves-{}",
                MAIN_BINS_DIR, $num_l0_proofs, $leaves_per_l0
            );

            // Pre-generate layer0 proof using the layer0-{leaves_per_l0} directory
            let l0_proof = generate_dummy_layer0_proof($leaves_per_l0);

            let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
                .expect("Failed to create aggregator address");

            c.bench_function(
                &format!("layer1_prove_{}x{}", $num_l0_proofs, $leaves_per_l0),
                |b| {
                    b.iter_batched(
                        || {
                            let mut aggregator =
                                Layer1Aggregator::new(&bins_dir, aggregator_address).unwrap();
                            for _ in 0..$num_l0_proofs {
                                aggregator.push_proof(l0_proof.clone()).unwrap();
                            }
                            aggregator
                        },
                        |mut aggregator| {
                            aggregator.aggregate().unwrap();
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

macro_rules! layer1_verify_benchmark {
    ($fn_name:ident, $num_l0_proofs:expr, $leaves_per_l0:expr) => {
        pub fn $fn_name(c: &mut Criterion) {
            // Use existing layer1 directories with naming: layer1-M-l0leaves-N
            let bins_dir = format!(
                "{}/layer1-{}-l0leaves-{}",
                MAIN_BINS_DIR, $num_l0_proofs, $leaves_per_l0
            );

            // Pre-generate layer0 proof using the layer0-{leaves_per_l0} directory
            let l0_proof = generate_dummy_layer0_proof($leaves_per_l0);

            let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
                .expect("Failed to create aggregator address");

            // Pre-generate the layer1 proof to verify
            let mut aggregator = Layer1Aggregator::new(&bins_dir, aggregator_address).unwrap();
            for _ in 0..$num_l0_proofs {
                aggregator.push_proof(l0_proof.clone()).unwrap();
            }
            let aggregated_proof = aggregator.aggregate().unwrap();

            c.bench_function(
                &format!("layer1_verify_{}x{}", $num_l0_proofs, $leaves_per_l0),
                |b| {
                    b.iter(|| {
                        aggregator.verify(aggregated_proof.clone()).unwrap();
                    });
                },
            );
        }
    };
}

// Second-layer benchmarks: (M first-layer proofs, N leaves per first-layer)
// All existing layer1 directories have l0leaves-8, so all configs use 8 leaves
layer1_prove_benchmark!(bench_layer1_prove_2x8, 2, 8);
layer1_prove_benchmark!(bench_layer1_prove_4x8, 4, 8);
layer1_prove_benchmark!(bench_layer1_prove_8x8, 8, 8);
layer1_prove_benchmark!(bench_layer1_prove_16x8, 16, 8);
layer1_prove_benchmark!(bench_layer1_prove_32x8, 32, 8);

layer1_verify_benchmark!(bench_layer1_verify_2x8, 2, 8);
layer1_verify_benchmark!(bench_layer1_verify_4x8, 4, 8);
layer1_verify_benchmark!(bench_layer1_verify_8x8, 8, 8);
layer1_verify_benchmark!(bench_layer1_verify_16x8, 16, 8);
layer1_verify_benchmark!(bench_layer1_verify_32x8, 32, 8);

// =============================================================================
// Criterion configuration
// =============================================================================

criterion_group!(
    name = layer0_benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_layer0_prove_2, bench_layer0_prove_4, bench_layer0_prove_8,
        bench_layer0_prove_16, bench_layer0_prove_32,
        bench_layer0_verify_2, bench_layer0_verify_4, bench_layer0_verify_8,
        bench_layer0_verify_16, bench_layer0_verify_32
);

criterion_group!(
    name = layer1_benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_layer1_prove_2x8, bench_layer1_prove_4x8,
        bench_layer1_prove_8x8, bench_layer1_prove_16x8, bench_layer1_prove_32x8,
        bench_layer1_verify_2x8, bench_layer1_verify_4x8,
        bench_layer1_verify_8x8, bench_layer1_verify_16x8, bench_layer1_verify_32x8
);

criterion_main!(layer0_benches, layer1_benches);
