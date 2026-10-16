//! CPU versus GPU public-batch proving on the real circuit, with the GPU path
//! split into its CPU-side witness work and its device-coordinated stages.
//! Requires a hardware adapter with native u64 shaders; the GPU prover for an
//! arity-53 batch plans roughly 5.5 GB of device buffers.
//!
//! `cargo bench -p qp-wormhole-aggregator --features gpu --bench gpu`
//!
//! Every target proves a full batch (one real inner proof, dummy-padded; see
//! `prepare_public_batch_fixture`), so a sample takes seconds. Filter by arity
//! or backend, e.g. `-- 53` or `-- public_batch_prove/gpu`, to skip the other
//! fixtures' circuit generation.
#[path = "support/fixtures.rs"]
mod fixtures;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use fixtures::*;
use plonky2::iop::generator::generate_partial_witness;
use qp_wormhole_aggregator::public_batch::prover::{PublicBatchInputs, PublicBatchProver};
use qp_wormhole_gpu::{DeviceContext, PreparationOptions, PreparedCircuit};
use qp_wormhole_inputs::BytesDigest;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// 53 is the production circuit size; 8 keeps a quick comparison available.
const ARITIES: &[usize] = &[8, 53];
/// Proving workers sharing one GPU prover, as a service would run them. The
/// GPU stages are serialized on the shared workspace; only the CPU witness
/// work overlaps.
const WORKER_COUNTS: &[usize] = &[2, 4];

fn device() -> Arc<DeviceContext> {
    static DEVICE: OnceLock<Arc<DeviceContext>> = OnceLock::new();
    Arc::clone(DEVICE.get_or_init(|| {
        let context = futures::executor::block_on(DeviceContext::new())
            .expect("GPU benches require a hardware GPU with native u64 shader support");
        eprintln!("adapter: {:?}", context.adapter_info());
        Arc::new(context)
    }))
}

fn public_batch_targets(arity: usize) -> Vec<String> {
    let mut ids = vec![
        format!("public_batch_prove/cpu/{arity}"),
        format!("public_batch_prove/gpu/{arity}"),
        format!("public_batch_prove/witness_generation/{arity}"),
        format!("public_batch_prove/gpu_stages/{arity}"),
    ];
    ids.extend(
        WORKER_COUNTS
            .iter()
            .map(|workers| format!("public_batch_prove/gpu_{workers}_workers/{arity}")),
    );
    ids
}

fn bench_public_batch(c: &mut Criterion) {
    for &arity in ARITIES {
        if public_batch_targets(arity)
            .iter()
            .all(|id| skip_by_filter(id))
        {
            continue;
        }
        let proof = prepare_public_batch_fixture(arity);
        let aggregator_address = BytesDigest::try_from(LAYER1_AGGREGATOR_ADDRESS)
            .expect("Failed to create aggregator address bytes digest");
        let inputs = || PublicBatchInputs {
            proofs: vec![proof.clone()],
            aggregator_address,
        };
        // Built once and reused, like production (`ProvingContext` builds the
        // circuit at aggregator construction and proves many batches on it).
        let mut prover = PublicBatchProver::new_from_binaries_dir(Path::new(bins_dir()))
            .expect("Failed to load public-batch prover");

        let mut group = c.benchmark_group("public_batch_prove");
        group.sampling_mode(SamplingMode::Flat).sample_size(10);

        // End-to-end CPU proving: admission, witness fill and generation, prove.
        group.bench_function(BenchmarkId::new("cpu", arity), |b| {
            b.iter_batched(
                inputs,
                |inputs| prover.prove_batch(inputs).unwrap(),
                criterion::BatchSize::SmallInput,
            )
        });

        // The CPU-side share of a GPU proof: admission, witness fill and the
        // circuit's witness generators, which run before any upload.
        let circuit = Arc::clone(&prover.circuit_data);
        let generate = |inputs| {
            generate_partial_witness(
                prover.build_witness(inputs).unwrap(),
                &circuit.prover_only,
                &circuit.common,
            )
            .unwrap()
        };
        group.bench_function(BenchmarkId::new("witness_generation", arity), |b| {
            b.iter_batched(inputs, generate, criterion::BatchSize::SmallInput)
        });

        // Device-coordinated stages only, from a generated witness to an
        // assembled proof. Uses a separately prepared circuit and workspace so
        // the measurement does not include the backend's workspace lock.
        {
            let context = device();
            let prepared =
                PreparedCircuit::prepare(&context, &circuit, PreparationOptions::default())
                    .expect("Failed to prepare public-batch GPU circuit");
            let mut workspace = prepared
                .prepare_workspace(&context)
                .expect("Failed to allocate public-batch GPU workspace");
            group.bench_function(BenchmarkId::new("gpu_stages", arity), |b| {
                b.iter_batched(
                    || generate(inputs()),
                    |partition| {
                        prepared
                            .prove_with_partition_witness(&context, &mut workspace, partition)
                            .unwrap()
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }

        // End-to-end GPU-assisted proving through the backend a service uses.
        prover
            .with_gpu(device(), PreparationOptions::default())
            .expect("Failed to select the GPU backend");
        let prover = Arc::new(prover);
        group.bench_function(BenchmarkId::new("gpu", arity), |b| {
            b.iter_batched(
                inputs,
                |inputs| prover.prove_batch(inputs).unwrap(),
                criterion::BatchSize::SmallInput,
            )
        });

        // Batch throughput with several workers sharing the prover. Reported
        // per proof, so this is directly comparable with the single-worker
        // `gpu` time.
        for &workers in WORKER_COUNTS {
            group.throughput(Throughput::Elements(workers as u64));
            group.bench_function(
                BenchmarkId::new(format!("gpu_{workers}_workers"), arity),
                |b| {
                    b.iter_custom(|iterations| {
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iterations {
                            let batches: Vec<_> = (0..workers).map(|_| inputs()).collect();
                            let started = Instant::now();
                            std::thread::scope(|scope| {
                                for inputs in batches {
                                    let prover = Arc::clone(&prover);
                                    scope.spawn(move || prover.prove_batch(inputs).unwrap());
                                }
                            });
                            elapsed += started.elapsed();
                        }
                        elapsed
                    })
                },
            );
        }
        group.finish();
    }
}

criterion_group!(benches, bench_public_batch);
criterion_main!(benches);
