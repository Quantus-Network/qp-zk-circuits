//! Device-side throughput of the individual proving kernels, independent of
//! any circuit. Each sample encodes one submission, submits it and waits for
//! completion, so timings include queue and driver latency as a real proving
//! phase would see it. Shapes follow the public-batch circuit
//! (`standard_recursion_config`: rate 8, cap height 4, FRI arity 16, 135 wire
//! columns, 16 quotient columns, 16 PoW bits); rows range up to the LDE size of
//! an arity-53 batch. Requires a hardware adapter with native u64 shaders.
//!
//! `cargo bench -p qp-wormhole-gpu --features wgpu --bench kernels`
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::challenger::Challenger;
use qp_wormhole_gpu::{
    ArithmeticKernels, ArithmeticPlan, CommitmentPlan, DeviceContext, EvaluationOrder, FftKernels,
    FftPlan, FieldOperation, FieldSource, FriFoldPlan, FriKernels, PoseidonKernels, PowKernels,
    PowPlan, ProofWorkspace,
};
use std::sync::{Arc, OnceLock};

const RATE_BITS: u32 = 3;
const CAP_HEIGHT: usize = 4;
const FRI_ARITY: usize = 16;
const WIRE_COLUMNS: usize = 135;
const QUOTIENT_COLUMNS: usize = 16;
const POW_BITS: u32 = 16;
const CHUNK_ROWS: usize = 1 << 16;

fn context() -> &'static DeviceContext {
    static CONTEXT: OnceLock<DeviceContext> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        let context = futures::executor::block_on(DeviceContext::new())
            .expect("kernel benches require a hardware GPU with native u64 shader support");
        eprintln!("adapter: {:?}", context.adapter_info());
        context
    })
}

fn samples(n: usize, seed: u64) -> Vec<F> {
    let mut state = seed;
    (0..n)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            F::from_noncanonical_u64(state)
        })
        .collect()
}

fn bench_arithmetic(c: &mut Criterion) {
    let context = context();
    let kernels = Arc::new(ArithmeticKernels::prepare(context).unwrap());
    let mut group = c.benchmark_group("goldilocks_multiply");
    for log_elements in [20u32, 24] {
        let elements = 1usize << log_elements;
        let plan = ArithmeticPlan::prepare(
            context,
            Arc::clone(&kernels),
            elements,
            FieldOperation::Multiply,
        )
        .unwrap();
        let mut workspace = ProofWorkspace::prepare(context, &[2 * elements, elements]).unwrap();
        let input = workspace.buffer(0).unwrap();
        let output = workspace.buffer(1).unwrap();
        let mut encoder = workspace.begin(context).unwrap();
        encoder.upload(&input, &samples(2 * elements, 1)).unwrap();
        encoder.submit().unwrap().finish().unwrap();
        group.throughput(Throughput::Elements(elements as u64));
        group.bench_function(BenchmarkId::from_parameter(elements), |b| {
            b.iter(|| {
                let mut encoder = workspace.begin(context).unwrap();
                plan.encode(&mut encoder, &input, &output).unwrap();
                encoder.submit().unwrap().finish().unwrap();
            })
        });
    }
    group.finish();
}

/// Forward coset LDE of a batch of `QUOTIENT_COLUMNS` polynomials from
/// coefficient to evaluation form, the per-column shape of every oracle
/// commitment. Throughput counts output evaluations.
fn bench_coset_lde(c: &mut Criterion) {
    let context = context();
    let kernels = Arc::new(FftKernels::prepare(context).unwrap());
    let mut group = c.benchmark_group("coset_lde");
    group.sample_size(20);
    for degree_bits in [14u32, 16, 18] {
        let degree = 1usize << degree_bits;
        let rows = degree << RATE_BITS;
        let plan = FftPlan::prepare_coset(
            context,
            Arc::clone(&kernels),
            degree,
            rows,
            F::coset_shift(),
        )
        .unwrap();
        let coefficients = context
            .prepare_fixed(&samples(degree * QUOTIENT_COLUMNS, 2))
            .unwrap();
        let mut workspace = ProofWorkspace::prepare(context, &[rows * QUOTIENT_COLUMNS]).unwrap();
        let evaluations = workspace.buffer(0).unwrap();
        group.throughput(Throughput::Elements((rows * QUOTIENT_COLUMNS) as u64));
        group.bench_function(
            BenchmarkId::from_parameter(format!(
                "degree_2^{degree_bits}_x{QUOTIENT_COLUMNS}_columns"
            )),
            |b| {
                b.iter(|| {
                    let mut encoder = workspace.begin(context).unwrap();
                    plan.encode(&mut encoder, &coefficients, &evaluations)
                        .unwrap();
                    encoder.submit().unwrap().finish().unwrap();
                })
            },
        );
    }
    group.finish();
}

/// Poseidon Merkle commitment of `width` evaluation columns over `rows` LDE
/// rows into the packed tree layout, with the chunked leaf packing the circuit
/// stages use. Throughput counts leaf rows.
fn bench_merkle_commitment(c: &mut Criterion) {
    let context = context();
    let kernels = Arc::new(PoseidonKernels::prepare(context).unwrap());
    let mut group = c.benchmark_group("poseidon_merkle_commitment");
    group.sample_size(20);
    for (width, rows_bits) in [
        (QUOTIENT_COLUMNS, 17u32),
        (QUOTIENT_COLUMNS, 21),
        (WIRE_COLUMNS, 17),
        (WIRE_COLUMNS, 21),
    ] {
        let rows = 1usize << rows_bits;
        let plan = CommitmentPlan::prepare_chunked(
            context,
            Arc::clone(&kernels),
            rows,
            width,
            CAP_HEIGHT,
            EvaluationOrder::BitReversed,
            CHUNK_ROWS,
        )
        .unwrap();
        // Hashing cost is data-independent, so every column reads one shared
        // buffer rather than allocating `width` distinct LDE columns.
        let column = context.prepare_fixed(&samples(rows, 3)).unwrap();
        let columns = vec![FieldSource::from(&column); width];
        let mut workspace =
            ProofWorkspace::prepare(context, &plan.workspace_field_counts()).unwrap();
        let input_chunk = workspace.buffer(0).unwrap();
        let leaf_chunk = workspace.buffer(1).unwrap();
        let tree = workspace.buffer(2).unwrap();
        group.throughput(Throughput::Elements(rows as u64));
        group.bench_function(
            BenchmarkId::from_parameter(format!("rows_2^{rows_bits}_x{width}_columns")),
            |b| {
                b.iter(|| {
                    let mut encoder = workspace.begin(context).unwrap();
                    plan.encode(&mut encoder, &columns, &input_chunk, &leaf_chunk, &tree)
                        .unwrap();
                    encoder.submit().unwrap().finish().unwrap();
                })
            },
        );
    }
    group.finish();
}

/// One FRI folding step over extension-field coefficients. Throughput counts
/// input coefficients.
fn bench_fri_fold(c: &mut Criterion) {
    let context = context();
    let kernels = Arc::new(FriKernels::prepare(context).unwrap());
    let mut group = c.benchmark_group("fri_fold");
    for coefficient_bits in [17u32, 21] {
        let coefficients = 1usize << coefficient_bits;
        let plan =
            FriFoldPlan::prepare(context, Arc::clone(&kernels), coefficients, FRI_ARITY).unwrap();
        let mut workspace =
            ProofWorkspace::prepare(context, &[2 * coefficients, 2, plan.output_field_count()])
                .unwrap();
        let input = workspace.buffer(0).unwrap();
        let beta = workspace.buffer(1).unwrap();
        let output = workspace.buffer(2).unwrap();
        let mut encoder = workspace.begin(context).unwrap();
        encoder
            .upload(&input, &samples(2 * coefficients, 4))
            .unwrap();
        encoder.upload(&beta, &samples(2, 5)).unwrap();
        encoder.submit().unwrap().finish().unwrap();
        group.throughput(Throughput::Elements(coefficients as u64));
        group.bench_function(
            BenchmarkId::from_parameter(format!(
                "2^{coefficient_bits}_coefficients_arity_{FRI_ARITY}"
            )),
            |b| {
                b.iter(|| {
                    let mut encoder = workspace.begin(context).unwrap();
                    plan.encode(&mut encoder, &input, &beta, &output).unwrap();
                    encoder.submit().unwrap().finish().unwrap();
                })
            },
        );
    }
    group.finish();
}

/// One bounded proof-of-work search chunk against a fixed transcript state.
/// The result is read back and validated on the CPU exactly as the coordinator
/// does; the transcript is cloned per iteration so acceptance never advances
/// the shared state. Throughput counts dispatched nonce trials.
fn bench_pow(c: &mut Criterion) {
    let context = context();
    let poseidon = Arc::new(PoseidonKernels::prepare(context).unwrap());
    let kernels = Arc::new(PowKernels::prepare(context, poseidon).unwrap());
    let mut challenger = Challenger::<F, PoseidonHash>::new();
    challenger.observe_elements(&samples(9, 6));
    let mut group = c.benchmark_group("fri_pow_search");
    for trial_bits in [16u32, 20] {
        let trials = 1usize << trial_bits;
        let plan = PowPlan::prepare(context, Arc::clone(&kernels), POW_BITS, trials).unwrap();
        let mut workspace =
            ProofWorkspace::prepare(context, &plan.workspace_field_counts()).unwrap();
        let buffers = [
            workspace.buffer(0).unwrap(),
            workspace.buffer(1).unwrap(),
            workspace.buffer(2).unwrap(),
        ];
        group.throughput(Throughput::Elements(trials as u64));
        group.bench_function(
            BenchmarkId::from_parameter(format!("2^{trial_bits}_trials_{POW_BITS}_bits")),
            |b| {
                b.iter(|| {
                    let mut transcript = challenger.clone();
                    let mut encoder = workspace.begin(context).unwrap();
                    let result = plan
                        .encode(
                            &mut encoder,
                            &transcript,
                            0,
                            [&buffers[0], &buffers[1], &buffers[2]],
                        )
                        .unwrap();
                    encoder.submit().unwrap().finish().unwrap();
                    result.readback(context, &mut transcript).unwrap()
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_arithmetic, bench_coset_lde, bench_merkle_commitment, bench_fri_fold, bench_pow
);
criterion_main!(benches);
