use circuit_builder::generate_all_circuit_binaries;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_wormhole_aggregator::aggregator::{AggregationBackend, Layer0Aggregator};
use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use test_helpers::TestInputs;
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;
use zk_circuits_common::circuit::{C, D, F};

const SHIPPING_LAYER0_NUM_LEAVES: usize = 16;

type Proof = ProofWithPublicInputs<F, C, D>;

static BENCH_BINS_DIR: OnceLock<PathBuf> = OnceLock::new();

fn bench_bins_dir() -> &'static PathBuf {
    BENCH_BINS_DIR.get_or_init(|| {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX_EPOCH")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "qp-wormhole-aggregator-bench-{}-{}",
            std::process::id(),
            suffix
        ));

        create_dir_all(&dir).expect("failed to create benchmark bins dir");
        generate_all_circuit_binaries(&dir, true, SHIPPING_LAYER0_NUM_LEAVES, None)
            .expect("failed to generate shipping 2x8 circuit binaries for benches");
        dir
    })
}

fn load_leaf_proof(bins_dir: &Path) -> Proof {
    let prover_path = bins_dir.join("prover.bin");
    let common_path = bins_dir.join("common.bin");
    let prover = WormholeProver::new_from_files(&prover_path, &common_path)
        .expect("failed to load leaf prover from generated binaries");
    let inputs = CircuitInputs::test_inputs_0();

    prover
        .commit(&inputs)
        .expect("failed to commit leaf inputs")
        .prove()
        .expect("failed to prove leaf circuit")
}

fn setup_layer0_aggregate_case(
    bins_dir: &Path,
    leaf_proof: &Proof,
    count: usize,
) -> Layer0Aggregator {
    let mut aggregator = Layer0Aggregator::new(bins_dir)
        .expect("failed to load shipping layer-0 aggregator from generated binaries");

    for proof in std::iter::repeat_n(leaf_proof.clone(), count) {
        aggregator
            .push_proof(proof)
            .expect("failed to push leaf proof");
    }

    aggregator
}

fn setup_layer0_verify_case(
    bins_dir: &Path,
    leaf_proof: &Proof,
    count: usize,
) -> (Layer0Aggregator, Proof) {
    let mut aggregator = setup_layer0_aggregate_case(bins_dir, leaf_proof, count);
    let aggregated = aggregator
        .aggregate()
        .expect("failed to precompute aggregated proof for verify benchmark");

    (aggregator, aggregated)
}

macro_rules! bench_layer0_aggregate {
    ($fn_name:ident, $count:expr) => {
        fn $fn_name(c: &mut Criterion) {
            let bins_dir = bench_bins_dir().clone();
            let leaf_proof = load_leaf_proof(&bins_dir);

            c.bench_function(
                concat!("layer0_shipping_aggregate_", stringify!($count)),
                |b| {
                    b.iter_batched(
                        || setup_layer0_aggregate_case(&bins_dir, &leaf_proof, $count),
                        |mut aggregator| {
                            aggregator
                                .aggregate()
                                .expect("shipping layer-0 aggregation failed")
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

macro_rules! bench_layer0_verify {
    ($fn_name:ident, $count:expr) => {
        fn $fn_name(c: &mut Criterion) {
            let bins_dir = bench_bins_dir().clone();
            let leaf_proof = load_leaf_proof(&bins_dir);

            c.bench_function(
                concat!("layer0_shipping_verify_", stringify!($count)),
                |b| {
                    b.iter_batched(
                        || setup_layer0_verify_case(&bins_dir, &leaf_proof, $count),
                        |(aggregator, proof)| {
                            aggregator
                                .verify(proof)
                                .expect("shipping layer-0 verification failed")
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    };
}

bench_layer0_aggregate!(bench_layer0_aggregate_2, 2);
bench_layer0_aggregate!(bench_layer0_aggregate_4, 4);
bench_layer0_aggregate!(bench_layer0_aggregate_8, 8);
bench_layer0_aggregate!(bench_layer0_aggregate_16, 16);

bench_layer0_verify!(bench_layer0_verify_2, 2);
bench_layer0_verify!(bench_layer0_verify_4, 4);
bench_layer0_verify!(bench_layer0_verify_8, 8);
bench_layer0_verify!(bench_layer0_verify_16, 16);

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_layer0_aggregate_2,
        bench_layer0_aggregate_4,
        bench_layer0_aggregate_8,
        bench_layer0_aggregate_16,
        bench_layer0_verify_2,
        bench_layer0_verify_4,
        bench_layer0_verify_8,
        bench_layer0_verify_16,
);
criterion_main!(benches);
