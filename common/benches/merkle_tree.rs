use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOut, poseidon2::Poseidon2Hash},
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::Hasher},
};
use qp_zk_circuits_common::circuit::{C, D, F};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Generate random field elements for merkle tree nodes
fn generate_random_hash(rng: &mut StdRng) -> HashOut<F> {
    let data = [
        F::from_canonical_u64(rng.gen()),
        F::from_canonical_u64(rng.gen()),
        F::from_canonical_u64(rng.gen()),
        F::from_canonical_u64(rng.gen()),
    ];
    Poseidon2Hash::hash_no_pad(&data)
}

/// Circuit implementation for binary merkle tree verification (arity 2)
fn binary_merkle_proof_circuit(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOut<F>,
    siblings: &[HashOut<F>],
    path_indices: &[bool],
) -> plonky2::hash::hash_types::HashOutTarget {
    let leaf_target = builder.constant_hash(leaf);
    let mut current = leaf_target;

    for (i, &sibling) in siblings.iter().enumerate() {
        let sibling_target = builder.constant_hash(sibling);
        let path_bit = builder.constant_bool(path_indices[i]);

        // Select left and right based on path bit
        let left_elements = current
            .elements
            .iter()
            .zip(sibling_target.elements.iter())
            .map(|(&c, &s)| builder.select(path_bit, c, s))
            .collect::<Vec<_>>();
        let right_elements = current
            .elements
            .iter()
            .zip(sibling_target.elements.iter())
            .map(|(&c, &s)| builder.select(path_bit, s, c))
            .collect::<Vec<_>>();

        // Hash the pair
        let mut combined = Vec::new();
        combined.extend_from_slice(&left_elements);
        combined.extend_from_slice(&right_elements);
        current = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(combined);
    }

    current
}

/// Circuit implementation for n-ary merkle tree verification
fn nary_merkle_proof_circuit(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOut<F>,
    siblings_per_level: &[Vec<HashOut<F>>], // For each level, siblings (arity-1 per level)
    indices_per_level: &[usize],            // Index within each group of arity
    arity: usize,
) -> plonky2::hash::hash_types::HashOutTarget {
    let leaf_target = builder.constant_hash(leaf);
    let mut current = leaf_target;

    for (_level, (siblings, &index)) in siblings_per_level
        .iter()
        .zip(indices_per_level.iter())
        .enumerate()
    {
        let mut input = Vec::new();

        // Build the input array for this level
        for i in 0..arity {
            if i == index {
                // This is our current node
                input.extend_from_slice(&current.elements);
            } else if i < siblings.len() + if i > index { 1 } else { 0 } {
                // This is a sibling
                let sibling_idx = if i > index { i - 1 } else { i };
                if sibling_idx < siblings.len() {
                    let sibling_target = builder.constant_hash(siblings[sibling_idx]);
                    input.extend_from_slice(&sibling_target.elements);
                } else {
                    // Pad with zeros
                    input.extend_from_slice(&[builder.zero(); 4]);
                }
            } else {
                // Pad with zeros
                input.extend_from_slice(&[builder.zero(); 4]);
            }
        }

        current = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(input);
    }

    current
}

/// Generic function to benchmark merkle proof circuit building
fn bench_merkle_circuit_build(c: &mut Criterion, name: &str, depth: usize, arity: usize) {
    let mut rng = StdRng::seed_from_u64(12345);

    c.bench_function(&format!("{}_circuit_build", name), move |b| {
        if arity == 2 {
            // Binary case
            let leaf = generate_random_hash(&mut rng);
            let siblings: Vec<HashOut<F>> =
                (0..depth).map(|_| generate_random_hash(&mut rng)).collect();
            let path_indices: Vec<bool> = (0..depth).map(|_| rng.gen()).collect();

            b.iter(|| {
                let config = CircuitConfig::standard_recursion_config();
                let mut builder = CircuitBuilder::<F, D>::new(config);

                let _root =
                    binary_merkle_proof_circuit(&mut builder, leaf, &siblings, &path_indices);

                let _circuit = builder.build::<C>();
            });
        } else {
            // N-ary case
            let leaf = generate_random_hash(&mut rng);
            let siblings_per_level: Vec<Vec<HashOut<F>>> = (0..depth)
                .map(|_| {
                    (0..arity - 1)
                        .map(|_| generate_random_hash(&mut rng))
                        .collect()
                })
                .collect();
            let indices_per_level: Vec<usize> =
                (0..depth).map(|_| rng.gen_range(0..arity)).collect();

            b.iter(|| {
                let config = CircuitConfig::standard_recursion_config();
                let mut builder = CircuitBuilder::<F, D>::new(config);

                let _root = nary_merkle_proof_circuit(
                    &mut builder,
                    leaf,
                    &siblings_per_level,
                    &indices_per_level,
                    arity,
                );

                let _circuit = builder.build::<C>();
            });
        }
    });
}

/// Generic function to benchmark merkle proof proving
fn bench_merkle_proving(c: &mut Criterion, name: &str, depth: usize, arity: usize) {
    let mut rng = StdRng::seed_from_u64(98765);

    c.bench_function(&format!("{}_proving", name), move |b| {
        if arity == 2 {
            // Binary case
            let leaf = generate_random_hash(&mut rng);
            let siblings: Vec<HashOut<F>> =
                (0..depth).map(|_| generate_random_hash(&mut rng)).collect();
            let path_indices: Vec<bool> = (0..depth).map(|_| rng.gen()).collect();

            b.iter_batched(
                || {
                    let config = CircuitConfig::standard_recursion_config();
                    let mut builder = CircuitBuilder::<F, D>::new(config);
                    let root_target =
                        binary_merkle_proof_circuit(&mut builder, leaf, &siblings, &path_indices);
                    builder.register_public_inputs(&root_target.elements);
                    let data = builder.build::<C>();
                    let pw = PartialWitness::new();
                    (data, pw)
                },
                |(data, pw)| data.prove(pw).unwrap(),
                criterion::BatchSize::SmallInput,
            )
        } else {
            // N-ary case
            let leaf = generate_random_hash(&mut rng);
            let siblings_per_level: Vec<Vec<HashOut<F>>> = (0..depth)
                .map(|_| {
                    (0..arity - 1)
                        .map(|_| generate_random_hash(&mut rng))
                        .collect()
                })
                .collect();
            let indices_per_level: Vec<usize> =
                (0..depth).map(|_| rng.gen_range(0..arity)).collect();

            b.iter_batched(
                || {
                    let config = CircuitConfig::standard_recursion_config();
                    let mut builder = CircuitBuilder::<F, D>::new(config);
                    let root_target = nary_merkle_proof_circuit(
                        &mut builder,
                        leaf,
                        &siblings_per_level,
                        &indices_per_level,
                        arity,
                    );
                    builder.register_public_inputs(&root_target.elements);
                    let data = builder.build::<C>();
                    let pw = PartialWitness::new();
                    (data, pw)
                },
                |(data, pw)| data.prove(pw).unwrap(),
                criterion::BatchSize::SmallInput,
            )
        }
    });
}

fn benchmark_storage_proof_circuits(c: &mut Criterion) {
    // Binary sparse merkle tree - always depth 256
    bench_merkle_circuit_build(c, "binary_depth_256_arity_2", 256, 2);

    // Hexary cases
    bench_merkle_circuit_build(c, "hexary_worst_depth_64_arity_16", 64, 16);
    bench_merkle_circuit_build(c, "hexary_avg_depth_20_arity_16", 20, 16);

    // 256-ary cases
    bench_merkle_circuit_build(c, "256ary_avg_depth_10_arity_256", 10, 256);
    bench_merkle_circuit_build(c, "256ary_worst_depth_32_arity_256", 32, 256);
}

fn benchmark_storage_proof_proving(c: &mut Criterion) {
    // Binary sparse merkle tree - always depth 256
    bench_merkle_proving(c, "binary_depth_256_arity_2", 256, 2);

    // Hexary cases
    bench_merkle_proving(c, "hexary_avg_depth_20_arity_16", 20, 16);
    bench_merkle_proving(c, "hexary_avg_depth_25_arity_16", 25, 16);
    bench_merkle_proving(c, "hexary_avg_depth_28_arity_16", 28, 16);
    bench_merkle_proving(c, "hexary_avg_depth_29_arity_16", 29, 16);
    bench_merkle_proving(c, "hexary_avg_depth_30_arity_16", 30, 16);
    bench_merkle_proving(c, "hexary_avg_depth_40_arity_16", 40, 16);
    bench_merkle_proving(c, "hexary_avg_depth_50_arity_16", 50, 16);
    bench_merkle_proving(c, "hexary_avg_depth_60_arity_16", 60, 16);
    bench_merkle_proving(c, "hexary_worst_depth_64_arity_16", 64, 16);

    // 256-ary cases - using smaller depths to avoid memory issues
    bench_merkle_proving(c, "256ary_small_depth_5_arity_256", 5, 256);
    bench_merkle_proving(c, "256ary_avg_depth_10_arity_256", 10, 256);
    bench_merkle_proving(c, "256ary_avg_depth_20_arity_256", 20, 256);
    bench_merkle_proving(c, "256ary_worst_depth_32_arity_256", 32, 256);
}

criterion_group!(
    name = storage_proof_benches;
    config = Criterion::default().sample_size(10);
    targets =
        benchmark_storage_proof_circuits,
        benchmark_storage_proof_proving
);

criterion_main!(storage_proof_benches);
