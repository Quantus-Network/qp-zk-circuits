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

fn benchmark_storage_proof_circuits(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_proof_circuit_build");

    let mut rng = StdRng::seed_from_u64(12345); // Fixed seed for reproducible benchmarks

    // Case 1: Binary - always depth 256 (sparse merkle tree), arity 2
    let binary_depth = 256;
    let binary_leaf = generate_random_hash(&mut rng);
    let binary_siblings: Vec<HashOut<F>> = (0..binary_depth)
        .map(|_| generate_random_hash(&mut rng))
        .collect();
    let binary_path_indices: Vec<bool> = (0..binary_depth).map(|_| rng.gen()).collect();

    group.bench_function("binary_depth_256_arity_2", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let _root = binary_merkle_proof_circuit(
                &mut builder,
                binary_leaf,
                &binary_siblings,
                &binary_path_indices,
            );

            let _circuit = builder.build::<C>();
        });
    });

    // Case 2: Hexary - worst case depth 64, arity 16
    let hexary_depth = 64;
    let mut rng2 = StdRng::seed_from_u64(12345);
    let hexary_leaf = generate_random_hash(&mut rng2);
    let hexary_siblings_per_level: Vec<Vec<HashOut<F>>> = (0..hexary_depth)
        .map(|_| (0..15).map(|_| generate_random_hash(&mut rng2)).collect())
        .collect();
    let hexary_indices_per_level: Vec<usize> =
        (0..hexary_depth).map(|_| rng2.gen_range(0..16)).collect();

    group.bench_function("hexary_worst_depth_64_arity_16", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let _root = nary_merkle_proof_circuit(
                &mut builder,
                hexary_leaf,
                &hexary_siblings_per_level,
                &hexary_indices_per_level,
                16,
            );

            let _circuit = builder.build::<C>();
        });
    });

    // Case 2b: Hexary - average case depth 20, arity 16
    let hexary_avg_depth = 20;
    let hexary_avg_leaf = generate_random_hash(&mut rng2);
    let hexary_avg_siblings_per_level: Vec<Vec<HashOut<F>>> = (0..hexary_avg_depth)
        .map(|_| (0..15).map(|_| generate_random_hash(&mut rng2)).collect())
        .collect();
    let hexary_avg_indices_per_level: Vec<usize> = (0..hexary_avg_depth)
        .map(|_| rng2.gen_range(0..16))
        .collect();

    group.bench_function("hexary_avg_depth_20_arity_16", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let _root = nary_merkle_proof_circuit(
                &mut builder,
                hexary_avg_leaf,
                &hexary_avg_siblings_per_level,
                &hexary_avg_indices_per_level,
                16,
            );

            let _circuit = builder.build::<C>();
        });
    });

    // Case 3: 256-ary - worst case depth 32, arity 256
    let ary256_depth = 32;
    let mut rng3 = StdRng::seed_from_u64(12345);
    let ary256_leaf = generate_random_hash(&mut rng3);
    let ary256_siblings_per_level: Vec<Vec<HashOut<F>>> = (0..ary256_depth)
        .map(|_| (0..255).map(|_| generate_random_hash(&mut rng3)).collect())
        .collect();
    let ary256_indices_per_level: Vec<usize> =
        (0..ary256_depth).map(|_| rng3.gen_range(0..256)).collect();

    group.bench_function("256ary_worst_depth_32_arity_256", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let _root = nary_merkle_proof_circuit(
                &mut builder,
                ary256_leaf,
                &ary256_siblings_per_level,
                &ary256_indices_per_level,
                256,
            );

            let _circuit = builder.build::<C>();
        });
    });

    // Case 3b: 256-ary - average case depth 16, arity 256
    let ary256_avg_depth = 16;
    let ary256_avg_leaf = generate_random_hash(&mut rng3);
    let ary256_avg_siblings_per_level: Vec<Vec<HashOut<F>>> = (0..ary256_avg_depth)
        .map(|_| (0..255).map(|_| generate_random_hash(&mut rng3)).collect())
        .collect();
    let ary256_avg_indices_per_level: Vec<usize> = (0..ary256_avg_depth)
        .map(|_| rng3.gen_range(0..256))
        .collect();

    group.bench_function("256ary_avg_depth_16_arity_256", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let _root = nary_merkle_proof_circuit(
                &mut builder,
                ary256_avg_leaf,
                &ary256_avg_siblings_per_level,
                &ary256_avg_indices_per_level,
                256,
            );

            let _circuit = builder.build::<C>();
        });
    });

    group.finish();
}

fn benchmark_storage_proof_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_proof_proving_time");

    let mut rng = StdRng::seed_from_u64(98765); // Fixed seed for reproducible benchmarks

    // Case 1: Binary - always depth 256 (sparse merkle tree), arity 2
    let binary_depth = 256;
    let binary_leaf = generate_random_hash(&mut rng);
    let binary_siblings: Vec<HashOut<F>> = (0..binary_depth)
        .map(|_| generate_random_hash(&mut rng))
        .collect();
    let binary_path_indices: Vec<bool> = (0..binary_depth).map(|_| rng.gen()).collect();

    group.bench_function("binary_depth_256_arity_2", |b| {
        b.iter_batched(
            || {
                let config = CircuitConfig::standard_recursion_config();
                let mut builder = CircuitBuilder::<F, D>::new(config);
                let root_target = binary_merkle_proof_circuit(
                    &mut builder,
                    binary_leaf,
                    &binary_siblings,
                    &binary_path_indices,
                );
                builder.register_public_inputs(&root_target.elements);
                let data = builder.build::<C>();
                let pw = PartialWitness::new();
                (data, pw)
            },
            |(data, pw)| data.prove(pw).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    // Case 2: Hexary - worst case depth 64, arity 16
    let hexary_depth = 64;
    let mut rng2 = StdRng::seed_from_u64(98765);
    let hexary_leaf = generate_random_hash(&mut rng2);
    let hexary_siblings_per_level: Vec<Vec<HashOut<F>>> = (0..hexary_depth)
        .map(|_| (0..15).map(|_| generate_random_hash(&mut rng2)).collect())
        .collect();
    let hexary_indices_per_level: Vec<usize> =
        (0..hexary_depth).map(|_| rng2.gen_range(0..16)).collect();

    group.bench_function("hexary_worst_depth_64_arity_16", |b| {
        b.iter_batched(
            || {
                let config = CircuitConfig::standard_recursion_config();
                let mut builder = CircuitBuilder::<F, D>::new(config);
                let root_target = nary_merkle_proof_circuit(
                    &mut builder,
                    hexary_leaf,
                    &hexary_siblings_per_level,
                    &hexary_indices_per_level,
                    16,
                );
                builder.register_public_inputs(&root_target.elements);
                let data = builder.build::<C>();
                let pw = PartialWitness::new();
                (data, pw)
            },
            |(data, pw)| data.prove(pw).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    // Case 2b: Hexary - average case depth 20, arity 16
    let hexary_avg_depth = 20;
    let hexary_avg_leaf = generate_random_hash(&mut rng2);
    let hexary_avg_siblings_per_level: Vec<Vec<HashOut<F>>> = (0..hexary_avg_depth)
        .map(|_| (0..15).map(|_| generate_random_hash(&mut rng2)).collect())
        .collect();
    let hexary_avg_indices_per_level: Vec<usize> = (0..hexary_avg_depth)
        .map(|_| rng2.gen_range(0..16))
        .collect();

    group.bench_function("hexary_avg_depth_20_arity_16", |b| {
        b.iter_batched(
            || {
                let config = CircuitConfig::standard_recursion_config();
                let mut builder = CircuitBuilder::<F, D>::new(config);
                let root_target = nary_merkle_proof_circuit(
                    &mut builder,
                    hexary_avg_leaf,
                    &hexary_avg_siblings_per_level,
                    &hexary_avg_indices_per_level,
                    16,
                );
                builder.register_public_inputs(&root_target.elements);
                let data = builder.build::<C>();
                let pw = PartialWitness::new();
                (data, pw)
            },
            |(data, pw)| data.prove(pw).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    
    // Case 3: 256-ary - average case depth 16, arity 256
    let mut rng3 = StdRng::seed_from_u64(98765);
    let ary256_avg_depth = 10;
    let ary256_avg_leaf = generate_random_hash(&mut rng3);
    let ary256_avg_siblings_per_level: Vec<Vec<HashOut<F>>> = (0..ary256_avg_depth)
        .map(|_| (0..255).map(|_| generate_random_hash(&mut rng3)).collect())
        .collect();
    let ary256_avg_indices_per_level: Vec<usize> = (0..ary256_avg_depth)
        .map(|_| rng3.gen_range(0..256))
        .collect();

    group.bench_function("256ary_avg_depth_10_arity_256", |b| {
        b.iter_batched(
            || {
                let config = CircuitConfig::standard_recursion_config();
                let mut builder = CircuitBuilder::<F, D>::new(config);
                let root_target = nary_merkle_proof_circuit(
                    &mut builder,
                    ary256_avg_leaf,
                    &ary256_avg_siblings_per_level,
                    &ary256_avg_indices_per_level,
                    256,
                );
                builder.register_public_inputs(&root_target.elements);
                let data = builder.build::<C>();
                let pw = PartialWitness::new();
                (data, pw)
            },
            |(data, pw)| data.prove(pw).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
    
    // Case 3b: 256-ary - worst case depth 32, arity 256
    let ary256_depth = 32;
    let ary256_leaf = generate_random_hash(&mut rng3);
    let ary256_siblings_per_level: Vec<Vec<HashOut<F>>> = (0..ary256_depth)
        .map(|_| (0..255).map(|_| generate_random_hash(&mut rng3)).collect())
        .collect();
    let ary256_indices_per_level: Vec<usize> =
        (0..ary256_depth).map(|_| rng3.gen_range(0..256)).collect();

    group.bench_function("256ary_worst_depth_32_arity_256", |b| {
        b.iter_batched(
            || {
                let config = CircuitConfig::standard_recursion_config();
                let mut builder = CircuitBuilder::<F, D>::new(config);
                let root_target = nary_merkle_proof_circuit(
                    &mut builder,
                    ary256_leaf,
                    &ary256_siblings_per_level,
                    &ary256_indices_per_level,
                    256,
                );
                builder.register_public_inputs(&root_target.elements);
                let data = builder.build::<C>();
                let pw = PartialWitness::new();
                (data, pw)
            },
            |(data, pw)| data.prove(pw).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });


    group.finish();
}

criterion_group!(
    name = storage_proof_benches;
    config = Criterion::default().sample_size(10);
    targets =
        benchmark_storage_proof_circuits,
        benchmark_storage_proof_proving
);

criterion_main!(storage_proof_benches);
