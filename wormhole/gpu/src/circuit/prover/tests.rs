use super::*;
use crate::DeviceOptions;
use plonky2::fri::FriReductionStrategy;
use plonky2::iop::target::Target;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{layer::Context as TraceContext, prelude::*, registry::LookupSpan, Layer};

#[derive(Clone, Default)]
struct HostSpans(Arc<Mutex<BTreeMap<String, u64>>>);

#[derive(Default)]
struct HostFields {
    name: String,
    elapsed: Option<u64>,
}

impl tracing::field::Visit for HostFields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if matches!(field.name(), "operation" | "phase") {
            self.name = value.to_owned();
        }
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "elapsed_ns" {
            self.elapsed = Some(value);
        }
    }
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl<S: tracing::Subscriber + for<'lookup> LookupSpan<'lookup>> Layer<S> for HostSpans {
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        context: TraceContext<'_, S>,
    ) {
        let mut fields = HostFields::default();
        attributes.record(&mut fields);
        context.span(id).unwrap().extensions_mut().insert(fields);
    }
    fn on_record(
        &self,
        id: &tracing::span::Id,
        record: &tracing::span::Record<'_>,
        context: TraceContext<'_, S>,
    ) {
        let mut fields = HostFields::default();
        record.record(&mut fields);
        if let Some(elapsed) = fields.elapsed {
            let span = context.span(id).unwrap();
            let extensions = span.extensions();
            let name = &extensions.get::<HostFields>().unwrap().name;
            *self.0.lock().unwrap().entry(name.clone()).or_default() += elapsed;
        }
    }
}

/// A circuit small enough to prove quickly whose FRI still has two
/// reduction rounds and a grind.
fn two_round_fri_circuit() -> (CircuitData<F, C, 2>, Target) {
    let mut config = CircuitConfig::standard_recursion_config();
    config.fri_config.reduction_strategy = FriReductionStrategy::Fixed(vec![1, 1]);
    config.fri_config.proof_of_work_bits = 8;
    config.security_bits = 80;
    let mut builder = CircuitBuilder::<F, 2>::new(config);
    let input = builder.add_virtual_target();
    let square = builder.mul(input, input);
    builder.register_public_input(square);
    // Pad enough rows for both reductions and the configured cap; do not
    // rely on public-input hashing to supply the padding rows.
    for _ in 0..16 {
        builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
    }
    (builder.build::<C>(), input)
}

fn prove_two_inputs_on_one_workspace(context: &DeviceContext) -> Result<()> {
    let (circuit, input) = two_round_fri_circuit();
    let prepared = PreparedCircuit::prepare(context, &circuit, PreparationOptions::default())?;
    let mut workspace = prepared.prepare_workspace(context)?;
    for value in [F::from_canonical_usize(3), F::from_canonical_usize(5)] {
        let mut inputs = PartialWitness::new();
        inputs.set_target(input, value)?;
        let proof = prepared.prove(context, &mut workspace, inputs)?;
        assert_eq!(proof.public_inputs, [value * value]);
        assert_eq!(proof.proof.opening_proof.commit_phase_merkle_caps.len(), 2);
        circuit.verify(proof)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn coordinator_generates_verifiable_proofs_with_fri_and_reuses_workspace() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    prove_two_inputs_on_one_workspace(&context)
}

#[test]
#[ignore = "requires hardware timestamp queries and native u64 shaders"]
fn profiled_coordinator_records_every_host_span() -> Result<()> {
    let captured = HostSpans::default();
    let dispatcher = tracing::Dispatch::new(tracing_subscriber::registry().with(captured.clone()));
    tracing::dispatcher::with_default(&dispatcher, || -> Result<()> {
        let context = futures::executor::block_on(DeviceContext::with_options(DeviceOptions {
            timestamps: true,
            ..Default::default()
        }))?;
        // Callsite interest is a process-wide cache. A concurrent test that
        // proves without a subscriber can register a span callsite as
        // disabled in the window before this dispatcher's rebuild, so touch
        // every callsite once and rebuild before the measured run.
        prove_two_inputs_on_one_workspace(&context)?;
        tracing::callsite::rebuild_interest_cache();
        captured.0.lock().unwrap().clear();
        prove_two_inputs_on_one_workspace(&context)
    })?;
    let host = captured.0.lock().unwrap();
    for name in [
        "witness_generation",
        "gpu_prove",
        "wires",
        "permutation",
        "quotient",
        "openings",
        "fri_input_and_first_commitment",
        "fri_fold_and_next_commitment",
        "final_polynomial",
        "pow",
        "queries",
        "submit",
        "wait",
        "readback",
        "transcript",
        "timestamp_collection",
    ] {
        assert!(
            host.get(name).is_some_and(|&ns| ns > 0),
            "missing host measurement: {name}"
        );
    }
    assert!(host["gpu_prove"] >= host["wait"]);
    Ok(())
}

/// With one trial per dispatch the grind walks the nonce space one chunk at
/// a time through `next_pow_base`, so a proof only succeeds if the retry
/// path is correct. For a fixed partition witness proving is deterministic,
/// so the proof must be bit-identical to the single-chunk GPU proof and to
/// the CPU proof, nonce included.
#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn pow_grind_spanning_many_chunks_matches_single_chunk_and_cpu_proofs() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let mut config = CircuitConfig::standard_recursion_config();
    config.fri_config.reduction_strategy = FriReductionStrategy::Fixed(vec![]);
    config.fri_config.proof_of_work_bits = 6;
    config.security_bits = 80;
    let mut builder = CircuitBuilder::<F, 2>::new(config);
    let input = builder.add_virtual_target();
    let square = builder.mul(input, input);
    builder.register_public_input(square);
    let circuit = builder.build::<C>();
    let chunked = PreparedCircuit::prepare(
        &context,
        &circuit,
        PreparationOptions {
            pow_chunk_trials: 1,
            ..Default::default()
        },
    )?;
    assert_eq!(chunked.pow_chunk_trials(), 1);
    let single = PreparedCircuit::prepare(&context, &circuit, PreparationOptions::default())?;
    let mut chunked_workspace = chunked.prepare_workspace(&context)?;
    let mut single_workspace = single.prepare_workspace(&context)?;
    let mut saw_retry = false;
    for value in 1..=4u64 {
        let mut inputs = PartialWitness::new();
        inputs.set_target(input, F::from_canonical_u64(value))?;
        let partition = plonky2::iop::generator::generate_partial_witness(
            inputs,
            &circuit.prover_only,
            &circuit.common,
        )?;
        let cpu = plonky2::plonk::prover::prove_with_partition_witness(
            &circuit.prover_only,
            &circuit.common,
            partition.clone(),
            &mut plonky2::util::timing::TimingTree::default(),
        )?;
        let gpu_single = single.prove_with_partition_witness(
            &context,
            &mut single_workspace,
            partition.clone(),
        )?;
        let gpu_chunked =
            chunked.prove_with_partition_witness(&context, &mut chunked_workspace, partition)?;
        assert_eq!(gpu_chunked, gpu_single);
        assert_eq!(gpu_chunked, cpu);
        saw_retry |= gpu_chunked.proof.opening_proof.pow_witness != F::ZERO;
        circuit.verify(gpu_chunked)?;
    }
    assert!(saw_retry, "every grind succeeded on the first nonce");
    Ok(())
}

/// Witness values at the Goldilocks boundaries (p-1, the 2^32 split points,
/// 2^63) flow through upload, public-input hashing, wire LDEs, the
/// permutation argument and the quotient as canonical field elements, not
/// raw u64s. With a fixed partition witness the GPU proof must match the CPU
/// proof bit-for-bit.
#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn boundary_witness_values_prove_identically_to_cpu() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let mut config = CircuitConfig::standard_recursion_config();
    config.fri_config.reduction_strategy = FriReductionStrategy::Fixed(vec![1]);
    config.fri_config.proof_of_work_bits = 4;
    config.security_bits = 80;
    let mut builder = CircuitBuilder::<F, 2>::new(config);
    let inputs: [_; 4] = core::array::from_fn(|_| builder.add_virtual_target());
    builder.register_public_inputs(&inputs);
    let mut acc = builder.one();
    for &input in &inputs {
        acc = builder.mul(acc, input);
        let shifted = builder.mul_const(F::from_canonical_u64(1 << 32), input);
        builder.register_public_input(shifted);
    }
    builder.register_public_input(acc);
    for _ in 0..8 {
        builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
    }
    let circuit = builder.build::<C>();
    let prepared = PreparedCircuit::prepare(&context, &circuit, PreparationOptions::default())?;
    let mut workspace = prepared.prepare_workspace(&context)?;
    let edges = [
        F::NEG_ONE,
        F::from_canonical_u64((1 << 32) - 1),
        F::from_canonical_u64(1 << 32),
        F::from_canonical_u64((1 << 32) + 1),
        F::from_canonical_u64(1 << 63),
        F::from_canonical_u64(F::ORDER - (1 << 32)),
        F::ZERO,
        F::ONE,
    ];
    for assignment in [
        [edges[0], edges[1], edges[2], edges[3]],
        [edges[4], edges[5], edges[0], edges[0]],
        [edges[6], edges[0], edges[7], edges[4]],
    ] {
        let mut partial = PartialWitness::new();
        for (target, value) in inputs.iter().zip(assignment) {
            partial.set_target(*target, value)?;
        }
        let partition = plonky2::iop::generator::generate_partial_witness(
            partial,
            &circuit.prover_only,
            &circuit.common,
        )?;
        let cpu = plonky2::plonk::prover::prove_with_partition_witness(
            &circuit.prover_only,
            &circuit.common,
            partition.clone(),
            &mut plonky2::util::timing::TimingTree::default(),
        )?;
        let gpu = prepared.prove_with_partition_witness(&context, &mut workspace, partition)?;
        assert_eq!(gpu, cpu);
        let product = assignment.iter().copied().product::<F>();
        assert_eq!(gpu.public_inputs[..4], assignment);
        assert_eq!(*gpu.public_inputs.last().unwrap(), product);
        circuit.verify(gpu)?;
    }
    Ok(())
}

#[test]
fn workspace_ranges_and_pow_retries_are_checked() {
    let layout = ProvingWorkspaceLayout::new([&[1, 2], &[3], &[4, 5], &[6], &[], &[7, 8]]);
    assert_eq!(layout.first, [0, 2, 3, 5, 6, 6]);
    assert_eq!(layout.fields, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(next_pow_base(0, 17).unwrap(), 17);
    assert_eq!(next_pow_base(F::ORDER - 2, 1).unwrap(), F::ORDER - 1);
    assert!(next_pow_base(F::ORDER - 1, 1).is_err());
    assert!(next_pow_base(u64::MAX, 1).is_err());
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn coordinator_handles_zero_fri_rounds_and_reuses_workspace_after_input_errors() -> Result<()> {
    let context = futures::executor::block_on(DeviceContext::new())?;
    let mut config = CircuitConfig::standard_recursion_config();
    config.fri_config.reduction_strategy = FriReductionStrategy::Fixed(vec![]);
    config.fri_config.proof_of_work_bits = 8;
    config.security_bits = 80;
    let mut builder = CircuitBuilder::<F, 2>::new(config);
    let input = builder.add_virtual_target();
    let square = builder.mul(input, input);
    builder.register_public_input(square);
    let circuit = builder.build::<C>();
    assert!(circuit.common.fri_params.reduction_arity_bits.is_empty());
    let prepared = PreparedCircuit::prepare(&context, &circuit, PreparationOptions::default())?;
    let mut workspace = prepared.prepare_workspace(&context)?;
    assert_eq!(
        workspace.allocated_bytes(),
        prepared
            .proof_workspace_field_counts()
            .iter()
            .map(|&n| n as u64 * 8)
            .sum()
    );
    let incomplete = PartitionWitness::new(
        circuit.common.config.num_wires,
        circuit.common.degree(),
        &circuit.prover_only.representative_map,
    );
    assert_eq!(
        prepared
            .prove_with_partition_witness(&context, &mut workspace, incomplete.clone())
            .unwrap_err()
            .to_string(),
        "missing public-input witness value"
    );
    let mut wrong_shape = incomplete.clone();
    wrong_shape.degree *= 2;
    assert_eq!(
        prepared
            .prove_with_partition_witness(&context, &mut workspace, wrong_shape)
            .unwrap_err()
            .to_string(),
        "partition witness does not match prepared circuit"
    );
    let mut wrong_map = circuit.prover_only.representative_map.clone();
    wrong_map[0] = (wrong_map[0] + 1) % wrong_map.len();
    let mut wrong_witness = incomplete;
    wrong_witness.representative_map = &wrong_map;
    assert_eq!(
        prepared
            .prove_with_partition_witness(&context, &mut workspace, wrong_witness)
            .unwrap_err()
            .to_string(),
        "partition witness does not match prepared circuit"
    );
    // Two distinct inputs overwrite the same allocations and generate fresh
    // transcripts/proofs; neither the result nor the public inputs are cached.
    for value in [F::NEG_ONE, F::from_canonical_usize(2)] {
        let mut inputs = PartialWitness::new();
        inputs.set_target(input, value)?;
        let proof = prepared.prove(&context, &mut workspace, inputs)?;
        assert_eq!(proof.public_inputs, [value * value]);
        assert!(proof
            .proof
            .opening_proof
            .commit_phase_merkle_caps
            .is_empty());
        assert!(proof
            .proof
            .opening_proof
            .query_round_proofs
            .iter()
            .all(|round| round.steps.is_empty()));
        circuit.verify(proof)?;
    }
    Ok(())
}
