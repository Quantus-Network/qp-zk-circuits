use super::*;
use plonky2::field::types::Field;
use qp_wormhole_gpu::{DeviceContext, PreparationOptions};

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn gpu_backend_proves_through_aggregator_and_cloned_workers() -> Result<()> {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PublicBatchProver>();
    assert_send_sync::<ProvingContext>();
    let (prover, inner, private_batch_verifier) =
        crate::public_batch::prover::lib::tests::gpu_fixture();
    let context = Arc::new(futures::executor::block_on(DeviceContext::new())?);
    let options = PreparationOptions::default();
    let address = BytesDigest::try_from([7u8; 32])?;
    let proving = ProvingContext {
        aggregator_address: address,
        verifier: prover.verifier_data(),
        private_batch_verifier: private_batch_verifier.clone(),
        prover: Arc::new(prover),
    };
    let cpu_proof = proving.prove_batch(vec![inner.clone()])?;
    let mut aggregator = PublicBatchAggregator {
        pool: ProofPool::new(private_batch_verifier, 1, 1, PoolLimits::default())?,
        proving,
    };
    let key = aggregator.push_proof(inner.clone())?;
    let circuit = Arc::clone(&aggregator.proving.prover.circuit_data);
    let saved_context = aggregator.proving_context();
    assert_eq!(
        aggregator
            .with_gpu(Arc::clone(&context), options)
            .unwrap_err()
            .to_string(),
        "select GPU backend before cloning the proving context"
    );
    // Failed setup preserves the aggregator, queued proof and cloned worker.
    assert_eq!(aggregator.pool.len(), 1);
    assert!(Arc::ptr_eq(
        &circuit,
        &aggregator.proving.prover.circuit_data
    ));
    assert_eq!(
        aggregator.snapshot_batch(&key)?[0].public_inputs,
        inner.public_inputs
    );
    saved_context.verify(cpu_proof.clone())?;
    drop(saved_context);

    let invalid_options = PreparationOptions {
        quotient_chunk_rows: 0,
        ..options
    };
    let error = aggregator
        .with_gpu(Arc::clone(&context), invalid_options)
        .unwrap_err();
    assert!(format!("{error:#}").contains("preparation resource limits must be nonzero"));
    assert_eq!(aggregator.pool.len(), 1);
    assert!(Arc::ptr_eq(
        &circuit,
        &aggregator.proving.prover.circuit_data
    ));
    let snapshot = aggregator.snapshot_batch(&key)?;
    let retry = aggregator.prove_batch(snapshot)?;
    assert_eq!(retry.public_inputs, cpu_proof.public_inputs);
    aggregator.verify(retry)?;

    aggregator.with_gpu(Arc::clone(&context), options)?;
    // Invalid options must not release a working GPU backend.
    let context_owners = Arc::strong_count(&context);
    let error = aggregator
        .with_gpu(Arc::clone(&context), invalid_options)
        .unwrap_err();
    assert!(format!("{error:#}").contains("preparation resource limits must be nonzero"));
    assert_eq!(Arc::strong_count(&context), context_owners);
    assert_eq!(aggregator.pool.len(), 1);
    // Exercise re-preparation on the same device context.
    aggregator.with_gpu(Arc::clone(&context), options)?;
    let worker = aggregator.proving_context();
    let mut invalid = inner.clone();
    invalid.public_inputs[0] += F::ONE;
    assert!(
        format!("{:#}", worker.prove_batch(vec![invalid]).unwrap_err())
            .contains("failed verification")
    );
    assert!(format!("{:#}", worker.prove_batch(vec![]).unwrap_err())
        .contains("no private-batch proofs"));
    let proof = aggregator.aggregate(&key)?;
    assert_eq!(proof.public_inputs, cpu_proof.public_inputs);
    aggregator.verify(proof.clone())?;
    assert_eq!(aggregator.pool.len(), 1);
    let mut wrong_address = worker.clone();
    wrong_address.aggregator_address = BytesDigest::try_from([8u8; 32])?;
    assert!(wrong_address
        .verify(proof)
        .unwrap_err()
        .to_string()
        .contains("does not match configured aggregator address"));
    let snapshot = aggregator.snapshot_batch(&key)?;
    // A cloned context is owned/Send, selects the same GPU backend and reuses
    // its prepared circuit/workspace, with no pool lock held during proving.
    let second = std::thread::spawn(move || worker.prove_batch(snapshot))
        .join()
        .map_err(|_| anyhow!("GPU proving worker panicked"))??;
    assert_eq!(second.public_inputs, cpu_proof.public_inputs);
    aggregator.verify(second)?;
    assert_eq!(aggregator.pool.len(), 1);
    Ok(())
}
