use super::*;

#[test]
fn pow_ranges_and_snapshots_are_checked() -> Result<()> {
    for (bits, trials) in [(65, 1), (0, 0), (8, u32::MAX as usize + 1)] {
        assert!(validate_pow(bits, trials).is_err());
    }
    for bits in [0, 8, 64] {
        validate_pow(bits, 1)?;
    }
    let challenger = Challenger::<F, PoseidonHash>::new();
    assert_eq!(pow_snapshot(&challenger, 0)?, [F::ZERO; 14]);
    assert!(pow_snapshot(&challenger, F::ORDER).is_err());
    Ok(())
}

#[test]
#[ignore = "requires a hardware GPU with native u64 shader support"]
fn pow_matches_cpu_transcript_and_retries_without_advancing_on_exhaustion() -> Result<()> {
    use crate::ProofWorkspace;
    let context = futures::executor::block_on(DeviceContext::new())?;
    let kernels = Arc::new(PowKernels::prepare(
        &context,
        Arc::new(PoseidonKernels::prepare(&context)?),
    )?);
    let plan = PowPlan::prepare(&context, kernels.clone(), 8, 8192)?;
    let mut workspace = ProofWorkspace::prepare(&context, &plan.workspace_field_counts())?;
    let buffers = [
        workspace.buffer(0)?,
        workspace.buffer(1)?,
        workspace.buffer(2)?,
    ];
    let alias = buffers[2].slice(0..1)?;
    let mut encoder = workspace.begin(&context)?;
    assert_eq!(
        plan.encode(
            &mut encoder,
            &Challenger::new(),
            0,
            [&buffers[0], &alias, &buffers[2]],
        )
        .err()
        .unwrap()
        .to_string(),
        "FRI PoW atomic scratch and result must use separate buffers"
    );
    drop(encoder);
    for pending in 0..8 {
        let mut cpu = Challenger::<F, PoseidonHash>::new();
        cpu.observe_elements(
            &(0..13)
                .map(|i| -F::from_canonical_usize(i + 1))
                .collect::<Vec<_>>(),
        );
        cpu.get_n_challenges(3);
        cpu.observe_elements(
            &(0..pending)
                .map(|i| F::from_canonical_usize(i + 33))
                .collect::<Vec<_>>(),
        );
        assert_eq!(cpu.input_buffer().len(), pending);
        let mut expected = cpu.clone();
        let mut encoder = workspace.begin(&context)?;
        let result = plan.encode(
            &mut encoder,
            &cpu,
            100,
            [&buffers[0], &buffers[1], &buffers[2]],
        )?;
        encoder.submit()?.finish()?;
        let mut changed = cpu.clone();
        changed.observe_element(F::ONE);
        assert_eq!(
            result
                .readback(&context, &mut changed)
                .unwrap_err()
                .to_string(),
            "FRI PoW transcript changed before acceptance"
        );
        let nonce = result
            .readback(&context, &mut cpu)?
            .expect("deterministic fixture has a winner");
        expected.observe_element(nonce);
        assert!(expected.get_challenge().to_canonical_u64().leading_zeros() >= 8);
        assert_eq!(cpu.get_n_challenges(11), expected.get_n_challenges(11));
    }
    let mut cpu = Challenger::<F, PoseidonHash>::new();
    let single = PowPlan::prepare(&context, kernels.clone(), 8, 1)?;
    let response = |base| {
        let mut trial = cpu.clone();
        trial.observe_element(F::from_canonical_u64(base));
        trial.get_challenge()
    };
    let failed = (0..8192)
        .find(|&base| response(base).to_canonical_u64().leading_zeros() < 8)
        .unwrap();
    let successful = (failed + 1..8192)
        .find(|&base| response(base).to_canonical_u64().leading_zeros() >= 8)
        .unwrap();
    let before = pow_snapshot(&cpu, 0)?;
    let mut encoder = workspace.begin(&context)?;
    let result = single.encode(
        &mut encoder,
        &cpu,
        failed,
        [&buffers[0], &buffers[1], &buffers[2]],
    )?;
    encoder.submit()?.finish()?;
    assert_eq!(result.readback(&context, &mut cpu)?, None);
    assert_eq!(pow_snapshot(&cpu, 0)?, before);
    let mut encoder = workspace.begin(&context)?;
    let result = single.encode(
        &mut encoder,
        &cpu,
        successful,
        [&buffers[0], &buffers[1], &buffers[2]],
    )?;
    encoder.submit()?.finish()?;
    assert_eq!(
        result.readback(&context, &mut cpu)?,
        Some(F::from_canonical_u64(successful))
    );
    for (bits, base, trials) in [(64, 0, 1), (0, F::ORDER - 1, 67)] {
        let plan = PowPlan::prepare(&context, kernels.clone(), bits, trials)?;
        let before = cpu.clone();
        let mut expected = before.clone();
        expected.observe_element(F::from_canonical_u64(base));
        let valid = expected.get_challenge().to_canonical_u64().leading_zeros() >= bits;
        let mut encoder = workspace.begin(&context)?;
        let result = plan.encode(
            &mut encoder,
            &cpu,
            base,
            [&buffers[0], &buffers[1], &buffers[2]],
        )?;
        encoder.submit()?.finish()?;
        assert_eq!(
            result.readback(&context, &mut cpu)?,
            valid.then(|| F::from_canonical_u64(base))
        );
    }
    Ok(())
}
