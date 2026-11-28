use super::commitment::PERMUTATION;
use super::{read, write, PoseidonKernels, FIELD};
use crate::runtime::{FieldBinding, KernelParams, PreparedKernel};
use crate::{DeviceContext, DeviceFieldSlice, ProofEncoder};
use anyhow::{ensure, Result};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::{Field, Field64, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::challenger::Challenger;
use std::sync::Arc;

/// Prepared FRI grinding pipelines sharing the commitment permutation/tables.
pub struct PowKernels {
    poseidon: Arc<PoseidonKernels>,
    initialize: PreparedKernel,
    search: PreparedKernel,
}

impl PowKernels {
    pub fn prepare(context: &DeviceContext, poseidon: Arc<PoseidonKernels>) -> Result<Self> {
        let source = format!(
            "{FIELD}\n{PERMUTATION}\n{}",
            include_str!("../shaders/pow.wgsl")
        );
        let specs = [write(1), read(14), read(12), read(12), read(999)];
        let prepare = |entry, label| {
            PreparedKernel::prepare_entry(context, &source, &specs, label, entry, true)
        };
        Ok(Self {
            poseidon,
            initialize: prepare("initialize", "FRI PoW initialization")?,
            search: prepare("search", "FRI PoW search")?,
        })
    }
}

/// One bounded, retryable nonce-search chunk. Every valid parallel winner is
/// acceptable; the protocol does not require the smallest valid nonce.
pub struct PowPlan {
    kernels: Arc<PowKernels>,
    bits: u32,
    trials: usize,
    groups: u32,
    params: KernelParams,
}

pub(crate) fn validate_pow(bits: u32, trials: usize) -> Result<()> {
    ensure!(
        bits <= 64,
        "FRI PoW difficulty exceeds field response width"
    );
    // u32::MAX is the atomic no-winner sentinel, never a candidate offset.
    ensure!(
        trials > 0 && trials <= u32::MAX as usize,
        "invalid FRI PoW trial count"
    );
    Ok(())
}

pub(crate) fn pow_snapshot(challenger: &Challenger<F, PoseidonHash>, base: u64) -> Result<[F; 14]> {
    ensure!(base < F::ORDER, "FRI PoW nonce base is not canonical");
    let mut snapshot = [F::ZERO; 14];
    snapshot[..12].copy_from_slice(challenger.sponge_state().as_ref());
    let pending = challenger.input_buffer();
    ensure!(pending.len() < 8, "invalid FRI PoW challenger input buffer");
    snapshot[..pending.len()].copy_from_slice(pending);
    snapshot[12] = F::from_canonical_usize(pending.len());
    snapshot[13] = F::from_canonical_u64(base);
    Ok(snapshot)
}

impl PowPlan {
    pub fn prepare(
        context: &DeviceContext,
        kernels: Arc<PowKernels>,
        bits: u32,
        trials: usize,
    ) -> Result<Self> {
        validate_pow(bits, trials)?;
        let groups = trials.div_ceil(64).min(256) as u32;
        Ok(Self {
            kernels,
            bits,
            trials,
            groups,
            params: context.prepare_params([bits, trials as u32, groups, 0])?,
        })
    }

    /// Snapshot (14) and winner offset (one field allocation).
    pub fn workspace_field_counts(&self) -> [usize; 2] {
        [14, 1]
    }

    /// Snapshot the CPU transcript without changing it, then encode a search
    /// starting at base. Candidates outside the canonical field range are skipped.
    pub fn encode(
        &self,
        encoder: &mut ProofEncoder<'_>,
        challenger: &Challenger<F, PoseidonHash>,
        base: u64,
        buffers: [&DeviceFieldSlice; 2],
    ) -> Result<PowResult> {
        ensure!(
            buffers
                .iter()
                .map(|buffer| buffer.len())
                .eq(self.workspace_field_counts()),
            "FRI PoW workspace shape mismatch"
        );
        let snapshot = pow_snapshot(challenger, base)?;
        encoder.upload(buffers[0], &snapshot)?;
        let bindings = [
            FieldBinding::ReadWrite(buffers[1]),
            FieldBinding::Read(buffers[0].into()),
            FieldBinding::Read((&self.kernels.poseidon.circ).into()),
            FieldBinding::Read((&self.kernels.poseidon.diag).into()),
            FieldBinding::Read((&self.kernels.poseidon.constants).into()),
        ];
        for (kernel, groups, label) in [
            (&self.kernels.initialize, 1, "FRI PoW initialization"),
            (&self.kernels.search, self.groups, "FRI PoW search"),
        ] {
            let group = encoder.bind_with_params(kernel, &bindings, Some(&self.params), label)?;
            encoder.dispatch(kernel, &group, [groups, 1, 1], label)?;
        }
        Ok(PowResult {
            winner: buffers[1].clone(),
            bits: self.bits,
            trials: self.trials,
            snapshot,
        })
    }
}

/// Small resident grinding result. Views pin allocations and are overwritten
/// on workspace reuse. Exhaustion is retryable, never an accepted witness.
pub struct PowResult {
    winner: DeviceFieldSlice,
    bits: u32,
    trials: usize,
    snapshot: [F; 14],
}

impl PowResult {
    /// After completion, validate the result with the CPU Challenger and consume
    /// exactly one PoW response. Return None on exhaustion; the transcript is
    /// unchanged on exhaustion or error. Successful acceptance advances it.
    pub fn readback(
        &self,
        context: &DeviceContext,
        challenger: &mut Challenger<F, PoseidonHash>,
    ) -> Result<Option<F>> {
        let base = self.snapshot[13].to_canonical_u64();
        ensure!(
            pow_snapshot(challenger, base)? == self.snapshot,
            "FRI PoW transcript changed before acceptance"
        );
        let winner = context.readback(&self.winner)?;
        ensure!(winner.len() == 1, "FRI PoW result shape mismatch");
        let offset = winner[0].to_canonical_u64();
        if offset == u64::from(u32::MAX) {
            return Ok(None);
        }
        ensure!(
            offset < self.trials as u64,
            "FRI PoW offset is outside the search range"
        );
        let nonce = base + offset;
        ensure!(nonce < F::ORDER, "FRI PoW nonce is not canonical");
        let nonce = F::from_canonical_u64(nonce);
        let mut advanced = challenger.clone();
        advanced.observe_element(nonce);
        let response = advanced.get_challenge();
        ensure!(
            response.to_canonical_u64().leading_zeros() >= self.bits,
            "invalid FRI PoW response"
        );
        *challenger = advanced;
        Ok(Some(nonce))
    }
}

#[cfg(test)]
mod tests;
