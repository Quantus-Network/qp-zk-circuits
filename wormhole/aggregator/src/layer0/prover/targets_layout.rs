//! Layer-0 aggregation prover target layout.
//!
//! This stores only the layer-0-specific target bundle shape:
//! - leaf verifier target
//! - N leaf proof targets
//! - N dummy nullifier targets
//!
//! The nested plonky2 target serialization is delegated to `crate::common::targets_layout`.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use plonky2::iop::target::Target;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use zk_circuits_common::circuit::D;

use crate::common::targets_layout::{
    from_json_bytes, to_json_bytes, ProofWithPublicInputsTargetLayout, TargetLayout,
    VerifierCircuitTargetLayout,
};

/// Runtime targets needed to fill a prebuilt Layer-0 aggregation circuit witness.
#[derive(Clone, Debug)]
pub struct Layer0RuntimeTargets<const D2: usize> {
    pub leaf_verifier_data_t: VerifierCircuitTarget,
    pub leaf_proof_targets: Vec<ProofWithPublicInputsTarget<D2>>,
    pub dummy_nullifier_targets: Vec<[Target; 4]>,
}

/// Serializable target layout for `Layer0RuntimeTargets`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Layer0TargetsLayout<const D2: usize> {
    pub version: u32,
    pub n_leaf: usize,

    pub leaf_verifier_data_t: VerifierCircuitTargetLayout,
    pub leaf_proof_targets: Vec<ProofWithPublicInputsTargetLayout<D2>>,
    pub dummy_nullifier_targets: Vec<[TargetLayout; 4]>,
}

impl<const D2: usize> Layer0TargetsLayout<D2> {
    pub const VERSION: u32 = 1;

    pub fn from_runtime(
        n_leaf: usize,
        leaf_verifier_data_t: &VerifierCircuitTarget,
        leaf_proof_targets: &[ProofWithPublicInputsTarget<D2>],
        dummy_nullifier_targets: &[[Target; 4]],
    ) -> Result<Self> {
        if leaf_proof_targets.len() != n_leaf {
            return Err(anyhow!(
                "leaf_proof_targets len {} != n_leaf {}",
                leaf_proof_targets.len(),
                n_leaf
            ));
        }
        if dummy_nullifier_targets.len() != n_leaf {
            return Err(anyhow!(
                "dummy_nullifier_targets len {} != n_leaf {}",
                dummy_nullifier_targets.len(),
                n_leaf
            ));
        }

        let mut proof_layouts = Vec::with_capacity(n_leaf);
        for pt in leaf_proof_targets {
            proof_layouts.push(ProofWithPublicInputsTargetLayout::from_runtime(pt)?);
        }

        let mut dummy_layouts = Vec::with_capacity(n_leaf);
        for dn in dummy_nullifier_targets {
            dummy_layouts.push([
                TargetLayout::try_from_target(dn[0])?,
                TargetLayout::try_from_target(dn[1])?,
                TargetLayout::try_from_target(dn[2])?,
                TargetLayout::try_from_target(dn[3])?,
            ]);
        }

        Ok(Self {
            version: Self::VERSION,
            n_leaf,
            leaf_verifier_data_t: VerifierCircuitTargetLayout::from_runtime(leaf_verifier_data_t)?,
            leaf_proof_targets: proof_layouts,
            dummy_nullifier_targets: dummy_layouts,
        })
    }

    pub fn to_runtime(&self) -> Result<Layer0RuntimeTargets<D2>> {
        if self.version != Self::VERSION {
            return Err(anyhow!(
                "unsupported Layer0TargetsLayout version {}, expected {}",
                self.version,
                Self::VERSION
            ));
        }

        if self.leaf_proof_targets.len() != self.n_leaf {
            return Err(anyhow!(
                "leaf_proof_targets len {} != n_leaf {}",
                self.leaf_proof_targets.len(),
                self.n_leaf
            ));
        }

        if self.dummy_nullifier_targets.len() != self.n_leaf {
            return Err(anyhow!(
                "dummy_nullifier_targets len {} != n_leaf {}",
                self.dummy_nullifier_targets.len(),
                self.n_leaf
            ));
        }

        let mut leaf_proof_targets = Vec::with_capacity(self.n_leaf);
        for pt in &self.leaf_proof_targets {
            leaf_proof_targets.push(pt.to_runtime()?);
        }

        let mut dummy_nullifier_targets = Vec::with_capacity(self.n_leaf);
        for dn in &self.dummy_nullifier_targets {
            dummy_nullifier_targets.push([
                dn[0].to_runtime(),
                dn[1].to_runtime(),
                dn[2].to_runtime(),
                dn[3].to_runtime(),
            ]);
        }

        Ok(Layer0RuntimeTargets {
            leaf_verifier_data_t: self.leaf_verifier_data_t.to_runtime(),
            leaf_proof_targets,
            dummy_nullifier_targets,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_json_bytes(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        from_json_bytes(bytes)
    }
}

/// Convenience aliases using your project-wide recursion degree `D`.
pub type Layer0TargetsLayoutD = Layer0TargetsLayout<D>;
pub type Layer0RuntimeTargetsD = Layer0RuntimeTargets<D>;
