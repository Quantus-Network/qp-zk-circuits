//! Generic serializable layouts for plonky2 targets.
//!
//! These types are reusable across layer-0 and layer-1 aggregation circuits.
//! They only encode target indices (virtual targets), plus nested proof target structure.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use plonky2::fri::proof::{
    FriInitialTreeProofTarget, FriProofTarget, FriQueryRoundTarget, FriQueryStepTarget,
};
use plonky2::gadgets::polynomial::PolynomialCoeffsExtTarget;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::MerkleCapTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::{OpeningSetTarget, ProofTarget, ProofWithPublicInputsTarget};

//
// ---- Base target index layout ----
//

/// Serializable form of a plonky2 `Target`.
///
/// We intentionally only support virtual targets for persisted layouts.
/// All targets used by `add_virtual_*` APIs fall into this category.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TargetLayout {
    pub virtual_index: usize,
}

impl TargetLayout {
    pub fn try_from_target(t: Target) -> Result<Self> {
        match t {
            Target::VirtualTarget { index } => Ok(Self {
                virtual_index: index,
            }),
            other => Err(anyhow!(
                "TargetLayout only supports virtual targets; got {:?}",
                other
            )),
        }
    }

    pub fn to_runtime(self) -> Target {
        Target::VirtualTarget {
            index: self.virtual_index,
        }
    }
}

//
// ---- Hash / Merkle ----
//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashOutTargetLayout {
    pub elements: [TargetLayout; 4],
}

impl HashOutTargetLayout {
    pub fn from_runtime(h: &HashOutTarget) -> Result<Self> {
        Ok(Self {
            elements: [
                TargetLayout::try_from_target(h.elements[0])?,
                TargetLayout::try_from_target(h.elements[1])?,
                TargetLayout::try_from_target(h.elements[2])?,
                TargetLayout::try_from_target(h.elements[3])?,
            ],
        })
    }

    pub fn to_runtime(&self) -> HashOutTarget {
        HashOutTarget {
            elements: [
                self.elements[0].to_runtime(),
                self.elements[1].to_runtime(),
                self.elements[2].to_runtime(),
                self.elements[3].to_runtime(),
            ],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleCapTargetLayout {
    pub nodes: Vec<HashOutTargetLayout>,
}

impl MerkleCapTargetLayout {
    pub fn from_runtime(cap: &MerkleCapTarget) -> Result<Self> {
        let mut nodes = Vec::with_capacity(cap.0.len());
        for h in &cap.0 {
            nodes.push(HashOutTargetLayout::from_runtime(h)?);
        }
        Ok(Self { nodes })
    }

    pub fn to_runtime(&self) -> MerkleCapTarget {
        MerkleCapTarget(self.nodes.iter().map(|h| h.to_runtime()).collect())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProofTargetLayout {
    pub siblings: Vec<HashOutTargetLayout>,
}

impl MerkleProofTargetLayout {
    pub fn from_runtime(p: &MerkleProofTarget) -> Result<Self> {
        let mut siblings = Vec::with_capacity(p.siblings.len());
        for h in &p.siblings {
            siblings.push(HashOutTargetLayout::from_runtime(h)?);
        }
        Ok(Self { siblings })
    }

    pub fn to_runtime(&self) -> MerkleProofTarget {
        MerkleProofTarget {
            siblings: self.siblings.iter().map(|h| h.to_runtime()).collect(),
        }
    }
}

//
// ---- Extension / polynomial ----
//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtensionTargetLayout<const D: usize> {
    /// Stored as Vec for serde compatibility (serde doesn't derive for [T; D] const-generic arrays).
    /// Must always have length D.
    pub coeffs: Vec<TargetLayout>,
}

impl<const D: usize> ExtensionTargetLayout<D> {
    pub fn from_runtime(x: &ExtensionTarget<D>) -> Result<Self> {
        let mut coeffs = Vec::with_capacity(D);
        for t in x.0.iter() {
            coeffs.push(TargetLayout::try_from_target(*t)?);
        }
        Ok(Self { coeffs })
    }

    pub fn to_runtime(&self) -> ExtensionTarget<D> {
        assert!(
            self.coeffs.len() == D,
            "ExtensionTargetLayout coeffs len {} != D {}",
            self.coeffs.len(),
            D
        );

        ExtensionTarget(core::array::from_fn(|i| self.coeffs[i].to_runtime()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolynomialCoeffsExtTargetLayout<const D: usize> {
    pub coeffs: Vec<ExtensionTargetLayout<D>>,
}

impl<const D: usize> PolynomialCoeffsExtTargetLayout<D> {
    pub fn from_runtime(p: &PolynomialCoeffsExtTarget<D>) -> Result<Self> {
        let mut coeffs = Vec::with_capacity(p.0.len());
        for e in &p.0 {
            coeffs.push(ExtensionTargetLayout::from_runtime(e)?);
        }
        Ok(Self { coeffs })
    }

    pub fn to_runtime(&self) -> PolynomialCoeffsExtTarget<D> {
        PolynomialCoeffsExtTarget(self.coeffs.iter().map(|e| e.to_runtime()).collect())
    }
}

//
// ---- FRI ----
//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriInitialTreeProofTargetLayout {
    pub evals_proofs: Vec<(Vec<TargetLayout>, MerkleProofTargetLayout)>,
}

impl FriInitialTreeProofTargetLayout {
    pub fn from_runtime(p: &FriInitialTreeProofTarget) -> Result<Self> {
        let mut evals_proofs = Vec::with_capacity(p.evals_proofs.len());
        for (evals, proof) in &p.evals_proofs {
            let mut evals_layout = Vec::with_capacity(evals.len());
            for t in evals {
                evals_layout.push(TargetLayout::try_from_target(*t)?);
            }
            evals_proofs.push((evals_layout, MerkleProofTargetLayout::from_runtime(proof)?));
        }
        Ok(Self { evals_proofs })
    }

    pub fn to_runtime(&self) -> FriInitialTreeProofTarget {
        FriInitialTreeProofTarget {
            evals_proofs: self
                .evals_proofs
                .iter()
                .map(|(evals, proof)| {
                    (
                        evals.iter().map(|t| t.to_runtime()).collect(),
                        proof.to_runtime(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriQueryStepTargetLayout<const D: usize> {
    pub evals: Vec<ExtensionTargetLayout<D>>,
    pub merkle_proof: MerkleProofTargetLayout,
}

impl<const D: usize> FriQueryStepTargetLayout<D> {
    pub fn from_runtime(s: &FriQueryStepTarget<D>) -> Result<Self> {
        let mut evals = Vec::with_capacity(s.evals.len());
        for e in &s.evals {
            evals.push(ExtensionTargetLayout::from_runtime(e)?);
        }
        Ok(Self {
            evals,
            merkle_proof: MerkleProofTargetLayout::from_runtime(&s.merkle_proof)?,
        })
    }

    pub fn to_runtime(&self) -> FriQueryStepTarget<D> {
        FriQueryStepTarget {
            evals: self.evals.iter().map(|e| e.to_runtime()).collect(),
            merkle_proof: self.merkle_proof.to_runtime(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriQueryRoundTargetLayout<const D: usize> {
    pub initial_trees_proof: FriInitialTreeProofTargetLayout,
    pub steps: Vec<FriQueryStepTargetLayout<D>>,
}

impl<const D: usize> FriQueryRoundTargetLayout<D> {
    pub fn from_runtime(r: &FriQueryRoundTarget<D>) -> Result<Self> {
        Ok(Self {
            initial_trees_proof: FriInitialTreeProofTargetLayout::from_runtime(
                &r.initial_trees_proof,
            )?,
            steps: r
                .steps
                .iter()
                .map(FriQueryStepTargetLayout::from_runtime)
                .collect::<Result<Vec<_>>>()?,
        })
    }

    pub fn to_runtime(&self) -> FriQueryRoundTarget<D> {
        FriQueryRoundTarget {
            initial_trees_proof: self.initial_trees_proof.to_runtime(),
            steps: self.steps.iter().map(|s| s.to_runtime()).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriProofTargetLayout<const D: usize> {
    pub commit_phase_merkle_caps: Vec<MerkleCapTargetLayout>,
    pub query_round_proofs: Vec<FriQueryRoundTargetLayout<D>>,
    pub final_poly: PolynomialCoeffsExtTargetLayout<D>,
    pub pow_witness: TargetLayout,
}

impl<const D: usize> FriProofTargetLayout<D> {
    pub fn from_runtime(p: &FriProofTarget<D>) -> Result<Self> {
        Ok(Self {
            commit_phase_merkle_caps: p
                .commit_phase_merkle_caps
                .iter()
                .map(MerkleCapTargetLayout::from_runtime)
                .collect::<Result<Vec<_>>>()?,
            query_round_proofs: p
                .query_round_proofs
                .iter()
                .map(FriQueryRoundTargetLayout::from_runtime)
                .collect::<Result<Vec<_>>>()?,
            final_poly: PolynomialCoeffsExtTargetLayout::from_runtime(&p.final_poly)?,
            pow_witness: TargetLayout::try_from_target(p.pow_witness)?,
        })
    }

    pub fn to_runtime(&self) -> FriProofTarget<D> {
        FriProofTarget {
            commit_phase_merkle_caps: self
                .commit_phase_merkle_caps
                .iter()
                .map(|c| c.to_runtime())
                .collect(),
            query_round_proofs: self
                .query_round_proofs
                .iter()
                .map(|q| q.to_runtime())
                .collect(),
            final_poly: self.final_poly.to_runtime(),
            pow_witness: self.pow_witness.to_runtime(),
        }
    }
}

//
// ---- PLONK proof targets ----
//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpeningSetTargetLayout<const D: usize> {
    pub constants: Vec<ExtensionTargetLayout<D>>,
    pub plonk_sigmas: Vec<ExtensionTargetLayout<D>>,
    pub wires: Vec<ExtensionTargetLayout<D>>,
    pub plonk_zs: Vec<ExtensionTargetLayout<D>>,
    pub plonk_zs_next: Vec<ExtensionTargetLayout<D>>,
    pub partial_products: Vec<ExtensionTargetLayout<D>>,
    pub quotient_polys: Vec<ExtensionTargetLayout<D>>,
    pub lookup_zs: Vec<ExtensionTargetLayout<D>>,
    pub next_lookup_zs: Vec<ExtensionTargetLayout<D>>,
}

impl<const D: usize> OpeningSetTargetLayout<D> {
    fn map_ext(v: &[ExtensionTarget<D>]) -> Result<Vec<ExtensionTargetLayout<D>>> {
        v.iter().map(ExtensionTargetLayout::from_runtime).collect()
    }

    fn map_ext_back(v: &[ExtensionTargetLayout<D>]) -> Vec<ExtensionTarget<D>> {
        v.iter().map(|x| x.to_runtime()).collect()
    }

    pub fn from_runtime(o: &OpeningSetTarget<D>) -> Result<Self> {
        Ok(Self {
            constants: Self::map_ext(&o.constants)?,
            plonk_sigmas: Self::map_ext(&o.plonk_sigmas)?,
            wires: Self::map_ext(&o.wires)?,
            plonk_zs: Self::map_ext(&o.plonk_zs)?,
            plonk_zs_next: Self::map_ext(&o.plonk_zs_next)?,
            partial_products: Self::map_ext(&o.partial_products)?,
            quotient_polys: Self::map_ext(&o.quotient_polys)?,
            lookup_zs: Self::map_ext(&o.lookup_zs)?,
            next_lookup_zs: Self::map_ext(&o.next_lookup_zs)?,
        })
    }

    pub fn to_runtime(&self) -> OpeningSetTarget<D> {
        OpeningSetTarget {
            constants: Self::map_ext_back(&self.constants),
            plonk_sigmas: Self::map_ext_back(&self.plonk_sigmas),
            wires: Self::map_ext_back(&self.wires),
            plonk_zs: Self::map_ext_back(&self.plonk_zs),
            plonk_zs_next: Self::map_ext_back(&self.plonk_zs_next),
            partial_products: Self::map_ext_back(&self.partial_products),
            quotient_polys: Self::map_ext_back(&self.quotient_polys),
            lookup_zs: Self::map_ext_back(&self.lookup_zs),
            next_lookup_zs: Self::map_ext_back(&self.next_lookup_zs),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofTargetLayout<const D: usize> {
    pub wires_cap: MerkleCapTargetLayout,
    pub plonk_zs_partial_products_cap: MerkleCapTargetLayout,
    pub quotient_polys_cap: MerkleCapTargetLayout,
    pub openings: OpeningSetTargetLayout<D>,
    pub opening_proof: FriProofTargetLayout<D>,
}

impl<const D: usize> ProofTargetLayout<D> {
    pub fn from_runtime(p: &ProofTarget<D>) -> Result<Self> {
        Ok(Self {
            wires_cap: MerkleCapTargetLayout::from_runtime(&p.wires_cap)?,
            plonk_zs_partial_products_cap: MerkleCapTargetLayout::from_runtime(
                &p.plonk_zs_partial_products_cap,
            )?,
            quotient_polys_cap: MerkleCapTargetLayout::from_runtime(&p.quotient_polys_cap)?,
            openings: OpeningSetTargetLayout::from_runtime(&p.openings)?,
            opening_proof: FriProofTargetLayout::from_runtime(&p.opening_proof)?,
        })
    }

    pub fn to_runtime(&self) -> ProofTarget<D> {
        ProofTarget {
            wires_cap: self.wires_cap.to_runtime(),
            plonk_zs_partial_products_cap: self.plonk_zs_partial_products_cap.to_runtime(),
            quotient_polys_cap: self.quotient_polys_cap.to_runtime(),
            openings: self.openings.to_runtime(),
            opening_proof: self.opening_proof.to_runtime(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofWithPublicInputsTargetLayout<const D: usize> {
    pub proof: ProofTargetLayout<D>,
    pub public_inputs: Vec<TargetLayout>,
}

impl<const D: usize> ProofWithPublicInputsTargetLayout<D> {
    pub fn from_runtime(p: &ProofWithPublicInputsTarget<D>) -> Result<Self> {
        let mut public_inputs = Vec::with_capacity(p.public_inputs.len());
        for t in &p.public_inputs {
            public_inputs.push(TargetLayout::try_from_target(*t)?);
        }

        Ok(Self {
            proof: ProofTargetLayout::from_runtime(&p.proof)?,
            public_inputs,
        })
    }

    pub fn to_runtime(&self) -> Result<ProofWithPublicInputsTarget<D>> {
        Ok(ProofWithPublicInputsTarget {
            proof: self.proof.to_runtime(),
            public_inputs: self.public_inputs.iter().map(|t| t.to_runtime()).collect(),
        })
    }
}

//
// ---- Verifier target ----
//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierCircuitTargetLayout {
    pub constants_sigmas_cap: MerkleCapTargetLayout,
    pub circuit_digest: HashOutTargetLayout,
}

impl VerifierCircuitTargetLayout {
    pub fn from_runtime(v: &VerifierCircuitTarget) -> Result<Self> {
        Ok(Self {
            constants_sigmas_cap: MerkleCapTargetLayout::from_runtime(&v.constants_sigmas_cap)?,
            circuit_digest: HashOutTargetLayout::from_runtime(&v.circuit_digest)?,
        })
    }

    pub fn to_runtime(&self) -> VerifierCircuitTarget {
        VerifierCircuitTarget {
            constants_sigmas_cap: self.constants_sigmas_cap.to_runtime(),
            circuit_digest: self.circuit_digest.to_runtime(),
        }
    }
}

/// Small helpers for JSON persistence (handy for target layouts)
pub fn to_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value).context("serialize target layout to JSON")
}

pub fn from_json_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).context("deserialize target layout from JSON")
}
