//! Lower the dependency's backend-neutral gate expressions to WGSL. Permutation
//! and boundary terms follow plonk/vanishing_poly.rs; lookup circuits fail export.
use super::{read, table_size, write, FIELD};
use crate::runtime::{
    DeviceContext, DeviceFieldSlice, FieldBinding, FieldSource, KernelParams, PreparedKernel,
    ProofEncoder,
};
use anyhow::{ensure, Result};
use plonky2::constraint_export::{
    export_gate_constraints, ArithmeticNode, ConstraintInput, GateConstraintExpression,
    GateConstraintProgram,
};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::circuit_data::CommonCircuitData;
use std::fmt::Write;

/// Column-major row inputs. Scalars are separate: public-input hash (4), beta,
/// gamma, alpha (each num_challenges). Helpers x, L0(x), and 1/Z_H(x) are fixed
/// coset data, prepared once; next_zs are the rotated Z evaluations.
#[derive(Clone, Debug)]
pub struct QuotientLayout {
    pub constants: usize,
    pub sigmas: usize,
    pub wires: usize,
    pub zs: usize,
    pub partial_products: usize,
    pub next_zs: usize,
    pub x: usize,
    pub l0: usize,
    pub inverse_zero: usize,
    pub columns: usize,
    pub scalar_count: usize,
}

pub struct QuotientPlan {
    layout: QuotientLayout,
    rows: usize,
    challenges: usize,
    powers: PreparedKernel,
    permutation: PreparedKernel,
    gates: Vec<PreparedKernel>,
    params: KernelParams,
}

impl QuotientPlan {
    pub fn layout(&self) -> &QuotientLayout {
        &self.layout
    }

    /// Prepare a quotient row chunk. The caller gathers the columns described
    /// by layout; this operation does not gather oracle rows or interpolate the
    /// quotient coefficients. FFT interpolation is a separate prepared operation.
    pub fn prepare(
        context: &DeviceContext,
        common: &CommonCircuitData<F, 2>,
        rows: usize,
    ) -> Result<Self> {
        let program = export_gate_constraints(common)?;
        let challenges = common.config.num_challenges;
        let routed = common.config.num_routed_wires;
        let pp_degree = common.permutation_partial_product_degree();
        ensure!(
            challenges > 0 && routed > 0 && pp_degree > 1 && common.k_is.len() == routed,
            "unsupported permutation metadata"
        );
        ensure!(
            common.num_partial_products + 1 == routed.div_ceil(pp_degree),
            "partial-product count mismatch"
        );
        let layout = QuotientLayout::new(common);
        table_size(rows, layout.columns)?;
        table_size(rows, challenges)?;
        validate_program(&program)?;
        let prefix = challenges + challenges * (common.num_partial_products + 1);
        let power_source = format!("{FIELD}\n@group(0) @binding(0) var<storage,read_write> weights:array<u64>;\n@group(0) @binding(1) var<storage,read> scalars:array<u64>;\n@compute @workgroup_size(1) fn main() {{ for(var i=0u;i<{challenges}u;i++) {{ var power=1lu; for(var j=0u;j<{prefix}u;j++) {{ power=gf64_mul(power,scalars[{}u+i]); }} weights[i]=gf64_canon(power); }} }}", 4 + challenges * 2);
        let powers = PreparedKernel::prepare(
            context,
            &power_source,
            &[write(challenges), read(layout.scalar_count)],
            "quotient alpha powers",
        )?;
        let specs = [
            write(rows * challenges),
            read(rows * layout.columns),
            read(layout.scalar_count),
            read(challenges),
        ];
        let permutation_source = row_source(&permutation_body(common, &layout), layout.columns);
        let permutation = PreparedKernel::prepare_entry(
            context,
            &permutation_source,
            &specs,
            "quotient permutation and boundary",
            "main",
            true,
        )?;
        let mut gates = Vec::new();
        for gate in &program.gates {
            if let Some(body) = gate_body(gate, &layout, challenges) {
                gates.push(PreparedKernel::prepare_entry(
                    context,
                    &row_source(&body, layout.columns),
                    &specs,
                    &format!("quotient gate {}", gate.gate_id),
                    "main",
                    true,
                )?);
            }
        }
        Ok(Self {
            layout,
            rows,
            challenges,
            powers,
            permutation,
            gates,
            params: context.prepare_params([rows as u32, 0, 0, 0])?,
        })
    }

    /// Field counts for row input, per-proof scalars, shared alpha weights, and
    /// challenge-major quotient evaluations. No gate-residual matrix is stored.
    pub fn workspace_field_counts(&self) -> [usize; 4] {
        [
            self.rows * self.layout.columns,
            self.layout.scalar_count,
            self.challenges,
            self.rows * self.challenges,
        ]
    }

    pub fn encode<'a>(
        &self,
        encoder: &mut ProofEncoder<'_>,
        rows: impl Into<FieldSource<'a>>,
        scalars: impl Into<FieldSource<'a>>,
        weights: &DeviceFieldSlice,
        output: &DeviceFieldSlice,
    ) -> Result<()> {
        let rows = rows.into();
        let scalars = scalars.into();
        ensure!(
            [rows.len(), scalars.len(), weights.len(), output.len()]
                == self.workspace_field_counts(),
            "quotient buffer shape mismatch"
        );
        self.encode_weights(encoder, scalars, weights)?;
        self.encode_rows(encoder, rows, scalars, weights, output)
    }

    pub(crate) fn encode_weights<'a>(
        &self,
        encoder: &mut ProofEncoder<'_>,
        scalars: impl Into<FieldSource<'a>>,
        weights: &DeviceFieldSlice,
    ) -> Result<()> {
        let scalars = scalars.into();
        ensure!(
            scalars.len() == self.layout.scalar_count && weights.len() == self.challenges,
            "quotient weight buffer shape mismatch"
        );
        let group = encoder.bind(
            &self.powers,
            &[
                FieldBinding::ReadWrite(weights),
                FieldBinding::Read(scalars),
            ],
            "quotient alpha powers",
        )?;
        encoder.dispatch(&self.powers, &group, [1, 1, 1], "quotient alpha powers")?;
        Ok(())
    }

    pub(crate) fn encode_rows<'a>(
        &self,
        encoder: &mut ProofEncoder<'_>,
        rows: impl Into<FieldSource<'a>>,
        scalars: impl Into<FieldSource<'a>>,
        weights: &DeviceFieldSlice,
        output: &DeviceFieldSlice,
    ) -> Result<()> {
        let rows = rows.into();
        let scalars = scalars.into();
        ensure!(
            [rows.len(), scalars.len(), weights.len(), output.len()]
                == self.workspace_field_counts(),
            "quotient buffer shape mismatch"
        );
        let inputs = [
            FieldBinding::ReadWrite(output),
            FieldBinding::Read(rows),
            FieldBinding::Read(scalars),
            FieldBinding::Read(weights.into()),
        ];
        for kernel in std::iter::once(&self.permutation).chain(&self.gates) {
            let group = encoder.bind_with_params(
                kernel,
                &inputs,
                Some(&self.params),
                "quotient row evaluation",
            )?;
            encoder.dispatch_elements(kernel, &group, self.rows, "quotient row evaluation")?;
        }
        Ok(())
    }
}

impl QuotientLayout {
    pub(crate) fn new(common: &CommonCircuitData<F, 2>) -> Self {
        let c = common.config.num_challenges;
        let constants = 0;
        let sigmas = common.num_constants;
        let wires = sigmas + common.config.num_routed_wires;
        let zs = wires + common.config.num_wires;
        let partial_products = zs + c;
        let next_zs = partial_products + c * common.num_partial_products;
        let x = next_zs + c;
        let l0 = x + 1;
        let inverse_zero = l0 + 1;
        Self {
            constants,
            sigmas,
            wires,
            zs,
            partial_products,
            next_zs,
            x,
            l0,
            inverse_zero,
            columns: inverse_zero + 1,
            scalar_count: 4 + c * 3,
        }
    }
}

fn row_source(body: &str, columns: usize) -> String {
    format!("{FIELD}\n@group(0) @binding(0) var<storage,read_write> output:array<u64>;\n@group(0) @binding(1) var<storage,read> table:array<u64>;\n@group(0) @binding(2) var<storage,read> scalars:array<u64>;\n@group(0) @binding(3) var<storage,read> weights:array<u64>;\n@group(0) @binding(4) var<uniform> dims:vec4<u32>;\nfn read(column:u32,row:u32)->u64 {{ return table[column*dims.x+row]; }}\nfn sub(a:u64,b:u64)->u64 {{ return gf64_add(a,P64-gf64_canon(b)); }}\n@compute @workgroup_size(64) fn main(@builtin(global_invocation_id) gid:vec3<u32>) {{ let row=gid.x+gid.y*2097152u; if(row>=dims.x || {columns}u==0u){{return;}}\n{body}\n}}")
}

fn permutation_body(common: &CommonCircuitData<F, 2>, layout: &QuotientLayout) -> String {
    let c = common.config.num_challenges;
    let mut body = String::new();
    for k in 0..c {
        writeln!(body, "var sum{k}=0lu; var power{k}=1lu;").unwrap();
    }
    let mut add_term = |expression: String| {
        body.push_str("{\n");
        writeln!(body, "let term={expression};").unwrap();
        for k in 0..c {
            writeln!(body,"sum{k}=gf64_add(sum{k},gf64_mul(power{k},term)); power{k}=gf64_mul(power{k},scalars[{}u]);",4+2*c+k).unwrap();
        }
        body.push_str("}\n");
    };
    // Exact CPU term order: all boundary terms, all permutation checks, gates.
    for i in 0..c {
        add_term(format!(
            "gf64_mul(read({}u,row),sub(read({}u,row),1lu))",
            layout.l0,
            layout.zs + i
        ));
    }
    for i in 0..c {
        for chunk in 0..=common.num_partial_products {
            body.push_str("{ var numerator=1lu; var denominator=1lu;\n");
            let degree = common.permutation_partial_product_degree();
            for j in chunk * degree..((chunk + 1) * degree).min(common.config.num_routed_wires) {
                writeln!(body,"numerator=gf64_mul(numerator,gf64_add(read({}u,row),gf64_add(gf64_mul(scalars[{}u],gf64_mul({}lu,read({}u,row))),scalars[{}u])));",layout.wires+j,4+i,common.k_is[j].to_canonical_u64(),layout.x,4+c+i).unwrap();
                writeln!(body,"denominator=gf64_mul(denominator,gf64_add(read({}u,row),gf64_add(gf64_mul(scalars[{}u],read({}u,row)),scalars[{}u])));",layout.wires+j,4+i,layout.sigmas+j,4+c+i).unwrap();
            }
            let previous = if chunk == 0 {
                layout.zs + i
            } else {
                layout.partial_products + i * common.num_partial_products + chunk - 1
            };
            let next = if chunk == common.num_partial_products {
                layout.next_zs + i
            } else {
                layout.partial_products + i * common.num_partial_products + chunk
            };
            writeln!(body,"let term=sub(gf64_mul(read({previous}u,row),numerator),gf64_mul(read({next}u,row),denominator));").unwrap();
            for k in 0..c {
                writeln!(body,"sum{k}=gf64_add(sum{k},gf64_mul(power{k},term)); power{k}=gf64_mul(power{k},scalars[{}u]);",4+2*c+k).unwrap();
            }
            body.push_str("}\n");
        }
    }
    for k in 0..c {
        writeln!(
            body,
            "output[{k}u*dims.x+row]=gf64_canon(gf64_mul(sum{k},read({}u,row)));",
            layout.inverse_zero
        )
        .unwrap();
    }
    body
}

fn gate_body(
    gate: &GateConstraintExpression<F>,
    layout: &QuotientLayout,
    challenges: usize,
) -> Option<String> {
    // Ignore known-zero padding, not arbitrary runtime constraints.
    let last = gate.outputs.iter().rposition(
        |&index| !matches!(gate.nodes[index],ArithmeticNode::Constant(value) if value==F::ZERO),
    )?;
    let mut body = String::new();
    for (index, node) in gate.nodes.iter().enumerate() {
        let expression = match *node {
            ArithmeticNode::Constant(value) => format!("{}lu", value.to_canonical_u64()),
            ArithmeticNode::Input(ConstraintInput::Constant(column)) => {
                format!("read({column}u,row)")
            }
            ArithmeticNode::Input(ConstraintInput::Wire(column)) => {
                format!("read({}u,row)", layout.wires + column)
            }
            ArithmeticNode::Input(ConstraintInput::PublicInputHash(index)) => {
                format!("scalars[{index}u]")
            }
            ArithmeticNode::Add(a, b) => format!("gf64_add(v{a},v{b})"),
            ArithmeticNode::Mul(a, b) => format!("gf64_mul(v{a},v{b})"),
        };
        writeln!(body, "let v{index}={expression};").unwrap();
    }
    for k in 0..challenges {
        writeln!(body, "var sum{k}=0lu;").unwrap();
        for index in gate.outputs[..=last].iter().rev() {
            writeln!(
                body,
                "sum{k}=gf64_add(v{index},gf64_mul(sum{k},scalars[{}u]));",
                4 + 2 * challenges + k
            )
            .unwrap();
        }
        writeln!(body,"output[{k}u*dims.x+row]=gf64_canon(gf64_add(output[{k}u*dims.x+row],gf64_mul(gf64_mul(sum{k},weights[{k}u]),read({}u,row))));",layout.inverse_zero).unwrap();
    }
    Some(body)
}

fn validate_program(program: &GateConstraintProgram<F>) -> Result<()> {
    for gate in &program.gates {
        ensure!(
            gate.outputs.len() == program.num_constraints,
            "gate constraint count mismatch"
        );
        for (index, node) in gate.nodes.iter().enumerate() {
            match *node {
                ArithmeticNode::Add(a, b) | ArithmeticNode::Mul(a, b) => ensure!(
                    a < index && b < index,
                    "non-topological constraint expression"
                ),
                ArithmeticNode::Input(ConstraintInput::Constant(column)) => ensure!(
                    column < program.num_constants,
                    "constraint constant index out of range"
                ),
                ArithmeticNode::Input(ConstraintInput::Wire(column)) => ensure!(
                    column < program.num_wires,
                    "constraint wire index out of range"
                ),
                ArithmeticNode::Input(ConstraintInput::PublicInputHash(index)) => {
                    ensure!(index < 4, "constraint hash index out of range")
                }
                ArithmeticNode::Constant(_) => {}
            }
        }
        ensure!(
            gate.outputs.iter().all(|&index| index < gate.nodes.len()),
            "constraint output index out of range"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
