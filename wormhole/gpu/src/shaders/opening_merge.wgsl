@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> quotient: array<u64>;
@group(0) @binding(2) var<storage, read> weights: array<vec2<u64>>;
// degree, accumulation weight index, accumulate, unused
@group(0) @binding(3) var<uniform> dims: vec4<u32>;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x + gid.y * 2097152u;
    if row >= dims.x { return; }
    var value = vec2<u64>(quotient[row], quotient[dims.x + row]);
    if dims.z != 0u { value = ext_add(value, ext_mul(weights[dims.y], vec2<u64>(output[row], output[dims.x + row]))); }
    output[row] = value.x;
    output[dims.x + row] = value.y;
}
