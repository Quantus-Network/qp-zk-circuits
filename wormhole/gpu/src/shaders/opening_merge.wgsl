@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> quotient: array<u64>;
@group(0) @binding(2) var<storage, read> scalars: array<vec2<u64>>;
// degree, exponent shifting previous batches, accumulate, unused
@group(0) @binding(3) var<uniform> dims: vec4<u32>;
var<workgroup> factor: vec2<u64>;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>, @builtin(local_invocation_index) lane: u32) {
    if lane == 0u { factor = ext_pow(scalars[1], dims.y); }
    workgroupBarrier();
    let row = gid.x + gid.y * 2097152u;
    if row >= dims.x { return; }
    var value = vec2<u64>(quotient[row], quotient[dims.x + row]);
    if dims.z != 0u { value = ext_add(value, ext_mul(factor, vec2<u64>(output[row], output[dims.x + row]))); }
    output[row] = value.x;
    output[dims.x + row] = value.y;
}
