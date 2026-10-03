@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
@group(0) @binding(2) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if (i >= dims.x) { return; }
    let a = input[i];
    var value = 0lu;
    switch dims.y {
        case 0u: { value = gf64_add(a, input[dims.x + i]); }
        case 1u: { value = gf64_add(a, P64 - gf64_canon(input[dims.x + i])); }
        case 2u: { value = gf64_mul(a, input[dims.x + i]); }
        case 3u: { value = gf64_sqr(a); }
        case 4u: { value = gf64_sbox(a); }
        default: {}
    }
    output[i] = gf64_canon(value);
}
