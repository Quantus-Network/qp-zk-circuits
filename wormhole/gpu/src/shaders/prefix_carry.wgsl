@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> prefixes: array<u64>;
@group(0) @binding(2) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i >= arrayLength(&output) { return; }
    let column = i / dims.x;
    let row = i % dims.x;
    output[i] = gf64_canon(gf64_mul(output[i], prefixes[column * dims.y + row / 256u]));
}
