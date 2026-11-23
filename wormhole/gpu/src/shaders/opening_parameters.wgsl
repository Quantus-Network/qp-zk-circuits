@group(0) @binding(0) var<storage, read_write> output: array<vec2<u64>>;
@group(0) @binding(1) var<storage, read> scalars: array<vec2<u64>>;
// all-polynomial opening count, next-row opening count, unused, unused
@group(0) @binding(2) var<uniform> dims: vec4<u32>;
@compute @workgroup_size(64)
fn weights(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i >= dims.x + dims.y { return; }
    var power = i;
    if i >= dims.x { power -= dims.x; }
    output[i] = ext_pow(scalars[0], power);
}
