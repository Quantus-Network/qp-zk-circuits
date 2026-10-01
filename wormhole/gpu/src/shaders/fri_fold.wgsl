@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
@group(0) @binding(2) var<storage, read> beta: array<vec2<u64>>;
// Coefficient count, arity, unused, unused.
@group(0) @binding(3) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn fold(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x + gid.y * 2097152u;
    let rows = dims.x / dims.y;
    if row >= rows { return; }
    var value = vec2<u64>(0lu);
    for (var i = dims.y; i > 0u; i -= 1u) {
        let index = row * dims.y + i - 1u;
        value = ext_add(ext_mul(value, beta[0]), vec2<u64>(input[index], input[dims.x + index]));
    }
    output[row] = value.x;
    output[rows + row] = value.y;
}
