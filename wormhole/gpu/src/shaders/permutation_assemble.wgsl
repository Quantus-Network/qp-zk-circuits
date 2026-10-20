const CHUNKS: u32 = __CHUNKS__u;
@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> factors: array<u64>;
@group(0) @binding(2) var<storage, read> zs: array<u64>;
// trace rows, challenges, first oracle column, columns in this output batch
@group(0) @binding(3) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i >= arrayLength(&output) { return; }
    let column = dims.z + i / dims.x;
    let row = i % dims.x;
    if column < dims.y {
        output[i] = zs[column * dims.x + row];
    } else {
        let partial = column - dims.y;
        let challenge = partial / (CHUNKS - 1u);
        let chunk = partial % (CHUNKS - 1u);
        output[i] = gf64_canon(gf64_mul(zs[challenge * dims.x + row], factors[(challenge * CHUNKS + chunk) * dims.x + row]));
    }
}
