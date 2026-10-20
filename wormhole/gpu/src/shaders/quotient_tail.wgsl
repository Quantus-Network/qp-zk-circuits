@group(0) @binding(0) var<storage, read_write> status: array<atomic<u32>>;
@group(0) @binding(1) var<storage, read> coefficients: array<u64>;
// padded quotient rows, permitted coefficients per challenge, challenges
@group(0) @binding(2) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i >= arrayLength(&coefficients) { return; }
    if i % dims.x >= dims.y && gf64_canon(coefficients[i]) != 0lu {
        atomicOr(&status[0], 1u);
    }
}
