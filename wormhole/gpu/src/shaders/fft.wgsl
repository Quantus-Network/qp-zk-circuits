@group(0) @binding(0) var<storage, read_write> data: array<u64>;
@group(0) @binding(1) var<storage, read> coeffs: array<u64>;
@group(0) @binding(2) var<storage, read> roots: array<u64>;
@group(0) @binding(3) var<storage, read> shifts: array<u64>;
// n, degree, log2(n), zero-padding bits for prepare / butterfly half-width
@group(0) @binding(4) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn prepare(@builtin(global_invocation_id) gid: vec3<u32>) {
    let linear = gid.x + gid.y * 2097152u;
    if (linear >= arrayLength(&data)) { return; }
    let column = linear / dims.x;
    let i = linear % dims.x;
    var k = 0u;
    // After bit reversal, a degree-n/2^r input has a nonzero value only
    // at each 2^r-th position. Replicate it across that block, which is
    // exactly the result of the first r butterfly rounds on the zero tail.
    if (dims.z > 0u) {
        let block_start = (i >> dims.w) << dims.w;
        k = reverseBits(block_start) >> (32u-dims.z);
    }
    var value = 0lu;
    if (k < dims.y) { value = gf64_canon(gf64_mul(coeffs[column * dims.y + k], shifts[k])); }
    data[linear] = value;
}

@compute @workgroup_size(64)
fn butterfly(@builtin(global_invocation_id) gid: vec3<u32>) {
    let linear = gid.x + gid.y * 2097152u;
    if (linear >= arrayLength(&data) / 2u) { return; }
    let column = linear / (dims.x / 2u);
    let i = linear % (dims.x / 2u);
    let half = dims.w;
    let j = i % half;
    let a = column * dims.x + (i / half) * (2u*half) + j;
    let b = a + half;
    let u = data[a];
    let v = gf64_canon(gf64_mul(data[b], roots[j * (dims.x / (2u*half))]));
    data[a] = gf64_canon(gf64_add(u, v));
    data[b] = gf64_canon(gf64_add(u, P64-v));
}

@compute @workgroup_size(64)
fn normalize(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if (i < arrayLength(&data)) { data[i] = gf64_canon(gf64_mul(data[i], shifts[i % dims.x])); }
}
