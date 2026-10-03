// Poseidon1 adapter; field helpers included from the pinned Quantus miner.
// Fast partial rounds match qp-plonky2-core's Goldilocks Poseidon implementation.
struct Digest { elems: array<u64, 4>, }
@group(0) @binding(0) var<storage, read_write> output: array<Digest>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
@group(0) @binding(5) var<uniform> params: vec4<u32>;
@group(0) @binding(2) var<storage, read> mdsCirc: array<u64, 12>;
@group(0) @binding(3) var<storage, read> mdsDiag: array<u64, 12>;
// 360 ordinary round constants, then 12 first constants, 121 initial-matrix
// entries, 22 partial constants, 242 W-hat entries and 242 V entries.
@group(0) @binding(4) var<storage, read> rc: array<u64, 999>;


@compute @workgroup_size(64)
fn hash_leaves(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x + gid.y * 2097152u;
    if (row >= params.x) { return; }
    var state: array<u64, 12>;
    state[8] = u64(params.y + 1u);
    for (var start = 0u; start < params.y; start += 8u) {
        let n = min(8u, params.y - start);
        for (var lane = 0u; lane < n; lane++) {
            state[lane] = input[(start + lane) * params.x + row];
        }
        permute(&state);
    }
    for (var i = 0u; i < 4u; i++) {
        output[row].elems[i] = gf64_canon(state[i]);
    }
}

// Plonky2's sibling-interleaved layout, including the contiguous cap suffix.
// Each level is dispatched separately, so a parent's children are complete.
fn packed_index(n: u32, caps: u32, level: u32, i: u32) -> u32 {
    let count = n >> level;
    if (count == caps) {
        return 2u * (n - caps) + i;
    }
    let width = (n / caps) >> level;
    let local = i % width;
    return (i / width) * 2u * (n / caps - 1u)
        + 2u * (((local >> 1u) << (level + 1u)) + (1u << level) - 1u)
        + (local & 1u);
}

@compute @workgroup_size(64)
fn scatter_leaves(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if (i >= params.x) { return; }
    var r = 0u;
    let bits = 31u - countLeadingZeros(params.z);
    if (bits > 0u) { r = reverseBits(params.y + i) >> (32u - bits); }
    let dst = packed_index(params.z, params.w, 0u, r);
    for (var j = 0u; j < 4u; j++) {
        output[dst].elems[j] = input[4u * i + j];
    }
}

@compute @workgroup_size(64)
fn scatter_natural(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if (i >= params.x) { return; }
    let dst = packed_index(params.z, params.w, 0u, params.y + i);
    for (var j = 0u; j < 4u; j++) { output[dst].elems[j] = input[4u * i + j]; }
}

@compute @workgroup_size(64)
fn hash_nodes(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if (i >= params.x) { return; }
    let n = params.z;
    let caps = params.w;
    let level = params.y;
    let left = packed_index(n, caps, level - 1u, 2u * i);
    let right = packed_index(n, caps, level - 1u, 2u * i + 1u);
    var state: array<u64, 12>;
    for (var j = 0u; j < 4u; j++) {
        state[j] = output[left].elems[j];
        state[j + 4u] = output[right].elems[j];
    }
    permute(&state);
    let dst = packed_index(n, caps, level, i);
    for (var j = 0u; j < 4u; j++) {
        output[dst].elems[j] = gf64_canon(state[j]);
    }
}
