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

fn full_round(state: ptr<function, array<u64, 12>>, round: u32) {
    for (var i = 0u; i < 12u; i++) {
        (*state)[i] = gf64_add((*state)[i], rc[round * 12u + i]);
    }
    for (var i = 0u; i < 12u; i++) {
        (*state)[i] = gf64_sbox((*state)[i]);
    }
    var next: array<u64, 12>;
    for (var row = 0u; row < 12u; row++) {
        // The small MDS coefficients keep this dot product within 96 bits.
        // Accumulate wide products, then reduce once per output lane.
        var sum_lo = 0lu;
        var sum_hi = 0lu;
        for (var col = 0u; col < 12u; col++) {
            let product = mul_wide((*state)[(col + row) % 12u], mdsCirc[col]);
            let next_lo = sum_lo + product.lo;
            sum_hi += product.hi + select(0lu, 1lu, next_lo < sum_lo);
            sum_lo = next_lo;
        }
        let diagonal = mul_wide((*state)[row], mdsDiag[row]);
        let next_lo = sum_lo + diagonal.lo;
        sum_hi += diagonal.hi + select(0lu, 1lu, next_lo < sum_lo);
        next[row] = gf64_reduce(U128(next_lo, sum_hi));
    }
    *state = next;
}

fn permute(state: ptr<function, array<u64, 12>>) {
    for (var round = 0u; round < 4u; round++) {
        full_round(state, round);
    }

    for (var i = 0u; i < 12u; i++) {
        (*state)[i] = gf64_add((*state)[i], rc[360u + i]);
    }
    // Initial change of basis. The first lane is unchanged.
    var initial: array<u64, 12>;
    initial[0] = (*state)[0];
    for (var row = 1u; row < 12u; row++) {
        let value = (*state)[row];
        for (var col = 1u; col < 12u; col++) {
            initial[col] = gf64_add(initial[col],
                gf64_mul(value, rc[372u + (row - 1u) * 11u + col - 1u]));
        }
    }
    *state = initial;

    for (var round = 0u; round < 22u; round++) {
        let old_first = gf64_add(gf64_sbox((*state)[0]), rc[493u + round]);
        var new_first = gf64_mul(old_first, gf64_add(mdsCirc[0], mdsDiag[0]));
        for (var i = 1u; i < 12u; i++) {
            new_first = gf64_add(new_first,
                gf64_mul((*state)[i], rc[515u + round * 11u + i - 1u]));
            (*state)[i] = gf64_add((*state)[i],
                gf64_mul(old_first, rc[757u + round * 11u + i - 1u]));
        }
        (*state)[0] = new_first;
    }

    for (var round = 26u; round < 30u; round++) {
        full_round(state, round);
    }
}

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
