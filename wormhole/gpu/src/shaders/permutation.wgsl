const CHUNKS: u32 = __CHUNKS__u;
@group(0) @binding(0) var<storage, read_write> factors: array<u64>;
@group(0) @binding(1) var<storage, read_write> totals: array<u64>;
// One field holds two u32 atomics; only its low word is used.
@group(0) @binding(2) var<storage, read_write> status: array<atomic<u32>>;
@group(0) @binding(3) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn initialize(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i < arrayLength(&factors) { factors[i] = 1lu; }
}

fn inverse(x: u64) -> u64 {
    var base = x;
    var exponent = P64 - 2lu;
    var result = 1lu;
    while exponent > 0lu {
        if (exponent & 1lu) != 0lu { result = gf64_mul(result, base); }
        base = gf64_sqr(base);
        exponent >>= 1u;
    }
    return gf64_canon(result);
}

@compute @workgroup_size(64)
fn ratios(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i >= dims.x * dims.y { return; }
    let row = i % dims.x;
    let challenge = i / dims.x;
    let start = challenge * CHUNKS * dims.x + row;
    let den_start = dims.y * CHUNKS * dims.x + start;
    var prefixes: array<u64, __CHUNKS__>;
    var quotient: array<u64, __CHUNKS__>;
    var denominator = 1lu;
    for (var chunk = 0u; chunk < CHUNKS; chunk++) {
        prefixes[chunk] = denominator;
        denominator = gf64_mul(denominator, factors[den_start + chunk * dims.x]);
    }
    if gf64_canon(denominator) == 0lu {
        atomicOr(&status[0], 1u);
        totals[i] = 0lu;
        for (var chunk = 0u; chunk < CHUNKS; chunk++) { factors[start + chunk * dims.x] = 0lu; }
        return;
    }
    // One inversion per row/challenge, not per wire or partial-product chunk.
    var inv = inverse(denominator);
    for (var j = CHUNKS; j > 0u; j--) {
        let chunk = j - 1u;
        let index = start + chunk * dims.x;
        quotient[chunk] = gf64_mul(factors[index], gf64_mul(inv, prefixes[chunk]));
        inv = gf64_mul(inv, factors[den_start + chunk * dims.x]);
    }
    var product = 1lu;
    for (var chunk = 0u; chunk < CHUNKS; chunk++) {
        product = gf64_mul(product, quotient[chunk]);
        factors[start + chunk * dims.x] = gf64_canon(product);
    }
    totals[i] = gf64_canon(product);
}
