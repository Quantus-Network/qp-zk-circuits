// Goldilocks quadratic extension: a + b*u, with u^2 = 7.
fn ext_add(a: vec2<u64>, b: vec2<u64>) -> vec2<u64> {
    return vec2<u64>(gf64_canon(gf64_add(a.x, b.x)), gf64_canon(gf64_add(a.y, b.y)));
}
fn ext_mul(a: vec2<u64>, b: vec2<u64>) -> vec2<u64> {
    return vec2<u64>(
        gf64_canon(gf64_add(gf64_mul(a.x, b.x), gf64_mul(7lu, gf64_mul(a.y, b.y)))),
        gf64_canon(gf64_add(gf64_mul(a.x, b.y), gf64_mul(a.y, b.x))));
}
fn ext_scale(a: vec2<u64>, b: u64) -> vec2<u64> {
    return vec2<u64>(gf64_canon(gf64_mul(a.x, b)), gf64_canon(gf64_mul(a.y, b)));
}
fn ext_pow(a: vec2<u64>, exponent: u32) -> vec2<u64> {
    var power = a;
    var remaining = exponent;
    var result = vec2<u64>(1lu, 0lu);
    while remaining > 0u {
        if (remaining & 1u) != 0u { result = ext_mul(result, power); }
        remaining >>= 1u;
        if remaining > 0u { power = ext_mul(power, power); }
    }
    return result;
}
