// SPDX-License-Identifier: Apache-2.0
// Extracted from Quantus-Network/quantus-miner c7838cbc86f7d74477da1771139f377a8e438072,
// crates/engine-gpu/src/kernels/mining_u64_apple.wgsl.
// Modified: retained arithmetic only; unused helpers, mining bindings and Poseidon2 rounds removed.
const P64: u64 = 0xFFFFFFFF00000001lu;
const EPS64: u64 = 0xFFFFFFFFlu;
fn gf64_add(a: u64, b: u64) -> u64 {
    let s0 = a + b;
    let c1 = s0 < a;
    let s1 = s0 + select(0lu, EPS64, c1);
    let c2 = c1 && (s1 < s0);
    return s1 + select(0lu, EPS64, c2);
}

struct U128 {
    lo: u64,
    hi: u64,
}

// Reduce a 128-bit value (lo + hi*2^64) mod P using
// 2^64 ≡ EPS64 and 2^96 ≡ -1 (mod P).
fn gf64_reduce(v: U128) -> u64 {
    // With B=2^32, reduce to (w0-w2-w3) + (w1+w2)*B.
    // Track the low limb's two possible borrows in u32 instead of
    // carrying a signed 64-bit intermediate through the reduction.
    let w0 = u32(v.lo);
    let w1 = u32(v.lo >> 32u);
    let w2 = u32(v.hi);
    let w3 = u32(v.hi >> 32u);
    let low0 = w0 - w2;
    let low = low0 - w3;
    let borrow = select(0u, 1u, w0 < w2) + select(0u, 1u, low0 < w3);
    let high0 = w1 + w2;
    let high = high0 - borrow;
    // The mathematical high limb lies in [-1, 2B-2], so carry minus
    // borrow is -1, 0 or 1. A positive correction cannot overflow;
    // a negative correction has high=B-1 and cannot underflow.
    let correction = i64(select(0i, 1i, high0 < w1) - select(0i, 1i, high0 < borrow));
    let bits = bitcast<u64>(correction);
    return ((u64(high) << 32u) | u64(low)) + ((bits << 32u) - bits);
}

fn mul_wide(a: u64, b: u64) -> U128 {
    let a_lo = a & EPS64;
    let a_hi = a >> 32u;
    let b_lo = b & EPS64;
    let b_hi = b >> 32u;
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    // Accumulate the middle limb in 32 bits; keep both carry bits explicitly.
    let mid0 = u32(ll >> 32u) + u32(lh);
    let c0 = select(0u, 1u, mid0 < u32(lh));
    let mid = mid0 + u32(hl);
    let c = c0 + select(0u, 1u, mid < mid0);
    return U128((u64(mid) << 32u) | u64(u32(ll)), hh + (lh >> 32u) + (hl >> 32u) + u64(c));
}

fn gf64_mul(a: u64, b: u64) -> u64 {
    return gf64_reduce(mul_wide(a, b));
}

fn gf64_sqr(a: u64) -> u64 {
    let a_lo = a & EPS64;
    let a_hi = a >> 32u;
    let ll = a_lo * a_lo;
    let lh = a_lo * a_hi;
    let hh = a_hi * a_hi;
    // Accumulate the middle limb in 32 bits; keep both carry bits explicitly.
    let mid0 = u32(ll >> 32u) + u32(lh);
    let c0 = select(0u, 1u, mid0 < u32(lh));
    let mid = mid0 + u32(lh);
    let c = c0 + select(0u, 1u, mid < mid0);
    return gf64_reduce(U128((u64(mid) << 32u) | u64(u32(ll)), hh + ((lh >> 32u) << 1u) + u64(c)));
}

fn gf64_sbox(x: u64) -> u64 {
    let x2 = gf64_sqr(x);
    let x4 = gf64_sqr(x2);
    let x6 = gf64_mul(x4, x2);
    return gf64_mul(x6, x);
}

fn gf64_canon(a: u64) -> u64 {
    return a - select(0lu, P64, a >= P64);
}
