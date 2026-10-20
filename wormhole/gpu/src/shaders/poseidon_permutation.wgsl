// Shared Poseidon1 permutation; callers bind mdsCirc, mdsDiag and rc.
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
