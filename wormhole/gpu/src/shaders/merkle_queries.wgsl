struct Params { rows: u32, width: u32, depth: u32, count: u32,
    shift: u32, first_column: u32, columns: u32, arity: u32 }
@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> challenges: array<u64>;
@group(0) @binding(2) var<storage, read> source: array<u64>;
@group(0) @binding(3) var<uniform> p: Params;

fn leaf_index(query: u32) -> u32 {
    return u32((challenges[query] >> p.shift) & u64(p.rows - 1u));
}

fn natural_index(reversed: u32, rows: u32) -> u32 {
    let bits = 31u - countLeadingZeros(rows);
    var natural = 0u;
    if bits > 0u { natural = reverseBits(reversed) >> (32u - bits); }
    return natural;
}

@compute @workgroup_size(64)
fn columns(@builtin(global_invocation_id) gid: vec3<u32>) {
    let query = gid.x + gid.y * 2097152u;
    if query >= p.count { return; }
    let natural = natural_index(leaf_index(query), p.rows);
    let record = query * (p.width + 4u * p.depth);
    for (var column = 0u; column < p.columns; column++) {
        output[record + p.first_column + column] = source[column * p.rows + natural];
    }
}

@compute @workgroup_size(64)
fn extension(@builtin(global_invocation_id) gid: vec3<u32>) {
    let query = gid.x + gid.y * 2097152u;
    if query >= p.count { return; }
    let first = leaf_index(query) * p.arity;
    let rows = p.rows * p.arity;
    let record = query * (p.width + 4u * p.depth);
    for (var element = 0u; element < p.arity; element++) {
        let natural = natural_index(first + element, rows);
        output[record + 2u * element] = source[natural];
        output[record + 2u * element + 1u] = source[rows + natural];
    }
}

@compute @workgroup_size(64)
fn paths(@builtin(global_invocation_id) gid: vec3<u32>) {
    let query = gid.x + gid.y * 2097152u;
    if query >= p.count { return; }
    let index = leaf_index(query);
    let subtree = index >> p.depth;
    let subtree_length = 2u * ((1u << p.depth) - 1u);
    var local = index & ((1u << p.depth) - 1u);
    let record = query * (p.width + 4u * p.depth);
    for (var level = 0u; level < p.depth; level++) {
        let parity = local & 1u;
        local >>= 1u;
        let sibling = subtree * subtree_length
            + 2u * ((local << (level + 1u)) + (1u << level) - 1u) + (1u - parity);
        for (var component = 0u; component < 4u; component++) {
            output[record + p.width + 4u * level + component] = source[4u * sibling + component];
        }
    }
}
