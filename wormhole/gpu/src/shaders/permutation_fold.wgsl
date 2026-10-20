const CHUNKS: u32 = __CHUNKS__u;
const CHUNK_SIZE: u32 = __CHUNK_SIZE__u;
@group(0) @binding(0) var<storage, read_write> factors: array<u64>;
@group(0) @binding(1) var<storage, read> wires: array<u64>;
@group(0) @binding(2) var<storage, read> sigmas: array<u64>;
@group(0) @binding(3) var<storage, read> identities: array<u64>;
@group(0) @binding(4) var<storage, read> scalars: array<u64>;
// trace rows, batch columns, routed columns in this batch, first global column
@group(0) @binding(5) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    let challenges = arrayLength(&scalars) / 2u;
    if i >= dims.x * challenges { return; }
    let row = i % dims.x;
    let challenge = i / dims.x;
    let beta = scalars[challenge];
    let gamma = scalars[challenges + challenge];
    for (var column = 0u; column < dims.z; column++) {
        let global_column = dims.w + column;
        let wire = wires[column * dims.x + row];
        let id = gf64_mul(identities[dims.x + global_column], identities[row]);
        let numerator = gf64_add(wire, gf64_add(gf64_mul(beta, id), gamma));
        let denominator = gf64_add(wire, gf64_add(gf64_mul(beta, sigmas[column * dims.x + row]), gamma));
        let offset = (challenge * CHUNKS + global_column / CHUNK_SIZE) * dims.x + row;
        let den_offset = challenges * CHUNKS * dims.x + offset;
        factors[offset] = gf64_canon(gf64_mul(factors[offset], numerator));
        factors[den_offset] = gf64_canon(gf64_mul(factors[den_offset], denominator));
    }
}
