@group(0) @binding(0) var<storage, read_write> wires: array<u64>;
@group(0) @binding(1) var<storage, read> representative_indices: array<u64>;
@group(0) @binding(2) var<storage, read> witness_values: array<u64>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i < arrayLength(&wires) {
        wires[i] = witness_values[u32(representative_indices[i])];
    }
}
