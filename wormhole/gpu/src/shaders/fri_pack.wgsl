@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
// Evaluation count, arity, leaf chunk rows, leaf offset.
@group(0) @binding(2) var<uniform> dims: vec4<u32>;

// Group bit-reversed extension values into FRI leaves, flatten each pair, and
// write the hash operation's column-major chunk. No full reordered LDE exists.
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i >= dims.z * dims.y * 2u { return; }
    let column = i / dims.z;
    let leaf = dims.w + i % dims.z;
    let reversed = leaf * dims.y + column / 2u;
    let bits = 31u - countLeadingZeros(dims.x);
    var natural = 0u;
    if bits > 0u { natural = reverseBits(reversed) >> (32u - bits); }
    output[i] = input[(column % 2u) * dims.x + natural];
}
