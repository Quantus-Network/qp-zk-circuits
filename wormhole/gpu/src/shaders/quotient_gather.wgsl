const SOURCE_ROWS: u32 = __SOURCE_ROWS__u;
const QUOTIENT_ROWS: u32 = __QUOTIENT_ROWS__u;
const STEP: u32 = __STEP__u;
const ROTATION: u32 = __ROTATION__u;
@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
// chunk rows, first quotient row, destination column, column count
@group(0) @binding(2) var<uniform> dims: vec4<u32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x + gid.y * 2097152u;
    if i >= dims.x * dims.w { return; }
    let column = i / dims.x;
    let row = i % dims.x;
    let source_row = ((dims.y + row + ROTATION) % QUOTIENT_ROWS) * STEP;
    output[(dims.z + column) * dims.x + row] = input[column * SOURCE_ROWS + source_row];
}
