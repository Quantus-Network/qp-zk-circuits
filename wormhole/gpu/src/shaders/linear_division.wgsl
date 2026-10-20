@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
@group(0) @binding(2) var<storage, read_write> totals: array<u64>;
@group(0) @binding(3) var<storage, read> points: array<vec2<u64>>;
// rows at this level, blocks, point exponent per input, point index
@group(0) @binding(4) var<uniform> dims: vec4<u32>;
var<workgroup> sums: array<vec2<u64>, 256>;
var<workgroup> step_power: vec2<u64>;

fn scan_block(group: u32, lane: u32, reverse: bool) {
    let row = group * 256u + lane;
    var value = vec2<u64>(0lu);
    if row < dims.x {
        var index = row;
        if reverse { index = dims.x - 1u - row; }
        value = vec2<u64>(input[index], input[dims.x + index]);
    }
    sums[lane] = value;
    if lane == 0u { step_power = ext_pow(points[dims.w], dims.z); }
    workgroupBarrier();
    for (var offset = 1u; offset < 256u; offset *= 2u) {
        var left = vec2<u64>(0lu);
        if lane >= offset { left = ext_mul(step_power, sums[lane - offset]); }
        workgroupBarrier();
        sums[lane] = ext_add(sums[lane], left);
        if lane == 0u { step_power = ext_mul(step_power, step_power); }
        workgroupBarrier();
    }
    if row < dims.x {
        output[row] = sums[lane].x;
        output[dims.x + row] = sums[lane].y;
    }
    if lane == min(256u, dims.x - group * 256u) - 1u {
        totals[group] = sums[lane].x;
        totals[dims.y + group] = sums[lane].y;
    }
}
@compute @workgroup_size(256)
fn scan_coefficients(@builtin(workgroup_id) group: vec3<u32>, @builtin(local_invocation_index) lane: u32) {
    scan_block(group.x, lane, true);
}
@compute @workgroup_size(256)
fn scan_totals(@builtin(workgroup_id) group: vec3<u32>, @builtin(local_invocation_index) lane: u32) {
    scan_block(group.x, lane, false);
}
@compute @workgroup_size(64)
fn carry(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x + gid.y * 2097152u;
    if row >= dims.x || row / 256u == 0u { return; }
    let previous = row / 256u - 1u;
    let prefix = vec2<u64>(input[previous], input[dims.y + previous]);
    let factor = ext_pow(points[dims.w], dims.z * (row % 256u + 1u));
    let value = ext_add(vec2<u64>(output[row], output[dims.x + row]), ext_mul(factor, prefix));
    output[row] = value.x;
    output[dims.x + row] = value.y;
}
@compute @workgroup_size(64)
fn finish(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x + gid.y * 2097152u;
    if row >= dims.x { return; }
    var value = vec2<u64>(0lu);
    if row + 1u < dims.x {
        let source = dims.x - 2u - row;
        value = vec2<u64>(input[source], input[dims.x + source]);
    }
    output[row] = value.x;
    output[dims.x + row] = value.y;
}
