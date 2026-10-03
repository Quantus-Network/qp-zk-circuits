@group(0) @binding(0) var<storage, read_write> output: array<vec2<u64>>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
@group(0) @binding(2) var<storage, read> points: array<vec2<u64>>;
// coefficients per polynomial, blocks per column, columns, point index
@group(0) @binding(3) var<uniform> dims: vec4<u32>;
var<workgroup> sums: array<vec2<u64>, 64>;
var<workgroup> block_power: vec2<u64>;
var<workgroup> lane_step: vec2<u64>;

fn sum_block(lane: u32, value: vec2<u64>) {
    sums[lane] = value;
    workgroupBarrier();
    for (var stride = 32u; stride > 0u; stride >>= 1u) {
        if lane < stride { sums[lane] = ext_add(sums[lane], sums[lane + stride]); }
        workgroupBarrier();
    }
}

@compute @workgroup_size(64)
fn evaluate(@builtin(workgroup_id) group: vec3<u32>, @builtin(local_invocation_index) lane: u32) {
    let point = points[dims.w];
    if lane == 0u {
        block_power = ext_pow(point, group.x * 4096u);
        lane_step = ext_pow(point, 64u);
    }
    workgroupBarrier();
    let start = group.x * 4096u + lane * 64u;
    var value = vec2<u64>(0lu);
    // Bounded Horner chunks, not one sequential traversal per polynomial.
    for (var offset = 64u; offset > 0u; offset -= 1u) {
        value = ext_mul(value, point);
        let row = start + offset - 1u;
        if row < dims.x { value.x = gf64_canon(gf64_add(value.x, input[group.y * dims.x + row])); }
    }
    value = ext_mul(value, ext_mul(block_power, ext_pow(lane_step, lane)));
    sum_block(lane, value);
    if lane == 0u { output[group.y * dims.y + group.x] = sums[0]; }
}

@compute @workgroup_size(64)
fn reduce(@builtin(workgroup_id) group: vec3<u32>, @builtin(local_invocation_index) lane: u32) {
    let row = group.x * 64u + lane;
    var value = vec2<u64>(0lu);
    if row < dims.x {
        let index = 2u * (group.y * dims.x + row);
        value = vec2<u64>(input[index], input[index + 1u]);
    }
    sum_block(lane, value);
    if lane == 0u { output[group.y * dims.y + group.x] = sums[0]; }
}
