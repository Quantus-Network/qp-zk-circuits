@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
@group(0) @binding(2) var<storage, read_write> totals: array<u64>;
@group(0) @binding(3) var<uniform> dims: vec4<u32>;
var<workgroup> products: array<u64, 256>;

@compute @workgroup_size(256)
fn scan(@builtin(workgroup_id) group: vec3<u32>, @builtin(local_invocation_index) lane: u32) {
    let row = group.x * 256u + lane;
    var value = 1lu;
    if row < dims.x { value = input[group.y * dims.x + row]; }
    products[lane] = value;
    workgroupBarrier();
    for (var offset = 1u; offset < 256u; offset *= 2u) {
        var left = 1lu;
        if lane >= offset { left = products[lane - offset]; }
        // Every lane reads before any lane overwrites this scan step.
        workgroupBarrier();
        products[lane] = gf64_canon(gf64_mul(products[lane], left));
        workgroupBarrier();
    }
    if row < dims.x {
        var prefix = 1lu;
        if lane > 0u { prefix = products[lane - 1u]; }
        output[group.y * dims.x + row] = prefix;
    }
    if lane == 255u { totals[group.y * dims.y + group.x] = products[lane]; }
}
