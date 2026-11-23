@group(0) @binding(0) var<storage, read_write> output: array<u64>;
@group(0) @binding(1) var<storage, read> input: array<u64>;
@group(0) @binding(2) var<storage, read_write> totals: array<u64>;
@group(0) @binding(3) var<uniform> dims: vec4<u32>;
var<workgroup> products: array<u64, 256>;

@compute @workgroup_size(256)
fn scan(@builtin(workgroup_id) group: vec3<u32>, @builtin(local_invocation_index) local_index: u32) {
    let row = group.x * 256u + local_index;
    var value = 1lu;
    if row < dims.x { value = input[group.y * dims.x + row]; }
    products[local_index] = value;
    workgroupBarrier();
    for (var offset = 1u; offset < 256u; offset *= 2u) {
        var left = 1lu;
        if local_index >= offset { left = products[local_index - offset]; }
        // All invocations read before any invocation overwrites this scan step.
        workgroupBarrier();
        products[local_index] = gf64_canon(gf64_mul(products[local_index], left));
        workgroupBarrier();
    }
    if row < dims.x {
        var prefix = 1lu;
        if local_index > 0u { prefix = products[local_index - 1u]; }
        output[group.y * dims.x + row] = prefix;
    }
    if local_index == 255u { totals[group.y * dims.y + group.x] = products[local_index]; }
}
