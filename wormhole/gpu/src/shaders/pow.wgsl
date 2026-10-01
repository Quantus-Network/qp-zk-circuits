@group(0) @binding(0) var<storage, read_write> winner: array<atomic<u32>>;
@group(0) @binding(1) var<storage, read_write> result: array<u64>;
// State with pending inputs already overwritten, pending count, nonce base.
@group(0) @binding(2) var<storage, read> snapshot: array<u64>;
@group(0) @binding(3) var<storage, read> mdsCirc: array<u64, 12>;
@group(0) @binding(4) var<storage, read> mdsDiag: array<u64, 12>;
@group(0) @binding(5) var<storage, read> rc: array<u64, 999>;
// Leading-zero bits, trial count, searching workgroups, unused.
@group(0) @binding(6) var<uniform> dims: vec4<u32>;

fn trial_response(nonce: u64) -> u64 {
    var state: array<u64, 12>;
    for (var i = 0u; i < 12u; i++) { state[i] = snapshot[i]; }
    state[u32(snapshot[12])] = nonce;
    permute(&state);
    // Challenger pops the last element of the rate-8 squeeze.
    return gf64_canon(state[7]);
}

@compute @workgroup_size(64)
fn initialize(@builtin(global_invocation_id) gid: vec3<u32>) {
    if gid.x == 0u {
        atomicStore(&winner[0], 0xffffffffu);
        result[0] = 0lu; result[1] = 0lu; result[2] = 0lu;
    }
}

@compute @workgroup_size(64)
fn search(@builtin(local_invocation_index) lane: u32, @builtin(workgroup_id) group: vec3<u32>) {
    var threshold = 0lu;
    if dims.x < 64u { threshold = 0xfffffffffffffffflu >> dims.x; }
    let blocks = (dims.y - 1u) / 64u + 1u;
    for (var block = group.x; block < blocks; block += dims.z) {
        if atomicLoad(&winner[0]) != 0xffffffffu { break; }
        let offset = block * 64u + lane;
        if offset >= dims.y { continue; }
        let nonce = snapshot[13] + u64(offset);
        if nonce >= 0xffffffff00000001lu { continue; }
        if trial_response(nonce) <= threshold { atomicMin(&winner[0], offset); }
    }
}

@compute @workgroup_size(64)
fn finish(@builtin(global_invocation_id) gid: vec3<u32>) {
    if gid.x == 0u {
        let offset = atomicLoad(&winner[0]);
        if offset != 0xffffffffu {
            let nonce = snapshot[13] + u64(offset);
            result[0] = nonce; result[1] = 1lu; result[2] = trial_response(nonce);
        }
    }
}
