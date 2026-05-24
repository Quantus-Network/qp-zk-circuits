# wormhole-memprof

Single-shot peak-memory profiler for the wormhole proof + aggregation pipeline.
Reproduces what the Quantus mobile app does when redeeming miner rewards, and
prints a phase-by-phase memory report so we can iterate on circuit/runtime
tweaks without firing up Xcode and the mobile app.

This complements the existing criterion benches:

- **Criterion benches** (`cargo bench`) measure speed at warm steady state.
  They iterate the hot loop many times, which pollutes peak-memory readings.
- **memprof** runs the full pipeline ONCE in a fresh process and reports the
  peak resident memory. Mirrors mobile behavior exactly.

## Methodology

A background thread samples `task_info(TASK_VM_INFO).phys_footprint` (Apple) or
`/proc/self/status:VmRSS` (Linux) every 25ms and tracks the max. `phys_footprint`
is the same metric iOS uses to decide which apps to jetsam-kill — so when this
report shows >3GB peak on macOS, that's exactly what crashes on iPhone.

## Usage

```bash
# Default: 16 leaf proofs, 16 leaves in agg circuit (mobile app config)
cargo run -p wormhole-memprof --release

# Same memory shape as mobile when there are 4 unspent transfers
cargo run -p wormhole-memprof --release -- \
    --num-leaf-proofs 16 --real-proofs 4 --rayon-threads 1

# Just the aggregation circuit data structure cost (no prove)
cargo run -p wormhole-memprof --release -- --circuit-only --num-leaf-proofs 16

# Try a smaller aggregation circuit (would need chain-side change)
cargo run -p wormhole-memprof --release -- --num-leaf-proofs 4

# CI guard: fail if peak > 1.5GB
cargo run -p wormhole-memprof --release -- \
    --num-leaf-proofs 4 --peak-target-mb 1500
```

## Output

```
============================== MEMPROF REPORT ==============================
phase                        |  wall (ms) |     start (MB) |       end (MB) |      peak (MB)
----------------------------------------------------------------------------------------------
startup                      |          0 |            0.0 |           18.4 |           18.4
build_leaf_circuit           |       1240 |           18.4 |          182.1 |          204.6
gen_leaf_proof[0]            |       3210 |          182.1 |          611.0 |          720.5
gen_leaf_proof[1]            |       3105 |          611.0 |          970.4 |         1080.2
...
build_agg_circuit            |       6520 |         1610.0 |         3850.7 |         3892.0
agg_commit                   |          5 |         3850.7 |         3851.2 |         3851.2
agg_prove                    |      45000 |         3851.2 |         4170.3 |         4188.4
----------------------------------------------------------------------------------------------
total wall:              68000 ms
overall peak phys:        4188.4 MB
STATUS: WOULD CRASH on iPhone (>3GB even with entitlement)
===========================================================================
```

## Knobs

| flag | effect |
| --- | --- |
| `--num-leaf-proofs N` | Aggregation circuit width. 16 = production chain config. |
| `--real-proofs M` | How many real proofs to generate (rest are dummy padding). |
| `--rayon-threads T` | Limit plonky2's parallel FFTs. 1 = lowest peak. |
| `--skip-leaf-gen` | Use cloned dummy proofs; isolates aggregation memory. |
| `--circuit-only` | Build agg circuit only, don't prove. |
| `--release-after-each` | Call `malloc_zone_pressure_relief` between phases. |
| `--peak-target-mb T` | Exit non-zero if peak > T MB (CI guard). |
