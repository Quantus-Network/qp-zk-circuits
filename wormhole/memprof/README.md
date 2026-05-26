# wormhole-memprof

Single-shot peak-memory profiler for the wormhole proof + aggregation pipeline.
Runs the full flow once in a fresh process and reports per-phase peak resident
memory. Use it to compare circuit configurations, runtime tuning, and allocator
behavior without spinning up a full client.

This complements the existing criterion benches:

- **Criterion benches** (`cargo bench`) measure speed at warm steady state.
  They iterate the hot loop many times, reusing setup state, which pollutes
  peak-memory readings.
- **memprof** runs the pipeline ONCE in a fresh process and reports the peak.

## Methodology

A background thread samples the resident set every ~25ms and tracks the
maximum. On macOS it reads `mach_task_basic_info.resident_size`; on Linux it
reads `/proc/self/status:VmRSS`. Phases are bracketed by `phase_start` /
`phase_end` calls so each phase reports its own start/end/peak.

## Usage

```bash
# Default: build leaf circuit, generate 16 leaf proofs, aggregate them
cargo run -p wormhole-memprof --release

# Mimic a smaller batch: 16-leaf agg circuit but only 4 real proofs
cargo run -p wormhole-memprof --release -- \
    --num-leaf-proofs 16 --real-proofs 4

# Just the aggregation circuit data structure (no proving)
cargo run -p wormhole-memprof --release -- --circuit-only --num-leaf-proofs 16

# Skip leaf-proof generation; clones a dummy proof instead.
# Useful to isolate aggregation cost from leaf proving cost.
cargo run -p wormhole-memprof --release -- \
    --skip-leaf-gen --num-leaf-proofs 16 --real-proofs 4

# Try a smaller aggregation circuit (chain-side change required to use)
cargo run -p wormhole-memprof --release -- --num-leaf-proofs 4

# Force single-threaded to compare against rayon-parallel
cargo run -p wormhole-memprof --release -- --rayon-threads 1

# CI guard: fail if peak > 1.5 GB
cargo run -p wormhole-memprof --release -- \
    --num-leaf-proofs 4 --peak-target-mb 1500
```

## Output

```
============================== MEMPROF REPORT ==============================
phase                        |  wall (ms) |     start (MB) |       end (MB) |      peak (MB)
----------------------------------------------------------------------------------------------
startup                      |          0 |            2.0 |            2.0 |            2.0
build_leaf_circuit           |         56 |            2.0 |           23.5 |           23.5
build_agg_circuit            |       6919 |           23.7 |         2301.1 |         2663.8
agg_commit                   |          8 |         2301.1 |         2302.1 |         2302.1
agg_prove                    |      20715 |         2302.1 |         3449.4 |         3972.6
----------------------------------------------------------------------------------------------
total time:             27699 ms
overall peak rss:      3972.6 MB
===========================================================================
```

## Knobs

| flag | effect |
| --- | --- |
| `--num-leaf-proofs N` | Width of the aggregation circuit (production = 16). |
| `--real-proofs M` | Real proofs to generate; rest are dummy padding. |
| `--rayon-threads T` | Limit plonky2's parallel FFT pool. `0` = system default. |
| `--skip-leaf-gen` | Use cloned dummy proofs; isolates aggregation cost. |
| `--circuit-only` | Build agg circuit only, don't prove. |
| `--release-after-each` | Call `malloc_zone_pressure_relief` between phases (Apple only). |
| `--sample-period-ms P` | Memory sampler poll period in ms (default 25). |
| `--peak-target-mb T` | Exit non-zero if overall peak > T MB (CI guard). |

### Circuit-config knobs

The aggregator's `CircuitConfig` is also reachable from the CLI as overrides on
top of the production `wormhole_aggregator_circuit_config()` (currently
RowBlinding ZK, `num_wires=135`, `num_routed_wires=60`). Run
`cargo run -p wormhole-memprof --release -- --help` for the full list. Safe
(non-security-affecting) knobs include `--zk-mode {polyfri,rowblinding}`,
`--rate-bits` (auto-rebalances `num_query_rounds`), `--num-wires`,
`--num-routed-wires`, and `--max-quotient-degree-factor`. Anything that lowers
soundness or removes ZK is gated behind `--allow-weakening-security`.
