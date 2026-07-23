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
`phase_end` calls so each phase reports its own start/end/peak. A global peak
is tracked across the entire run (including inter-phase gaps) for accurate
`--peak-target-mb` checks.

## Usage

```bash
# Default: build leaf circuit, generate 7 leaf proofs, aggregate them
cargo run -p wormhole-memprof --release

# Mimic a smaller batch: 7-leaf agg circuit but only 4 real proofs
cargo run -p wormhole-memprof --release -- \
    --num-leaf-proofs 7 --real-proofs 4

# Just the aggregation circuit data structure (no proving)
cargo run -p wormhole-memprof --release -- --circuit-only

# Skip leaf-proof generation; clones a dummy proof instead.
# Useful to isolate aggregation cost from leaf proving cost.
cargo run -p wormhole-memprof --release -- \
    --skip-leaf-gen --real-proofs 4

# Try a different aggregation batch size (chain-side verifier update required)
cargo run -p wormhole-memprof --release -- --num-leaf-proofs 4

# Force single-threaded to compare against rayon-parallel
cargo run -p wormhole-memprof --release -- --rayon-threads 1

# CI guard: fail if peak > 1.6 GB
cargo run -p wormhole-memprof --release -- --peak-target-mb 1600
```

## Output

```
============================== MEMPROF REPORT ==============================
phase                        |  wall (ms) |     start (MB) |       end (MB) |      peak (MB)
----------------------------------------------------------------------------------------------
startup                      |          0 |            2.0 |            2.0 |            2.0
build_leaf_circuit           |         56 |            2.0 |           23.5 |           23.5
build_agg_circuit            |       1823 |           23.7 |          812.4 |          923.1
agg_commit                   |          6 |          812.4 |          813.2 |          813.2
agg_prove                    |       2412 |          813.2 |         1287.6 |         1498.3
----------------------------------------------------------------------------------------------
total time:              4297 ms
overall peak rss:      1498.3 MB
===========================================================================
```

## Knobs

| flag | effect |
| --- | --- |
| `--num-leaf-proofs N` | Width of the aggregation circuit (production default = 7). |
| `--real-proofs M` | Real proofs to generate; rest are dummy padding. |
| `--rayon-threads T` | Limit plonky2's parallel FFT pool. `0` = system default. |
| `--skip-leaf-gen` | Use cloned dummy proofs; isolates aggregation cost. |
| `--circuit-only` | Build agg circuit only, don't prove. |
| `--release-after-each` | Call `malloc_zone_pressure_relief` between phases (Apple only). |
| `--sample-period-ms P` | Memory sampler poll period in ms (default 25). |
| `--peak-target-mb T` | Exit non-zero if overall peak > T MB (CI guard). |

### Circuit-config knobs

The aggregator's `CircuitConfig` is also reachable from the CLI as overrides on
top of the production `wormhole_private_batch_circuit_config()` (currently
RowBlinding ZK, `num_wires=135`, `num_routed_wires=60`). Run
`cargo run -p wormhole-memprof --release -- --help` for the full list. Safe
(non-security-affecting) knobs include `--zk-mode {polyfri,rowblinding}`,
`--rate-bits` (auto-rebalances `num_query_rounds`), `--num-wires` (>= 135),
`--num-routed-wires` (>= 37, <= num_wires), and
`--max-quotient-degree-factor` (>= 7). Values below the documented structural
floors are rejected at the CLI: they cannot express the recursion stack's
gates, so profiling them would label broken circuit shapes as viable. Anything
that lowers soundness or removes ZK is gated behind
`--allow-weakening-security`.
