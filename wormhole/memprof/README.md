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
startup                      |          0 |            0.0 |            2.0 |            2.0
build_leaf_circuit           |         56 |            2.0 |           23.5 |           23.5
build_agg_circuit            |       6919 |           23.7 |         2301.1 |         2663.8
agg_commit                   |          8 |         2301.1 |         2302.1 |         2302.1
agg_prove                    |      20715 |         2302.1 |         3449.4 |         3972.6
----------------------------------------------------------------------------------------------
total time elapsed:             27699 ms
overall peak rss:      3972.6 MB
===========================================================================
```

## Knobs

### Pipeline

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

### Circuit configuration (preserves security)

The leaf and aggregator `CircuitConfig` can be tuned. By default, settings
match the production `wormhole_aggregator_circuit_config()`. The leaf circuit
is always rebuilt with the same FRI/wires/quotient knobs so recursive
verification remains valid.

| flag | effect | default |
| --- | --- | --- |
| `--zk-mode {polyfri,rowblinding,disabled}` | Zero-knowledge construction. `polyfri` and `rowblinding` are both fully ZK; `disabled` leaks witness and requires `--allow-weakening-security`. | `polyfri` |
| `--rate-bits N` | FRI blowup exponent. Companion `num_query_rounds` is auto-adjusted to preserve the original `rate_bits × queries` soundness product. | 3 |
| `--cap-height N` | FRI Merkle cap height. Affects proof size only. | 4 |
| `--num-wires N` | Plonk trace columns. Lowering forces taller circuits; minimum 130 (Poseidon2 width). | 143 |
| `--num-routed-wires N` | Routed wires. | 80 |
| `--max-quotient-degree-factor N` | Quotient polynomial degree factor; minimum ~7 with Poseidon. | 8 |

### Circuit configuration (security-affecting; gated)

Use of these flags requires `--allow-weakening-security`. They lower
soundness or ZK security and exist only for measurement/exploration.

| flag | effect |
| --- | --- |
| `--num-query-rounds N` | Override FRI queries directly (use `--rate-bits` instead for safe tuning). |
| `--security-bits N` | Target security level. |
| `--num-challenges N` | Plonk challenge count. |

## Tuning observations (qp-plonky2 1.4.1, 16-leaf agg, 4 real proofs)

| config | peak (MB) | time | notes |
| --- | ---: | ---: | --- |
| default (`PolyFri` ZK) | 4038 | 12.8s | matches production |
| `--zk-mode rowblinding` | **2858** | 7.7s | ~–29% memory, faster; still cryptographically ZK |
| `--rate-bits 2` | crashes | – | plonky2 1.4.1 internal limitation in recursive verification |
| `--num-wires < 130` | rejected | – | Poseidon2 gate requires 130-wire minimum |
| `--max-quotient-degree-factor < 7` | rejected | – | Poseidon gate degree exceeds factor |

`PolyFri` and `RowBlinding` are both fully zero-knowledge; the difference is
the construction (polynomial-domain masked commitments vs row-level blinding).
RowBlinding has been the standard ZK approach in plonky2 since the project's
inception. Switching to it on the production chain requires a verifier-key
update but lets the aggregator proof fit comfortably within mobile memory
budgets without weakening soundness or ZK guarantees.
