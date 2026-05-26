#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib"]
# ///
"""Sweep `wormhole-memprof` across every safe (security-preserving) circuit
knob and emit per-knob PNG charts, a CSV, and a markdown report.

Each sweep varies ONE parameter while holding the rest at their production
defaults (sourced from `wormhole_aggregator_circuit_config()` — currently
RowBlinding ZK, num_wires=135, num_routed_wires=60). The memprof binary
applies CLI flags as overrides on top of that production baseline, so the
unset knobs always track production.

Usage:
    uv run scripts/sweep_and_plot.py
    uv run scripts/sweep_and_plot.py --quick    # smaller batches
"""
from __future__ import annotations

import argparse
import csv
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt

SCRIPT_DIR = Path(__file__).resolve().parent
MEMPROF_DIR = SCRIPT_DIR.parent
WORKSPACE_ROOT = MEMPROF_DIR.parents[1]
OUT_DIR = MEMPROF_DIR / "sweep-results"

PEAK_RE = re.compile(r"overall peak rss:\s*([\d.]+)\s*MB")
TIME_RE = re.compile(r"total time:\s*(\d+)\s*ms")


@dataclass
class RunResult:
    label: str
    args: list[str]
    peak_mb: float
    wall_ms: int


@dataclass
class SweepDef:
    name: str
    title: str
    xlabel: str
    points: list[tuple[str, list[str]]]
    notes: str = ""


def run_memprof(extra_args: list[str]) -> RunResult | None:
    cargo_args = [
        "cargo",
        "run",
        "-q",
        "--release",
        "-p",
        "wormhole-memprof",
        "--",
    ] + extra_args
    print(f"$ {' '.join(shlex.quote(a) for a in cargo_args)}", file=sys.stderr)
    proc = subprocess.run(
        cargo_args,
        cwd=WORKSPACE_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(
            f"  FAILED (exit={proc.returncode}): {proc.stderr.strip().splitlines()[-3:]}",
            file=sys.stderr,
        )
        return None
    out = proc.stdout
    peak = PEAK_RE.search(out)
    wall = TIME_RE.search(out)
    if not peak or not wall:
        print("  WARN: could not parse output", file=sys.stderr)
        return None
    return RunResult(
        label=" ".join(extra_args),
        args=extra_args,
        peak_mb=float(peak.group(1)),
        wall_ms=int(wall.group(1)),
    )


def define_sweeps(quick: bool) -> list[SweepDef]:
    common = ["--skip-leaf-gen", "--real-proofs", "1"]
    leaf16 = ["--num-leaf-proofs", "16"]

    # Quick mode: fewer points per sweep, skip expensive combo sweep
    if quick:
        return [
            SweepDef(
                name="zk_mode",
                title="ZK mode (security-preserving variants only)",
                xlabel="ZK mode",
                points=[
                    ("rowblinding (production)", common + leaf16),
                    ("polyfri", common + leaf16 + ["--zk-mode", "polyfri"]),
                ],
                notes=(
                    "Both modes are fully zero-knowledge at security_bits=100. "
                    "PolyFri adds explicit wire/Z/batch masking polynomials, "
                    "which is where the memory bloat lives. `disabled` is "
                    "excluded (would weaken security)."
                ),
            ),
            SweepDef(
                name="num_leaf_proofs",
                title="Aggregation batch size (num_leaf_proofs) at production defaults",
                xlabel="num_leaf_proofs",
                points=[(str(n), common + ["--num-leaf-proofs", str(n)]) for n in [1, 4, 7, 16]],
                notes=(
                    "Number of leaves recursively verified inside one aggregated "
                    "proof. Each run uses the production aggregator config "
                    "(RowBlinding ZK, num_wires=135, num_routed_wires=60). "
                    "Lowering N requires a chain-side update to a matching "
                    "aggregator verifier."
                ),
            ),
            SweepDef(
                name="num_routed_wires",
                title="num_routed_wires (production baseline)",
                xlabel="num_routed_wires",
                points=[(str(n), common + leaf16 + ["--num-routed-wires", str(n)]) for n in [54, 60, 80]],
                notes=(
                    "Below ~54 the circuit width forces an extra degree-bit, "
                    "doubling memory. 60 is the production default."
                ),
            ),
        ]

    # Full mode: comprehensive sweeps
    return [
        SweepDef(
            name="zk_mode",
            title="ZK mode (security-preserving variants only)",
            xlabel="ZK mode",
            points=[
                ("rowblinding (production)", common + leaf16),
                ("polyfri", common + leaf16 + ["--zk-mode", "polyfri"]),
            ],
            notes=(
                "Both modes are fully zero-knowledge at security_bits=100. "
                "PolyFri adds explicit wire/Z/batch masking polynomials, "
                "which is where the memory bloat lives. `disabled` is "
                "excluded (would weaken security)."
            ),
        ),
        SweepDef(
            name="num_leaf_proofs",
            title="Aggregation batch size (num_leaf_proofs) at production defaults",
            xlabel="num_leaf_proofs",
            points=[(str(n), common + ["--num-leaf-proofs", str(n)]) for n in [1, 2, 4, 7, 8, 16]],
            notes=(
                "Number of leaves recursively verified inside one aggregated "
                "proof. Each run uses the production aggregator config "
                "(RowBlinding ZK, num_wires=135, num_routed_wires=60). "
                "Lowering N requires a chain-side update to a matching "
                "aggregator verifier."
            ),
        ),
        SweepDef(
            name="num_routed_wires",
            title="num_routed_wires (production baseline)",
            xlabel="num_routed_wires",
            points=[(str(n), common + leaf16 + ["--num-routed-wires", str(n)]) for n in [54, 56, 60, 65, 70, 75, 80]],
            notes=(
                "Below ~54 the circuit width forces an extra degree-bit, "
                "doubling memory. 60 is the production default."
            ),
        ),
        SweepDef(
            name="num_wires",
            title="num_wires (production baseline, nrw=54)",
            xlabel="num_wires",
            points=[(str(n), common + leaf16 + ["--num-routed-wires", "54", "--num-wires", str(n)]) for n in [135, 138, 140, 143]],
            notes="135 is the floor (Poseidon needs 135 wires) and the production default. 143 was the pre-#139 default.",
        ),
        SweepDef(
            name="max_qdf",
            title="max_quotient_degree_factor (production baseline)",
            xlabel="max_quotient_degree_factor",
            points=[(str(n), common + leaf16 + ["--max-quotient-degree-factor", str(n)]) for n in [7, 8]],
            notes="7 is the floor (Poseidon constraint). 8 is the production default.",
        ),
        SweepDef(
            name="rayon_threads",
            title="rayon thread count (production baseline)",
            xlabel="rayon threads (0 = system default)",
            points=[(str(n) if n else "default", common + leaf16 + (["--rayon-threads", str(n)] if n else [])) for n in [1, 2, 4, 8, 0]],
            notes=(
                "Pure runtime knob, no security impact. More threads = "
                "smaller per-thread allocations and faster wall time."
            ),
        ),
        SweepDef(
            name="combo_per_N",
            title="Production + nrw=54 at every aggregation batch size (REAL leaf proofs)",
            xlabel="num_leaf_proofs (N)",
            points=[
                (
                    str(n),
                    [
                        "--num-leaf-proofs",
                        str(n),
                        "--real-proofs",
                        str(min(n, 4)),
                        "--num-routed-wires",
                        "54",
                    ],
                )
                for n in [1, 2, 4, 7, 8, 16]
            ],
            notes=(
                "Production config with one extra safe override (nrw=54 "
                "instead of the production 60). Real leaf proofs are "
                "generated for production-equivalent results. This is the "
                "absolute floor reachable WITHOUT changing FRI/PoW "
                "soundness parameters."
            ),
        ),
    ]


def best_safe_combo() -> list[str]:
    return [
        "--skip-leaf-gen",
        "--real-proofs",
        "1",
        "--num-leaf-proofs",
        "16",
        "--num-routed-wires",
        "54",
    ]


def plot_sweep(sweep: SweepDef, results: list[RunResult | None], outpath: Path) -> None:
    fig, ax1 = plt.subplots(figsize=(8, 5))
    labels = [p[0] for p in sweep.points]
    peaks = [r.peak_mb if r else 0.0 for r in results]
    times = [(r.wall_ms / 1000.0 if r else 0.0) for r in results]
    x = list(range(len(labels)))

    bars = ax1.bar(x, peaks, color="#4C72B0", label="Peak memory (MB)")
    ax1.set_xlabel(sweep.xlabel)
    ax1.set_ylabel("Peak memory (MB)", color="#4C72B0")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=20, ha="right")
    ax1.tick_params(axis="y", labelcolor="#4C72B0")
    ax1.grid(axis="y", linestyle=":", alpha=0.5)

    ax1.axhline(1024, color="#2ca02c", linestyle="--", linewidth=1.2, alpha=0.7, label="1 GB mobile target")
    ax1.axhline(2048, color="#ff7f0e", linestyle="--", linewidth=1.0, alpha=0.5, label="2 GB stretch target")

    for bar, peak in zip(bars, peaks):
        if peak > 0:
            ax1.annotate(
                f"{peak:.0f}",
                xy=(bar.get_x() + bar.get_width() / 2, peak),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                fontsize=8,
                color="#1e3a5f",
            )

    ax2 = ax1.twinx()
    ax2.plot(x, times, color="#C44E52", marker="o", linewidth=2, label="Wall time (s)")
    ax2.set_ylabel("Wall time (s)", color="#C44E52")
    ax2.tick_params(axis="y", labelcolor="#C44E52")

    ax1.legend(loc="upper left", fontsize=8)
    plt.title(sweep.title)
    fig.tight_layout()
    fig.savefig(outpath, dpi=140)
    plt.close(fig)


def render_markdown(sweeps_with_results: list[tuple[SweepDef, list[RunResult | None]]], combo: RunResult | None, default_baseline: RunResult | None) -> str:
    md: list[str] = []
    md.append("# Wormhole memprof — parameter sweep")
    md.append("")
    md.append(
        "Each sweep below varies a single circuit knob while keeping the rest "
        "at their defaults (or at the rowblinding baseline where noted). All "
        "configurations preserve full cryptographic security; weakening knobs "
        "(`zk-mode disabled`, lowering `security_bits`, etc.) are excluded."
    )
    md.append("")

    if default_baseline and combo:
        peak_save = default_baseline.peak_mb - combo.peak_mb
        peak_pct = peak_save / default_baseline.peak_mb * 100.0
        wall_save = default_baseline.wall_ms - combo.wall_ms
        wall_pct = wall_save / default_baseline.wall_ms * 100.0
        md.append("## Headline result")
        md.append("")
        md.append(f"![combo](chart_combo.png)")
        md.append("")
        md.append("| config | peak (MB) | wall (s) |")
        md.append("|--------|-----------|----------|")
        md.append(f"| production (RowBlinding, nw=135, nrw=60, 16 leaves) | {default_baseline.peak_mb:.0f} | {default_baseline.wall_ms/1000:.2f} |")
        md.append(f"| **production + nrw=54** | **{combo.peak_mb:.0f}** | **{combo.wall_ms/1000:.2f}** |")
        md.append(f"| Δ | -{peak_save:.0f} MB ({peak_pct:.0f}%) | -{wall_save/1000:.2f} s ({wall_pct:.0f}%) |")
        md.append("")
        md.append(f"Best safe combo flags: `{' '.join(best_safe_combo())}`")
        md.append("")

    for sweep, results in sweeps_with_results:
        md.append(f"## {sweep.title}")
        md.append("")
        if sweep.notes:
            md.append(f"_{sweep.notes}_")
            md.append("")
        md.append(f"![{sweep.name}](chart_{sweep.name}.png)")
        md.append("")
        md.append("| label | peak (MB) | wall (s) |")
        md.append("|-------|-----------|----------|")
        valid = [(p, r) for p, r in zip(sweep.points, results) if r is not None]
        for (label, _), r in valid:
            md.append(f"| {label} | {r.peak_mb:.1f} | {r.wall_ms/1000:.2f} |")
        invalid = [(p, r) for p, r in zip(sweep.points, results) if r is None]
        for (label, args_list), _ in invalid:
            md.append(f"| {label} | _failed_ | _failed_ |")
        md.append("")

        if valid:
            best = min(valid, key=lambda pr: pr[1].peak_mb)
            worst = max(valid, key=lambda pr: pr[1].peak_mb)
            if best[1].peak_mb < worst[1].peak_mb:
                save = worst[1].peak_mb - best[1].peak_mb
                pct = save / worst[1].peak_mb * 100.0
                md.append(f"**Best: `{best[0][0]}`** ({save:.0f} MB / {pct:.0f}% lower than worst)")
                md.append("")

    md.append("## Notes")
    md.append("")
    md.append(
        "- All measurements are RSS / `phys_footprint` peaks captured by a "
        "background sampler in `wormhole-memprof`."
    )
    md.append(
        "- `--skip-leaf-gen --real-proofs 1` is used so each run isolates "
        "the aggregation step. The aggregation circuit is always built for "
        "the full `num_leaf_proofs`; padding leaves are dummies (matching "
        "production behavior). Leaf-proof generation is sequential at "
        "runtime and never exceeds ~80 MB peak."
    )
    md.append(
        "- Knobs that affect the aggregator's verifier hash (everything in "
        "`CircuitConfig`) require coordinated chain updates: rebuild "
        "`pallets/wormhole/build.rs`-generated `aggregated_verifier.bin` and "
        "`aggregated_common.bin` with the same config."
    )
    return "\n".join(md) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Building wormhole-memprof binary once for warmup...", file=sys.stderr)
    subprocess.run(
        ["cargo", "build", "-q", "--release", "-p", "wormhole-memprof"],
        cwd=WORKSPACE_ROOT,
        check=True,
    )

    print("Establishing default baseline...", file=sys.stderr)
    default_baseline = run_memprof(["--skip-leaf-gen", "--real-proofs", "1", "--num-leaf-proofs", "16"])
    print("Establishing best safe combo...", file=sys.stderr)
    combo = run_memprof(best_safe_combo())

    sweeps = define_sweeps(quick=args.quick)
    sweeps_with_results: list[tuple[SweepDef, list[RunResult | None]]] = []

    csv_path = OUT_DIR / "data.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["sweep", "label", "peak_mb", "wall_ms", "args"])
        if default_baseline:
            writer.writerow(["baseline", "default", default_baseline.peak_mb, default_baseline.wall_ms, " ".join(default_baseline.args)])
        if combo:
            writer.writerow(["baseline", "best_safe_combo", combo.peak_mb, combo.wall_ms, " ".join(combo.args)])
        for sweep in sweeps:
            print(f"\n=== Sweep: {sweep.name} ===", file=sys.stderr)
            results: list[RunResult | None] = []
            for label, args_list in sweep.points:
                r = run_memprof(args_list)
                if r:
                    r.label = label
                    print(f"  {label}: peak={r.peak_mb}MB time={r.wall_ms}ms", file=sys.stderr)
                    writer.writerow([sweep.name, label, r.peak_mb, r.wall_ms, " ".join(args_list)])
                    f.flush()
                else:
                    print(f"  {label}: FAILED", file=sys.stderr)
                    writer.writerow([sweep.name, label, "", "", " ".join(args_list)])
                    f.flush()
                results.append(r)
            plot_sweep(sweep, results, OUT_DIR / f"chart_{sweep.name}.png")
            sweeps_with_results.append((sweep, results))

    if default_baseline and combo:
        fig, ax1 = plt.subplots(figsize=(7, 5))
        labels = ["production\n(RowBlinding,\nnw=135, nrw=60)", "production\n+ nrw=54"]
        peaks = [default_baseline.peak_mb, combo.peak_mb]
        times = [default_baseline.wall_ms / 1000.0, combo.wall_ms / 1000.0]
        x = list(range(2))
        bars = ax1.bar(x, peaks, color=["#888888", "#4C72B0"], label="Peak memory (MB)")
        for bar, peak in zip(bars, peaks):
            ax1.annotate(
                f"{peak:.0f} MB",
                xy=(bar.get_x() + bar.get_width() / 2, peak),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
            )
        ax1.set_ylabel("Peak memory (MB)", color="#4C72B0")
        ax1.set_xticks(x)
        ax1.set_xticklabels(labels)
        ax1.set_title("Production vs production + nrw=54")
        ax1.grid(axis="y", linestyle=":", alpha=0.5)
        ax2 = ax1.twinx()
        ax2.plot(x, times, color="#C44E52", marker="o", linewidth=2)
        ax2.set_ylabel("Wall time (s)", color="#C44E52")
        fig.tight_layout()
        fig.savefig(OUT_DIR / "chart_combo.png", dpi=140)
        plt.close(fig)

    md = render_markdown(sweeps_with_results, combo, default_baseline)
    (OUT_DIR / "report.md").write_text(md)

    print(f"\nWrote {csv_path}", file=sys.stderr)
    print(f"Wrote {OUT_DIR / 'report.md'}", file=sys.stderr)
    print(f"Wrote charts to {OUT_DIR}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
