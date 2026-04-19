#!/usr/bin/env python3
"""Experiment analysis and thesis graph generation.

Loads CSV results from S1-S6 scenarios, computes derived metrics,
and generates publication-quality plots for the diploma thesis.

Usage:
    python analysis/analyze.py [--results-dir build/experiments/results] [--output-dir analysis/plots]
"""

import argparse
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# ---------------------------------------------------------------------------
# Style
# ---------------------------------------------------------------------------

PROFILE_ORDER = ["A1-R0", "A1-R1", "A1-R2", "A2-R0", "A2-R1", "A2-R2"]
PROFILE_PALETTE = {
    "A1-R0": "#1f77b4", "A1-R1": "#ff7f0e", "A1-R2": "#2ca02c",
    "A2-R0": "#9467bd", "A2-R1": "#d62728", "A2-R2": "#8c564b",
}
MODE_LABELS = {"R0": "Random nonce", "R1": "Deterministic nonce", "R2": "Det. + detector"}
ALGO_LABELS = {"A1": "ChaCha20-Poly1305", "A2": "XChaCha20-Poly1305"}

SCENARIO_TITLES = {
    "S1_replay": "S1: Replay Attack",
    "S2_tamper": "S2: Field Tampering (AAD)",
    "S3a_fixed_nonce": "S3a: Nonce Enforcement (R2)",
    "S3b_cross_reader": "S3b: Cross-Reader Key Isolation",
    "S4_seq_reset": "S4: Sequence Rollback",
    "S5_tag_probe": "S5: Tag Probe (Forgery Resistance)",
    "S6_throughput": "S6: Throughput Benchmark",
    "S7_nonce_tamper": "S7: Nonce Tamper (MITM)",
}


def setup_style():
    """Configure matplotlib for thesis-quality plots."""
    plt.rcParams.update({
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.labelsize": 11,
        "legend.fontsize": 9,
        "figure.figsize": (10, 6),
    })
    sns.set_theme(style="whitegrid", palette="muted")


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------

def load_all(results_dir: Path) -> pd.DataFrame:
    """Load and concatenate all scenario CSVs into one DataFrame."""
    frames = []
    for csv in sorted(results_dir.glob("s[1-9]*.csv")):
        if csv.name.startswith("ref"):
            continue
        df = pd.read_csv(csv)
        frames.append(df)
        print(f"  Loaded {csv.name}: {len(df):,} rows")
    if not frames:
        print(f"ERROR: No CSV files found in {results_dir}", file=sys.stderr)
        sys.exit(1)
    data = pd.concat(frames, ignore_index=True)
    # Keep only scenarios listed in SCENARIO_TITLES.
    data = data[data["scenario"].isin(SCENARIO_TITLES.keys())]
    # Derived columns.
    data["mode"] = data["profile"].str[-2:]  # R0, R1, R2
    data["algo"] = data["profile"].str[:2]   # A1, A2
    data["latency_us"] = data["latency_ns"] / 1_000
    print(f"  Total: {len(data):,} rows\n")
    return data


# ---------------------------------------------------------------------------
# Metric Computation
# ---------------------------------------------------------------------------

def compute_attack_success_rate(data: pd.DataFrame) -> pd.DataFrame:
    """Per (scenario, profile, attack_n, run_idx): fraction of attack frames allowed."""
    attack = data[data["phase"] == "attack"]
    grouped = attack.groupby(["scenario", "profile", "attack_n", "run_idx"])["allowed"].mean()
    return grouped.reset_index().rename(columns={"allowed": "success_rate"})


def compute_attack_success_agg(data: pd.DataFrame) -> pd.DataFrame:
    """Per (scenario, profile, attack_n): mean/std/min/max of success_rate across runs."""
    per_run = compute_attack_success_rate(data)
    agg = per_run.groupby(["scenario", "profile", "attack_n"])["success_rate"].agg(
        ["mean", "std", "count", "min", "max"]
    ).reset_index()
    agg.columns = ["scenario", "profile", "attack_n", "sr_mean", "sr_std", "n_runs",
                    "sr_min", "sr_max"]
    agg["sr_std"] = agg["sr_std"].fillna(0)
    # Range bands (min/max across runs).
    agg["sr_ci95"] = 1.96 * agg["sr_std"] / np.sqrt(agg["n_runs"])  # kept for compat
    return agg


def compute_time_to_quarantine(data: pd.DataFrame) -> pd.DataFrame:
    """Per (scenario, profile, attack_n, run_idx): first attack frame_idx where quarantined."""
    attack = data[(data["phase"] == "attack") & (data["quarantined"] == True)]
    first_q = attack.groupby(["scenario", "profile", "attack_n", "run_idx"])["frame_idx"].min()
    return first_q.reset_index().rename(columns={"frame_idx": "frames_to_quarantine"})


def compute_quarantine_agg(data: pd.DataFrame) -> pd.DataFrame:
    """Per (scenario, profile): mean/std of frames_to_quarantine across runs (at max N)."""
    ttq = compute_time_to_quarantine(data)
    max_n = ttq.groupby(["scenario", "profile"])["attack_n"].max().reset_index()
    ttq = ttq.merge(max_n, on=["scenario", "profile", "attack_n"])
    agg = ttq.groupby(["scenario", "profile"])["frames_to_quarantine"].agg(
        ["mean", "std", "count"]
    ).reset_index()
    agg.columns = ["scenario", "profile", "q_mean", "q_std", "n_runs"]
    agg["q_std"] = agg["q_std"].fillna(0)
    return agg


def compute_baseline_correctness(data: pd.DataFrame) -> pd.DataFrame:
    """Per (scenario, profile): fraction of baseline frames that were denied (false reject)."""
    baseline = data[data["phase"] == "baseline"]
    grouped = baseline.groupby(["scenario", "profile"])["allowed"].apply(
        lambda x: 1.0 - x.mean()
    )
    return grouped.reset_index().rename(columns={"allowed": "false_reject_rate"})


def compute_latency_stats(data: pd.DataFrame) -> pd.DataFrame:
    """Per (scenario, profile, phase): latency percentiles in us."""
    stats = data.groupby(["scenario", "profile", "phase"])["latency_us"].describe(
        percentiles=[0.5, 0.95, 0.99]
    ).reset_index()
    return stats


def compute_throughput(data: pd.DataFrame) -> pd.DataFrame:
    """Per (profile, attack_n, run_idx): throughput in frames/sec from S6."""
    s6 = data[data["scenario"] == "S6_throughput"]
    if s6.empty:
        return pd.DataFrame()
    grouped = s6.groupby(["profile", "attack_n", "run_idx"]).agg(
        total_ns=("latency_ns", "sum"),
        frame_count=("latency_ns", "count"),
    ).reset_index()
    grouped["throughput_fps"] = grouped["frame_count"] / (grouped["total_ns"] / 1e9)
    return grouped


# ---------------------------------------------------------------------------
# Plotting Functions
# ---------------------------------------------------------------------------

def plot_attack_success_heatmap(data: pd.DataFrame, out: Path):
    """Heatmap: mean attack success rate per scenario x profile (at max attack_n)."""
    asr = compute_attack_success_agg(data)
    # Keep only max attack_n per scenario.
    max_n = asr.groupby("scenario")["attack_n"].max().reset_index()
    asr = asr.merge(max_n, on=["scenario", "attack_n"])

    pivot_mean = asr.pivot(index="scenario", columns="profile", values="sr_mean")
    pivot_mean = pivot_mean.reindex(columns=PROFILE_ORDER)
    pivot_mean.index = [SCENARIO_TITLES.get(s, s) for s in pivot_mean.index]

    # Annotation: "mean +/- std" when std > 0.
    pivot_std = asr.pivot(index="scenario", columns="profile", values="sr_std")
    pivot_std = pivot_std.reindex(columns=PROFILE_ORDER)
    pivot_std.index = pivot_mean.index  # align renamed index
    annot = pivot_mean.astype(str).copy()
    for sc in annot.index:
        for pr in annot.columns:
            m = pivot_mean.loc[sc, pr]
            s = pivot_std.loc[sc, pr]
            if pd.isna(m):
                annot.loc[sc, pr] = ""
            elif pd.notna(s) and s > 0.001:
                annot.loc[sc, pr] = f"{m:.0%}\n\u00b1{s:.1%}"
            else:
                annot.loc[sc, pr] = f"{m:.0%}"

    fig, ax = plt.subplots(figsize=(10, 5))
    sns.heatmap(pivot_mean, annot=annot, fmt="", cmap="RdYlGn_r",
                vmin=0, vmax=1, linewidths=0.5, ax=ax,
                cbar_kws={"label": "Attack Success Rate"})
    ax.set_title("Attack Success Rate by Scenario x Profile (mean over runs)")
    ax.set_ylabel("")
    ax.set_xlabel("")
    fig.savefig(out / "attack_success_heatmap.png")
    plt.close(fig)
    print("  -> attack_success_heatmap.png")


def plot_quarantine_speed(data: pd.DataFrame, out: Path):
    """Bar plot: frames to quarantine per scenario for R2 profiles, with error bars."""
    qagg = compute_quarantine_agg(data)
    r2 = qagg[qagg["profile"].str.endswith("R2")].copy()
    r2["scenario_label"] = r2["scenario"].map(SCENARIO_TITLES)

    fig, ax = plt.subplots(figsize=(10, 5))
    profiles_r2 = [p for p in PROFILE_ORDER if p.endswith("R2")]
    x = np.arange(len(r2["scenario_label"].unique()))
    width = 0.35

    for i, profile in enumerate(profiles_r2):
        sub = r2[r2["profile"] == profile].sort_values("scenario_label")
        ax.bar(x + i * width, sub["q_mean"], width,
               yerr=sub["q_std"], capsize=4,
               label=profile, color=PROFILE_PALETTE[profile])

    ax.set_title("Frames to Quarantine (R2 Profiles, mean \u00b1 std)")
    ax.set_ylabel("Frame Index at First Quarantine")
    ax.set_xlabel("")
    ax.set_xticks(x + width / 2)
    scenarios_sorted = sorted(r2["scenario_label"].unique())
    ax.set_xticklabels(scenarios_sorted, rotation=25, ha="right")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "quarantine_speed.png")
    plt.close(fig)
    print("  -> quarantine_speed.png")


def plot_attack_success_by_n(data: pd.DataFrame, out: Path):
    """Line plot with error bands: success rate vs attack_n, one subplot per scenario."""
    asr = compute_attack_success_agg(data)
    scenarios = [s for s in asr["scenario"].unique() if s != "S6_throughput"]
    n_cols = 3
    n_rows = (len(scenarios) + n_cols - 1) // n_cols

    fig, axes = plt.subplots(n_rows, n_cols, figsize=(14, 4.5 * n_rows), squeeze=False)
    for i, scenario in enumerate(sorted(scenarios)):
        ax = axes[i // n_cols][i % n_cols]
        sub = asr[asr["scenario"] == scenario]
        for profile in PROFILE_ORDER:
            d = sub[sub["profile"] == profile].sort_values("attack_n")
            if d.empty:
                continue
            ax.plot(d["attack_n"], d["sr_mean"],
                    marker="o", markersize=4, label=profile,
                    color=PROFILE_PALETTE[profile])
            ax.fill_between(d["attack_n"],
                            d["sr_min"].clip(0, 1),
                            d["sr_max"].clip(0, 1),
                            alpha=0.15, color=PROFILE_PALETTE[profile])
        ax.set_title(SCENARIO_TITLES.get(scenario, scenario))
        ax.set_xlabel("Attack Frames (N)")
        ax.set_ylabel("Success Rate")
        ax.set_ylim(-0.05, 1.05)
        ax.legend(fontsize=7, ncol=2)
    # Hide unused axes.
    for j in range(len(scenarios), n_rows * n_cols):
        axes[j // n_cols][j % n_cols].set_visible(False)
    fig.suptitle("Attack Success Rate vs. N (mean over 5 runs, bands = range)", fontsize=14)
    fig.tight_layout()
    fig.savefig(out / "attack_success_by_n.png")
    plt.close(fig)
    print("  -> attack_success_by_n.png")


def plot_latency_boxplot(data: pd.DataFrame, out: Path):
    """Boxplot: baseline + attack latency per profile, one row per scenario."""
    scenarios = sorted([s for s in data["scenario"].unique() if s != "S6_throughput"])
    fig, axes = plt.subplots(len(scenarios), 1, figsize=(12, 3.5 * len(scenarios)),
                             squeeze=False)
    for i, scenario in enumerate(scenarios):
        ax = axes[i][0]
        sub = data[(data["scenario"] == scenario) & (data["attack_n"] == 500)]
        if sub.empty:
            sub = data[data["scenario"] == scenario]
        sns.boxplot(data=sub, x="profile", y="latency_us", hue="phase",
                    order=PROFILE_ORDER, ax=ax, fliersize=1)
        ax.set_title(SCENARIO_TITLES.get(scenario, scenario))
        ax.set_ylabel("Latency (\u00b5s)")
        ax.set_xlabel("")
    fig.suptitle("Per-Frame Latency Distribution", fontsize=14, y=1.01)
    fig.tight_layout(rect=[0, 0, 1, 0.99])
    fig.savefig(out / "latency_boxplot.png", bbox_inches="tight")
    plt.close(fig)
    print("  -> latency_boxplot.png")


def plot_throughput(data: pd.DataFrame, out: Path):
    """S6: throughput (frames/sec) with error bars and latency percentiles per profile."""
    tp = compute_throughput(data)
    if tp.empty:
        print("  SKIP throughput (no S6 data)")
        return

    # Throughput bar chart (at max N).
    max_n = tp["attack_n"].max()
    tp_max = tp[tp["attack_n"] == max_n]
    tp_agg = tp_max.groupby("profile")["throughput_fps"].agg(["mean", "std"]).reset_index()
    tp_agg["profile"] = pd.Categorical(tp_agg["profile"], categories=PROFILE_ORDER, ordered=True)
    tp_agg = tp_agg.sort_values("profile")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    ax1.bar(tp_agg["profile"], tp_agg["mean"],
            yerr=tp_agg["std"], capsize=4,
            color=[PROFILE_PALETTE[p] for p in tp_agg["profile"]])
    ax1.set_title(f"Throughput at N={max_n:,} (mean \u00b1 std)")
    ax1.set_ylabel("Frames / sec")
    ax1.set_xlabel("")

    # Latency percentile table.
    s6 = data[data["scenario"] == "S6_throughput"]
    s6_max = s6[s6["attack_n"] == max_n]
    latency_stats = s6_max.groupby("profile")["latency_us"].quantile(
        [0.50, 0.95, 0.99]).unstack()
    latency_stats = latency_stats.reindex(PROFILE_ORDER)
    latency_stats.columns = ["p50", "p95", "p99"]

    ax2.axis("off")
    table = ax2.table(
        cellText=latency_stats.round(1).values,
        rowLabels=latency_stats.index,
        colLabels=["p50 (\u00b5s)", "p95 (\u00b5s)", "p99 (\u00b5s)"],
        loc="center",
        cellLoc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.5)
    ax2.set_title(f"Latency Percentiles at N={max_n:,}")

    fig.suptitle("S6: Throughput Benchmark", fontsize=14)
    fig.tight_layout()
    fig.savefig(out / "throughput.png")
    plt.close(fig)
    print("  -> throughput.png")


def plot_detector_overhead(data: pd.DataFrame, out: Path):
    """Compare R1 vs R2 baseline latency to quantify detector overhead."""
    baseline = data[(data["phase"] == "baseline") & (data["scenario"] != "S6_throughput")]
    r1r2 = baseline[baseline["mode"].isin(["R1", "R2"])]
    if r1r2.empty:
        print("  SKIP detector_overhead (no data)")
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    sns.boxplot(data=r1r2, x="algo", y="latency_us", hue="mode",
                order=["A1", "A2"], ax=ax, fliersize=1)
    ax.set_title("Detector Overhead: R1 (no detector) vs R2 (with detector)")
    ax.set_ylabel("Baseline Latency (\u00b5s)")
    ax.set_xlabel("Algorithm")
    ax.legend(title="Mode")
    fig.savefig(out / "detector_overhead.png")
    plt.close(fig)
    print("  -> detector_overhead.png")


def plot_scenario_summary_table(data: pd.DataFrame, out: Path):
    """Summary table image: outcome per (scenario x profile) at max attack_n."""
    attack = data[data["phase"] == "attack"]
    max_n = attack.groupby("scenario")["attack_n"].max()

    rows = []
    for scenario in sorted(attack["scenario"].unique()):
        n = max_n[scenario]
        for profile in PROFILE_ORDER:
            sub = attack[(attack["scenario"] == scenario) &
                         (attack["profile"] == profile) &
                         (attack["attack_n"] == n)]
            if sub.empty:
                continue
            # Aggregate across runs.
            per_run = sub.groupby("run_idx")["allowed"].mean()
            sr_mean = per_run.mean()
            sr_std = per_run.std() if len(per_run) > 1 else 0.0
            q_pct = sub["quarantined"].any()
            top_reason = sub["reason"].value_counts().index[0]
            atype = sub["anomaly_type"].dropna().loc[lambda s: s != ""]
            anomaly = str(atype.iloc[0]) if len(atype) > 0 else "-"
            sr_str = f"{sr_mean:.0%}" if sr_std < 0.001 else f"{sr_mean:.0%}\u00b1{sr_std:.1%}"
            rows.append({
                "Scenario": SCENARIO_TITLES.get(scenario, scenario),
                "Profile": profile,
                "Success %": sr_str,
                "Quarantined": "Yes" if q_pct else "No",
                "Reason": top_reason,
                "Anomaly": anomaly,
            })
    summary = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(14, 0.35 * len(rows) + 1.5))
    ax.axis("off")
    table = ax.table(
        cellText=summary.values,
        colLabels=summary.columns,
        loc="center",
        cellLoc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.auto_set_column_width(list(range(len(summary.columns))))
    table.scale(1.0, 1.3)

    # Color cells: green for 0% success, red for >0%.
    for row_idx in range(len(rows)):
        sr_text = rows[row_idx]["Success %"]
        cell = table[row_idx + 1, 2]  # +1 for header row
        if sr_text.startswith("0%"):
            cell.set_facecolor("#d4edda")
        elif sr_text != "0%":
            cell.set_facecolor("#f8d7da")

    ax.set_title("Scenario x Profile Summary (at max attack_n, aggregated over runs)",
                 fontsize=13, pad=20)
    fig.savefig(out / "scenario_summary_table.png")
    plt.close(fig)
    print("  -> scenario_summary_table.png")


# ---------------------------------------------------------------------------
# LaTeX Table Generation
# ---------------------------------------------------------------------------

def generate_latex_summary(data: pd.DataFrame, out: Path):
    """Generate a LaTeX table file for direct inclusion in the thesis."""
    attack = data[data["phase"] == "attack"]
    max_n = attack.groupby("scenario")["attack_n"].max()

    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{Attack success rate and detector response by scenario and profile}")
    lines.append(r"\label{tab:scenario-summary}")
    lines.append(r"\small")
    lines.append(r"\begin{tabular}{l l r c l l}")
    lines.append(r"\toprule")
    lines.append(r"Scenario & Profile & Success \% & Quarantine & Reason & Anomaly \\")
    lines.append(r"\midrule")

    prev_scenario = None
    for scenario in sorted(attack["scenario"].unique()):
        n = max_n[scenario]
        title = SCENARIO_TITLES.get(scenario, scenario)
        for profile in PROFILE_ORDER:
            sub = attack[(attack["scenario"] == scenario) &
                         (attack["profile"] == profile) &
                         (attack["attack_n"] == n)]
            if sub.empty:
                continue
            per_run = sub.groupby("run_idx")["allowed"].mean()
            sr_mean = per_run.mean()
            sr_std = per_run.std() if len(per_run) > 1 else 0.0
            q = sub["quarantined"].any()
            top_reason = sub["reason"].value_counts().index[0]
            atype = sub.loc[sub["anomaly_type"] != "", "anomaly_type"]
            anomaly = str(atype.iloc[0]) if len(atype) > 0 else "--"
            if anomaly == "nan" or anomaly == "":
                anomaly = "--"

            # Escape underscores for LaTeX.
            reason_tex = str(top_reason).replace("_", r"\_")
            anomaly_tex = str(anomaly).replace("_", r"\_")
            profile_tex = profile.replace("-", "--")

            if sr_std < 0.001:
                sr_tex = f"{sr_mean:.0%}".replace("%", r"\%")
            else:
                sr_tex = f"${sr_mean*100:.0f} \\pm {sr_std*100:.1f}$\\%"

            sc_col = title if profile == PROFILE_ORDER[0] else ""
            if prev_scenario and prev_scenario != scenario and profile == PROFILE_ORDER[0]:
                lines.append(r"\midrule")
            lines.append(
                f"  {sc_col} & {profile_tex} & {sr_tex} & "
                f"{'Yes' if q else 'No'} & "
                f"\\texttt{{{reason_tex}}} & \\texttt{{{anomaly_tex}}} \\\\"
            )
        prev_scenario = scenario

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    tex_path = out / "scenario_summary.tex"
    tex_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  -> {tex_path.name}")


def generate_latex_throughput(data: pd.DataFrame, out: Path):
    """Generate a LaTeX table for S6 throughput results."""
    tp = compute_throughput(data)
    if tp.empty:
        print("  SKIP throughput LaTeX (no S6 data)")
        return

    max_n = tp["attack_n"].max()
    tp_max = tp[tp["attack_n"] == max_n]
    tp_agg = tp_max.groupby("profile")["throughput_fps"].agg(["mean", "std"]).reset_index()
    tp_agg["profile"] = pd.Categorical(tp_agg["profile"], categories=PROFILE_ORDER, ordered=True)
    tp_agg = tp_agg.sort_values("profile")

    # Also get latency percentiles.
    s6 = data[data["scenario"] == "S6_throughput"]
    s6_max = s6[s6["attack_n"] == max_n]

    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(f"\\caption{{Throughput and latency at N={max_n:,} frames}}")
    lines.append(r"\label{tab:throughput}")
    lines.append(r"\begin{tabular}{l r r r r r}")
    lines.append(r"\toprule")
    lines.append(r"Profile & FPS (mean) & FPS (std) & p50 ($\mu$s) & p95 ($\mu$s) & p99 ($\mu$s) \\")
    lines.append(r"\midrule")

    for _, row in tp_agg.iterrows():
        p = row["profile"]
        p_tex = str(p).replace("-", "--")
        sub = s6_max[s6_max["profile"] == p]["latency_us"]
        p50 = sub.quantile(0.50)
        p95 = sub.quantile(0.95)
        p99 = sub.quantile(0.99)
        lines.append(
            f"  {p_tex} & {row['mean']:,.0f} & {row['std']:,.0f} & "
            f"{p50:.1f} & {p95:.1f} & {p99:.1f} \\\\"
        )

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    tex_path = out / "throughput_table.tex"
    tex_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  -> {tex_path.name}")


def generate_latex_baseline(data: pd.DataFrame, out: Path):
    """Generate a LaTeX table for baseline correctness (false reject rate)."""
    correctness = compute_baseline_correctness(data)
    pivot = correctness.pivot(index="scenario", columns="profile", values="false_reject_rate")
    pivot = pivot.reindex(columns=PROFILE_ORDER)
    pivot.index = [SCENARIO_TITLES.get(s, s) for s in pivot.index]

    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{False reject rate during baseline (valid frames)}")
    lines.append(r"\label{tab:baseline}")
    cols = " ".join(["r"] * len(PROFILE_ORDER))
    header_profiles = " & ".join([p.replace("-", "--") for p in PROFILE_ORDER])
    lines.append(r"\begin{tabular}{l " + cols + "}")
    lines.append(r"\toprule")
    lines.append(f"Scenario & {header_profiles} \\\\")
    lines.append(r"\midrule")

    for sc in pivot.index:
        vals = " & ".join([f"{pivot.loc[sc, p]:.2%}".replace("%", r"\%") if pd.notna(pivot.loc[sc, p]) else "--"
                           for p in PROFILE_ORDER])
        lines.append(f"  {sc} & {vals} \\\\")

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    tex_path = out / "baseline_correctness.tex"
    tex_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  -> {tex_path.name}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Experiment analysis and thesis plots")
    parser.add_argument("--results-dir", type=Path, default=Path("build/experiments/results"),
                        help="Directory with CSV files")
    parser.add_argument("--output-dir", type=Path, default=Path("analysis/plots"),
                        help="Output directory for plots")
    args = parser.parse_args()

    setup_style()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    print("Loading data...")
    data = load_all(args.results_dir)

    print("Generating plots...")
    plot_attack_success_heatmap(data, args.output_dir)
    plot_quarantine_speed(data, args.output_dir)
    plot_attack_success_by_n(data, args.output_dir)
    plot_latency_boxplot(data, args.output_dir)
    plot_throughput(data, args.output_dir)
    plot_detector_overhead(data, args.output_dir)
    plot_scenario_summary_table(data, args.output_dir)

    print("\nGenerating LaTeX tables...")
    generate_latex_summary(data, args.output_dir)
    generate_latex_throughput(data, args.output_dir)
    generate_latex_baseline(data, args.output_dir)

    # Print key metrics to stdout.
    print("\n=== Key Metrics ===")
    correctness = compute_baseline_correctness(data)
    max_frr = correctness["false_reject_rate"].max()
    print(f"  Max false reject rate (baseline): {max_frr:.4%}")

    asr = compute_attack_success_agg(data)
    for scenario in sorted(asr["scenario"].unique()):
        if scenario == "S6_throughput":
            continue
        sub = asr[(asr["scenario"] == scenario) &
                  (asr["attack_n"] == asr[asr["scenario"] == scenario]["attack_n"].max())]
        print(f"\n  {SCENARIO_TITLES.get(scenario, scenario)}:")
        for _, row in sub.iterrows():
            marker = "\u2713" if row["sr_mean"] == 0 else "\u2717"
            std_str = f" \u00b1{row['sr_std']:.1%}" if row["sr_std"] > 0.001 else ""
            print(f"    {marker} {row['profile']}: {row['sr_mean']:.0%}{std_str} success "
                  f"(n={row['n_runs']:.0f} runs)")

    tp = compute_throughput(data)
    if not tp.empty:
        max_n = tp["attack_n"].max()
        tp_max = tp[tp["attack_n"] == max_n]
        tp_agg = tp_max.groupby("profile")["throughput_fps"].agg(["mean", "std"])
        print(f"\n  S6: Throughput at N={max_n:,}:")
        for profile in PROFILE_ORDER:
            if profile in tp_agg.index:
                m, s = tp_agg.loc[profile]
                print(f"    {profile}: {m:,.0f} \u00b1 {s:,.0f} fps")

    print(f"\nPlots saved to: {args.output_dir}/")
    print(f"LaTeX tables saved to: {args.output_dir}/")


if __name__ == "__main__":
    main()
