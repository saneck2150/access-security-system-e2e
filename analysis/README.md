# analysis

Python pipeline that consumes the CSV outputs of the experimental harness
(`experiments/`) and produces publication-quality plots plus LaTeX tables
used in Chapter 3 of the diploma thesis.

This module is purely additive — it reads from `build/experiments/results/`
and writes to `analysis/plots/`. It never modifies production code or state.

## Contents

| File | Purpose |
|------|---------|
| `analyze.py` | Entry point: loads CSVs, computes metrics, writes plots + tables |
| `requirements.txt` | Python dependencies (pandas, matplotlib, seaborn, numpy) |

## Setup

```bash
# From repository root
python3 -m venv analysis/venv
source analysis/venv/bin/activate
pip install -r analysis/requirements.txt
```

The virtual environment directory (`analysis/venv/`) is ignored by git and is
not part of the submission archive — each user recreates it locally.

## Usage

Prerequisite: the experiment harness has been run and CSVs exist in
`build/experiments/results/` (see `experiments/README.md` or the root
`README.md` for how to run the experiments).

```bash
# From repository root, with the virtualenv active
python3 analysis/analyze.py \
    --results-dir build/experiments/results \
    --output-dir  analysis/plots
```

Default values: `--results-dir=build/experiments/results`,
`--output-dir=analysis/plots` — the two positional arguments above are
therefore optional if the layout matches.

## Outputs

Written to `--output-dir` (default `analysis/plots/`):

**PNG figures (300 dpi):**

| File | Content |
|------|---------|
| `attack_success_heatmap.png` | Attack success rate per scenario × profile |
| `attack_success_by_n.png` | Success rate vs. number of attack frames |
| `quarantine_speed.png` | Frames to first quarantine (R2 profiles) |
| `latency_boxplot.png` | Per-frame latency distribution |
| `throughput.png` | S6 throughput benchmark (mean ± std) |
| `detector_overhead.png` | R1 vs. R2 latency on baseline frames |
| `scenario_summary_table.png` | Rendered summary table (image form) |

**LaTeX tables (`\input` directly into the thesis):**

| File | Content |
|------|---------|
| `scenario_summary.tex` | Attack success + detector response per scenario |
| `throughput_table.tex` | S6 throughput + latency percentiles (p50/p95/p99) |
| `baseline_correctness.tex` | Baseline false-reject rate per scenario/profile |

## Dependencies

See `requirements.txt`:

- pandas ≥ 2.0 — CSV loading and aggregation
- matplotlib ≥ 3.7 — plot rendering
- seaborn ≥ 0.13 — statistical plot styling
- numpy ≥ 1.24 — numerical utilities

Python ≥ 3.10 is required (tested on 3.10–3.12).

## Notes

The thesis text references hand-translated Slovak versions of
`scenario_summary.tex` and `throughput_table.tex` located under
`tukedip_output/plots/`. The files produced by this pipeline are English
and serve both as validation of the Slovak copies and as ready-to-use
artifacts if the thesis is translated.
