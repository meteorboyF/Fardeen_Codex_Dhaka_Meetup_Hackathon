#!/usr/bin/env python3
"""Consolidated-table generator, v2 (audit findings N12/N14).

Recomputes every derived value quoted in Table `tab:consolidated` of the BCRA
manuscript from the released per-sample data, with ONE convention throughout:

  - point estimate: statistics.median (central / mean-of-middle-two)
  - interval:       bootstrap percentile 95% CI for the median,
                    10,000 resamples, random.Random(seed) with seed 42
  - n:              the actual number of raw samples loaded

Run:  python3 build_table_v2.py            (prints rows + writes table_v2.csv)
"""
import csv
import glob
import pathlib
import random
import statistics as st

ROOT = pathlib.Path(__file__).resolve().parents[2]
E = ROOT / "experiments"
R = ROOT / "results"
SEED, NBOOT = 42, 10_000
rng = random.Random(SEED)

def ci(vals):
    meds = sorted(st.median(rng.choices(vals, k=len(vals))) for _ in range(NBOOT))
    return meds[int(NBOOT * 0.025)], meds[int(NBOOT * 0.975)]

def rows(path):
    return list(csv.DictReader(open(path)))

out = []
def add(label, vals, unit="ms", nd=2):
    vals = [float(v) for v in vals]
    lo, hi = ci(vals)
    out.append((label, len(vals), round(st.median(vals), nd), round(lo, nd),
                round(hi, nd), unit))

# ── Read-path cost (canonical run 20260801_155550, warmed: sample_idx > 20,
#    fabric brackets fabric1+fabric2 pooled per RESULTS.md) ────────────────
e2 = {}
for r in rows(E / "function_latency_exp2/results/20260801_155550/exp2_latency.csv"):
    if int(r["sample_idx"]) > 20:
        mode = "fabric" if r["mode"] == "fabric" else r["mode"]
        e2.setdefault((r["operation"], mode), []).append(r["latency_ms"])
add("CheckAccess P50 ledger (pooled brackets)", e2[("checkaccess", "fabric")])
add("CheckAccess P50 database", e2[("checkaccess", "db_only")])
add("RegisterDocument P50", e2[("registerdoc", "fabric")], nd=1)

# ── Divergence windows: NEW-BUILD reruns (peer-clock/signed-outbox build) ──
def outbox_windows(pattern):
    vals = []
    for d in sorted(glob.glob(str(pattern))):
        p = pathlib.Path(d) / "pending_anchor_row.txt"
        if p.exists():
            for line in p.read_text().splitlines():
                parts = line.strip().split("|")
                if len(parts) >= 2 and parts[0] == "1":
                    vals.append(float(parts[1]))
    return vals

rev = outbox_windows(E / "orderer_outage_reconciliation_16b/results/202609*")
add("Revocation divergence window (new build)", rev, "s")

grant = []
for d in sorted(glob.glob(str(E / "grant_outage_reconciliation_18/results/grant_202609*"))):
    for r in rows(pathlib.Path(d) / "sequence.csv"):
        if "divergence window" in r["description"]:
            grant.append(float(r["result"].split()[0]))
add("Grant divergence window (new build)", grant, "s")

# ── Architectural comparison (durable-baseline rerun, per-request samples) ──
s = {}
for r in rows(E / "baseline_auditlog/results/20260731_150414/samples.csv"):
    s.setdefault((r["mode"], int(r["conc"])), []).append(r["latency_ms"])
add("Release P50 on-path, conc 10", s[("onpath", 10)])
add("Release P50 audit-log durable, conc 10", s[("auditlog-durable", 10)])

# ── Compressed rows ────────────────────────────────────────────────────────
e3 = [r["value_ms"] for r in rows(R / "exp3_filesize.csv") if r["kind"] == "fabric_commit"]
add("Fabric commit latency (size-independent)", e3, nd=1)

e4 = [r["ms"] for r in rows(R / "exp4_audit.csv") if r["method"] == "pg_query_1000"]
add("Audit query P50 operational store", e4, nd=3)

e7 = [r["latency_ms"] for r in rows(R / "exp7_history.csv")]
add("History retrieval P50 depth 107", e7, nd=1)

e10 = [r["latency_ms"] for r in rows(E / "ipfs_cost/results/20260715_173114/retrieval.csv")
       if r["source"] == "remote" and r["concurrency"] == "1"
       and r["size_mb"] == "50" and int(r["ok"])]
add("Storage retrieval P50 50MB cross-node conc1", e10)

# ── Print + write ──────────────────────────────────────────────────────────
w = csv.writer(open(pathlib.Path(__file__).parent / "table_v2.csv", "w"))
w.writerow(["metric", "n", "median", "ci95_lo", "ci95_hi", "unit"])
for row in out:
    w.writerow(row)
    print(f"{row[0]:52s} n={row[1]:<5d} {row[2]:>10} [{row[3]}, {row[4]}] {row[5]}")
print(f"\nconvention: central median; bootstrap percentile CI, {NBOOT} resamples, seed {SEED}")
