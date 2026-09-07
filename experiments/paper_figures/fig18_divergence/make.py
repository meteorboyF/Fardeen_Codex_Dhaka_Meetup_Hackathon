#!/usr/bin/env python3
"""fig18 — write-path divergence: unattended reconvergence on both mutation paths.

Single clean panel: per-run divergence windows for RevokeAccess (Exp. 16b, n=5)
and GrantAccess (Exp. 18, n=5), medians drawn as bars. Both series are the
2026-09-07 reruns on the hardened build (peer-clock freshness, signed outbox,
inline FIFO guard), loaded from ./data/divergence_runs.csv, which is extracted
verbatim from each run's own outbox timestamps (created_at -> committed_at).
No plotted value is an inline literal; the loader asserts the full observation
vector against the expected run IDs so a silent data swap fails the build.
"""
import csv, statistics as st, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pangostyle as ps

HERE = Path(__file__).parent
series = {"revoke": {}, "grant": {}}
for r in csv.DictReader(open(HERE / "data/divergence_runs.csv")):
    series[r["path"]][r["run_id"]] = float(r["window_s"])

# Assert the entire observation vector, not just the medians (audit N5).
assert len(series["revoke"]) == 5 and len(series["grant"]) == 5, series
assert all(rid.startswith("202609") for rid in series["revoke"]), series["revoke"]
assert all(rid.startswith("grant_202609") for rid in series["grant"]), series["grant"]
revoke_w = sorted(series["revoke"].values())
grant_w = sorted(series["grant"].values())
assert revoke_w == [11.871487, 12.266028, 13.917705, 14.938261, 14.949673], revoke_w
assert grant_w == [13.631087, 14.113037, 15.274115, 16.287240, 20.157906], grant_w

ps.apply()
fig, ax = ps.figure(width=5.2, height=3.3)
panels = [
    (0, "RevokeAccess\n(Exp. 16b, n=5)", revoke_w, ps.C[1]),
    (1, "GrantAccess\n(Exp. 18, n=5)", grant_w, ps.C[0]),
]
for i, label, xs, color in panels:
    jitter = [i + (j - (len(xs) - 1) / 2) * 0.05 for j in range(len(xs))]
    ax.scatter(jitter, xs, s=42, color=color, edgecolor=ps.EDGE, linewidth=0.8, zorder=3)
    med = st.median(xs)
    ax.hlines(med, i - 0.24, i + 0.24, color=ps.EDGE, linewidth=2.4, zorder=4)
    ax.annotate(f"median\n{med:.1f} s", (i + 0.30, med), va="center", ha="left",
                fontsize=ps.FONT_SIZE - 0.5, fontweight="bold")

ax.set_xlim(-0.6, 1.9)
ax.set_ylim(10, 22)
ax.set_xticks([0, 1], [p[1] for p in panels])
ax.set_ylabel("Measured outbox age at commit (s)")
ax.set_title("Unattended reconvergence after an ordering outage")
ax.grid(axis="y")
ax.annotate("bounded by the same durable outbox on both paths;\nrevoke exposure is confidentiality, grant exposure is availability",
            xy=(0.5, -0.30), xycoords="axes fraction", ha="center",
            fontsize=ps.FONT_SIZE - 1.5, style="italic", annotation_clip=False)
ps.save(fig, "fig18_write_divergence", outdir=HERE / "out")
