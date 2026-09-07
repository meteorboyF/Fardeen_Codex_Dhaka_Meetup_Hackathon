# Experiment 18 — Grant-Path Outage Divergence: the Durable Outbox, Completed

**Status:** measured. n=6 grant runs (5 campaign + 1 protocol-identical smoke run,
all under the same script and geometry), n=3 FIFO runs. All raw output under
`results/`, aggregated by `analyze18.py` into `summary18.json`.

**Build:** branch `write-path-hardening`, changeset 029 (grant outbox), backend
rebuilt and redeployed before the first run. Fresh from-scratch deployment of the
full stack (Fabric 2.4 three-org network, CouchDB, Kubo, PostgreSQL 16, gateway)
on a second Linux host — itself a reproduction check on the released deployment
scripts.

## Why this experiment exists

Experiments 16/16b measured the revocation half of the write-path asymmetry and
bounded it with the `pending_anchor` outbox. `grant()` retained the original
fire-and-forget defect: a grant issued during an ordering outage updated the
operational ACL, was never anchored, and the paper could only report it as "the
same class of defect on the other write path, not addressed here."

The exposure direction is the mirror image of revocation, and that mirror is the
point. A revocation that diverges leaves a revoked user **still authorized**
(confidentiality exposure). A grant that diverges leaves an authorized user
**still denied** — the ledger-gated release path refuses the grantee the owner
just authorized, indefinitely (availability exposure). Together the two runs
complete the divergence taxonomy: on-path enforcement converts write-path
divergence into whichever failure the diverged operation was meant to prevent.

## Sequence and results (grant mode, all runs agree)

| step | action | result (every run) |
|---|---|---|
| 0 | baseline download, no grant, healthy | 403 |
| 1 | stop 3 orderers, peers up | — |
| 2 | owner grants during outage | **202**, `ledgerSyncStatus=pending` |
| 3 | grantee download mid-outage | **403** — ledger has no grant |
| 4 | grantee wrapped-key mid-outage | 403 — same gate |
| 5 | tri-state | ledger `false` / DB row active / anchor `PENDING` |
| 6 | restart orderers, **no operator action** | converged, anchor `COMMITTED` |
| 7 | grantee download after reconciliation | **200** |

**Divergence window** (outbox `created_at -> committed_at`, no poll jitter),
n=6: **median 14.35 s** (mean 14.38, SD 1.37, range 12.14–15.91, bootstrap 95%
CI [13.01, 15.78], 10,000 resamples, seed 42). Statistically indistinguishable
from the revocation window of 16b (median 15.92 s, [14.86, 16.51]) — as the
mechanism predicts, since both are dominated by Raft leader re-election plus the
worker's 5 s poll, not by anything specific to the function being replayed.

Every anchor committed on its first retry. The API reported `pending` rather
than success in every run: the 202/`ledgerSyncStatus` contract carries over from
revocation unchanged.

## FIFO: intent order under a mixed queue (n=3, all runs agree)

Grant issued during the outage (202/pending), then revoke of the same
(doc, user) while still mid-outage (202/pending), then orderers restarted with
no operator action. In all three runs:

- the worker committed the **grant before the revoke** (`min(committed_at)`
  ordering verified in SQL);
- final ledger state `CheckAccess=false`, final download **403**;
- the on-ledger history therefore contains the grant *and* its revocation in
  the caller's intent order, rather than a re-authorization or a lost grant.

This is the property the per-(doc,user) creation-order drain guard exists to
provide: reconciliation preserves intent order, so a queued grant can never be
replayed after the revoke that superseded it.

## What this does and does not establish

Established: the write-path divergence bound now covers both mutation paths of
the access-control state (grant and revoke); the response contract is honest on
both; reconciliation is unattended on both; and mixed-order queues drain in
intent order. Not established: behavior under outages long enough to drive the
retry schedule to its 60 s cap (same limit as 16b); document registration and
audit anchoring remain availability-first without an outbox (RegisterDocument's
divergence is confined to provenance, not authorization — the release path never
authorizes from an unanchored registration); and n=6/n=3 on one host and one
outage geometry, matching the scope of 16b.

## 2026-09-07 rerun on the hardened build (audit response)

Grant arm rerun n=5 plus two mixed-queue FIFO runs on the hardened build
(signed outbox, inline FIFO guard). All grant runs: 202/pending during the
outage, 403 for the grantee mid-outage, unattended convergence, 200 after.
Windows (outbox timestamps): 16.287240, 13.631087, 15.274115, 20.157906,
14.113037 s; median 15.27 s (mean 15.89, SD 2.60, bootstrap 95% CI
[13.63, 20.16]). Both FIFO runs drained grant before revoke with final
CheckAccess=false and download 403. These supersede the 20260831 grant
windows (n=6, median 14.35 s), which describe the pre-hardening build.
