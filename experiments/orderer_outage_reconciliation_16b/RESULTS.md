# Experiment 16b — Bounded, Auto-Reconciling Divergence After the Durable-Outbox Fix

**Evidence runs:** `results/20260730_181516/` (run 1, full sequence CSV) plus four
repeat runs, `n = 5` total. Linux x86_64, Fabric 2.4, 3-org `legal-channel`,
majority endorsement.
**Runner:** `run.sh` (orchestration) + `../orderer_outage_divergence/setup.mjs`
(fresh fixture, shared with Experiment 16 so the geometry is identical).

## Why this experiment exists

Experiment 16 (`../orderer_outage_divergence/`) measured the pre-fix behaviour:
under an orderer-only outage, `RevokeAccess` returned **HTTP 204 "success"**
while never reaching the ledger, and the divergence was **permanent** — after
the orderers recovered nothing re-anchored the revoke, so `CheckAccess` kept
authorizing the revoked user until someone manually re-issued the revocation.
That is reviewer finding **M1** (`bra_submission/bcra_peer_review.md`, Tier 1
item 1), which called for a transactional outbox with queued re-anchoring and
asked for the **divergence window duration** to be reported as the measured
result.

This experiment re-runs the identical scenario against the fixed code and
prices that window.

## What changed in the code under test

- `AccessControlService.revoke()` writes the DB revoke **and** a
  `pending_anchor` outbox row in the same PostgreSQL transaction; a Fabric
  submit failure now leaves the row `PENDING` instead of being logged and
  dropped.
- `AnchorReconciliationWorker` (`@Scheduled(fixedDelay=5000)`) drains `PENDING`
  anchors with capped exponential backoff (5 s base, 300 s cap).
- `DELETE /api/access/{docId}/user/{userId}` returns **202 Accepted** with
  `ledgerSyncStatus: pending` while the anchor is queued, and **204** only once
  the anchor has committed.

## Method

Identical to Experiment 16 — same fixture generator, same orderer-only outage
geometry (stop all three orderers, peers stay up), same fresh throwaway
document with a genuine cross-firm read grant. The only procedural difference
is step 7: instead of one manual CLI re-revoke, the script **polls** after
restarting the orderers and takes **no manual action**, waiting for both
`CheckAccess` to flip to `false` *and* `pending_anchor.status` to reach
`COMMITTED`.

The reported divergence window is taken from the database's own timestamps
(`committed_at - created_at` on the anchor row), not from the polling loop, so
it is free of poll-interval jitter.

Backend run with `DOCUMENT_MATERIAL_DB_FALLBACK=false` — the shipped strict
fail-closed default (commit `fc50593`). Note that `scripts/dev.sh` defaults
this to `true`; running the experiment under that default would let reads fall
back to the PostgreSQL ACL and confound the result.

## Results

Step-by-step (run 1; all five runs agree on every HTTP code and state):

| Step | Action | Exp 16 (pre-fix) | **Exp 16b (post-fix)** |
|---|---|---|---|
| 0 | Baseline grantee download, healthy | HTTP 200 | **HTTP 200** |
| 1 | Stop `orderer1/2/3` (peers stay up) | orderers down | orderers down |
| 2 | Grantee download during outage (evaluate → peer) | HTTP 200 | **HTTP 200** |
| 3 | Owner revoke during outage (submit → orderer) | HTTP **204 "success"** | **HTTP 202 + `ledgerSyncStatus: pending`** |
| 4 | Grantee download **after** the revoke, still mid-outage | HTTP 200, 669 bytes | **HTTP 200** |
| 5 | Grantee wrapped-key after the revoke | HTTP 403 | **HTTP 403** |
| 6 | Ledger vs DB vs outbox during outage | ledger `true` / DB `revoked=t` | **ledger `true` / DB `revoked=t` / anchor `PENDING`** |
| 7 | Orderers restarted, **no manual action** | ledger **still `true`** (permanent) | **ledger `false`, anchor `COMMITTED` — automatic** |
| 8 | Grantee download after recovery | (permanently 200) | **HTTP 403** |

### A note on the six result directories

`results/` contains **six** directories for a reported `n = 5`. The extra one,
`20260730_174352`, is an **aborted run that produced no measurement** and is
excluded. It is preserved rather than deleted so the exclusion is auditable.

The exclusion criterion is objective and does not depend on the value observed:
*a run is discarded if the harness fails before reaching step 7*. This run
aborted at step 6 because the backend's Fabric client credentials were stale
copies of regenerated network crypto material (see the environment caveat under
Reproduce), so every Fabric call failed at the TLS handshake and no
reconciliation could occur. That is a broken harness, not a system behaviour —
the run yielded no divergence-window value to include or exclude. Its partial
`sequence.csv` is retained for inspection.

### Divergence window (n = 5)

Measured from the anchor row's `created_at` → `committed_at`:

| Run | Divergence window (s) | Retry attempts |
|---|---|---|
| 1 | 16.51 | 1 |
| 2 | 16.46 | 1 |
| 3 | 14.86 | 1 |
| 4 | 15.51 | 1 |
| 5 | 15.92 | 1 |

**median 15.92 s, mean 15.85 s, SD 0.69 s, range 14.86–16.51 s.**
Every run reconciled on the **first** retry after Fabric became reachable.

## Findings

1. **The divergence no longer outlives the outage.** The headline pre-fix
   finding — divergence "permanent, not window-bounded," clearing only on a
   manual re-revoke — no longer holds. Across five runs the ledger converged
   automatically in a median of **15.9 s** with no operator action, and the
   release path then correctly denied the revoked user (step 8: 403, where
   Exp 16 was permanently 200).

   **Read this number carefully.** It is not "exposure is bounded at 15.9 s."
   The divergence window decomposes as

   > *outage duration* + *reconciliation lag*

   and the fix addresses only the second term. In these runs the orderers were
   down for barely a second before being restarted, so the measured 15.9 s is
   almost entirely Raft leader re-election — i.e. the reconciliation lag with a
   near-zero outage. Under a one-hour outage the divergence is approximately
   one hour. What changed is that the pre-fix second term was **infinite**
   (nothing ever re-anchored), and is now bounded by the retry schedule. The
   defensible claim is *"the divergence no longer outlives the outage,"* not
   *"the exposure is bounded at 15.9 s."*

2. **The revoke API no longer lies to the caller.** Step 3 returns 202 with an
   explicit `ledgerSyncStatus: pending` and an anchor id during the outage,
   rather than a bare 204 that is indistinguishable from a committed
   revocation. This is the part of M1 that mattered most: the pre-fix failure
   was *silent*.

3. **The window is dominated by orderer recovery, not by the outbox.** All
   five runs committed on the first retry, and the 0.69 s SD tracks Raft
   leader re-election rather than anything in the queue mechanism. The worker's
   5 s poll interval sets the floor on detection latency; the rest is how long
   Fabric takes to accept writes again. This window should be read as
   *recovery-bound*, not as a cost imposed by the fix.

   The retry schedule is `min(base × 2^attempts, cap)` with base 5 s and cap
   **60 s** (`access.anchor-retry.*` in `application.yml`). The cap is
   deliberately shorter than a generic outbox would use: it is the upper bound
   on how long a revoked user stays ledger-authorized *after Fabric is already
   healthy*, which is the only part of the divergence window the system
   controls. Retries during an outage are cheap because the resilience4j
   breaker fast-fails them while open. **These five runs are unaffected by the
   cap** — every one reconciled on its first retry (backoff 10 s), so the cap
   never engaged; the measurements stand as reported.

4. **The exposure during the outage itself is completely unchanged**, and this
   experiment does not claim otherwise. Steps 4–5 are identical to
   Experiment 16: ciphertext is still released to the revoked user for as long
   as the outage lasts (the release path evaluates against last-committed
   world state), and the wrapped-key endpoint is still DB-gated to 403. The
   fix does not make reads fail-closed under an orderer-only outage, and does
   not shorten the outage-window exposure by a single millisecond — it removes
   the unbounded tail *after* recovery. The residual risk noted in
   Experiment 16 — a prior grantee already holds the wrapped key, so continued
   ciphertext release defeats the revocation against exactly the party it
   targets — still applies in full for the duration of the outage.

   Making reads fail closed under an orderer-only outage is *not* proposed
   here: it would convert every ordering outage into a total read outage for
   all users to defend against one stale grant. The principled alternative is
   a staleness bound — refuse to authorize from world state more than Δ behind
   a known-fresh reference — which is the same mechanism reviewer finding M2
   needs for trustworthy grant expiry (a periodic ordered time anchor). If
   that is built, it should be built once and priced once, with Δ swept to
   produce the security/availability tradeoff curve the review notes is
   missing from Experiment 9.

## Limitations

- `n = 5`, single host, single outage geometry, and — importantly — a
  **near-zero outage duration** (orderers stopped and restarted within
  seconds). The measured window is therefore essentially pure recovery lag.
  The window under a partial orderer outage, a rolling restart, or a
  minutes-to-hours outage that drives the backoff to its 60 s cap is **not**
  measured here. Since divergence = outage + reconciliation lag, a long outage
  produces a proportionally larger window; that curve is not characterized.
- The outbox is implemented for `RevokeAccess` only.
  `AccessControlService.grant()` retains the original fire-and-forget pattern,
  so grants issued during an outage are still silently unanchored. That is the
  same class of defect on the other write path and is not addressed by this
  experiment or the fix it tests.

## Reproduce

```bash
# prerequisites: 3-org network + backend up; demo users seeded
#   (ui_retake_seed/seed_demo.mjs register|flows)
# NOTE: run the backend with DOCUMENT_MATERIAL_DB_FALLBACK=false (shipped default);
#       scripts/dev.sh defaults it to true, which confounds the result.
PANGOCHAIN_POLL_TIMEOUT=300 bash experiments/orderer_outage_reconciliation_16b/run.sh
# raw evidence: experiments/orderer_outage_reconciliation_16b/results/<stamp>/
```

Each run creates its own throwaway document and leaves the ledger reconciled,
so it is safe to repeat back to back.

**Environment caveat worth recording:** the backend's Fabric client credentials
under `pangochain-backend/config/fabric/crypto/` (gitignored) are copies of the
network's crypto material. If `pangochain-fabric/` is regenerated (`make up`
recreating `crypto-config/`), these copies go stale and *every* Fabric call
fails with `UNAVAILABLE: io exception` at the TLS handshake — which looks like
a network outage but is not. Refresh them from
`pangochain-fabric/crypto-config/peerOrganizations/firma.pangochain.com/`
(tlsca cert, Admin signcert, and Admin `keystore/priv_sk`) before running.
The first attempt at this experiment was blocked by exactly that.

## 2026-09-07 rerun on the hardened build (audit response)

After the pre-submission audit repairs (peer-clock freshness check, signed
outbox rows, inline FIFO guard), the full revoke arm was rerun n=5 on the
second host (i5-1035G1, 14 GB). Every run reproduces every row of the
post-fix sequence (202/pending during outage, unattended reconvergence,
403 after). Divergence windows from the outbox row's own timestamps:

| run | window (s) |
|---|---|
| 20260907_203258 | 12.266028 |
| 20260907_203333 | 11.871487 |
| 20260907_203408 | 14.938261 |
| 20260907_203446 | 13.917705 |
| 20260907_203522 | 14.949673 |

Median 13.92 s (mean 13.59, SD 1.46, bootstrap 95% CI [11.87, 14.95] at seed
42 via consolidated/build_table_v2.py). These supersede the 20260831 windows
(median 15.92 s) quoted in earlier drafts; the earlier runs describe the
pre-hardening build and are retained.
