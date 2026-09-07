# Submission validation protocol — 2026-09-07

Written before the new measurements. Historical datasets remain immutable.

Purpose: resolve the co-author audit using executable checks, correct the audit
baseline, and restrict claims to what the resulting evidence supports.

1. Restore existing research network without deleting volumes; record host,
   runtime, source hash, chaincode definition and image identity.
2. Reproduce database-command injection and the key-selection timing gap against
   fresh disposable documents. Record HTTP/ledger outcomes. Do not claim a full
   database-administrator defense on the basis of isolated ACL mutations.
3. Replace asynchronous-before-persistence audit logging with synchronous durable
   append and a separate batched anchoring worker. Both authorization arms use
   the same audit guarantee. Verify acknowledged request IDs survive a killed
   gateway, then verify their committed batch records after restart.
4. Measure ledger versus DB authorization at concurrency 10 and 50, five trials
   per arm with alternating order. Each cell: 200 warmup requests discarded,
   1000 measured requests, complete response drain. Report success throughput,
   total requests, failures, median/P95 latency and trial-level mean throughput
   with Student-t CI. Do not infer saturation from these levels. Include a
   durable-append-only setting separately from append+batch anchoring.
5. Recheck current grant/revoke responses and fail-closed reads with fresh
   fixtures. Record outage and recovery timestamps; report actual window age,
   not a retry-derived unconditional bound. Include long outage recovery and
   queued grant followed by a post-recovery inline revoke where feasible.
6. Independently recompute all reused statistics from released raw samples;
   bootstrap central-pair medians with 10000 resamples, seed 7. Use exact
   Mann–Whitney for the small grant/revoke sample. Preserve 50ms pre-existing
   equivalence margin, explicitly defining its estimand as mean overhead.

Inclusion: retain all completed trials; failed setup is recorded and excluded
only when requests never reach the intended measurement boundary. Record host
load, available memory and swap counters per trial. Do not drop an inconvenient
completed trial. Additional changes after this protocol are logged with reason.

No existing experiment is represented as a new run. A counterexample proved
from source or a mock is not represented as an end-to-end exploit.
