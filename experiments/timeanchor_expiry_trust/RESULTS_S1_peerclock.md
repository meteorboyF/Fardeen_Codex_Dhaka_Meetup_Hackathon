# Experiment 17b, redone: staleness ceiling on the peer-clock freshness check

**Status:** measured, and it supersedes the earlier staleness sweep. Raw data under
`results/sweepv2_20260907_201505/`.

## Why this rerun exists

Pre-submission audit finding **S1** showed the earlier freshness check was circular.
`assertProposalTimeIsFresh` measured anchor staleness against the caller-supplied
proposal timestamp `P` and the committed anchor `A`, using two comparisons
(`A - P <= skew` and `P - A <= ceiling`). A caller choosing `P = A` satisfies both
for any ceiling, so an arbitrarily stale anchor looks fresh and an expired grant is
authorized from the past. The ceiling bounded nothing against the very adversary
(a gateway that controls its own proposal clock) it was meant to constrain.

## The repair

Staleness is now measured against the **answering peer's own wall clock**:
`stale := time.Now().UTC().Sub(anchored)`. `CheckAccess` runs only as an evaluate
answered by a single peer, so consulting that peer's clock introduces no endorsement
nondeterminism and extends an assumption the design already makes (that the answering
peer returns honest world state). The skew comparison against `P` is retained, so the
composed bound holds against a malicious proposal clock: the anchor is at most the
ceiling old by the peer's clock, and the proposal is at most the skew tolerance behind
the anchor, so a proposal timestamp cannot sit more than ceiling + skew behind the
peer's present.

A Go unit test (`TestCheckAccess_RejectsForgedFreshness_PEqualsA`) constructs the exact
`P = A` counterexample against a two-hour-stale anchor. It fails on the old check and
passes on the repaired one. The full suite passes.

## Measured sweep (gateway heartbeat stopped, one fresh anchor per ceiling)

| Ceiling | Measured availability window | Backdating bound (window + 120 s skew) | Outcome |
|---|---|---|---|
| 30 s | 28 s | 148 s | refused |
| 60 s | 59 s | 179 s | refused |
| 120 s | 119 s | 239 s | refused |
| 0 (disabled, shipped) | none within 200 s | unbounded by this mechanism | still authorizing |

Each measured window tracks its configured ceiling to within the 3 s poll granularity,
and the enabled ceilings now refuse from the peer clock rather than from a value the
caller controls. Zero remains the shipped default (reads stay available during an
outage, accepting the weaker bound), the same availability-versus-backdating trade the
earlier sweep described, but now on a check that actually bounds a malicious clock.

## Scope

What is measured is the enforcement of the ceiling against the answering peer's clock.
Two things remain out of scope, as before: the end-to-end backdating attack was not
constructed against the deployment (the SDK does not expose the proposal timestamp),
and the peer clock is trusted under the same honest-answering-peer assumption CheckAccess
already relies on. The measured windows and the composed bound are the transferable
results.
