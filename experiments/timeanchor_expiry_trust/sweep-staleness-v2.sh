#!/usr/bin/env bash
# Experiment 17b, v2 — staleness-ceiling sweep on the peer-clock freshness check.
#
# This supersedes sweep-staleness-ceiling.sh after pre-submission audit finding S1.
# The original check measured anchor staleness against the caller-supplied proposal
# timestamp, which is circular; the repaired chaincode measures it against the
# answering peer's own wall clock (legalcc >= v1.2 seq 3). The gateway heartbeat MUST
# be stopped before running this, or a fresh anchor every 60 s prevents any ceiling
# from ever being reached.
#
# For each ceiling: deploy the chaincode with that constant, commit exactly one fresh
# anchor, then poll CheckAccess every POLL seconds until the decision flips from
# authorised to refused. The elapsed time to the flip is the measured availability
# window, and the backdating bound is that window plus the fixed 120 s proposal-skew
# tolerance. Ceiling 0 (disabled) is expected never to refuse within GIVE_UP.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXP_DIR="$ROOT_DIR/experiments/timeanchor_expiry_trust"
FABRIC_DIR="$ROOT_DIR/pangochain-fabric"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
OUT_DIR="${PANGOCHAIN_SWEEP_OUT:-$EXP_DIR/results/sweepv2_$STAMP}"
CC_SRC="$ROOT_DIR/pangochain-chaincode/legalcc/types.go"
CHANNEL=legal-channel; CC=legalcc; CLI=fabric-cli
POLL="${PANGOCHAIN_SWEEP_POLL:-3}"
GIVE_UP="${PANGOCHAIN_SWEEP_GIVEUP:-200}"
CEILINGS=(${PANGOCHAIN_SWEEP_CEILINGS:-30 60 120 0})
START_SEQ="${PANGOCHAIN_SWEEP_START_SEQ:-10}"
SKEW=120

CRYPTO=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto
ORD_CA="$CRYPTO/ordererOrganizations/pangochain.com/orderers/orderer1.pangochain.com/msp/tlscacerts/tlsca.pangochain.com-cert.pem"
CA_A="$CRYPTO/peerOrganizations/firma.pangochain.com/peers/peer0.firma.pangochain.com/tls/ca.crt"
CA_B="$CRYPTO/peerOrganizations/firmb.pangochain.com/peers/peer0.firmb.pangochain.com/tls/ca.crt"
CA_R="$CRYPTO/peerOrganizations/regulator.pangochain.com/peers/peer0.regulator.pangochain.com/tls/ca.crt"

mkdir -p "$OUT_DIR"
exec > >(tee -a "$OUT_DIR/run.log") 2>&1
log(){ printf '[sweepv2 %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
CSV="$OUT_DIR/sweep.csv"
echo "ceiling_seconds,availability_window_seconds,backdating_bound_seconds,outcome" > "$CSV"

if pgrep -f "pangochain-backend-2.0.0.jar" >/dev/null; then
  log "WARNING: a gateway process is running; its heartbeat will refresh the anchor and invalidate this sweep."
fi

DOC="$(cat "$EXP_DIR/doc.txt")"; GRANTEE="$(cat "$EXP_DIR/grantee.txt")"
[ -n "$DOC" ] && [ -n "$GRANTEE" ] || { echo "missing fixture ids"; exit 1; }
CHECK="{\"function\":\"CheckAccess\",\"Args\":[\"$DOC\",\"$GRANTEE\",\"FirmBMSP\"]}"

{ echo "{"; echo "  \"experiment\": \"17b v2 - staleness sweep, peer-clock freshness (audit S1)\",";
  echo "  \"timestamp_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",";
  echo "  \"host\": \"$(uname -srm)\", \"chaincode\": \"legalcc peer-clock freshness\",";
  echo "  \"max_clock_skew_seconds\": $SKEW, \"ceilings\": \"${CEILINGS[*]}\",";
  echo "  \"poll_seconds\": $POLL, \"give_up_seconds\": $GIVE_UP,";
  echo "  \"git_commit\": \"$(git -C "$ROOT_DIR" rev-parse HEAD)\" }"; } > "$OUT_DIR/environment.json"

commit_anchor(){
  docker exec "$CLI" peer chaincode invoke -o orderer1.pangochain.com:7050 --tls --cafile "$ORD_CA" \
    -C "$CHANNEL" -n "$CC" --waitForEvent \
    --peerAddresses peer0.firma.pangochain.com:7051 --tlsRootCertFiles "$CA_A" \
    --peerAddresses peer0.firmb.pangochain.com:8051 --tlsRootCertFiles "$CA_B" \
    --peerAddresses peer0.regulator.pangochain.com:9051 --tlsRootCertFiles "$CA_R" \
    -c '{"function":"UpdateTimeAnchor","Args":[]}' 2>&1 | grep -c "status:200" || true
}
check_anchor_ts(){ docker exec "$CLI" peer chaincode query -C "$CHANNEL" -n "$CC" -c "{\"function\":\"GetTimeAnchor\",\"Args\":[]}" 2>/dev/null | grep -oP "timestamp\":\"\\K[^\"]+"; }
check(){ docker exec "$CLI" peer chaincode query -C "$CHANNEL" -n "$CC" -c "$CHECK" 2>&1; }

seq_no="$START_SEQ"
for ceiling in "${CEILINGS[@]}"; do
  log "=== ceiling ${ceiling}s (seq ${seq_no}) ==="
  sed -i "s/^\tMaxAnchorStalenessSeconds = .*/\tMaxAnchorStalenessSeconds = ${ceiling}/" "$CC_SRC"
  ( cd "$FABRIC_DIR" && CC_VERSION="1.$((seq_no+20))" CC_SEQUENCE="$seq_no" bash scripts/deploy-chaincode.sh ) \
    > "$OUT_DIR/deploy_${ceiling}.log" 2>&1 \
    || { log "deploy failed for ceiling ${ceiling}"; echo "$ceiling,,,deploy_failed" >> "$CSV"; seq_no=$((seq_no+1)); continue; }

  # UpdateTimeAnchor rejects a non-advancing heartbeat, so the prior anchor may already be
  # ahead of real time from an earlier ceiling. Wait until wall clock passes it, then commit.
  prior=$(check_anchor_ts)
  if [ -n "$prior" ]; then
    now_epoch=$(date -u +%s); prior_epoch=$(date -u -d "$prior" +%s 2>/dev/null || echo 0)
    if [ "$prior_epoch" -gt "$now_epoch" ]; then
      wait_s=$((prior_epoch - now_epoch + 2)); log "  prior anchor is ${wait_s}s ahead; waiting"; sleep "$wait_s"
    fi
  fi

  if [ "$(commit_anchor)" -lt 1 ]; then log "  fresh anchor did not commit; skipping"; echo "$ceiling,,,anchor_failed" >> "$CSV"; seq_no=$((seq_no+1)); continue; fi
  t0=$(date -u +%s)
  log "  fresh anchor committed; polling every ${POLL}s"

  outcome="still_authorising"; window=""
  deadline=$(( t0 + GIVE_UP ))
  while [ "$(date -u +%s)" -lt "$deadline" ]; do
    sleep "$POLL"
    res="$(check)"
    if echo "$res" | grep -q "exceeding the ${ceiling}s ceiling"; then
      window=$(( $(date -u +%s) - t0 )); outcome="refused"; break
    fi
  done

  if [ "$outcome" = "refused" ]; then
    bound=$(( window + SKEW ))
    log "  refused after ${window}s (backdating bound ${bound}s)"
    echo "$ceiling,$window,$bound,refused" >> "$CSV"
  else
    log "  no refusal within ${GIVE_UP}s (expected for disabled ceiling 0)"
    echo "$ceiling,,,no_refusal_within_${GIVE_UP}s" >> "$CSV"
  fi
  seq_no=$((seq_no+1))
done

log "sweep complete; source left at MaxAnchorStalenessSeconds = $(grep -oP 'MaxAnchorStalenessSeconds = \K[0-9]+' "$CC_SRC" | head -1)"
cat "$CSV"
