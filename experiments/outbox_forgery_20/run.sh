#!/usr/bin/env bash
# Experiment 20 — the outbox no longer trusts the database (audit finding S2).
#
# The reconciliation worker submits pending_anchor rows to the ledger with the gateway's
# Fabric credentials. If those rows were trusted unconditionally, a database writer could
# insert a forged GrantAccess row and have the worker enact it. Each row is now signed with
# an HMAC the gateway holds only in configuration; the worker refuses rows whose signature
# does not verify. This experiment performs the forgery a database writer would perform and
# confirms the forged mutation never reaches the ledger.
#
# Cases (all applied directly with psql, reverted between cases):
#   A. control  — a legitimate grant issued through the API commits and is signed.
#   B. forge    — insert a GrantAccess pending_anchor row for an attacker subject with a
#                 plausible-looking but invalid signature; wait for the worker; the row is
#                 marked FAILED, an OUTBOX_ANCHOR_REJECTED_FORGED audit event is written, and
#                 the ledger never grants the attacker.
#   C. tamper   — take a legitimate PENDING row and alter its target_user_id; the signature
#                 no longer matches, so the worker refuses it.
set -uo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXP_DIR="$ROOT_DIR/experiments/outbox_forgery_20"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
OUT_DIR="${PANGOCHAIN_EXP20_OUT:-$EXP_DIR/results/$STAMP}"
BASE="${API_URL:-http://localhost:8080/api}"; PW="${DEMO_PASSWORD:-Demo2026#Secure}"
PG=pangochain-postgres; CLI=fabric-cli; CHANNEL=legal-channel; CC=legalcc
mkdir -p "$OUT_DIR"; exec > >(tee -a "$OUT_DIR/run.log") 2>&1
SEQ="$OUT_DIR/sequence.csv"; echo "case,description,result" > "$SEQ"
log(){ printf '[exp20 %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
step(){ printf '%s,"%s","%s"\n' "$1" "$2" "${3//\"/\"\"}" >> "$SEQ"; }
pg(){ docker exec "$PG" psql -U pangochain -d pangochain -tA -c "$1" 2>/dev/null; }
token(){ curl -s -X POST "$BASE/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$1\",\"password\":\"$PW\"}" | python3 -c "import json,sys;print(json.load(sys.stdin)['accessToken'])"; }
ledger_grant(){ docker exec "$CLI" peer chaincode query -C "$CHANNEL" -n "$CC" -c "{\"function\":\"CheckAccess\",\"Args\":[\"$1\",\"$2\",\"FirmBMSP\"]}" 2>/dev/null; }

{ echo "{\"experiment\":\"20 - outbox forgery resistance (audit S2)\","
  echo " \"timestamp_utc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo " \"git_commit\":\"$(git -C "$ROOT_DIR" rev-parse HEAD)\"}"; } > "$OUT_DIR/environment.json"

# Fixture: fresh case + document owned by rahman, plus a would-be attacker subject (karim).
FIX="$(node "$ROOT_DIR/experiments/grant_outage_reconciliation_18/setup_grant.mjs")"
echo "$FIX" > "$OUT_DIR/fixture.json"
jqf(){ python3 -c "import json;print(json.load(open('$OUT_DIR/fixture.json'))['$1'])"; }
DOC=$(jqf docId); GRANTEE=$(jqf granteeId); OWNER=$(jqf granterEmail); WRAP=$(jqf wrappedKeyToken)
ATTACKER=$(pg "SELECT id FROM users WHERE email='m.karim@regulator.example'")
OWNER_ID=$(pg "SELECT id FROM users WHERE email='$OWNER'")
log "fixture doc=$DOC grantee=$GRANTEE attacker=$ATTACKER"

# ── A: control — legitimate grant through the API commits ──────────────────
TOK_O="$(token "$OWNER")"
curl -s -o /dev/null -X POST "$BASE/access/grant" -H "Authorization: Bearer $TOK_O" \
  -H 'Content-Type: application/json' \
  -d "{\"docId\":\"$DOC\",\"granteeId\":\"$GRANTEE\",\"capability\":\"read\",\"wrappedKeyToken\":\"$WRAP\"}"
sleep 3
SIGNED=$(pg "SELECT signature IS NOT NULL FROM pending_anchor WHERE doc_id='$DOC' AND target_user_id='$GRANTEE' ORDER BY created_at DESC LIMIT 1")
LG=$(ledger_grant "$DOC" "$GRANTEE")
log "[A] legitimate grant: ledger=$LG signed=$SIGNED"
step A "control: legitimate grant via API" "ledger=$LG signed=$SIGNED (expect true/t)"

# ── B: forge — insert a GrantAccess row for the attacker with a junk signature ─
FORGED_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
pg "INSERT INTO pending_anchor (id, chaincode_function, doc_id, target_user_id, revoker_id, status, attempts, next_attempt_at, created_at, payload, signature)
    VALUES ('$FORGED_ID','GrantAccess','$DOC','$ATTACKER','$OWNER_ID','PENDING',0, now(), now(),
    '{\"granteeMsp\":\"RegulatorMSP\",\"capability\":\"read\",\"expiresAt\":\"\",\"wrappedKeyRef\":\"forged\",\"recipientKeyHash\":\"\",\"keyHashSource\":\"gateway-db\"}',
    'deadbeefforgedsignature0000000000000000000000000000000000000000')" >/dev/null
log "[B] inserted forged GrantAccess row $FORGED_ID for attacker"
# Wait for the worker to process it (5s poll + backoff); poll up to 40s.
OUTCOME="still_pending"
for _ in $(seq 1 20); do
  st=$(pg "SELECT status FROM pending_anchor WHERE id='$FORGED_ID'")
  [ "$st" = "FAILED" ] && { OUTCOME="FAILED"; break; }
  [ "$st" = "COMMITTED" ] && { OUTCOME="COMMITTED"; break; }
  sleep 2
done
LG_ATT=$(ledger_grant "$DOC" "$ATTACKER")
REJ=$(pg "SELECT count(*) FROM audit_log WHERE event_type='OUTBOX_ANCHOR_REJECTED_FORGED' AND resource_id='$DOC'")
log "[B] forged row status=$OUTCOME ledger-grants-attacker=$LG_ATT rejected-audit-rows=$REJ"
step B "forge: attacker GrantAccess row with junk signature" "status=$OUTCOME ledger=$LG_ATT rejected=$REJ (expect FAILED/false/>=1)"
pg "DELETE FROM pending_anchor WHERE id='$FORGED_ID'" >/dev/null

# ── C: tamper — alter a legitimate pending row's target so the signature breaks ─
# Force a legitimate PENDING row: issue a revoke while a forged older sibling blocks inline.
# Simpler: insert a correctly shaped row via the API path during an induced failure is heavy;
# instead alter the control grant's committed row back to PENDING with a changed target.
TAMPER_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
GOODSIG=$(pg "SELECT signature FROM pending_anchor WHERE doc_id='$DOC' AND target_user_id='$GRANTEE' AND signature IS NOT NULL ORDER BY created_at DESC LIMIT 1")
if [ -n "$GOODSIG" ]; then
  # Copy a legitimately signed row but point it at the attacker: signature now covers the
  # wrong target, so verification must fail.
  pg "INSERT INTO pending_anchor (id, chaincode_function, doc_id, target_user_id, revoker_id, status, attempts, next_attempt_at, created_at, payload, signature)
      SELECT '$TAMPER_ID', chaincode_function, doc_id, '$ATTACKER', revoker_id, 'PENDING', 0, now(), now(), payload, signature
      FROM pending_anchor WHERE doc_id='$DOC' AND target_user_id='$GRANTEE' AND signature IS NOT NULL ORDER BY created_at DESC LIMIT 1" >/dev/null
  TOUT="still_pending"
  for _ in $(seq 1 20); do
    st=$(pg "SELECT status FROM pending_anchor WHERE id='$TAMPER_ID'")
    [ "$st" = "FAILED" ] && { TOUT="FAILED"; break; }
    [ "$st" = "COMMITTED" ] && { TOUT="COMMITTED"; break; }
    sleep 2
  done
  LG_ATT2=$(ledger_grant "$DOC" "$ATTACKER")
  log "[C] tampered (retargeted) row status=$TOUT ledger-grants-attacker=$LG_ATT2"
  step C "tamper: retarget a legitimately signed row" "status=$TOUT ledger=$LG_ATT2 (expect FAILED/false)"
  pg "DELETE FROM pending_anchor WHERE id='$TAMPER_ID'" >/dev/null
else
  log "[C] skipped: no signed row available (HMAC secret not configured?)"
  step C "tamper: retarget a legitimately signed row" "skipped: signing disabled"
fi

log "done — results in $OUT_DIR"
