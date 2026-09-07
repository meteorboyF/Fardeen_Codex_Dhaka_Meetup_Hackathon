#!/usr/bin/env bash
# Experiment 19 — Public-key substitution (threat-model Scenario S3), now closed.
#
# S3 is the sharpest residual risk in the prior manuscript: an adversary with write
# access to the operational identity table replaces a user's public wrapping key
# before a grant is formed, so the grant wraps the document key under the attacker's
# key while the ledger commits a cryptographically valid transaction. The prior paper
# could only ANALYZE this and state that closing it needs a ledger-witnessed
# user-to-key binding, "which is not implemented."
#
# It is now implemented (chaincode RegisterUserKey + GrantAccess verification,
# backend anchoring at enrollment). This experiment performs the substitution an
# attacker would perform and reports what the grant path does.
#
# Cases (all mutations applied directly with psql, reverted between cases):
#   A. control — grant to an unmodified, ledger-bound recipient        -> expect COMMIT
#   B. attack  — substitute the recipient's public key in the DB, then
#      grant: attested hash no longer matches the anchored binding     -> expect REFUSE
#   C. immutability — attacker tries to re-anchor the substitute key
#      via a second RegisterUserKey                                    -> expect REFUSE
#   D. migration — a user with NO anchored binding (legacy) is still
#      grantable (documented posture, audited as keyBinding=absent)    -> expect COMMIT
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXP_DIR="$ROOT_DIR/experiments/pubkey_substitution_19"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
OUT_DIR="${PANGOCHAIN_EXP19_OUTPUT_DIR:-$EXP_DIR/results/$STAMP}"
BASE="${API_URL:-http://localhost:8080/api}"
PW="${DEMO_PASSWORD:-Demo2026#Secure}"
PG="pangochain-postgres"; CLI="fabric-cli"; CHANNEL="legal-channel"; CC="legalcc"
mkdir -p "$OUT_DIR"
exec > >(tee -a "$OUT_DIR/run.log") 2>&1
SEQ="$OUT_DIR/sequence.csv"; echo "case,description,result" > "$SEQ"
log(){ printf '[exp19 %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
step(){ printf '%s,"%s","%s"\n' "$1" "$2" "${3//\"/\"\"}" >> "$SEQ"; }
pg(){ docker exec "$PG" psql -U pangochain -d pangochain -tA -c "$1" 2>/dev/null; }
token(){ curl -s -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$1\",\"password\":\"$PW\"}" | python3 -c "import json,sys;print(json.load(sys.stdin)['accessToken'])"; }

{ echo "{\"experiment\":\"19 - public-key substitution S3 closure\","
  echo " \"timestamp_utc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo " \"git_commit\":\"$(git -C "$ROOT_DIR" rev-parse HEAD)\","
  echo " \"chaincode\":\"legalcc v1.1 seq 2 (RegisterUserKey + GrantAccess binding check)\"}"; } > "$OUT_DIR/environment.json"

# Fresh fixture: a case + document owned by rahman, and a NEW grantee registered
# now so its key binding is anchored by the enrollment path under test.
FIX="$(node "$EXP_DIR/setup_s3.mjs")"
echo "$FIX" > "$OUT_DIR/fixture.json"
jqf(){ python3 -c "import json;print(json.load(open('$OUT_DIR/fixture.json'))['$1'])"; }
DOC=$(jqf docId); GRANTEE=$(jqf granteeId); GRANTEE_MSP=$(jqf granteeMsp)
OWNER_EMAIL=$(jqf ownerEmail); WRAP=$(jqf wrappedKeyToken); GOOD_JWK_HASH=$(jqf keyHash)
TOK_O="$(token "$OWNER_EMAIL")"
# Newly registered users are PENDING_APPROVAL; activate so the grant is not blocked
# upstream of the ledger check (the same account-status filter Table "excluded runs"
# flags in the prior campaign).
pg "UPDATE users SET status='ACTIVE' WHERE id='$GRANTEE'" >/dev/null
log "fixture doc=$DOC grantee=$GRANTEE anchoredKeyHash=${GOOD_JWK_HASH:0:16}..."

grant(){ curl -s -w '\n%{http_code}' -X POST "$BASE/access/grant" \
  -H "Authorization: Bearer $TOK_O" -H 'Content-Type: application/json' \
  -d "{\"docId\":\"$DOC\",\"granteeId\":\"$GRANTEE\",\"capability\":\"read\",\"wrappedKeyToken\":\"$WRAP\"}"; }

binding_raw(){ docker exec "$CLI" peer chaincode query -C "$CHANNEL" -n "$CC" \
  -c "{\"function\":\"GetUserKeyBinding\",\"Args\":[\"$GRANTEE\"]}" 2>/dev/null; }

# ── A: control — bound recipient, unmodified key ───────────────────────────
log "[A] anchored binding on chain: $(binding_raw | head -c 120)"
RESP=$(grant); CODE=$(echo "$RESP" | tail -1); BODY=$(echo "$RESP" | head -n -1)
SYNC=$(echo "$BODY" | python3 -c "import json,sys;print(json.load(sys.stdin).get('ledgerSyncStatus'))" 2>/dev/null || echo err)
log "[A] control grant (matching key): HTTP $CODE sync=$SYNC"
step A "control: grant to ledger-bound recipient, key unmodified" "HTTP $CODE sync=$SYNC (expect 200 committed)"
# revert to a clean slate for case B: remove the operational grant + on-chain ACL entry noise
pg "DELETE FROM document_access WHERE doc_id='$DOC' AND user_id='$GRANTEE'" >/dev/null

# ── B: attack — substitute the recipient public key in the DB, then grant ──
ORIG_KEY=$(pg "SELECT public_key_ecies FROM users WHERE id='$GRANTEE'")
# Attacker swaps in a different valid P-256 JWK (generated offline, attacker holds sk).
ATT_KEY=$(node "$EXP_DIR/attacker_key.mjs")
pg "UPDATE users SET public_key_ecies='$ATT_KEY' WHERE id='$GRANTEE'" >/dev/null
log "[B] substituted recipient public key in operational DB"
RESP=$(grant); CODE=$(echo "$RESP" | tail -1); BODY=$(echo "$RESP" | head -n -1)
MSG=$(echo "$BODY" | python3 -c "import json,sys;print(json.load(sys.stdin).get('message',''))" 2>/dev/null || echo "$BODY")
log "[B] grant after substitution: HTTP $CODE msg=${MSG:0:90}"
step B "attack: grant after DB key substitution" "HTTP $CODE (expect 4xx refused) msg=${MSG:0:80}"
# The refusal is audited in its own REQUIRES_NEW transaction, whose ledger anchor
# takes ~2s; poll so the check does not race the commit.
REJECTED=0
for _ in 1 2 3 4 5; do
  REJECTED=$(pg "SELECT count(*) FROM audit_log WHERE resource_id='$DOC' AND event_type='ACCESS_GRANT_REJECTED_KEY_MISMATCH'")
  [[ "$REJECTED" -ge 1 ]] && break; sleep 1
done
log "[B] key-mismatch audit rows: $REJECTED"
step B2 "attack refusal is audited on the ledger trail" "ACCESS_GRANT_REJECTED_KEY_MISMATCH rows=$REJECTED"

# ── C: immutability — attacker tries to re-anchor the substitute key ───────
ATT_HASH=$(node "$EXP_DIR/hash_jwk.mjs" "$ATT_KEY")
REANCHOR=$(docker exec "$CLI" peer chaincode invoke -C "$CHANNEL" -n "$CC" \
  --tls --cafile /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/pangochain.com/orderers/orderer1.pangochain.com/tls/ca.crt \
  -c "{\"function\":\"RegisterUserKey\",\"Args\":[\"$GRANTEE\",\"$ATT_HASH\"]}" 2>&1 || true)
if echo "$REANCHOR" | grep -q "already anchored"; then RES="REFUSED (immutable)"; else RES="UNEXPECTED: $REANCHOR"; fi
log "[C] attacker re-anchor attempt: $RES"
step C "immutability: attacker re-anchors substitute key" "$RES (expect REFUSED)"
pg "UPDATE users SET public_key_ecies='$ORIG_KEY' WHERE id='$GRANTEE'" >/dev/null  # revert

# ── D: migration — a genuinely unbound legacy user is still grantable ──────
# chowdhury was enrolled before key-anchoring was wired into registration, so it
# has no on-chain binding: an authentic pre-feature user, not a contrived one.
LG=$(pg "SELECT id FROM users WHERE email='s.chowdhury@lawfirm-b.example'")
BOUND=$(docker exec "$CLI" peer chaincode query -C "$CHANNEL" -n "$CC" -c "{\"function\":\"GetUserKeyBinding\",\"Args\":[\"$LG\"]}" 2>/dev/null)
RESP=$(curl -s -w '\n%{http_code}' -X POST "$BASE/access/grant" -H "Authorization: Bearer $TOK_O" \
  -H 'Content-Type: application/json' -d "{\"docId\":\"$DOC\",\"granteeId\":\"$LG\",\"capability\":\"read\",\"wrappedKeyToken\":\"$WRAP\"}")
CODE=$(echo "$RESP" | tail -1)
KB=$(pg "SELECT metadata_json FROM audit_log WHERE resource_id='$DOC' AND event_type='ACCESS_GRANTED' ORDER BY timestamp DESC LIMIT 1" | grep -o 'keyBinding[^,}]*' || echo "keyBinding:?")
log "[D] legacy-unbound grant: HTTP $CODE (on-chain binding empty=$([ -z "$BOUND" ] && echo yes || echo no); audit $KB)"
step D "migration: unbound legacy user still grantable" "HTTP $CODE binding_empty=$([ -z "$BOUND" ] && echo yes || echo no) audit=$KB (expect 2xx, keyBinding=absent)"

# ── E: restore race — client attests the substituted key, attacker restores DB key ──
# This is the case the audit (S4) flagged: hashing the current DB key at submission time
# would PASS after the attacker restores the original key, but the client attests the key
# it actually wrapped under, so the mismatch against the anchor survives the restore.
pg "UPDATE users SET status='ACTIVE' WHERE id='$GRANTEE'" >/dev/null
ORIG_KEY_E=$(pg "SELECT public_key_ecies FROM users WHERE id='$GRANTEE'")
ATT_KEY_E=$(node "$EXP_DIR/attacker_key.mjs")
ATT_HASH_E=$(node "$EXP_DIR/hash_jwk.mjs" "$ATT_KEY_E")
# 1. attacker substitutes the published key; 2. client fetches it and wraps+attests under it
pg "UPDATE users SET public_key_ecies='$ATT_KEY_E' WHERE id='$GRANTEE'" >/dev/null
# 3. attacker restores the original DB key before the grant is submitted
pg "UPDATE users SET public_key_ecies='$ORIG_KEY_E' WHERE id='$GRANTEE'" >/dev/null
# 4. grant carries the CLIENT attestation of the substituted key (what was wrapped under)
RESP=$(curl -s -w '\n%{http_code}' -X POST "$BASE/access/grant" -H "Authorization: Bearer $TOK_O" \
  -H 'Content-Type: application/json' \
  -d "{\"docId\":\"$DOC\",\"granteeId\":\"$GRANTEE\",\"capability\":\"read\",\"wrappedKeyToken\":\"$WRAP\",\"recipientKeyHash\":\"$ATT_HASH_E\"}")
CODE=$(echo "$RESP" | tail -1)
DB_MATCHES_ANCHOR=$(pg "SELECT public_key_ecies FROM users WHERE id='$GRANTEE'" | head -c 20)
log "[E] restore race (client attested substituted key, DB restored): HTTP $CODE"
step E "restore race: client-attested substitute vs restored DB key" "HTTP $CODE (expect 4xx: attestation catches it though DB key now matches anchor)"

log "done — results in $OUT_DIR"
