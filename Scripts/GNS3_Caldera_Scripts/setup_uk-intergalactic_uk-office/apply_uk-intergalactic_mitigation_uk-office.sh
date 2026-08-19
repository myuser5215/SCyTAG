#!/usr/bin/env bash
#
# UK-Intergalactic mitigation — apply on intergalactic-vpn (UK-Office topology)
# ------------------------------------------------------------------------------
# Blocks the UK-Intergalactic adversary attack chain at two independent points,
# preventing lateral movement to alpine-3.18-openvpn-1 and storage-server-1.
#
# Attack chain (8 abilities):
#   1  Version Discovery          T1016       — Unaffected (RCE not blocked)
#   2  RCE / shell-exec check     T1505.003   — Unaffected (RCE not blocked)
#   3  Credential exfiltration    T1555       — Unaffected (users.db still downloads)
#   4  Password cracking          T1110.002   — BLOCKED by Mitigation 1
#   5  Forge VPN cert & connect   T1133       — BLOCKED by Mitigation 2 (false positive exit 0 — real effect shows in Ability 6)
#   6  Network scan               T1046       — BLOCKED (times out — tun0 never comes up)
#   7  SSH lateral movement       T1021.004   — SKIPPED (no cracked password, no tunnel)
#   8  SSH tunnel into VLAN       T1021.004   — SKIPPED (no cracked password, no tunnel)
#
# Mitigation 1 — Harden alice's password in users.db (blocks Ability 4 → 7, 8):
#   Changes alice's password from the stock wordlist-crackable value to
#   'Xk9#mQ2vL7pR' (MD5: 4d0aaabaa6a1593d403ed5afbfb4b045).
#   app.py hashes passwords as plain unsalted MD5.
#   Applied via a base64-encoded Python script to avoid nested-shell quoting issues.
#
# Mitigation 2 — Disable CA signing capability (blocks Ability 5/6 → 7, 8):
#   Renames ca.key → ca.key.disabled inside intergalactic-vpn.
#   Breaks new VPN certificate issuance (add_client.sh fails to sign).
#   Existing legitimate cert on alpine-3.18-openvpn-1 is unaffected.
#
# Applied via nested docker exec:
#   docker exec gns3-server sh -c "docker exec <intergalactic-vpn_id> ..."
# This is necessary because intergalactic-vpn is a container nested inside
# the gns3-server container (UK-Office topology), unlike Bank topology.
#
# IMPORTANT — neither mitigation persists across sessions:
#   - Mitigation 1: app.py's init_db() re-inserts alice's original weak password
#     every time the container is recreated. Re-apply every session.
#   - Mitigation 2: the renamed ca.key lives in the container's writable layer,
#     which is discarded on every node/project restart. Re-apply every session.
# Both must be reapplied after confirming the current container ID (Step 0).
#
# Usage:
#   ./apply-uk-intergalactic-mitigation.sh
#   PROJECT_ID=<id> ./apply-uk-intergalactic-mitigation.sh   # skip project discovery
 
set -uo pipefail
 
# ---- Configuration ----
PROJECT_ID="${PROJECT_ID:-}"
PROJECT_NAME_PATTERN="${PROJECT_NAME_PATTERN:-UK-Office}"
GNS3_API="http://localhost:3080"
VPN_NODE_NAME="intergalactic-vpn"
 
# Hardened password for alice (change both values together if using a different password):
#   NEW_PASSWORD_PLAIN = Xk9#mQ2vL7pR
#   NEW_PASSWORD_MD5   = echo -n 'Xk9#mQ2vL7pR' | md5sum | cut -d' ' -f1
NEW_PASSWORD_MD5="4d0aaabaa6a1593d403ed5afbfb4b045"
 
# Base64-encoded Python script that updates alice's password in users.db.
# Decoded content:
#   import sqlite3
#   conn = sqlite3.connect('/app/web_ui/users.db')
#   conn.execute("UPDATE users SET password='4d0aaabaa6a1593d403ed5afbfb4b045' WHERE username='alice'")
#   conn.commit()
#   conn.close()
#   print('done')
PW_UPDATE_B64="aW1wb3J0IHNxbGl0ZTMKY29ubiA9IHNxbGl0ZTMuY29ubmVjdCgnL2FwcC93ZWJfdWkvdXNlcnMuZGInKQpjb25uLmV4ZWN1dGUoIlVQREFURSB1c2VycyBTRVQgcGFzc3dvcmQ9JzRkMGFhYWJhYTZhMTU5M2Q0MDNlZDVhZmJmYjRiMDQ1JyBXSEVSRSB1c2VybmFtZT0nYWxpY2UnIikKY29ubi5jb21taXQoKQpjb25uLmNsb3NlKCkKcHJpbnQoJ2RvbmUnKQo="
 
CA_KEY_PATH="/etc/openvpn/pki/private/ca.key"
CA_KEY_DISABLED_PATH="/etc/openvpn/pki/private/ca.key.disabled"
 
# ---- Helper: run a command inside intergalactic-vpn via nested docker exec ----
vpn_exec() {
  docker exec gns3-server sh -c "docker exec ${VPN_ID} sh -c '$*'"
}
 
# ---- 0. Resolve project ID ----
if [ -z "$PROJECT_ID" ]; then
  echo "== No PROJECT_ID set — searching projects matching '$PROJECT_NAME_PATTERN' =="
  MATCHES=$(curl -s "$GNS3_API/v2/projects" | python3 -c "
import json, sys
pat = '''$PROJECT_NAME_PATTERN'''
for p in json.load(sys.stdin):
    if pat in p.get('name',''):
        print(p.get('project_id'), '|', p.get('status'), '|', p.get('name'))
")
  MATCH_COUNT=$(echo "$MATCHES" | grep -c . || true)
 
  if [ "$MATCH_COUNT" -eq 0 ]; then
    echo "!! No project matched '$PROJECT_NAME_PATTERN'. Set PROJECT_ID explicitly:" >&2
    echo "   PROJECT_ID=<id> $0" >&2
    exit 1
  elif [ "$MATCH_COUNT" -eq 1 ]; then
    PROJECT_ID=$(echo "$MATCHES" | cut -d'|' -f1 | tr -d ' ')
    echo "   found: $MATCHES"
  else
    OPENED=$(echo "$MATCHES" | grep '| opened |' || true)
    OPENED_COUNT=$(echo "$OPENED" | grep -c . || true)
    if [ "$OPENED_COUNT" -eq 1 ]; then
      PROJECT_ID=$(echo "$OPENED" | cut -d'|' -f1 | tr -d ' ')
      echo "   multiple name matches, exactly one is 'opened' — using it:"
      echo "   $OPENED"
    else
      echo "!! Multiple candidate projects, can't pick automatically:" >&2
      echo "$MATCHES" >&2
      echo "   Set PROJECT_ID explicitly and re-run:" >&2
      echo "   PROJECT_ID=<id> $0" >&2
      exit 1
    fi
  fi
fi
echo "== Using project: $PROJECT_ID =="
 
# ---- 1. Resolve intergalactic-vpn container ID ----
echo "== Resolving $VPN_NODE_NAME =="
VPN_INFO=$(curl -s "$GNS3_API/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
name = '''$VPN_NODE_NAME'''
for n in json.load(sys.stdin):
    if n.get('name') == name:
        print(n.get('node_id',''), '|', n.get('status',''), '|', n.get('properties', {}).get('container_id',''))
")
if [ -z "$VPN_INFO" ]; then
  echo "!! No node named '$VPN_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
VPN_NODE_ID=$(echo "$VPN_INFO" | cut -d'|' -f1 | tr -d ' ')
VPN_STATUS=$(echo "$VPN_INFO"  | cut -d'|' -f2 | tr -d ' ')
VPN_ID=$(echo "$VPN_INFO"      | cut -d'|' -f3 | tr -d ' ')
echo "   node_id=$VPN_NODE_ID  status=$VPN_STATUS  container_id=$VPN_ID"
 
if [ "$VPN_STATUS" != "started" ]; then
  echo "!! $VPN_NODE_NAME is not started (status=$VPN_STATUS)." >&2
  echo "   Start the node (or run setup-caldera-lab_uk-intergalactic.sh) before applying." >&2
  exit 1
fi
 
# ---- 2. Fail-fast liveness check ----
if ! docker exec gns3-server sh -c "docker exec $VPN_ID echo alive" >/dev/null 2>&1; then
  echo "!! Container $VPN_ID ($VPN_NODE_NAME) is not reachable via nested docker exec." >&2
  echo "   Check that the inner dockerd inside gns3-server is running." >&2
  echo "   Run setup-caldera-lab_uk-intergalactic.sh first to ensure the environment is ready." >&2
  exit 1
fi
echo "   container reachable"
 
# ============================================================
# MITIGATION 1 — Harden alice's password in users.db
# ============================================================
echo ""
echo "== MITIGATION 1 — Hardening alice's password in users.db =="
 
# Baseline: show current hash
echo "-- Current alice row in users.db --"
docker exec gns3-server sh -c "docker exec $VPN_ID python3 -c \"
import sqlite3
conn = sqlite3.connect('/app/web_ui/users.db')
rows = conn.execute('SELECT username, password FROM users').fetchall()
for r in rows: print(r)
\"" 2>/dev/null || echo "   (could not query db — app may not have initialized yet)"
 
# Write the base64-encoded update script into the container
echo "-- Writing update script --"
if ! docker exec gns3-server sh -c \
  "docker exec $VPN_ID sh -c 'echo $PW_UPDATE_B64 | base64 -d > /tmp/update_pw.py'"; then
  echo "!! Failed to write update script to $VPN_NODE_NAME." >&2
  exit 1
fi
 
# Execute the update
echo "-- Running update script --"
RESULT=$(docker exec gns3-server sh -c "docker exec $VPN_ID python3 /tmp/update_pw.py" 2>&1)
if [ "$RESULT" != "done" ]; then
  echo "!! Password update script did not print 'done'. Output: '$RESULT'" >&2
  exit 1
fi
echo "   script returned: $RESULT"
 
# Verify the hash changed
echo "-- Verifying updated alice row --"
ALICE_HASH=$(docker exec gns3-server sh -c "docker exec $VPN_ID python3 -c \"
import sqlite3
conn = sqlite3.connect('/app/web_ui/users.db')
rows = conn.execute(\\\"SELECT password FROM users WHERE username='alice'\\\").fetchall()
print(rows[0][0] if rows else 'NOT_FOUND')
\"" 2>/dev/null | tr -d '[:space:]')
 
if [ "$ALICE_HASH" = "$NEW_PASSWORD_MD5" ]; then
  echo "   confirmed — alice's hash is now $ALICE_HASH"
else
  echo "!! Unexpected hash after update: '$ALICE_HASH' (expected '$NEW_PASSWORD_MD5')" >&2
  exit 1
fi
 
echo "== Mitigation 1 applied — Ability 4 (password cracking) will FAIL =="
 
# ============================================================
# MITIGATION 2 — Disable CA signing (rename ca.key)
# ============================================================
echo ""
echo "== MITIGATION 2 — Disabling CA signing capability =="
 
# Check current state of ca.key
echo "-- Checking PKI private directory --"
docker exec gns3-server sh -c \
  "docker exec $VPN_ID ls -la /etc/openvpn/pki/private/" 2>/dev/null || true
 
# Check if already disabled from a previous run
ALREADY_DISABLED=$(docker exec gns3-server sh -c \
  "docker exec $VPN_ID test -f $CA_KEY_DISABLED_PATH && echo yes || echo no" 2>/dev/null || echo "no")
KEY_PRESENT=$(docker exec gns3-server sh -c \
  "docker exec $VPN_ID test -f $CA_KEY_PATH && echo yes || echo no" 2>/dev/null || echo "no")
 
if [ "$ALREADY_DISABLED" = "yes" ] && [ "$KEY_PRESENT" = "no" ]; then
  echo "   ca.key.disabled already exists and ca.key is absent — mitigation already applied, skipping."
elif [ "$KEY_PRESENT" = "no" ] && [ "$ALREADY_DISABLED" = "no" ]; then
  echo "!! Neither ca.key nor ca.key.disabled found — unexpected state." >&2
  echo "   Check the PKI directory manually before continuing." >&2
  exit 1
else
  echo "-- Renaming ca.key → ca.key.disabled --"
  if ! docker exec gns3-server sh -c \
    "docker exec $VPN_ID mv $CA_KEY_PATH $CA_KEY_DISABLED_PATH"; then
    echo "!! mv ca.key → ca.key.disabled failed." >&2
    exit 1
  fi
  echo "   renamed successfully"
fi
 
# Verify
echo "-- Verifying ca.key is gone --"
docker exec gns3-server sh -c \
  "docker exec $VPN_ID ls -la /etc/openvpn/pki/private/" 2>/dev/null || true
 
KEY_GONE=$(docker exec gns3-server sh -c \
  "docker exec $VPN_ID test -f $CA_KEY_PATH && echo present || echo gone" 2>/dev/null)
if [ "$KEY_GONE" != "gone" ]; then
  echo "!! ca.key still present after rename — mitigation failed." >&2
  exit 1
fi
echo "   confirmed — ca.key is gone"
 
# Functional test: run add_client.sh and expect it to fail
echo "-- Functional test: attempting cert signing (should fail) --"
SIGN_OUTPUT=$(docker exec gns3-server sh -c \
  "docker exec $VPN_ID bash /app/web_ui/add_client.sh 172.100.1.1 test-should-fail" 2>&1 || true)
if echo "$SIGN_OUTPUT" | grep -qi "error\|failed\|no such file\|cannot\|not found"; then
  echo "   confirmed — add_client.sh fails to sign: $(echo "$SIGN_OUTPUT" | head -3)"
else
  echo "!! WARNING: add_client.sh did not produce an obvious error." >&2
  echo "   Output: $SIGN_OUTPUT" >&2
  echo "   Investigate manually before running the operation." >&2
fi
 
echo "== Mitigation 2 applied — Ability 5 cert forge will produce empty cert; Ability 6 will timeout =="
 
# ---- Done ----
echo ""
echo "== Both mitigations applied successfully =="
echo "   $VPN_NODE_NAME ($VPN_ID)"
echo ""
echo "   Expected Caldera operation results after mitigations:"
echo "     Ability 1 (T1016     — Version Discovery):      SUCCESS (unaffected)"
echo "     Ability 2 (T1505.003 — RCE / shell-exec check): SUCCESS (unaffected)"
echo "     Ability 3 (T1555     — Credential exfiltration): SUCCESS (users.db still readable)"
echo "     Ability 4 (T1110.002 — Password cracking):      FAIL — new password not in wordlist"
echo "     Ability 5 (T1133     — Forge VPN cert):         exit 0 (misleading — cert is empty)"
echo "     Ability 6 (T1046     — Network scan):           TIMEOUT — tun0 never comes up"
echo "     Ability 7 (T1021.004 — SSH lateral movement):   SKIP — fact dependency not fulfilled"
echo "     Ability 8 (T1021.004 — SSH tunnel into VLAN):   SKIP — fact dependency not fulfilled"
echo ""
echo "   NOTE: Ability 5's exit 0 is a false positive — check Ability 6 to confirm Mitigation 2's effect."
echo ""
echo "   To revert Mitigation 2 (restore ca.key):"
echo "     docker exec gns3-server sh -c \"docker exec $VPN_ID mv $CA_KEY_DISABLED_PATH $CA_KEY_PATH\""
echo ""
echo "   REMINDER: Neither mitigation persists across sessions."
echo "   GNS3 recreates intergalactic-vpn from its base image on every node restart."
echo "   Re-run this script at the start of every mitigated session."