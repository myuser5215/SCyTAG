#!/usr/bin/env bash
#
# Bank-Adversary mitigation — apply on camera_A_ssh-1 (Bank topology)
# -------------------------------------------------------------------
# Blocks the BGU Test Adversary attack chain by removing read access from the
# plaintext credential file on camera_A.
#
# Attack chain:
#   Ability 1 (T1552.001): SSH adminPC1 → camera_A, cat /home/testuser/password.txt
#   Ability 2 (T1105):     SCP splunkd adminPC1 → DVR using harvested password
#   Ability 3 (T1059.004): SSH adminPC1 → DVR, run splunkd agent
#
# Mitigation target (attack graph node [8]):
#   compromised('camera_A_ssh-1') ← maliciousInteraction(camera_A, attacker, sshd)
#
#   chmod 000 /home/testuser/password.txt on camera_A:
#     → Ability 1 fails (cat: Permission denied, exit 1)
#     → #{password} fact never populated
#     → Abilities 2 and 3 skipped ("Fact dependency not fulfilled")
#     → DVR never reached — full chain collapses at Ability 1
#
# Applied via direct docker exec from this host (no gns3-server nesting —
# Bank containers are directly visible to the host Docker daemon, unlike UK-Office).
# Requires root-level access via docker exec -u root.
#
# NOTE: This mitigation does NOT persist across sessions. GNS3 recreates the
# camera_A container from its base image on every node restart, restoring
# password.txt to its original permissions. Re-run this script at the start
# of every mitigated session before running the operation.
#
# Usage:
#   ./apply-bank-adversary-mitigation-bank.sh
#   PROJECT_ID=<id> ./apply-bank-adversary-mitigation-bank.sh
 
set -uo pipefail
 
# ---- Configuration ----
PROJECT_ID="${PROJECT_ID:-}"
PROJECT_NAME_PATTERN="${PROJECT_NAME_PATTERN:-Bank}"
GNS3_API="http://localhost:3080"
CAMERA_NODE_NAME="camera_A_ssh-1"
PASSWORD_FILE="/home/testuser/password.txt"
 
# ---- 1. Resolve project ID ----
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
 
# ---- 2. Resolve camera_A_ssh-1 ----
echo "== Resolving $CAMERA_NODE_NAME =="
CAMERA_INFO=$(curl -s "$GNS3_API/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
name = '''$CAMERA_NODE_NAME'''
for n in json.load(sys.stdin):
    if n.get('name') == name:
        print(n.get('node_id',''), '|', n.get('status',''), '|', n.get('properties', {}).get('container_id',''))
")
if [ -z "$CAMERA_INFO" ]; then
  echo "!! No node named '$CAMERA_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
CAMERA_NODE_ID=$(echo "$CAMERA_INFO" | cut -d'|' -f1 | tr -d ' ')
CAMERA_STATUS=$(echo "$CAMERA_INFO"  | cut -d'|' -f2 | tr -d ' ')
CAMERA_ID=$(echo "$CAMERA_INFO"      | cut -d'|' -f3 | tr -d ' ')
echo "   node_id=$CAMERA_NODE_ID  status=$CAMERA_STATUS  container_id=$CAMERA_ID"
 
if [ "$CAMERA_STATUS" != "started" ]; then
  echo "!! $CAMERA_NODE_NAME is not started (status=$CAMERA_STATUS)." >&2
  echo "   Start the node (or run setup-bank-adversary-on-bank.sh) before applying the mitigation." >&2
  exit 1
fi
 
# ---- 3. Fail-fast liveness check ----
if ! docker exec -u root "$CAMERA_ID" sh -c 'echo alive' >/dev/null 2>&1; then
  echo "!! Container $CAMERA_ID ($CAMERA_NODE_NAME) does not respond to docker exec." >&2
  echo "   The container ID may be stale — restart the node and re-run." >&2
  exit 1
fi
 
# ---- 4. Baseline: confirm file exists and is currently readable ----
echo "== Baseline: checking $PASSWORD_FILE on $CAMERA_NODE_NAME =="
BEFORE_PERMS=$(docker exec -u root "$CAMERA_ID" sh -c "ls -la $PASSWORD_FILE" 2>/dev/null || true)
if [ -z "$BEFORE_PERMS" ]; then
  echo "!! $PASSWORD_FILE not found on $CAMERA_NODE_NAME." >&2
  echo "   The file should be part of the container image — check node image." >&2
  exit 1
fi
echo "   Before: $BEFORE_PERMS"
 
BEFORE_CONTENT=$(docker exec -u root "$CAMERA_ID" sh -c "cat $PASSWORD_FILE" 2>/dev/null || true)
echo "   Content before mitigation: '$BEFORE_CONTENT'"
 
# ---- 5. Apply the mitigation ----
echo "== Applying mitigation: chmod 000 $PASSWORD_FILE =="
if ! docker exec -u root "$CAMERA_ID" sh -c "chmod 000 $PASSWORD_FILE"; then
  echo "!! chmod failed — check container state and re-run." >&2
  exit 1
fi
 
# ---- 6. Verify permissions changed ----
echo "== Verifying permissions =="
AFTER_PERMS=$(docker exec -u root "$CAMERA_ID" sh -c "ls -la $PASSWORD_FILE" 2>/dev/null || true)
echo "   After:  $AFTER_PERMS"
 
# Confirm the permission string starts with ----------
PERM_STRING=$(echo "$AFTER_PERMS" | awk '{print $1}')
if [ "$PERM_STRING" != "----------" ]; then
  echo "!! Unexpected permissions after chmod: '$PERM_STRING' (expected '----------')." >&2
  exit 1
fi
echo "   permissions confirmed: ---------- (zero access for all users)"
 
# ---- 7. Confirm Ability 1 would now fail (read as testuser) ----
echo "== Confirming Ability 1 is blocked (read as testuser) =="
READ_RESULT=$(docker exec "$CAMERA_ID" sh -c "cat $PASSWORD_FILE" 2>&1 || true)
if echo "$READ_RESULT" | grep -q "Permission denied"; then
  echo "   confirmed — 'cat password.txt' returns: $READ_RESULT"
else
  echo "!! WARNING: cat did not return 'Permission denied' as expected." >&2
  echo "   Got: '$READ_RESULT'" >&2
  echo "   Mitigation may not be effective — investigate before running the operation." >&2
  exit 1
fi
 
# ---- Done ----
echo ""
echo "== Done. Bank-Adversary mitigation applied. =="
echo "   $CAMERA_NODE_NAME ($CAMERA_ID)"
echo "   $PASSWORD_FILE — permissions: ---------- (chmod 000)"
echo ""
echo "   Expected Caldera operation results after mitigation:"
echo "     Ability 1 (T1552.001 — Retrieve Password): FAIL — exit 1, 'Permission denied'"
echo "     Ability 2 (T1105     — Transfer Agent):    SKIP — Fact dependency not fulfilled"
echo "     Ability 3 (T1059.004 — Activate Agent):    SKIP — Fact dependency not fulfilled"
echo ""
echo "   To revert (restore original permissions):"
echo "     docker exec -u root $CAMERA_ID chmod 664 $PASSWORD_FILE"
echo ""
echo "   REMINDER: This mitigation does NOT persist across sessions."
echo "   GNS3 recreates the container from its base image on every node restart."
echo "   Re-run this script at the start of every mitigated session."