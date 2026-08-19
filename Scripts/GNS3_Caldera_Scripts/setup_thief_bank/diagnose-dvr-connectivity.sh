#!/usr/bin/env bash
# Corrected diagnostic: the routers/firewall in this topology are QEMU VMs
# (OpenWRT), not Docker containers, so they have no container_id and can't
# be reached with `docker exec`. This script identifies node type/status
# for everything first, then only uses docker exec where it actually applies.

set -uo pipefail

PROJECT_ID="29109344-3cdf-465c-86c1-79a90e4e3eff"
GNS3_API="http://localhost:3080"

echo "== Full node inventory: type, status, and access method =="
curl -s "${GNS3_API}/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
nodes = json.load(sys.stdin)
wanted = ['DVR_ssh-1','Server-Room-SW','Floor4-L3SW','Floor4-Router','Floor4-FW','CoreRouterE','CoreRouterA','Cloud1']
for name in wanted:
    for n in nodes:
        if n.get('name') == name:
            props = n.get('properties', {})
            cid = props.get('container_id', '')
            node_type = n.get('node_type', '')
            status = n.get('status', '')
            console = n.get('console', '')
            console_type = n.get('console_type', '')
            console_host = n.get('console_host', '')
            access = f'docker exec {cid}' if cid else f'telnet {console_host} {console} ({console_type})'
            print(f'{name:16} status={status:10} node_type={node_type:12} access={access}')
            break
    else:
        print(f'{name:16} !! not found in this project')
"

echo ""
echo "== Reminder from the traceroute already run: =="
echo "   DVR_ssh-1's default gateway (192.168.110.1) is not answering ARP."
echo "   Whatever node owns that IP (most likely Floor4-Router) needs to be"
echo "   checked directly via its console (telnet, printed above) — confirm:"
echo "     1. The node status is 'started', not 'stopped'/'suspended'"
echo "     2. Once booted, its interface facing the DVR/Server-Room side"
echo "        actually has 192.168.110.1 configured (ip addr / ifconfig,"
echo "        or 'uci show network' on OpenWRT)"
echo "     3. That interface is administratively up and linked to the"
echo "        correct port in the GNS3 topology (not accidentally wired"
echo "        to a different subnet after the manual rebuild)"
