#!/usr/bin/env bash
# Correlates Floor4-L3SW's GNS3 link topology (which adapter connects to
# which neighbor) against its actual live OVS state (bridge assignment,
# VLAN tags, and whether forwarding flows exist at all).

set -uo pipefail

PROJECT_ID="29109344-3cdf-465c-86c1-79a90e4e3eff"
GNS3_API="http://localhost:3080"
L3SW_ID="3f39d99e03e0fd5434468aaabc659f4ea2804ddf37076f4a0c596e9728347d12"

echo "== Resolving Floor4-L3SW's node_id (needed to filter links) =="
NODE_ID=$(curl -s "${GNS3_API}/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
for n in json.load(sys.stdin):
    if n.get('name') == 'Floor4-L3SW':
        print(n.get('node_id',''))
")
echo "  Floor4-L3SW node_id: $NODE_ID"

echo ""
echo "== Floor4-L3SW's links: which adapter connects to which neighbor =="
curl -s "${GNS3_API}/v2/projects/${PROJECT_ID}/links" | python3 -c "
import json, sys
node_id = '$NODE_ID'
links = json.load(sys.stdin)
for link in links:
    endpoints = link.get('nodes', [])
    if any(e.get('node_id') == node_id for e in endpoints):
        for e in endpoints:
            if e.get('node_id') == node_id:
                my_adapter = e.get('adapter_number')
                my_port = e.get('port_number')
            else:
                other_node_id = e.get('node_id')
        # find neighbor's name from the other endpoint
        neighbor_name = None
        for e2 in endpoints:
            if e2.get('node_id') != node_id:
                neighbor_name = e2.get('node_id')
        print(f'adapter {my_adapter} (port {my_port})  <->  neighbor node_id {neighbor_name}')
"

echo ""
echo "== Resolving neighbor node_ids to names, for readability =="
curl -s "${GNS3_API}/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
nodes = json.load(sys.stdin)
for n in nodes:
    print(f\"{n.get('node_id')}  ->  {n.get('name')}\")
"

echo ""
echo "== OVS bridge/port/VLAN configuration on Floor4-L3SW =="
docker exec "$L3SW_ID" ovs-vsctl show 2>&1

echo ""
echo "== OVS flow tables per bridge (empty/no 'normal' action = total blackhole) =="
for BR in br0 br1 br2 br3; do
  echo "--- $BR ---"
  docker exec "$L3SW_ID" ovs-ofctl dump-flows "$BR" 2>&1
  echo ""
done
