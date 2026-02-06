# Reduce topology nodes according to the nodes that appear in the given AG
import os
import sys
import csv
import yaml
from pathlib import Path
from collections import defaultdict, deque
from os.path import isfile
import re
from dotenv import load_dotenv
from pathlib import Path
from collections import defaultdict, deque

def findAgTopologyNodes(agVerticesFileName):
    topologyNodes = []
    with open(agVerticesFileName, 'r', encoding='utf-8', newline='') as infile:
        reader = csv.reader(infile)

        for row in reader:
            # Skip malformed rows
            if len(row) != 4:
                continue

            number1, string1, string2, number2 = [field.strip() for field in row]

            # Skip lines ending with -1 in number2
            if number2 == "-1":
                continue

            # Separate string2 to predicate name and its params
            if string1.startswith("RULE"):
                continue
            # Find the opening and closing parentheses
            open_paren = string1.find('(')
            close_paren = string1.rfind(')')

            # Extract predicate name
            predicate = string1[:open_paren].strip()

            # Extract parameters string and split by comma
            params_str = string1[open_paren + 1:close_paren]
            params = [param.strip() for param in params_str.split(',') if param.strip()]

            match predicate:
                case "networkService" | "residesOn" | "fileOwner" | "ownerAccessible" | "deviceOnline" |\
                     "maliciousInteraction":
                    topologyNode1 = params[0].strip("'\"")  # Remove quotes
                    topologyNode2 = ''
                case "hasAccount" | "isInSubnet":
                    topologyNode1 = params[1].strip("'\"")  # Remove quotes
                    topologyNode2 = ''
                case "hasAccess":
                    topologyNode1 = params[2].strip("'\"")  # Remove quotes
                    topologyNode2 = ''
                case "dataFlow" | "hacl":  # These predicates have two topology nodes
                    topologyNode1 = params[0].strip("'\"")  # Remove quotes
                    topologyNode2 = params[1].strip("'\"")  # Remove quotes
                case "compromisedVPNClient" | "lateralMovementVPN" | "canAccessVPN" | "canCreateValidVPNCertificate" |\
                     "softwareCompromisedRemotely" | "softwareCompromisedLocally":
                    # These predicates typically have the attacker/source node as first param
                    topologyNode1 = params[0].strip("'\"")
                    # Some have target node as second param
                    if len(params) > 1:
                        topologyNode2 = params[1].strip("'\"")
                    else:
                        topologyNode2 = ''
                case "netAccess":
                    # netAccess(_,'source','target',protocol,port)
                    if len(params) >= 3:
                        topologyNode1 = params[1].strip("'\"")  # source
                        topologyNode2 = params[2].strip("'\"")  # target
                    else:
                        continue
                case _:
                    continue

            if topologyNode1 not in topologyNodes:
                topologyNodes.append(topologyNode1)
            if topologyNode2 != '' and topologyNode2 not in topologyNodes:
                topologyNodes.append(topologyNode2)

    return topologyNodes

def buildTopologyGraph(topology):
    """Build adjacency list graph from topology links"""
    graph = defaultdict(set)
    
    for link in topology.get("links", []):
        link_nodes = link.get("link_nodes", [])
        if len(link_nodes) == 2:
            node1 = link_nodes[0].get("node_name")
            node2 = link_nodes[1].get("node_name")
            if node1 and node2:
                graph[node1].add(node2)
                graph[node2].add(node1)
    
    return graph

def findShortestPath(graph, start, end):
    """Find shortest path between two nodes using BFS"""
    if start == end:
        return [start]
    
    visited = {start}
    queue = deque([(start, [start])])
    
    while queue:
        node, path = queue.popleft()
        
        for neighbor in graph[node]:
            if neighbor not in visited:
                new_path = path + [neighbor]
                if neighbor == end:
                    return new_path
                visited.add(neighbor)
                queue.append((neighbor, new_path))
    
    return []  # No path found

def findCloudNode(topology):
    """Find Cloud node in topology by checking node_type, template, or name pattern"""
    # Priority order: uk-site-internet or site-internet, then any cloud-type internet node
    cloud_nodes = []
    
    for node in topology.get("nodes", []):
        node_name = node.get("name", "")
        node_type = node.get("type", "")
        node_type_field = node.get("node_type", "")
        template = node.get("template", "")
        
        # Check if it's a cloud type node (not docker/qemu)
        if node_type.lower() == "cloud" or template.lower() == "cloud" or "cloud" in node_type_field.lower():
            cloud_nodes.append(node_name)
    
    # Prioritize nodes with "site-internet" in the name (e.g., uk-site-internet)
    for node_name in cloud_nodes:
        if "site-internet" in node_name.lower():
            return node_name
    
    # Fall back to any cloud node with "internet" that's not vpn/hacker
    for node_name in cloud_nodes:
        if "internet" in node_name.lower() and "vpn" not in node_name.lower() and "hacker" not in node_name.lower():
            return node_name
    
    # Return first cloud node if no internet-specific node found
    return cloud_nodes[0] if cloud_nodes else None

def findAllIntermediateNodes(topology, ag_nodes):
    """Find all intermediate nodes on paths between AG nodes"""
    graph = buildTopologyGraph(topology)
    all_nodes = set(ag_nodes)
    
    # Find paths between all pairs of AG nodes
    for i, node1 in enumerate(ag_nodes):
        for node2 in ag_nodes[i+1:]:
            path = findShortestPath(graph, node1, node2)
            if path:
                all_nodes.update(path)
    
    return all_nodes

# Create a reduced version of the ve-topology.yaml and ve-config.yaml files
# that includes only nodes that appear in the attack graph
def reduceTopology(topologyFileName, configFileName, agNodes, reducedTopologyFileName, reducedConfigFileName):
    # Load the YAML files
    with open(topologyFileName, 'r') as file:
        topology = yaml.safe_load(file)
    
    with open(configFileName, 'r') as file:
        config = yaml.safe_load(file)

    # Find all nodes including intermediate nodes on paths between AG nodes
    print(f"Finding paths between {len(agNodes)} AG nodes...")
    topology_node_names = {node.get("name") for node in topology.get("nodes", [])}
    
    # Filter AG nodes to only those that exist in topology
    valid_ag_nodes = [n for n in agNodes if n in topology_node_names]
    invalid_ag_nodes = set(agNodes) - set(valid_ag_nodes)
    
    if invalid_ag_nodes:
        print(f"\n⚠️  WARNING: {len(invalid_ag_nodes)} AG nodes not found in topology:")
        for node in sorted(invalid_ag_nodes):
            print(f"  - {node}")
        print("\nThis indicates a naming mismatch between facts and topology files.")
        print("Possible causes:")
        print("  1. Facts file uses aliases/shortened names")
        print("  2. Node was renamed in topology but not in facts")
        print("  3. Node exists in facts but not in actual topology")
    
    # Find all nodes including intermediate ones
    all_required_nodes = findAllIntermediateNodes(topology, valid_ag_nodes)
    
    # Build graph for pathfinding
    graph = buildTopologyGraph(topology)
    
    # Find Cloud node and add path to it
    cloud_node = findCloudNode(topology)
    if cloud_node:
        print(f"\n✓ Found main Cloud node: {cloud_node}")
        # Add Cloud node to required nodes
        all_required_nodes.add(cloud_node)
        
        # Find paths from all currently required nodes to Cloud
        nodes_to_check = list(all_required_nodes)
        for node in nodes_to_check:
            if node != cloud_node:
                path = findShortestPath(graph, node, cloud_node)
                if path:
                    all_required_nodes.update(path)
        
        print(f"✓ Added paths to main Cloud node (including intermediate nodes)")
    else:
        print(f"\n⚠️  WARNING: Main Cloud node not found in topology")
        print("  Internet access may not be available in reduced topology")
    
    # Find cloud nodes directly connected to any required nodes (especially agents)
    # This handles cases like intergalactic-hacker-internet
    additional_cloud_nodes = []
    for node in topology.get("nodes", []):
        node_name = node.get("name", "")
        node_type = node.get("type", "")
        template = node.get("template", "")
        
        # Check if it's a cloud type node
        if node_type.lower() == "cloud" or template.lower() == "cloud":
            # Check if it's directly connected to any required node
            for neighbor in graph.get(node_name, []):
                if neighbor in all_required_nodes:
                    if node_name not in all_required_nodes:
                        all_required_nodes.add(node_name)
                        additional_cloud_nodes.append(node_name)
                    break
    
    if additional_cloud_nodes:
        print(f"✓ Added {len(additional_cloud_nodes)} additional cloud node(s) connected to required nodes:")
        for cloud in additional_cloud_nodes:
            print(f"  - {cloud}")
    
    print(f"\n✓ {len(valid_ag_nodes)} AG nodes found in topology")
    print(f"✓ {len(all_required_nodes) - len(valid_ag_nodes)} intermediate/cloud nodes added")
    print(f"✓ Total nodes in reduced topology: {len(all_required_nodes)}")
    
    # Filter nodes
    original_node_count = len(topology.get("nodes", []))
    reduced_nodes = [node for node in topology.get("nodes", []) if node.get("name") in all_required_nodes]

    # Filter links - both ends must be in all_required_nodes
    original_link_count = len(topology.get("links", []))
    reduced_links = []
    for link in topology.get("links", []):
        link_nodes = link.get("link_nodes", [])
        if len(link_nodes) == 2:
            node1_name = link_nodes[0].get("node_name")
            node2_name = link_nodes[1].get("node_name")
            if node1_name in all_required_nodes and node2_name in all_required_nodes:
                reduced_links.append(link)
    
    print(f"Original topology had {original_link_count} links")
    print(f"Reduced topology has {len(reduced_links)} links")

    # Collect required templates from original topology
    required_template_names = set()
    for node in reduced_nodes:
        template_name = node.get("template")
        if template_name and template_name not in ["Ethernet switch", "VPCS", "Ethernet hub", "Cloud"]:
            required_template_names.add(template_name)
    
    # Extract required templates from original topology
    original_templates = topology.get("templates", [])
    required_templates = [t for t in original_templates if t.get("name") in required_template_names]
    
    # Add standard templates
    standard_templates = [
        {
            "adapters": 1,
            "builtin": False,
            "category": "guest",
            "compute_id": "local",
            "console_auto_start": False,
            "console_http_path": "/",
            "console_http_port": 80,
            "console_resolution": "1024x768",
            "console_type": "telnet",
            "custom_adapters": [],
            "default_name_format": "{name}-{0}",
            "environment": "",
            "extra_hosts": "",
            "extra_volumes": [],
            "image": "intergalactic-vpn:latest",
            "mac_address": "",
            "name": "intergalactic-vpn",
            "start_command": "",
            "symbol": ":/symbols/docker_guest.svg",
            "template_type": "docker",
            "usage": ""
        },
        {
            "adapters": 1,
            "builtin": False,
            "category": "guest",
            "compute_id": "local",
            "console_auto_start": False,
            "console_http_path": "/",
            "console_http_port": 80,
            "console_resolution": "1024x768",
            "console_type": "telnet",
            "custom_adapters": [],
            "default_name_format": "{name}-{0}",
            "environment": "",
            "extra_hosts": "",
            "extra_volumes": [],
            "image": "storage-server:latest",
            "mac_address": "",
            "name": "storage-server",
            "start_command": "",
            "symbol": ":/symbols/docker_guest.svg",
            "template_type": "docker",
            "usage": ""
        },
        {
            "adapters": 1,
            "builtin": False,
            "category": "guest",
            "compute_id": "local",
            "console_auto_start": False,
            "console_http_path": "/",
            "console_http_port": 80,
            "console_resolution": "1024x768",
            "console_type": "telnet",
            "custom_adapters": [],
            "default_name_format": "{name}-{0}",
            "environment": "",
            "extra_hosts": "",
            "extra_volumes": [],
            "image": "alpine-3.18-openvpn:latest",
            "mac_address": "",
            "name": "alpine-3.18-openvpn",
            "start_command": "",
            "symbol": ":/symbols/docker_guest.svg",
            "template_type": "docker",
            "usage": ""
        }
    ]
    
    # Combine templates (avoid duplicates)
    all_templates = required_templates + standard_templates
    print(f"✓ Including {len(required_templates)} templates from original topology")
    
    # Create reduced topology
    reduced_topology = {
        "drawings": topology.get("drawings", []),
        "labels": topology.get("labels", []),
        "links": reduced_links,
        "nodes": reduced_nodes,
        "templates": all_templates
    }

    # Filter configuration - remove commands/agents for nodes not in reduced topology
    # Note: Cloud node config is automatically included if Cloud node is in all_required_nodes
    reduced_config = config.copy()
    
    # Filter configuration commands
    if "configuration" in reduced_config and "nodes" in reduced_config["configuration"]:
        original_commands = reduced_config["configuration"]["nodes"]
        reduced_commands = [cmd for cmd in original_commands if cmd.get("name") in all_required_nodes]
        reduced_config["configuration"]["nodes"] = reduced_commands
        print(f"✓ Filtered configuration: {len(reduced_commands)}/{len(original_commands)} node configs retained")
        print(f"Configuration commands reduced from {len(original_commands)} to {len(reduced_commands)}")
    
    # Filter agents - keep agents on nodes in the reduced topology
    if "agents" in reduced_config and "nodes" in reduced_config["agents"]:
        original_agents = reduced_config["agents"]["nodes"]
        if isinstance(original_agents, list):
            reduced_agents = []
            for agent in original_agents:
                if isinstance(agent, dict):
                    # Check multiple possible keys: name, host, node_name, etc.
                    agent_node = agent.get("name") or agent.get("host") or agent.get("node_name") or agent.get("hostname")
                    if agent_node and agent_node in all_required_nodes:
                        reduced_agents.append(agent)
                elif isinstance(agent, str):
                    # If agents is a simple list of strings/hosts
                    if agent in all_required_nodes:
                        reduced_agents.append(agent)
            reduced_config["agents"]["nodes"] = reduced_agents
            print(f"✓ Agents: {len(reduced_agents)}/{len(original_agents)} retained")
            if len(reduced_agents) == 0 and len(original_agents) > 0:
                print(f"  ⚠️  WARNING: All agents were filtered out.")
                # Debug info
                agent_names = [agent.get("name") or agent.get("host") if isinstance(agent, dict) else agent for agent in original_agents]
                print(f"  Original agent nodes: {agent_names}")
                nodes_preview = sorted(list(all_required_nodes)[:10]) if len(all_required_nodes) > 10 else sorted(all_required_nodes)
                print(f"  Required nodes in topology: {nodes_preview}")
            elif reduced_agents:
                retained_names = [agent.get("name") or agent.get("host") if isinstance(agent, dict) else agent for agent in reduced_agents]
                print(f"  Retained agent nodes: {retained_names}")
        else:
            print("  ⚠️  Agents configuration format not recognized, keeping original")

    # Save the reduced files
    with open(reducedTopologyFileName, 'w') as file:
        yaml.dump(reduced_topology, file, default_flow_style=False, sort_keys=False)
    
    with open(reducedConfigFileName, 'w') as file:
        yaml.dump(reduced_config, file, default_flow_style=False, sort_keys=False)
    
    print(f"\nReduced topology saved to: {reducedTopologyFileName}")
    print(f"Reduced config saved to: {reducedConfigFileName}")


def main():
    # Load environment variables from .env file
    load_dotenv()
    topology_dir = os.getenv('TOPOLOGY_DIR')
    
    if len(sys.argv) > 1:
        topology_dir = sys.argv[1]
    
    # Construct file paths
    topology_path = Path(topology_dir)
    topologyFileName = str(topology_path / "ve-topology.yaml")
    configFileName = str(topology_path / "ve-config.yaml")
    agVerticesFileName = str(topology_path / "VERTICES.CSV")
    reducedTopologyFileName = str(topology_path / "ve-topology-reduced.yaml")
    reducedConfigFileName = str(topology_path / "ve-config-reduced.yaml")
    
    print(f"Processing topology: {topology_dir}")
    print(f"Input files:")
    print(f"  - Topology: {topologyFileName}")
    print(f"  - Config: {configFileName}")
    print(f"  - AG Vertices: {agVerticesFileName}")
    print(f"\nOutput files:")
    print(f"  - Reduced Topology: {reducedTopologyFileName}")
    print(f"  - Reduced Config: {reducedConfigFileName}")
    print()
    
    # Extract topology nodes from AG
    print("Extracting nodes from Attack Graph...")
    topologyNodes = findAgTopologyNodes(agVerticesFileName)
    print(f"Found {len(topologyNodes)} unique nodes in AG:")
    for node in sorted(topologyNodes):
        print(f"  - {node}")
    print()
    
    # Reduce topology and config
    print("Reducing topology and configuration...")
    reduceTopology(topologyFileName, configFileName, topologyNodes, reducedTopologyFileName, reducedConfigFileName)


if __name__ == "__main__":
    main()
