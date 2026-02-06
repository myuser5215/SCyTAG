# SCyTAG: Scalable Cyber Twin-based Attack Graph Framework

This repository contains the experimental artifacts, datasets, and scripts for the SCyTAG framework.

**"SCyTAG: Scalable Cyber Twins for Threat Assessment using Attack Graphs"**

### Abstract

Understanding the risks associated with an enterprise environment is the first step toward improving its security. Organizations employ various methods to assess and prioritize the risks identified in cyber threat intelligence (CTI) reports that may be relevant to their operations. Some methodologies rely heavily on manual analysis (which requires expertise and cannot be applied frequently), while others automate the assessment, using attack graphs (AGs) or threat emulators. Such emulators can be employed in conjunction with cyber twins to avoid disruptions in live production environments when evaluating the highlighted threats. Unfortunately, the use of cyber twins in organizational networks is limited due to their inability to scale.

**SCyTAG** is a multi-step framework that generates the minimal viable cyber twin required to assess the impact of a given attack scenario. Given the organizational computer network specifications and an attack scenario extracted from a CTI report, SCyTAG generates an AG. Then, based on the AG, it automatically constructs a cyber twin comprising the network components necessary to emulate the attack scenario and assess the relevance and risks of the attack to the organization.

SCyTAG has been evaluated on both real and fictitious organizational networks. The results show that compared to the full topology, SCyTAG **reduces the number of network components needed for emulation by up to 99%** while preserving the fidelity of the emulated attack. SCyTAG serves as a cost-effective, scalable, and highly adaptable threat assessment solution, improving organizational cyber defense by bridging the gap between abstract CTI and practical scenario-driven testing.

---

## Repository Structure

```
SCyTAG/
├── README.md                    # This file
├── .env                         # Environment configuration (file paths, etc.)
├── .gitignore                   # Git ignore rules
├── Caldera/                     # MITRE Caldera attack emulation data
│   ├── Abilitiy-1.yml           # Attack technique definition 1
│   ├── Ability-2.yaml           # Attack technique definition 2
│   ├── Ability-3.yml            # Attack technique definition 3
│   └── Bank_Adversary.yml       # Adversary profile for banking scenarios
├── Scripts/                     # Automation and analysis scripts
│   ├── CompleteMissingFacts.py  # Completes missing facts in topology
│   ├── ReduceTopologyWithAG.py  # Reduces topology based on attack graph
│   └── compare_debrief.py       # Compares and analyzes debrief data
├── Bank/                    # Fictitious banking enterprise (88 nodes)
│   ├── AttackGraph/             # Generated attack graph artifacts
│   │   ├── ARCS.CSV             # Attack graph edges
│   │   ├── AttackGraph.dot      # GraphViz format
│   │   ├── AttackGraph.eps      # EPS image format
│   │   ├── AttackGraph.pdf      # PDF visualization
│   │   ├── AttackGraph.txt      # Text representation
│   │   ├── AttackGraph.xml      # XML format
│   │   └── VERTICES.CSV         # Attack graph vertices
│   ├── Facts/                   # Network facts and rules
│   │   ├── Bank_Facts.P     # Network state facts
│   │   ├── Bank_MissingFacts.p  # Identified missing facts
│   │   └── IR_Bank_Topology.p   # Interaction rules for AG
│   ├── Images/                  # Topology visualizations
│   │   ├── Bank.jpg         # Full topology diagram
│   │   └── Bank-Reduced.jpg # Reduced cyber twin diagram
│   └── Topology-Files/          # GNS3 configuration files
│       ├── ve-config.yaml       # Virtual environment configuration
│       ├── ve-config-reduced.yaml   # Reduced VE configuration
│       ├── ve-topology.yaml     # Complete 88-node topology
│       └── ve-topology-reduced.yaml # Minimal cyber twin topology
├── Bank-XL/                    # Large-scale enterprise network (1,471 nodes)
│   ├── AttackGraph/             # Generated attack graph artifacts
│   │   ├── ARCS.CSV             # Attack graph edges
│   │   ├── AttackGraph.dot      # GraphViz format
│   │   ├── AttackGraph.eps      # EPS image format
│   │   ├── AttackGraph.pdf      # PDF visualization
│   │   ├── AttackGraph.txt      # Text representation
│   │   ├── AttackGraph.xml      # XML format
│   │   └── VERTICES.CSV         # Attack graph vertices
│   ├── Facts/                   # Network facts and rules
│   │   ├── Bank-XL_Facts.P     # Large-scale network facts
│   │   ├── Bank-XL_IR.p        # Interaction rules
│   │   └── Bank-XL_MissingFacts.p  # Identified missing facts
│   ├── Images/                  # Topology visualizations
│   │   ├── Bank-XL.jpg         # Full topology diagram
│   │   └── Bank-XL-Reduced.jpg # Reduced cyber twin diagram
│   └── Topology-Files/          # GNS3 configuration files
│       ├── ve-config.yaml       # Enterprise-scale VE configuration
│       ├── ve-config-reduced.yaml   # Reduced configuration
│       ├── ve-topology.yaml     # 1,471-node topology specification
│       └── ve-topology-reduced.yaml # Minimal cyber twin topology
└── UK-Office/                   # Real-world office network topology
    ├── AttackGraph/             # Generated attack graph artifacts
    │   ├── ARCS.CSV             # Attack graph edges
    │   ├── AttackGraph.dot      # GraphViz format
    │   ├── AttackGraph.eps      # EPS image format
    │   ├── AttackGraph.pdf      # PDF visualization
    │   ├── AttackGraph.txt      # Text representation
    │   ├── AttackGraph.xml      # XML format
    │   └── VERTICES.CSV         # Attack graph vertices
    ├── Facts/                   # Network facts and rules
    │   ├── UK-Office_Facts.p    # Network state facts
    │   ├── UK-Office_IR.p       # Interaction rules for AG
    │   └── UK-Office_MissingFacts.p # Identified missing facts
    ├── Images/                  # Topology visualizations
    │   ├── UK-Office.jpg        # Full topology diagram
    │   └── UK-Office-Reduced.jpg # Reduced cyber twin diagram
    └── Topology-Files/          # GNS3 configuration files
        ├── ve-config.yaml       # Virtual environment configuration
        ├── ve-config-reduced.yaml   # Reduced VE configuration
        ├── ve-topology.yaml     # Complete topology specification
        └── ve-topology-reduced.yaml # Minimal cyber twin topology
```

**Note on Proprietary Content:**
- UK-Office: Caldera abilities and adversary profiles are proprietary and not included in this repository.
- Additional pipeline execution scripts and automation code are proprietary and not shared publicly.

---

## Topology File Descriptions

Each experimental topology is organized in a consistent structure with four main subdirectories:

### Subdirectory Organization

#### `AttackGraph/`
Generated attack graph artifacts in multiple formats:
- **`ARCS.CSV`**: Attack graph edges representing state transitions
- **`AttackGraph.dot`**: GraphViz DOT format for visualization
- **`AttackGraph.eps`**: Encapsulated PostScript image
- **`AttackGraph.pdf`**: PDF visualization of the attack graph
- **`AttackGraph.txt`**: Human-readable text representation
- **`AttackGraph.xml`**: XML format for programmatic processing
- **`VERTICES.CSV`**: Attack graph vertices (states)

#### `Facts/`
Network specification and interaction rules:
- **`*_Facts.P`**: Prolog facts file containing the complete network state
  - Node definitions (hosts, routers, switches, firewalls)
  - Network connectivity and topology structure
  - Vulnerability information and CVE mappings
  - Service configurations and access control policies
  - User privileges and credential information
  
- **`*_IR.p`**: Interaction Rules for attack graph generation
  - State transition rules defining attacker capabilities
  - Exploit preconditions and postconditions
  - Privilege escalation rules
  - Lateral movement conditions
  - Multi-step attack chain logic

- **`*_MissingFacts.p`**: Identified missing facts that need completion for accurate AG generation

#### `Images/`
Visual representations of the network topologies:
- **`*.jpg`**: Full topology network diagram
- **`*-Reduced.jpg`**: Minimal cyber twin topology diagram (generated by SCyTAG)

#### `Topology-Files/`
GNS3 virtual environment configurations:
- **`ve-config.yaml`**: Virtual Environment configuration
  - GNS3 project settings
  - Resource allocation parameters
  - Node deployment specifications
  
- **`ve-config-reduced.yaml`**: Reduced virtual environment configuration (generated by SCyTAG)

- **`ve-topology.yaml`**: Complete GNS3 topology specification
  - Node definitions with coordinates
  - Link configurations and port mappings
  - Console settings and management interfaces
  - Docker container and QEMU VM specifications
  
- **`ve-topology-reduced.yaml`**: Minimal cyber twin topology (generated by SCyTAG)

### Caldera Attack Emulation Data

The `Caldera/` directory contains MITRE Caldera attack emulation configurations for Bank and Bank-XL scenarios:

- **`Abilitiy-1.yml`, `Ability-2.yaml`, `Ability-3.yml`**: Atomic attack techniques mapped to MITRE ATT&CK framework
  - Individual TTPs (Tactics, Techniques, and Procedures)
  - Platform-specific command implementations
  - Cleanup and undo operations
  - Requirements and execution parameters
  
- **`Bank_Adversary.yml`**: Adversary profile for banking attack scenarios
  - Pre-configured attack chains and operation sequences
  - Multi-stage attack scenarios
  - Objective-based operations (data exfiltration, etc.)

**Note**: UK-Office abilities and adversary profiles are proprietary and not included in this repository.

### Scripts

- **`CompleteMissingFacts.py`**: Automatically identifies and completes missing facts in the topology
- **`ReduceTopologyWithAG.py`**: Reduces the full topology to minimal cyber twin based on attack graph analysis
- **`compare_debrief.py`**: Compares and analyzes attack emulation debrief data

### Configuration

- **`.env`**: Environment configuration file containing file paths and settings (use `python-dotenv` to load)

---

## Experimental Environments

### 1. UK-Office (Real-World Network)
A real organizational office network used to validate SCyTAG's practical applicability. This topology represents a typical small-to-medium enterprise environment with:
- Realistic network segmentation (DMZ, internal networks, VLAN isolation)
- Production services (web servers, file servers, databases)
- End-user workstations and IoT devices
- Multi-factor authentication and security controls

**Purpose**: Demonstrate real-world applicability and validate threat assessment accuracy.

### 2. Bank (Fictitious Banking Network - 88 Nodes)
A synthetic banking enterprise network designed to represent a medium-scale financial institution with:
- 4 building floors with hierarchical network architecture
- Core routers, L3 switches, and departmental switches
- Segregated departments: Marketing, Finance, Accounting, HR, Research, Management, ICT, Logistics, Customer Service
- Security infrastructure: firewalls, DMZ, admin workstations, surveillance systems
- File servers and administrative endpoints

**Purpose**: Controlled environment for measuring cyber twin reduction effectiveness and resource optimization.

### 3. Bank-XL (Large-Scale Enterprise - 1,471 Nodes)
A massive enterprise topology representing a large financial institution or corporate network:
- 1,471 network nodes including switches, routers, firewalls, and endpoints
- Complex multi-floor architecture with 43 switches per floor across 4 floors
- 7 PCs per switch (1,204 endpoint devices)
- Multiple WiFi access points and controller infrastructure
- Enterprise-grade security segmentation

**Purpose**: Evaluate SCyTAG's scalability limits and demonstrate up to 85% component reduction in large-scale environments.

---

## Key Contributions

1. **Automated Cyber Twin Generation**: SCyTAG automatically constructs minimal viable cyber twins from organizational network specifications and CTI-derived attack scenarios.

2. **Attack Graph-Driven Reduction**: Uses attack graphs to identify only the network components necessary for emulating specific threats, dramatically reducing resource requirements.

3. **Scalability**: Successfully scales from small office networks (UK-Office) to enterprise environments with 1,471+ nodes (Bank-XL).

4. **Resource Efficiency**: Achieves up to **99% reduction** in network components while maintaining attack emulation fidelity.

5. **CTI Integration**: Bridges the gap between abstract threat intelligence reports and practical, scenario-driven security testing.

---

## Reproducibility Guide

### Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+ recommended) or Windows with WSL2
- **Python**: 3.8 or higher
- **Python Packages**: `python-dotenv` (for loading `.env` configuration)
- **GNS3 Server**: 2.2.x or higher
- **Docker**: 20.10+ (for containerized network nodes)
- **QEMU**: 4.2+ (for router/firewall emulation)
- **MITRE Caldera**: (Optional) For attack emulation
- **Memory**: Minimum 32GB RAM (64GB+ recommended for Bank-XL)
- **Storage**: 100GB+ available disk space

### Component Reduction (Table 1 from paper)

| Topology  | Full Nodes | Minimal Twin | Reduction | Attack Fidelity |
|-----------|-----------|--------------|-----------|----------------|
| UK-Office | 45        | 12           | 73.3%     | 100%           |
| Bank  | 88        | 13           | 85.0%     | 100%           |
| Bank-XL  | 1,471     | 13          | **99.1%** | 100%           |


### Attack Emulation Fidelity

All attack scenarios successfully reproduced in minimal cyber twins with **100% fidelity** compared to full topology emulation, validating that SCyTAG preserves attack paths while reducing infrastructure.

---

## Attack Scenarios

Attack scenarios have been tested for Bank and Bank-XL using the MITRE Caldera abilities and adversary profiles provided in the `Caldera/` directory.

### Bank & Bank-XL Scenarios
1. **Banking Trojan**: Financial malware targeting transaction systems
2. **Multi-Stage Attack**: Coordinated attack with lateral movement
3. **Data Exfiltration**: Sensitive data extraction from critical systems

### UK-Office Scenarios
The UK-Office topology represents a real organizational network. Attack scenarios and emulation data for this topology are proprietary and not included in this repository.

---

## Citation

If you use this artifact in your research, please cite our work:

```bibtex
@article{scytag2026,
  title={{SCyTAG}: Scalable Cyber Twins for Threat Assessment using Attack Graphs},
  author={[Authors]},
  year={2026}
}
```

---

## Ethical Considerations

All experiments were conducted in isolated virtual environments. The UK-Office topology represents a real network but has been sanitized to remove sensitive information. Bank and Bank-XL are entirely fictitious networks designed for research purposes.

Attack scenarios are based on publicly disclosed CTI reports and do not contain any novel exploitation techniques or zero-day vulnerabilities.

**Proprietary Content**: Certain attack emulation data (UK-Office Caldera abilities/adversaries) and additional pipeline execution scripts are proprietary and not included in this public repository.

---

## Contact

For questions about this artifact or the SCyTAG framework, please contact:

- **GitHub Issues**: https://github.com/myuser5215/SCyTAG/issues

---

## License

This artifact is released under the [MIT License](LICENSE) for academic and research purposes.

Components from third-party sources (GNS3, MITRE ATT&CK, MITRE Caldera, etc.) retain their original licenses.

---

## Acknowledgments

Special thanks to the GNS3 and MITRE Caldera communities for providing the network emulation and attack simulation infrastructure that made this research possible.

---

## Version History

- **v1.0.0**: Initial public release with Bank, Bank-XL, and UK-Office topologies

---

**Last Updated**: February 6, 2026
