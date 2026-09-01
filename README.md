# SCyTAG: Scalable Cyber Twin-based Attack Graph Framework

This repository contains the experimental artifacts, datasets, and scripts for the SCyTAG framework.

**"SCyTAG: Scalable Cyber-Twin for Threat-Assessment Based on Attack Graphs"**

### Abstract

Understanding the risks associated with an enterprise environment is the first step toward improving its security. Organizations employ various methods to assess and prioritize risks identified in cyber threat intelligence (CTI) reports relevant to their operations. Some methodologies rely heavily on manual analysis (which requires expertise), while others automate assessment using attack graphs (AGs) or threat emulators employed in conjunction with cyber twins (to avoid disruptions in live production environments when evaluating the highlighted threats). Unfortunately, cyber twins are not scalable.

**SCyTAG** is a multi-step framework that generates the minimal viable cyber twin required to assess the impact of a given attack scenario. Given the organizational computer network specifications and an attack scenario extracted from a CTI report, SCyTAG generates an AG. Then, based on the AG, it automatically constructs a cyber twin comprising the network elements needed to emulate the attack scenario and assess the attack's relevance and risks to the organization.

SCyTAG's evaluation results show that compared to the full topology, it **reduces the number of network elements needed for emulation by up to 99%** and halves the required resources while preserving the fidelity of the emulated attack.

---

## Repository Structure

<details>
<summary>Click to expand directory tree</summary>

```
SCyTAG/
├── README.md                        # This file
├── .gitignore
├── LICENSE
├── Caldera/                         # MITRE Caldera attack emulation data
│   ├── Bank-Adversary/              # Bank-Adversary abilities and profile
│   │   ├── Ability-1.yml            # T1552.001 — Credentials in Files (SSH cat password file)
│   │   ├── Ability-2.yml            # T1105    — Ingress Tool Transfer (sshpass scp agent)
│   │   ├── Ability-3.yml            # T1021    — Remote Services (activate agent on target)
│   │   └── Bank-Adversary.yml       # Adversary profile (3-ability chain)
│   └── Thief/                       # Thief abilities and profile
│       └── Thief.yml                # Adversary profile (file discovery and exfiltration chain)
├── Scripts/                         # Automation and analysis scripts
│   ├── CompleteMissingFacts.py      # Identifies and completes missing MulVAL facts
│   ├── ReduceTopologyWithAG.py      # Reduces full topology to minimal cyber twin via attack graph
│   ├── compare_debrief.py           # Compares and analyzes Caldera operation debrief data
│   └── GNS3_Caldera_Scripts/        # GNS3 setup and mitigation shell scripts
│       ├── README.md                # Usage guide for all setup and mitigation scripts
│       ├── setup_thief_uk-office/   # Setup the Thief adversary on UK-Office topology for the Info-Leak Scenario
│       │   ├── setup-caldera-lab_on_gns3_topology-fixed.sh
│       │   └── apply-thief-mitigation.sh
│       ├── setup_thief_bank/        # Setup the Thief adversary on Bank topology for the Info-Leak Scenario
│       │   ├── setup-thief-on-bank.sh
│       │   ├── apply-thief-mitigation-bank.sh
│       │   ├── diagnose-dvr-connectivity.sh
│       │   └── diagnose-ovs-l3sw.sh
│       ├── setup_uk-intergalactic_uk-office/  # Setup the UK-Intergalactic adversary on UK-Office topology for the Asset-Access Scenario
│       │   ├── setup-caldera-uk-intergalactic.sh
│       │   └── apply_uk-intergalactic_mitigation_uk-office.sh
│       └── setup_bank-adversary_bank/         # Setup the Bank-Adversary on Bank topology for the Code-Execution Scenario
│           ├── setup_bank-adversary_bank.sh
│           └── apply_bank-adversary_mitigation_bank.sh
├── Bank/                            # Fictitious banking enterprise (88 nodes)
│   ├── AttackGraph/
│   │   ├── Code-Execution/          # Attack graph artifacts for Code-Execution scenario
│   │   │   ├── ARCS.CSV
│   │   │   ├── AttackGraph.dot
│   │   │   ├── AttackGraph.eps
│   │   │   ├── AttackGraph.pdf
│   │   │   ├── AttackGraph.txt
│   │   │   ├── AttackGraph.xml
│   │   │   └── VERTICES.CSV
│   │   └── Info-Leak/                   # Attack graph artifacts for Info-Leak scenario
│   │       ├── ARCS.CSV
│   │       ├── AttackGraph.dot
│   │       ├── AttackGraph.eps
│   │       ├── AttackGraph.pdf
│   │       ├── AttackGraph.txt
│   │       ├── AttackGraph.xml
│   │       └── VERTICES.CSV
│   ├── Facts/
│   │   ├── Code-Execution/
│   │   │   ├── Bank_Facts_Code-Execution.p
│   │   │   └── Bank_IR_Code-Execution.p
│   │   └── Info-Leak/
│   │       ├── Bank_Facts_Info-Leak.p
│   │       └── Bank_IR_Info-Leak.p
│   ├── Images/
│   │   ├── Bank.png                          # Full 88-node topology diagram
│   │   ├── Bank_Reduced_Info-Leak.png            # Minimal cyber twin (Info-Leak scenario)
│   │   └── Bank_Reduced_Code-Execution.png   # Minimal cyber twin (Code-Execution scenario)
│   └── Topology-Files/
│       ├── Code-Execution/
│       │   ├── ve-config.yaml
│       │   ├── ve-config-reduced.yaml
│       │   ├── ve-topology.yaml
│       │   └── ve-topology-reduced.yaml
│       └── Info-Leak/
│           ├── ve-config.yaml
│           ├── ve-config-reduced.yaml
│           ├── ve-topology.yaml
│           └── ve-topology-reduced.yaml
├── Bank-XL/                         # Large-scale enterprise network (1,471 nodes)
│   ├── AttackGraph/
│   │   ├── Code-Execution/          # Attack graph artifacts for Code-Execution scenario
│   │   │   ├── ARCS.CSV
│   │   │   ├── AttackGraph.dot
│   │   │   ├── AttackGraph.eps
│   │   │   ├── AttackGraph.pdf
│   │   │   ├── AttackGraph.txt
│   │   │   ├── AttackGraph.xml
│   │   │   └── VERTICES.CSV
│   │   └── Info-Leak/                   # Attack graph artifacts for Info-Leak scenario
│   │       ├── ARCS.CSV
│   │       ├── AttackGraph.dot
│   │       ├── AttackGraph.eps
│   │       ├── AttackGraph.pdf
│   │       ├── AttackGraph.txt
│   │       ├── AttackGraph.xml
│   │       └── VERTICES.CSV
│   ├── Facts/
│   │   ├── Code-Execution/
│   │   │   ├── Bank-XL_Facts_Code-Execution.p
│   │   │   └── Bank-XL_IR_Code-Execution.p
│   │   └── Info-Leak/
│   │       ├── Bank-XL_Facts_Info-Leak.p
│   │       └── Bank-XL_IR_Info-Leak.p
│   ├── Images/
│   │   ├── Bank-XL.jpg                           # Full 1,471-node topology diagram
│   │   ├── Bank-XL-Reduced_Info-Leak.png             # Minimal cyber twin (Info-Leak scenario)
│   │   └── Bank-XL-Reduced_Code-Execution.png    # Minimal cyber twin (Code-Execution scenario)
│   └── Topology-Files/
│       ├── Code-Execution/
│       │   ├── ve-config.yaml
│       │   ├── ve-config-reduced.yaml
│       │   ├── ve-topology.yaml
│       │   └── ve-topology-reduced.yaml
│       └── Info-Leak/
│           ├── ve-config.yaml
│           ├── ve-config-reduced.yaml
│           ├── ve-topology.yaml
│           └── ve-topology-reduced.yaml
└── UK-Office/                       # Real-world office network topology
    ├── AttackGraph/
    │   ├── Info-Leak/                   # Attack graph artifacts for Info-Leak scenario
    │   │   ├── ARCS.CSV
    │   │   ├── AttackGraph.dot
    │   │   ├── AttackGraph.eps
    │   │   ├── AttackGraph.pdf
    │   │   ├── AttackGraph.txt
    │   │   ├── AttackGraph.xml
    │   │   └── VERTICES.CSV
    │   └── Asset-Access/        # Attack graph artifacts for Asset-Access scenario
    │       ├── ARCS.CSV
    │       ├── AttackGraph.dot
    │       ├── AttackGraph.eps
    │       ├── AttackGraph.pdf
    │       ├── AttackGraph.txt
    │       ├── AttackGraph.xml
    │       └── VERTICES.CSV
    ├── Facts/
    │   ├── Info-Leak/
    │   │   ├── UK-Office_Facts_Info-Leak.p
    │   │   └── UK-Office_IR_Info-Leak.p
    │   └── Asset-Access/
    │       ├── UK-Office_Asset-Access_Facts.p
    │       └── UK-Office_Asset-Access_IR.p
    ├── Images/
    │   ├── UK-Office.jpeg                              # Full topology diagram
    │   ├── UK-Office_Reduced_Info-Leak.jpeg                # Minimal cyber twin (Info-Leak scenario)
    │   └── UK-Office_Reduced_Asset-Access.jpeg     # Minimal cyber twin (Asset-Access scenario)
    └── Topology-Files/
        ├── Info-Leak/
        │   ├── ve-config.yaml
        │   ├── ve-config-reduced.yaml
        │   ├── ve-topology.yaml
        │   └── ve-topology-reduced.yaml
        └── Asset-Access/
            ├── ve-config.yaml
            ├── ve-config-reduced.yaml
            ├── ve-topology.yaml
            └── ve-topology-reduced.yaml
```

</details>

**Note on Proprietary Content:**
- UK-Office (Asset-Access scenario): Caldera abilities and adversary profile for the UK-Intergalactic adversary are proprietary and not included in this repository.
- Additional pipeline execution scripts and automation code are proprietary and not shared publicly.

---

## Naming Convention

Files follow a consistent scheme throughout the repository. Understanding it makes it easy to locate any artifact by topology and adversary.

**Logical parts and separators:**
- Parts of a filename (topology, type, adversary) are separated by underscores `_`.
- Hyphens `-` appear only *within* a multi-word name: `Bank-XL`, `UK-Office`, `Code-Execution`, `Asset-Access`.

**Facts and IR files:** `{Topology}_{Type}_{Scenario}.p`

| Topology | Scenario | Facts file | IR file |
|---|---|---|---|
| `Bank` | `Code-Execution` | `Bank_Facts_Code-Execution.p` | `Bank_IR_Code-Execution.p` |
| `Bank` | `Info-Leak` | `Bank_Facts_Info-Leak.p` | `Bank_IR_Info-Leak.p` |
| `Bank-XL` | `Code-Execution` | `Bank-XL_Facts_Code-Execution.p` | `Bank-XL_IR_Code-Execution.p` |
| `Bank-XL` | `Info-Leak` | `Bank-XL_Facts_Info-Leak.p` | `Bank-XL_IR_Info-Leak.p` |
| `UK-Office` | `Info-Leak` | `UK-Office_Facts_Info-Leak.p` | `UK-Office_IR_Info-Leak.p` |
| `UK-Office` | `Asset-Access` | `UK-Office_Asset-Access_Facts.p` | `UK-Office_Asset-Access_IR.p` |

**Image files:**
- Full topology: `{Topology}.{ext}`
- Minimal cyber twin: `{Topology}_Reduced_{Scenario}.{ext}`

**GNS3 setup script folders:** `setup_{Scenario}_{Topology}/`
- Adversary and topology names are lowercase with hyphens within each name.
- Examples: `setup_thief_uk-office/`, `setup_bank-adversary_bank/`, `setup_uk-intergalactic_uk-office/`

**Caldera YAML files:** `.yml` for ability files and adversary profiles.

---

## Topology File Descriptions

Each experimental topology is organized in a consistent structure with four main subdirectories, each further split by adversary scenario.

### `AttackGraph/{Scenario}/`

Generated attack graph artifacts in multiple formats:
- **`ARCS.CSV`**: Attack graph edges representing state transitions
- **`AttackGraph.dot`**: GraphViz DOT format for visualization
- **`AttackGraph.eps`**: Encapsulated PostScript image
- **`AttackGraph.pdf`**: PDF visualization of the attack graph
- **`AttackGraph.txt`**: Human-readable text representation
- **`AttackGraph.xml`**: XML format for programmatic processing
- **`VERTICES.CSV`**: Attack graph vertices (states)

### `Facts/{Scenario}/`

Network specification and interaction rules for a specific attack scenario:
- **`{Topology}_Facts_{Scenario}.p`**: Prolog facts file containing the complete network state
  - Node definitions (hosts, routers, switches, firewalls)
  - Network connectivity and topology structure
  - Vulnerability information and CVE mappings
  - Service configurations and access control policies
  - User privileges and credential information
  - Adversary-specific seed facts (e.g., `agentPresent`, `attackGoal`)

- **`{Topology}_IR_{Scenario}.p`**: Interaction Rules for attack graph generation
  - State transition rules defining attacker capabilities
  - Exploit preconditions and postconditions
  - Privilege escalation rules
  - Lateral movement conditions
  - Multi-step attack chain logic

### `Images/`

Visual representations of the network topology and its minimal cyber twins:
- **`{Topology}.{ext}`**: Full topology network diagram
- **`{Topology}_Reduced_{Scenario}.{ext}`**: Minimal cyber twin diagram generated by SCyTAG for the given attack scenario

### `Topology-Files/{Scenario}/`

GNS3 virtual environment configurations for a specific attack scenario:
- **`ve-config.yaml`**: Full virtual environment configuration (GNS3 project settings, resource allocation, node deployment)
- **`ve-config-reduced.yaml`**: Reduced virtual environment configuration (generated by SCyTAG)
- **`ve-topology.yaml`**: Complete GNS3 topology specification (node definitions, link configurations, console settings, Docker/QEMU specs)
- **`ve-topology-reduced.yaml`**: Minimal cyber twin topology (generated by SCyTAG)

---

## Caldera Attack Emulation Data

The `Caldera/` directory contains the MITRE Caldera adversary profiles and ability definitions used to emulate attack scenarios on the SCyTAG-generated cyber twins. Caldera serves as the threat emulator in the SCyTAG pipeline: once the minimal cyber twin is deployed in GNS3, Caldera executes the CTI-derived attack steps and produces a structured debrief report used to assess impact and validate mitigations. Ability definitions and adversary profiles for the Code-Execution and Info-Leak scenarios are included; the UK-Intergalactic profile is proprietary and not published. For the full ability descriptions and pre-requisite facts, see [`Caldera/README.md`](Caldera/README.md).

---

## Scripts

The `Scripts/` directory contains three Python analysis scripts and a set of GNS3 shell scripts for Caldera agent deployment and mitigation. For full usage instructions, argument details, and configuration, see [`Scripts/README.md`](Scripts/README.md). GNS3 setup and mitigation shell scripts are documented separately in [`Scripts/GNS3_Caldera_Scripts/README.md`](Scripts/GNS3_Caldera_Scripts/README.md).

---

## Experimental Environments

### 1. UK-Office

A network topology inspired by a real organizational office environment, used to validate SCyTAG's practical applicability. This topology represents a typical small-to-medium enterprise environment with realistic network segmentation (DMZ, internal networks, VLAN isolation), production services, end-user workstations, IoT devices, and security controls. Two adversary scenarios are evaluated: **Info-Leak** (post-compromise data exfiltration) and **Asset-Access** (VPN exploitation and lateral movement).

**Purpose**: Demonstrate practical applicability and validate threat assessment accuracy.

### 2. Bank (Fictitious Banking Network — 88 Nodes)

A synthetic banking enterprise network inspired by the [Enterprise Network Lab — Bank Project](https://gns3.com/marketplace/labs/enterprise-network-lab-bank-project) from the GNS3 Marketplace. The topology features 4 building floors, hierarchical network architecture, and segregated departments (Marketing, Finance, Accounting, HR, Research, Management, ICT, Logistics, Customer Service). Includes security infrastructure: firewalls, DMZ, admin workstations, surveillance systems, and file servers. Two adversary scenarios are evaluated: **Info-Leak** and **Code-Execution**.

**Purpose**: Controlled environment for measuring cyber twin reduction effectiveness and resource optimization.

### 3. Bank-XL (Large-Scale Enterprise — 1,471 Nodes)

A massive enterprise topology with 1,471 network nodes including switches, routers, firewalls, and endpoints. Complex multi-floor architecture with 43 switches per floor across 4 floors, 7 PCs per switch (1,204 endpoint devices), multiple WiFi access points, and enterprise-grade security segmentation. Two adversary scenarios are evaluated: **Info-Leak** and **Code-Execution**.

**Purpose**: Evaluate SCyTAG's scalability limits and demonstrate up to 99% component reduction in large-scale environments.

---

## Key Contributions

1. **Automated Cyber Twin Generation**: SCyTAG automatically constructs minimal viable cyber twins from organizational network specifications and CTI-derived attack scenarios.

2. **Attack Graph-Driven Reduction**: Uses attack graphs to identify only the network components necessary for emulating specific threats, dramatically reducing resource requirements.

3. **Scalability**: Successfully scales from small office networks (UK-Office, 56 nodes) to enterprise environments with 1,471+ nodes (Bank-XL).

4. **Resource Efficiency**: Achieves up to **99% reduction** in network components while maintaining 100% attack emulation fidelity.

5. **CTI Integration**: Bridges the gap between abstract threat intelligence reports and practical, scenario-driven security testing.

---

## Reproducibility Guide

### Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+ recommended) or Windows with WSL2
- **Python**: 3.8 or higher
- **Python Packages**: `python-dotenv`
- **GNS3 Server**: 2.2.x or higher
- **Docker**: 20.10+ (for containerized network nodes)
- **QEMU**: 4.2+ (for router/firewall emulation)
- **MITRE Caldera**: Required for attack emulation
- **Memory**: Minimum 32 GB RAM (64 GB+ recommended for Bank-XL)
- **Storage**: 100 GB+ available disk space

### Component Reduction per Attack Scenario

| Topology | Scenario | Full Nodes | Minimal Twin | Reduction | Attack Fidelity |
|---|---|---|---|---|---|
| UK-Office | Info-Leak | 56 | 4 | 92.9% | 100% |
| UK-Office | Asset-Access | 56 | 12 | 78.6% | 100% |
| Bank | Info-Leak | 88 | 8 | 90.9% | 100% |
| Bank | Code-Execution | 88 | 12 | 86.4% | 100% |
| Bank-XL | Info-Leak | 1,471 | 8 | **99.5%** | 100% |
| Bank-XL | Code-Execution | 1,471 | 12 | **99.2%** | 100% |

All attack scenarios successfully reproduced in minimal cyber twins with **100% fidelity** compared to full topology emulation.

> **Note:** The Bank and Bank-XL minimal cyber twins for the Info-Leak scenario are identical (8 nodes each), derived from equivalent Info-Leak-based MulVAL attack graphs with the same interaction rules and facts structure.

---

## Attack Scenarios

### Bank & Bank-XL

1. **Code-Execution**: Three-ability chain targeting a camera/DVR system — steal password from a known file via SSH (T1552.001), transfer the Caldera agent to the target via sshpass/scp (T1105), and activate the agent (T1021).
2. **Info-Leak**: Post-compromise data exfiltration — discover sensitive files by extension (T1005), stage them (T1074.001), archive to a tarball (T1560.001), and exfiltrate over the C2 channel (T1041).

### UK-Office

1. **Asset-Access**: Multi-stage exploitation chain targeting a VPN gateway — exploits a web-UI vulnerability for RCE, extracts credentials from a user database, cracks the password offline, forges a VPN certificate, and performs lateral movement to a backup file server.
2. **Info-Leak**: Same post-compromise data exfiltration chain as Bank/Bank-XL (see above).

Caldera abilities and adversary profile for the Asset-Access scenario are proprietary and not included in this repository.

### Mitigations

Each scenario is accompanied by an empirically validated mitigation, demonstrated to hold in both the full topology and the corresponding minimal cyber twin.

#### Info-Leak (UK-Office and Bank)

The Thief adversary discovers sensitive files by searching for files matching specific extensions and below a size threshold. The mitigation relocates the target files to a hidden directory and pads each file beyond the size threshold, rendering all three target files undiscoverable by the adversary's search. The mitigation is applied identically in the UK-Office topology (ADMIN node) and the Bank topology (DVR node).

#### Code-Execution (Bank)

The Bank-Adversary's first ability reads a credential file from a known path on the camera/DVR node. The mitigation removes all filesystem access permissions from that file, causing the credential-read step to fail with a permission error. Because the two downstream abilities (agent transfer and agent activation) depend on the credential produced by the first ability, both are skipped and the attack chain is halted entirely.

#### Asset-Access (UK-Office)

Two independent mitigations are applied, each targeting a different stage of the attack chain. The first hardens the password of the targeted user account in the web-UI host's user database, causing the adversary's offline credential-cracking step to fail and preventing any further progression. The second removes the Certificate Authority signing key from the VPN host, making it impossible to forge a valid VPN client certificate and blocking both the certificate-forgery step and the subsequent lateral movement step.

---

## Citation

If you use this artifact in your research, please cite our work:

```bibtex
@article{scytag2025,
  title={{SCyTAG}: Scalable Cyber-Twin for Threat-Assessment Based on Attack Graphs},
  author={[Authors]},
  journal={arXiv preprint arXiv:2512.22669},
  year={2025}
}
```

---

## Ethical Considerations

All experiments were conducted in isolated virtual environments. The UK-Office topology represents a real network but has been sanitized to remove sensitive information. Bank and Bank-XL are entirely fictitious networks designed for research purposes.

Attack scenarios are based on publicly disclosed CTI reports and do not contain any novel exploitation techniques or zero-day vulnerabilities.

**Proprietary Content**: The UK-Intergalactic Caldera abilities and adversary profile, and certain additional pipeline execution scripts, are proprietary and not included in this public repository.

---

## Contact

For questions about this artifact or the SCyTAG framework, please open an issue:

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
- **v1.1.0**: Expanded artifact coverage to include a second adversary scenario per topology, providing attack graphs, network facts and interaction rules, GNS3 topology configurations, and minimal cyber twins for all scenario–topology combinations. Each adversary scenario is accompanied by an empirically validated mitigation, demonstrated to hold in both the full topology and the minimal cyber twin.

---

**Last Updated**: August 19, 2026
