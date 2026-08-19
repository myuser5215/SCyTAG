# SCyTAG: Scalable Cyber Twin-based Attack Graph Framework

This repository contains the experimental artifacts, datasets, and scripts for the SCyTAG framework.

**"SCyTAG: Scalable Cyber-Twin for Threat-Assessment Based on Attack Graphs"**

### Abstract

Understanding the risks associated with an enterprise environment is the first step toward improving its security. Organizations employ various methods to assess and prioritize risks identified in cyber threat intelligence (CTI) reports relevant to their operations. Some methodologies rely heavily on manual analysis (which requires expertise), while others automate assessment using attack graphs (AGs) or threat emulators employed in conjunction with cyber twins (to avoid disruptions in live production environments when evaluating the highlighted threats). Unfortunately, cyber twins are not scalable.

**SCyTAG** is a multi-step framework that generates the minimal viable cyber twin required to assess the impact of a given attack scenario. Given the organizational computer network specifications and an attack scenario extracted from a CTI report, SCyTAG generates an AG. Then, based on the AG, it automatically constructs a cyber twin comprising the network elements needed to emulate the attack scenario and assess the attack's relevance and risks to the organization.

SCyTAG's evaluation results show that compared to the full topology, it **reduces the number of network elements needed for emulation by up to 99%** and halves the required resources while preserving the fidelity of the emulated attack.

---

## Repository Structure

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
│       ├── setup_thief_uk-office/   # Thief adversary on UK-Office topology
│       │   ├── setup-caldera-lab_on_gns3_topology-fixed.sh
│       │   └── apply-thief-mitigation.sh
│       ├── setup_thief_bank/        # Thief adversary on Bank topology
│       │   ├── setup-thief-on-bank.sh
│       │   ├── apply-thief-mitigation-bank.sh
│       │   ├── diagnose-dvr-connectivity.sh
│       │   └── diagnose-ovs-l3sw.sh
│       ├── setup_uk-intergalactic_uk-office/  # UK-Intergalactic adversary on UK-Office topology
│       │   ├── setup-caldera-uk-intergalactic.sh
│       │   └── apply_uk-intergalactic_mitigation_uk-office.sh
│       └── setup_bank-adversary_bank/         # Bank-Adversary on Bank topology
│           ├── setup_bank-adversary_bank.sh
│           └── apply_bank-adversary_mitigation_bank.sh
├── Bank/                            # Fictitious banking enterprise (88 nodes)
│   ├── AttackGraph/
│   │   ├── Bank-Adversary/          # Attack graph artifacts for Bank-Adversary scenario
│   │   │   ├── ARCS.CSV
│   │   │   ├── AttackGraph.dot
│   │   │   ├── AttackGraph.eps
│   │   │   ├── AttackGraph.pdf
│   │   │   ├── AttackGraph.txt
│   │   │   ├── AttackGraph.xml
│   │   │   └── VERTICES.CSV
│   │   └── Thief/                   # Attack graph artifacts for Thief scenario
│   │       ├── ARCS.CSV
│   │       ├── AttackGraph.dot
│   │       ├── AttackGraph.eps
│   │       ├── AttackGraph.pdf
│   │       ├── AttackGraph.txt
│   │       ├── AttackGraph.xml
│   │       └── VERTICES.CSV
│   ├── Facts/
│   │   ├── Bank-Adversary/
│   │   │   ├── Bank_Facts_Bank-Adversary.p
│   │   │   └── Bank_IR_Bank-Adversary.p
│   │   └── Thief/
│   │       ├── Bank_Facts_Thief.p
│   │       └── Bank_IR_Thief.p
│   ├── Images/
│   │   ├── Bank.png                          # Full 88-node topology diagram
│   │   ├── Bank_Reduced_Thief.png            # Minimal cyber twin (Thief scenario)
│   │   └── Bank_Reduced_Bank-Adversary.png   # Minimal cyber twin (Bank-Adversary scenario)
│   └── Topology-Files/
│       ├── Bank-Adversary/
│       │   ├── ve-config.yaml
│       │   ├── ve-config-reduced.yaml
│       │   ├── ve-topology.yaml
│       │   └── ve-topology-reduced.yaml
│       └── Thief/
│           ├── ve-config.yaml
│           ├── ve-config-reduced.yaml
│           ├── ve-topology.yaml
│           └── ve-topology-reduced.yaml
├── Bank-XL/                         # Large-scale enterprise network (1,471 nodes)
│   ├── AttackGraph/
│   │   ├── Bank-Adversary/          # Attack graph artifacts for Bank-Adversary scenario
│   │   │   ├── ARCS.CSV
│   │   │   ├── AttackGraph.dot
│   │   │   ├── AttackGraph.eps
│   │   │   ├── AttackGraph.pdf
│   │   │   ├── AttackGraph.txt
│   │   │   ├── AttackGraph.xml
│   │   │   └── VERTICES.CSV
│   │   └── Thief/                   # Attack graph artifacts for Thief scenario
│   │       ├── ARCS.CSV
│   │       ├── AttackGraph.dot
│   │       ├── AttackGraph.eps
│   │       ├── AttackGraph.pdf
│   │       ├── AttackGraph.txt
│   │       ├── AttackGraph.xml
│   │       └── VERTICES.CSV
│   ├── Facts/
│   │   ├── Bank-Adversary/
│   │   │   ├── Bank-XL_Facts_Bank-Adversary.p
│   │   │   └── Bank-XL_IR_Bank-Adversary.p
│   │   └── Thief/
│   │       ├── Bank-XL_Facts_Thief.p
│   │       └── Bank-XL_IR_Thief.p
│   ├── Images/
│   │   ├── Bank-XL.jpg                           # Full 1,471-node topology diagram
│   │   ├── Bank-XL-Reduced_Thief.png             # Minimal cyber twin (Thief scenario)
│   │   └── Bank-XL-Reduced_Bank-Adversary.png    # Minimal cyber twin (Bank-Adversary scenario)
│   └── Topology-Files/
│       ├── Bank-Adversary/
│       │   ├── ve-config.yaml
│       │   ├── ve-config-reduced.yaml
│       │   ├── ve-topology.yaml
│       │   └── ve-topology-reduced.yaml
│       └── Thief/
│           ├── ve-config.yaml
│           ├── ve-config-reduced.yaml
│           ├── ve-topology.yaml
│           └── ve-topology-reduced.yaml
└── UK-Office/                       # Real-world office network topology
    ├── AttackGraph/
    │   ├── Thief/                   # Attack graph artifacts for Thief scenario
    │   │   ├── ARCS.CSV
    │   │   ├── AttackGraph.dot
    │   │   ├── AttackGraph.eps
    │   │   ├── AttackGraph.pdf
    │   │   ├── AttackGraph.txt
    │   │   ├── AttackGraph.xml
    │   │   └── VERTICES.CSV
    │   └── UK-Intergalactic/        # Attack graph artifacts for UK-Intergalactic scenario
    │       ├── ARCS.CSV
    │       ├── AttackGraph.dot
    │       ├── AttackGraph.eps
    │       ├── AttackGraph.pdf
    │       ├── AttackGraph.txt
    │       ├── AttackGraph.xml
    │       └── VERTICES.CSV
    ├── Facts/
    │   ├── Thief/
    │   │   ├── UK-Office_Facts_Thief.p
    │   │   └── UK-Office_IR_Thief.p
    │   └── UK-Intergalactic/
    │       ├── UK-Office_UK-Intergalactic_Facts.p
    │       └── UK-Office_UK-Intergalactic_IR.p
    ├── Images/
    │   ├── UK-Office.jpeg                              # Full topology diagram
    │   ├── UK-Office_Reduced_Thief.jpeg                # Minimal cyber twin (Thief scenario)
    │   └── UK-Office_Reduced_UK-Intergalactic.jpeg     # Minimal cyber twin (UK-Intergalactic scenario)
    └── Topology-Files/
        ├── Thief/
        │   ├── ve-config.yaml
        │   ├── ve-config-reduced.yaml
        │   ├── ve-topology.yaml
        │   └── ve-topology-reduced.yaml
        └── UK-Intergalactic/
            ├── ve-config.yaml
            ├── ve-config-reduced.yaml
            ├── ve-topology.yaml
            └── ve-topology-reduced.yaml
```

**Note on Proprietary Content:**
- UK-Office (UK-Intergalactic scenario): Caldera abilities and adversary profile for the UK-Intergalactic adversary are proprietary and not included in this repository.
- Additional pipeline execution scripts and automation code are proprietary and not shared publicly.

---

## Naming Convention

Files follow a consistent scheme throughout the repository. Understanding it makes it easy to locate any artifact by topology and adversary.

**Logical parts and separators:**
- Parts of a filename (topology, type, adversary) are separated by underscores `_`.
- Hyphens `-` appear only *within* a multi-word name: `Bank-XL`, `UK-Office`, `Bank-Adversary`, `UK-Intergalactic`.

**Facts and IR files:** `{Topology}_{Type}_{Adversary}.p`

| Topology | Adversary | Facts file | IR file |
|---|---|---|---|
| `Bank` | `Bank-Adversary` | `Bank_Facts_Bank-Adversary.p` | `Bank_IR_Bank-Adversary.p` |
| `Bank` | `Thief` | `Bank_Facts_Thief.p` | `Bank_IR_Thief.p` |
| `Bank-XL` | `Bank-Adversary` | `Bank-XL_Facts_Bank-Adversary.p` | `Bank-XL_IR_Bank-Adversary.p` |
| `Bank-XL` | `Thief` | `Bank-XL_Facts_Thief.p` | `Bank-XL_IR_Thief.p` |
| `UK-Office` | `Thief` | `UK-Office_Facts_Thief.p` | `UK-Office_IR_Thief.p` |
| `UK-Office` | `UK-Intergalactic` | `UK-Office_UK-Intergalactic_Facts.p` | `UK-Office_UK-Intergalactic_IR.p` |

**Image files:**
- Full topology: `{Topology}.{ext}`
- Minimal cyber twin: `{Topology}_Reduced_{Adversary}.{ext}`

**GNS3 setup script folders:** `setup_{Adversary}_{Topology}/`
- Adversary and topology names are lowercase with hyphens within each name.
- Examples: `setup_thief_uk-office/`, `setup_bank-adversary_bank/`, `setup_uk-intergalactic_uk-office/`

**Caldera YAML files:** `.yml` for ability files and adversary profiles.

---

## Topology File Descriptions

Each experimental topology is organized in a consistent structure with four main subdirectories, each further split by adversary scenario.

### `AttackGraph/{Adversary}/`

Generated attack graph artifacts in multiple formats:
- **`ARCS.CSV`**: Attack graph edges representing state transitions
- **`AttackGraph.dot`**: GraphViz DOT format for visualization
- **`AttackGraph.eps`**: Encapsulated PostScript image
- **`AttackGraph.pdf`**: PDF visualization of the attack graph
- **`AttackGraph.txt`**: Human-readable text representation
- **`AttackGraph.xml`**: XML format for programmatic processing
- **`VERTICES.CSV`**: Attack graph vertices (states)

### `Facts/{Adversary}/`

Network specification and interaction rules for a specific adversary scenario:
- **`{Topology}_Facts_{Adversary}.p`**: Prolog facts file containing the complete network state
  - Node definitions (hosts, routers, switches, firewalls)
  - Network connectivity and topology structure
  - Vulnerability information and CVE mappings
  - Service configurations and access control policies
  - User privileges and credential information
  - Adversary-specific seed facts (e.g., `agentPresent`, `attackGoal`)

- **`{Topology}_IR_{Adversary}.p`**: Interaction Rules for attack graph generation
  - State transition rules defining attacker capabilities
  - Exploit preconditions and postconditions
  - Privilege escalation rules
  - Lateral movement conditions
  - Multi-step attack chain logic

### `Images/`

Visual representations of the network topology and its minimal cyber twins:
- **`{Topology}.{ext}`**: Full topology network diagram
- **`{Topology}_Reduced_{Adversary}.{ext}`**: Minimal cyber twin diagram generated by SCyTAG for the given adversary scenario

### `Topology-Files/{Adversary}/`

GNS3 virtual environment configurations for a specific adversary scenario:
- **`ve-config.yaml`**: Full virtual environment configuration (GNS3 project settings, resource allocation, node deployment)
- **`ve-config-reduced.yaml`**: Reduced virtual environment configuration (generated by SCyTAG)
- **`ve-topology.yaml`**: Complete GNS3 topology specification (node definitions, link configurations, console settings, Docker/QEMU specs)
- **`ve-topology-reduced.yaml`**: Minimal cyber twin topology (generated by SCyTAG)

---

## Caldera Attack Emulation Data

The `Caldera/` directory contains MITRE Caldera attack emulation configurations.

### Bank-Adversary (`Caldera/Bank-Adversary/`)

- **`Ability-1.yml`** — T1552.001 (Credentials in Files): SSH into a known host and `cat` a password file. Output is parsed to extract the password fact for downstream abilities.
- **`Ability-2.yml`** — T1105 (Ingress Tool Transfer): Use `sshpass` and `scp` to transfer the Caldera agent binary to the target machine, authenticated with the stolen password.
- **`Ability-3.yml`** — T1021 (Remote Services): Activate the transferred agent on the target machine to establish a C2 foothold.
- **`Bank-Adversary.yml`** — Adversary profile chaining all three abilities into a single operation.

**Pre-requisite facts** (must be pre-configured as IMPORTED in the operation source before running):
`vulnerable.hostname`, `vulnerable.ip`, `password.file`, `target.ip`, `target.path`, `agent_group`

### Thief (`Caldera/Thief/`)

- **`Thief.yml`** — Adversary profile for post-compromise data theft: discovers files by extension, stages them, archives to a tarball, and exfiltrates over the C2 channel.

### UK-Intergalactic

Caldera abilities and adversary profile for the UK-Intergalactic scenario are **proprietary and not included** in this repository.

---

## Scripts

### Analysis Scripts (`Scripts/`)

- **`CompleteMissingFacts.py`**: Parses a MulVAL IR file and facts file, identifies body predicates that are neither ground facts nor derivable by interaction rules, and outputs skeleton Prolog fact entries for manual completion. Run with:
  ```bash
  python3 CompleteMissingFacts.py <facts_file.p> <ir_file.p>
  ```

- **`ReduceTopologyWithAG.py`**: Takes a full GNS3 topology YAML and an attack graph, and produces the minimal cyber twin topology containing only the nodes required to emulate the attack path.

- **`compare_debrief.py`**: Parses and compares Caldera operation debrief JSON reports (baseline vs. mitigated), summarizing per-ability outcomes, fact propagation, and status codes.

### GNS3 Setup and Mitigation Scripts (`Scripts/GNS3_Caldera_Scripts/`)

Shell scripts for deploying Caldera agents into GNS3 topologies and applying mitigations before a mitigated run. Each subfolder corresponds to one adversary–topology combination. See `Scripts/GNS3_Caldera_Scripts/README.md` for full usage instructions.

| Folder | Adversary | Topology |
|---|---|---|
| `setup_thief_uk-office/` | Thief | UK-Office |
| `setup_thief_bank/` | Thief | Bank |
| `setup_uk-intergalactic_uk-office/` | UK-Intergalactic | UK-Office |
| `setup_bank-adversary_bank/` | Bank-Adversary | Bank |

**Typical session workflow:**

Baseline (no mitigation):
```
1. Start GNS3 project
2. Run setup script
3. Start Caldera operation
```

Mitigated:
```
1. Start GNS3 project
2. Run setup script
3. Run mitigation script
4. Start Caldera operation
```

> **Note:** GNS3 is ephemeral — container IDs change on restart. Always run the setup script at the start of each session.

---

## Configuration

- **`.env`** *(not tracked in version control — create locally)*: Environment configuration file containing file paths and settings for the Python scripts. Load with `python-dotenv`:
  ```python
  from dotenv import load_dotenv
  load_dotenv()
  ```

---

## Experimental Environments

### 1. UK-Office

A network topology inspired by a real organizational office environment, used to validate SCyTAG's practical applicability. This topology represents a typical small-to-medium enterprise environment with realistic network segmentation (DMZ, internal networks, VLAN isolation), production services, end-user workstations, IoT devices, and security controls. Two adversary scenarios are evaluated: **Thief** (post-compromise data exfiltration) and **UK-Intergalactic** (VPN exploitation and lateral movement).

**Purpose**: Demonstrate practical applicability and validate threat assessment accuracy.

### 2. Bank (Fictitious Banking Network — 88 Nodes)

A synthetic banking enterprise network inspired by the [Enterprise Network Lab — Bank Project](https://gns3.com/marketplace/labs/enterprise-network-lab-bank-project) from the GNS3 Marketplace. The topology features 4 building floors, hierarchical network architecture, and segregated departments (Marketing, Finance, Accounting, HR, Research, Management, ICT, Logistics, Customer Service). Includes security infrastructure: firewalls, DMZ, admin workstations, surveillance systems, and file servers. Two adversary scenarios are evaluated: **Thief** and **Bank-Adversary**.

**Purpose**: Controlled environment for measuring cyber twin reduction effectiveness and resource optimization.

### 3. Bank-XL (Large-Scale Enterprise — 1,471 Nodes)

A massive enterprise topology with 1,471 network nodes including switches, routers, firewalls, and endpoints. Complex multi-floor architecture with 43 switches per floor across 4 floors, 7 PCs per switch (1,204 endpoint devices), multiple WiFi access points, and enterprise-grade security segmentation. Two adversary scenarios are evaluated: **Thief** and **Bank-Adversary**.

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

### Component Reduction per Adversary Scenario

| Topology | Adversary | Full Nodes | Minimal Twin | Reduction | Attack Fidelity |
|---|---|---|---|---|---|
| UK-Office | Thief | 56 | 4 | 92.9% | 100% |
| UK-Office | UK-Intergalactic | 56 | 12 | 78.6% | 100% |
| Bank | Thief | 88 | 8 | 90.9% | 100% |
| Bank | Bank-Adversary | 88 | 12 | 86.4% | 100% |
| Bank-XL | Thief | 1,471 | 8 | **99.5%** | 100% |
| Bank-XL | Bank-Adversary | 1,471 | 12 | **99.2%** | 100% |

All attack scenarios successfully reproduced in minimal cyber twins with **100% fidelity** compared to full topology emulation.

> **Note:** The Bank and Bank-XL minimal cyber twins for the Thief scenario are identical (8 nodes each), derived from equivalent Thief-based MulVAL attack graphs with the same interaction rules and facts structure.

---

## Attack Scenarios

### Bank & Bank-XL

1. **Bank-Adversary**: Three-ability chain targeting a camera/DVR system — steal password from a known file via SSH (T1552.001), transfer the Caldera agent to the target via sshpass/scp (T1105), and activate the agent (T1021).
2. **Thief**: Post-compromise data exfiltration — discover sensitive files by extension (T1005), stage them (T1074.001), archive to a tarball (T1560.001), and exfiltrate over the C2 channel (T1041).

### UK-Office

1. **UK-Intergalactic**: Multi-stage exploitation chain targeting a VPN gateway — exploits a web-UI vulnerability for RCE, extracts credentials from a user database, cracks the password offline, forges a VPN certificate, and performs lateral movement to a backup file server.
2. **Thief**: Same post-compromise data exfiltration chain as Bank/Bank-XL (see above).

Caldera abilities and adversary profile for the UK-Intergalactic scenario are proprietary and not included in this repository.

### Mitigations

Each adversary scenario is accompanied by an empirically validated mitigation, demonstrated to hold in both the full topology and the corresponding minimal cyber twin.

#### Thief (UK-Office and Bank)

The Thief adversary discovers sensitive files by searching for files matching specific extensions and below a size threshold. The mitigation relocates the target files to a hidden directory and pads each file beyond the size threshold, rendering all three target files undiscoverable by the adversary's search. The mitigation is applied identically in the UK-Office topology (ADMIN node) and the Bank topology (DVR node).

#### Bank-Adversary (Bank)

The Bank-Adversary's first ability reads a credential file from a known path on the camera/DVR node. The mitigation removes all filesystem access permissions from that file, causing the credential-read step to fail with a permission error. Because the two downstream abilities (agent transfer and agent activation) depend on the credential produced by the first ability, both are skipped and the attack chain is halted entirely.

#### UK-Intergalactic (UK-Office)

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
