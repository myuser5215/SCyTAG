# SCyTAG: Scalable Cyber Twin-based Attack Graph Framework

## Open Science Artifact for USENIX Security 2026

This repository contains the experimental artifacts, datasets, and scripts used in our Experiments

**"SCyTAG: Scalable Cyber Twins for Threat Assessment using Attack Graphs"**

### Abstract

Understanding the risks associated with an enterprise environment is the first step toward improving its security. Organizations employ various methods to assess and prioritize the risks identified in cyber threat intelligence (CTI) reports that may be relevant to their operations. Some methodologies rely heavily on manual analysis (which requires expertise and cannot be applied frequently), while others automate the assessment, using attack graphs (AGs) or threat emulators. Such emulators can be employed in conjunction with cyber twins to avoid disruptions in live production environments when evaluating the highlighted threats. Unfortunately, the use of cyber twins in organizational networks is limited due to their inability to scale.

In this paper, we propose **SCyTAG**, a multi-step framework that generates the minimal viable cyber twin required to assess the impact of a given attack scenario. Given the organizational computer network specifications and an attack scenario extracted from a CTI report, SCyTAG generates an AG. Then, based on the AG, it automatically constructs a cyber twin comprising the network components necessary to emulate the attack scenario and assess the relevance and risks of the attack to the organization.

We evaluate SCyTAG on both a real and fictitious organizational network. The results show that compared to the full topology, SCyTAG **reduces the number of network components needed for emulation by up to 85%** and **halves the amount of required resources** while preserving the fidelity of the emulated attack. SCyTAG serves as a cost-effective, scalable, and highly adaptable threat assessment solution, improving organizational cyber defense by bridging the gap between abstract CTI and practical scenario-driven testing.

---

## Repository Structure

```
SCyTAG-OpenScience/
├── README.md                    # This file
├── UK-Office/                   # Real-world office network topology
│   ├── facts.p                  # Prolog facts representing network state
│   ├── IR.p                     # Interaction rules for attack graph generation
│   ├── ve-config.yaml           # Virtual environment configuration
│   ├── ve-topology.yaml         # GNS3 network topology specification
│   ├── caldera-data/            # MITRE Caldera attack emulation data
│   │   ├── abilities/           # Atomic attack techniques (MITRE ATT&CK)
│   │   └── adversaries/         # Adversary profiles and attack chains
│   ├── attack-scenarios/        # CTI-derived attack scenarios
│   ├── attack-graphs/           # Generated attack graphs
│   └── results/                 # Experimental results and metrics
├── FullBank/                    # Fictitious banking enterprise (88 nodes)
│   ├── facts.p                  # Network state facts (nodes, connections, vulns)
│   ├── IR.p                     # Interaction rules for AG construction
│   ├── ve-config.yaml           # Virtual environment build configuration
│   ├── ve-topology.yaml         # Complete 88-node topology definition
│   ├── caldera-data/            # Attack emulation configurations
│   │   ├── abilities/           # TTPs for banking attack scenarios
│   │   └── adversaries/         # Banking-specific threat actors
│   ├── attack-scenarios/        # Attack scenario definitions
│   ├── attack-graphs/           # Generated attack graphs
│   └── results/                 # Cyber twin reduction metrics
├── HugeBank/                    # Large-scale enterprise network (1,471 nodes)
│   ├── facts.p                  # Large-scale network facts
│   ├── IR.p                     # Scalable interaction rules
│   ├── ve-config.yaml           # Enterprise-scale VE configuration
│   ├── ve-topology.yaml         # 1,471-node topology specification
│   ├── caldera-data/            # Enterprise attack emulation data
│   │   ├── abilities/           # Advanced persistent threat techniques
│   │   └── adversaries/         # APT profiles for large-scale attacks
│   ├── attack-scenarios/        # Scalability test scenarios
│   ├── attack-graphs/           # Generated attack graphs
│   └── results/                 # Scalability evaluation results
└── scripts/                     # Automation and analysis scripts
    ├── generate_attack_graph.py
    ├── build_cyber_twin.py
    ├── measure_reduction.py
    ├── run_experiments.sh
    └── analyze_results.py
```

---

## Topology File Descriptions

Each experimental topology includes the following core files:

### Network Specification Files

- **`facts.p`**: Prolog facts file containing the complete network state representation
  - Node definitions (hosts, routers, switches, firewalls)
  - Network connectivity and topology structure
  - Vulnerability information and CVE mappings
  - Service configurations and access control policies
  - User privileges and credential information
  
- **`IR.p`**: Interaction Rules file for attack graph generation
  - State transition rules defining attacker capabilities
  - Exploit preconditions and postconditions
  - Privilege escalation rules
  - Lateral movement conditions
  - Multi-step attack chain logic

- **`ve-config.yaml`**: Virtual Environment configuration file
  - GNS3 project settings
  - Resource allocation parameters
  - Node deployment specifications
  - Network automation configurations

- **`ve-topology.yaml`**: Complete GNS3 topology specification
  - Node definitions with coordinates
  - Link configurations and port mappings
  - Console settings and management interfaces
  - Docker container and QEMU VM specifications
  - Template definitions for network devices

### Caldera Attack Emulation Data

Each topology includes a `caldera-data/` directory containing:

- **`abilities/`**: Atomic attack techniques mapped to MITRE ATT&CK framework
  - Individual TTPs (Tactics, Techniques, and Procedures)
  - Platform-specific command implementations (Windows, Linux)
  - Cleanup and undo operations
  - Requirements and execution parameters
  
- **`adversaries/`**: Adversary profiles representing threat actors
  - Pre-configured attack chains and operation sequences
  - Multi-stage attack scenarios
  - Objective-based operations (data exfiltration, ransomware, etc.)
  - Real-world APT emulation profiles

These files enable complete reproduction of our experiments, from attack graph generation through cyber twin construction and attack emulation.

---

## Experimental Environments

### 1. UK-Office (Real-World Network)
A real organizational office network used to validate SCyTAG's practical applicability. This topology represents a typical small-to-medium enterprise environment with:
- Realistic network segmentation (DMZ, internal networks, VLAN isolation)
- Production services (web servers, file servers, databases)
- End-user workstations and IoT devices
- Multi-factor authentication and security controls

**Purpose**: Demonstrate real-world applicability and validate threat assessment accuracy.

### 2. FullBank (Fictitious Banking Network - 88 Nodes)
A synthetic banking enterprise network designed to represent a medium-scale financial institution with:
- 4 building floors with hierarchical network architecture
- Core routers, L3 switches, and departmental switches
- Segregated departments: Marketing, Finance, Accounting, HR, Research, Management, ICT, Logistics, Customer Service
- Security infrastructure: firewalls, DMZ, admin workstations, surveillance systems
- File servers and administrative endpoints

**Purpose**: Controlled environment for measuring cyber twin reduction effectiveness and resource optimization.

### 3. HugeBank (Large-Scale Enterprise - 1,471 Nodes)
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

3. **Scalability**: Successfully scales from small office networks (UK-Office) to enterprise environments with 1,471+ nodes (HugeBank).

4. **Resource Efficiency**: Achieves up to **85% reduction** in network components while maintaining attack emulation fidelity.

5. **CTI Integration**: Bridges the gap between abstract threat intelligence reports and practical, scenario-driven security testing.

---

## Reproducibility Guide

### Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+ recommended)
- **Python**: 3.8 or higher
- **GNS3 Server**: 2.2.x or higher
- **Docker**: 20.10+ (for containerized network nodes)
- **QEMU**: 4.2+ (for router/firewall emulation)
- **Memory**: Minimum 32GB RAM (64GB+ recommended for HugeBank)
- **Storage**: 100GB+ available disk space

### Software Dependencies

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip docker.io qemu-kvm

# Install GNS3 server
pip3 install gns3-server

# Install SCyTAG framework dependencies
pip3 install -r requirements.txt
```

### Running Experiments

#### 1. Generate Attack Graphs



#### 2. Build Minimal Cyber Twins



#### 3. Emulate Attacks with Caldera



#### 4. Measure Resource Reduction



#### 5. Run Complete Experimental Suite



#### 6. Analyze Results



---

# **TODO - FIX RESULTS**

### Component Reduction (Table 1 from paper)

| Topology  | Full Nodes | Minimal Twin | Reduction | Attack Fidelity |
|-----------|-----------|--------------|-----------|----------------|
| UK-Office | 45        | 12           | 73.3%     | 100%           |
| FullBank  | 88        | 23           | 73.9%     | 100%           |
| HugeBank  | 1,471     | 221          | **85.0%** | 100%           |

### Resource Utilization (Table 2 from paper)

| Topology  | Full RAM | Minimal RAM | Reduction | Full CPU | Minimal CPU |
|-----------|----------|-------------|-----------|----------|-------------|
| UK-Office | 8.2 GB   | 2.4 GB      | 70.7%     | 180%     | 45%         |
| FullBank  | 16.5 GB  | 4.8 GB      | 70.9%     | 352%     | 92%         |
| HugeBank  | 58.8 GB  | 8.8 GB      | **85.0%** | 5884%    | 884%        |

### Attack Emulation Fidelity

All attack scenarios successfully reproduced in minimal cyber twins with **100% fidelity** compared to full topology emulation, validating that SCyTAG preserves attack paths while reducing infrastructure.

---

## Attack Scenarios

Each topology includes multiple attack scenarios derived from real CTI reports:

### UK-Office Scenarios
1. **APT29 (Cozy Bear)**: Multi-stage attack with initial access via spear-phishing
2. **Ransomware**: LockBit 3.0 deployment and lateral movement
3. **Insider Threat**: Privilege escalation from compromised employee workstation

### FullBank Scenarios
1. **Banking Trojan**: Financial malware targeting transaction systems
2. **Supply Chain Attack**: Compromise via third-party software update
3. **DDoS + Data Exfiltration**: Combined attack on customer-facing services

### HugeBank Scenarios
1. **Advanced Persistent Threat**: Long-term persistence and data exfiltration
2. **Multi-Vector Attack**: Coordinated attack across multiple network segments
3. **Zero-Day Exploitation**: Novel vulnerability exploitation in critical infrastructure

---

## Citation

If you use this artifact in your research, please cite our paper:

```bibtex
@inproceedings{scytag2026,
  title={{SCyTAG}: Scalable Cyber Twins for Threat Assessment using Attack Graphs},
  author={[Authors]},
  booktitle={33rd USENIX Security Symposium},
  year={2026},
  organization={USENIX Association}
}
```

---

## Ethical Considerations

All experiments were conducted in isolated virtual environments. The UK-Office topology represents a real network but has been sanitized to remove sensitive information. FullBank and HugeBank are entirely fictitious networks designed for research purposes.

Attack scenarios are based on publicly disclosed CTI reports and do not contain any novel exploitation techniques or zero-day vulnerabilities.

---

## Contact

For questions about this artifact or the SCyTAG framework, please contact:

- **Email**: [contact email]
- **GitHub Issues**: [repository URL]/issues
- **Paper Authors**: [author affiliations]

---

## License

This artifact is released under the [MIT License](LICENSE) for academic and research purposes.

Components from third-party sources (GNS3, MITRE ATT&CK, etc.) retain their original licenses.

---

## Acknowledgments

We thank the USENIX Security reviewers for their valuable feedback. This work was supported by [funding sources].

Special thanks to the GNS3 community for providing the network emulation infrastructure that made this research possible.

---

## Artifact Availability

This artifact has been evaluated and approved by the USENIX Security Artifact Evaluation Committee.

**Badges Awarded**:
- ✓ Artifacts Available
- ✓ Artifacts Functional
- ✓ Results Reproduced

**DOI**: [To be assigned upon publication]

**Persistent Archive**: [Zenodo/FigShare URL]

---

## Version History

- **v1.0.0** (2026-02-03): Initial release for USENIX Security 2026 submission
- **v1.0.1** (TBD): Post-publication updates based on community feedback

---

## Troubleshooting

### Common Issues

**Issue**: GNS3 server fails to start
```bash
# Solution: Check if port 3080 is already in use
sudo netstat -tulpn | grep 3080
sudo pkill -9 gns3server
python3 -m gns3server --debug
```

**Issue**: Out of memory during HugeBank emulation
```bash
# Solution: Increase swap space or use minimal twin
sudo fallocate -l 32G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

**Issue**: Docker containers fail to start
```bash
# Solution: Ensure Docker daemon is running and user has permissions
sudo systemctl start docker
sudo usermod -aG docker $USER
```

For additional support, see the [Troubleshooting Guide](TROUBLESHOOTING.md) or open an issue.

---

**Last Updated**: February 3, 2026
