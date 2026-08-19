# SCyTAG 2026 — Adversary Scripts

Scripts for setting up and mitigating adversary operations in Caldera/GNS3.
Each folder contains a **setup** script (deploys the agent, prepares the environment) and a **mitigation** script (applies the countermeasure before a mitigated run).

> **Before every session:** GNS3 is ephemeral — container IDs change on restart.
> Always run the setup script first, then the mitigation script if doing a mitigated run.

---

## Folder Overview

| Folder | Adversary | Topology |
|---|---|---|
| `setup_thief_uk-office/` | Thief | UK-Office |
| `setup_thief_bank/` | Thief | Bank |
| `setup_uk-intergalactic_uk-office/` | UK-Intergalactic | UK-Office |
| `setup_bank-adversary_bank/` | Bank-Adversary | Bank |

---

## 1. Thief — UK-Office

**Folder:** `setup_thief_uk-office/`

### Setup
```bash
chmod +x setup-caldera-lab_on_gns3_topology-fixed.sh
PROJECT_ID=<project_id> ./setup-caldera-lab_on_gns3_topology-fixed.sh
```
Or let it auto-discover the project by name:
```bash
PROJECT_NAME_PATTERN="UK-Office" ./setup-caldera-lab_on_gns3_topology-fixed.sh
```

### Mitigation (mitigated run only)
```bash
chmod +x apply-thief-mitigation.sh
sudo ./apply-thief-mitigation.sh <project_id>
```

---

## 2. Thief — Bank

**Folder:** `setup_thief_bank/`

### Setup
```bash
chmod +x setup-thief-on-bank.sh
PROJECT_ID=<project_id> ./setup-thief-on-bank.sh
```
The script prints the `exec_home` path at the end — **copy it**, you need it for the mitigation script.

Or auto-discover:
```bash
PROJECT_NAME_PATTERN="Bank" ./setup-thief-on-bank.sh
```

### Mitigation (mitigated run only)
Use the `exec_home` printed by the setup script:
```bash
chmod +x apply-thief-mitigation-bank.sh
./apply-thief-mitigation-bank.sh <project_id> <exec_home>
```
Example:
```bash
./apply-thief-mitigation-bank.sh 942ec581-725a-4b13-a21d-609548301b2c /root
```

---

## 3. UK-Intergalactic — UK-Office

**Folder:** `setup_uk-intergalactic_uk-office/`

### Setup
```bash
chmod +x setup-caldera-uk-intergalactic.sh
PROJECT_ID=<project_id> ./setup-caldera-uk-intergalactic.sh
```
Or auto-discover:
```bash
PROJECT_NAME_PATTERN="UK-Office" ./setup-caldera-uk-intergalactic.sh
```

### Mitigation (mitigated run only)
```bash
chmod +x apply_uk-intergalactic_mitigation_uk-office.sh
PROJECT_ID=<project_id> ./apply_uk-intergalactic_mitigation_uk-office.sh
```
What it does:
- **Mitigation 1** — Hardens `alice`'s password in `users.db` (blocks Ability 4 → password cracking fails)
- **Mitigation 2** — Removes CA signing key on `intergalactic-vpn` (blocks Ability 5/6 → VPN cert forge fails)

---

## 4. Bank-Adversary — Bank

**Folder:** `setup_bank-adversary_bank/`

> **Pre-requisite:** Caldera facts must be pre-configured as IMPORTED in the operation source before running:
> `vulnerable.hostname=testuser`, `vulnerable.ip=192.168.100.10`, `password.file=password.txt`,
> `target.ip=192.168.110.10`, `target.path=/home/testuser`, `agent_group=dvr_group`

### Setup
```bash
chmod +x setup_bank-adversary_bank.sh
PROJECT_ID=<project_id> ./setup_bank-adversary_bank.sh
```
Or auto-discover:
```bash
PROJECT_NAME_PATTERN="Bank" ./setup_bank-adversary_bank.sh
```

### Mitigation (mitigated run only)
```bash
chmod +x apply_bank-adversary_mitigation_bank.sh
PROJECT_ID=<project_id> ./apply_bank-adversary_mitigation_bank.sh
```
What it does: `chmod 000 /home/testuser/password.txt` on `camera_A` → Ability 1 fails (Permission denied) → Abilities 2 & 3 skipped.

---

## Finding Your Project ID

If you don't know the project ID, query GNS3:
```bash
curl -s http://localhost:3080/v2/projects | python3 -c "
import json, sys
for p in json.load(sys.stdin):
    print(p['project_id'], '|', p['status'], '|', p['name'])
"
```

---

## Typical Session Workflow

**Baseline (no mitigation):**
```
1. Start GNS3 project
2. Run setup script
3. Start Caldera operation
```

**Mitigated:**
```
1. Start GNS3 project
2. Run setup script
3. Run mitigation script
4. Start Caldera operation
```
