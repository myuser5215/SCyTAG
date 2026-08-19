# Caldera Attack Emulation Data

This directory contains MITRE Caldera adversary profiles and ability definitions used to emulate attack scenarios on the SCyTAG-generated cyber twins. Each subdirectory corresponds to one adversary.

---

## Bank-Adversary (`Caldera/Bank-Adversary/`)

A three-ability chain targeting a camera/DVR system in the Bank topology.

- **`Ability-1.yml`** — T1552.001 (Credentials in Files): SSH into a known host and `cat` a password file. Output is parsed to extract the password fact for downstream abilities.
- **`Ability-2.yml`** — T1105 (Ingress Tool Transfer): Use `sshpass` and `scp` to transfer the Caldera agent binary to the target machine, authenticated with the stolen password.
- **`Ability-3.yml`** — T1021 (Remote Services): Activate the transferred agent on the target machine to establish a C2 foothold.
- **`Bank-Adversary.yml`** — Adversary profile chaining all three abilities into a single operation.

**Pre-requisite facts** (must be pre-configured as IMPORTED in the operation source before running):
`vulnerable.hostname`, `vulnerable.ip`, `password.file`, `target.ip`, `target.path`, `agent_group`

---

## Thief (`Caldera/Thief/`)

A post-compromise data exfiltration adversary applicable across all three topologies (Bank, Bank-XL, UK-Office).

- **`Thief.yml`** — Adversary profile for post-compromise data theft: discovers files by extension, stages them, archives to a tarball, and exfiltrates over the C2 channel.

---

## UK-Intergalactic

Caldera abilities and adversary profile for the UK-Intergalactic scenario are **proprietary and not included** in this repository.
