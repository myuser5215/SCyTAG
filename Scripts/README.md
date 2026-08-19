# Scripts

## Analysis Scripts

### `CompleteMissingFacts.py`

Parses a MulVAL IR file and facts file, identifies body predicates that are neither ground facts nor derivable by interaction rules, and outputs skeleton Prolog fact entries for manual completion.

```bash
python3 CompleteMissingFacts.py <facts_file.p> <ir_file.p>
```

**Configuration:** requires the `MISSING_FACTS_FILE_PATH` environment variable, which sets the output path where the generated missing-fact skeletons are written. There are two ways to provide it:

- **Via a `.env` file** *(not tracked in version control — create locally in your working directory)*:
  ```
  MISSING_FACTS_FILE_PATH=/path/to/output_missing_facts.p
  ```

- **Via an inline environment variable** (no `.env` file needed):
  ```bash
  MISSING_FACTS_FILE_PATH=/path/to/output_missing_facts.p python3 CompleteMissingFacts.py <facts_file.p> <ir_file.p>
  ```

### `ReduceTopologyWithAG.py`

Takes a full GNS3 topology YAML and an attack graph, and produces the minimal cyber twin topology containing only the nodes required to emulate the attack path. Takes all arguments from the command line; no environment configuration required.

### `compare_debrief.py`

Parses and compares Caldera operation debrief JSON reports (baseline vs. mitigated), summarizing per-ability outcomes, fact propagation, and status codes. Takes all arguments from the command line; no environment configuration required.

---

## GNS3 Setup and Mitigation Scripts

Shell scripts for deploying Caldera agents into GNS3 topologies and applying mitigations before a mitigated run. Each subfolder corresponds to one adversary–topology combination. See [`GNS3_Caldera_Scripts/README.md`](GNS3_Caldera_Scripts/README.md) for full usage instructions.

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
