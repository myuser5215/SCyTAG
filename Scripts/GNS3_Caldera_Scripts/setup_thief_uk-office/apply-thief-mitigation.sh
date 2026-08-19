#!/usr/bin/env bash
#
# Thief mitigation — apply on ADMIN (UK-Office topology)
# --------------------------------------------------------
# Relocates the three sensitive files into a hidden config directory and
# pads them past 500KB, defeating Thief's two hardcoded discovery filters
# (-not -path '*/\.*' and -size -500k) without changing file permissions,
# content, or topology structure. Full rationale in
# Thief-UK-Office-Mitigation-Strategy.md.
#
# Usage:
#   ./apply-thief-mitigation.sh <project_id>
#   PROJECT_ID=<project_id> ./apply-thief-mitigation.sh
#
# GNS3 environment is ephemeral — this must be re-run every session after
# a container restart, same as the sensitive files themselves needing
# re-planting (see setup-caldera-lab_on_gns3_topology.sh).

set -uo pipefail

PROJECT_ID="${1:-${PROJECT_ID:-}}"
if [ -z "$PROJECT_ID" ]; then
  echo "!! No project ID given. Usage:" >&2
  echo "     $0 <project_id>" >&2
  echo "   or:" >&2
  echo "     PROJECT_ID=<project_id> $0" >&2
  exit 1
fi
echo "== Using project: $PROJECT_ID =="

# ---- 1. Discover ADMIN's current container ID ----
echo "== Resolving ADMIN's container ID =="
ADMIN_ID=$(curl -s "http://localhost:3080/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
for n in json.load(sys.stdin):
    if n.get('name') == 'ADMIN':
        print(n.get('properties', {}).get('container_id',''))
")
if [ -z "$ADMIN_ID" ]; then
  echo "!! Could not resolve ADMIN's container ID for project $PROJECT_ID." >&2
  echo "   Confirm the project ID is correct and ADMIN is started, or run" >&2
  echo "   setup-caldera-lab_on_gns3_topology.sh first to reprovision." >&2
  exit 1
fi
echo "   ADMIN container ID: $ADMIN_ID"

# ---- 2. Confirm sensitive files are currently present at /root/ ----
echo "== Checking for sensitive files at /root/ =="
PRESENT=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'ls -la /root/secrets.yml /root/photo.png /root/recording.wav 2>&1'")
echo "$PRESENT"
if echo "$PRESENT" | grep -qi "No such file"; then
  echo "!! One or more sensitive files are missing from /root/. Run" >&2
  echo "   setup-caldera-lab_on_gns3_topology.sh to re-plant them, then re-run this script." >&2
  exit 1
fi

# ---- 3. Part 1 — relocate into hidden config directory ----
echo "== Applying Part 1: relocate into /root/.config/secure/ =="
docker exec gns3-server sh -c "docker exec $ADMIN_ID mkdir -p /root/.config/secure"
docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'mv /root/secrets.yml /root/photo.png /root/recording.wav /root/.config/secure/'"

# ---- 4. Part 2 — pad each file past 500KB ----
echo "== Applying Part 2: padding each file past 500KB =="
docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'for f in secrets.yml photo.png recording.wav; do dd if=/dev/urandom bs=1024 count=512 >> /root/.config/secure/\$f 2>/dev/null; done'"

# ---- 5. Verify placement, size, and integrity ----
echo "== Verifying placement, size, and integrity =="
docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'ls -la /root/.config/secure/'"
echo "-- first 200 bytes of secrets.yml (original content should be readable) --"
docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'head -c 200 /root/.config/secure/secrets.yml'"
echo ""

# ---- 6. Verify against Thief's exact find filters, one extension at a time ----
# NOTE: must be three separate commands, not combined with -o — see the
# corrected Step 5 in Thief-UK-Office-Mitigation-Strategy.md for why a
# combined command silently skips filtering on all but the last extension.
echo "== Verifying against Thief's find filters (expect empty output x3) =="
FOUND_YML=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'find / -name \"*.yml\" -type f -not -path \"*/\\.*\" -size -500k 2>/dev/null'")
FOUND_WAV=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'find / -name \"*.wav\" -type f -not -path \"*/\\.*\" -size -500k 2>/dev/null'")
FOUND_PNG=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'find / -name \"*.png\" -type f -not -path \"*/\\.*\" -size -500k 2>/dev/null'")

echo "  .yml -> ${FOUND_YML:-<empty, mitigation holds>}"
echo "  .wav -> ${FOUND_WAV:-<empty, mitigation holds>}"
echo "  .png -> ${FOUND_PNG:-<empty, mitigation holds>}"

if [ -n "$FOUND_YML$FOUND_WAV$FOUND_PNG" ]; then
  echo "!! One or more files are still discoverable by Thief's filters. Mitigation" >&2
  echo "   did not fully apply — check the output above before running the operation." >&2
else
  echo "   confirmed — 0/3 files discoverable"
fi

# ---- 7. Clear staging residue before starting the Caldera operation ----
echo "== Clearing staging residue from any prior run =="
docker exec gns3-server sh -c "docker exec $ADMIN_ID rm -rf /staged /staged.tar.gz"

# ---- 8. Reminder: tar wrapper is a separate concern ----
echo ""
echo "== Checking tar -P support (separate from this mitigation, but Compress will fail without it) =="
TAR_WHICH=$(docker exec gns3-server sh -c "docker exec $ADMIN_ID sh -c 'which tar'")
echo "   which tar -> $TAR_WHICH"
if [ "$TAR_WHICH" != "/usr/local/sbin/tar" ]; then
  echo "!! tar -P wrapper not detected. Compress will fail with 'unrecognized option: P'" >&2
  echo "   unless this session already has GNU tar. Run setup-caldera-lab_on_gns3_topology.sh" >&2
  echo "   (which installs the wrapper) before starting the operation if unsure." >&2
fi

echo ""
echo "== Done. ADMIN ($ADMIN_ID) is mitigated and ready — start the Thief operation in Caldera. =="
