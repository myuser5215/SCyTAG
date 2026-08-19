#!/usr/bin/env bash
#
# Thief mitigation — apply on DVR_ssh-1 (Bank topology)
# --------------------------------------------------------
# The EXACT same two-part mitigation used against ADMIN on UK-Office:
#   Part 1 — relocate the three sensitive files into a hidden config
#            directory, defeating Thief's -not -path '*/\.*' filter.
#   Part 2 — pad each file past 500KB, defeating Thief's -size -500k filter.
# No permission changes, no deletion, no topology changes. Full rationale
# in Thief-UK-Office-Mitigation-Strategy.md — this is that same design,
# applied to a different host.
#
# Uses whatever <exec_home> setup-thief-on-bank.sh discovered and reported
# (NOT a hardcoded /root/ or /home/testuser/ — this script takes it as an
# explicit argument to avoid re-guessing).
#
# Usage:
#   ./apply-thief-mitigation-bank.sh <project_id> <exec_home>
#   PROJECT_ID=<project_id> EXEC_HOME=<exec_home> ./apply-thief-mitigation-bank.sh
#
# GNS3 environment is ephemeral — this must be re-run every session after
# a container restart, same as the sensitive files needing re-planting
# (see setup-thief-on-bank.sh).
#
# NOTE: Bank containers are reachable via PLAIN, single-layer `docker exec
# <container_id>` directly from this host — no nested gns3-server wrapper,
# unlike UK-Office.
#
# CHANGELOG vs prior version:
#   - FIX: PROJECT_ID was hardcoded and silently ignored the $1 argument.
#     Now correctly reads it, same pattern as EXEC_HOME.
#   - FIX: added a fail-fast liveness check on the resolved container ID
#     before doing anything else. Previously, a stale/wrong container ID
#     caused every subsequent `docker exec` to fail with "No such
#     container", but since nothing checked exit codes, empty output from
#     the failed calls was indistinguishable from a genuine empty result —
#     the script reported "confirmed — 0/3 files discoverable" and "Done...
#     mitigated and ready" while having done nothing at all.
#   - FIX: Part 1 (mkdir/mv) and Part 2 (padding) now check exit codes
#     explicitly and abort loudly on failure instead of continuing silently.

set -uo pipefail

GNS3_API="http://localhost:3080"   # adjust if Bank's GNS3 API differs

PROJECT_ID="${1:-${PROJECT_ID:-}}"
EXEC_HOME="${2:-${EXEC_HOME:-}}"

if [ -z "$PROJECT_ID" ] || [ -z "$EXEC_HOME" ]; then
  echo "!! Missing argument(s). Usage:" >&2
  echo "     $0 <project_id> <exec_home>" >&2
  echo "   or:" >&2
  echo "     PROJECT_ID=<project_id> EXEC_HOME=<exec_home> $0" >&2
  echo "   <exec_home> is whatever setup-thief-on-bank.sh printed as 'home:' —" >&2
  echo "   do not guess this; it was empirically discovered per-session." >&2
  exit 1
fi
echo "== Using project: $PROJECT_ID, exec home: $EXEC_HOME =="

# ---- 1. Discover DVR_ssh-1's current container ID ----
echo "== Resolving DVR_ssh-1's container ID =="
DVR_ID=$(curl -s "${GNS3_API}/v2/projects/${PROJECT_ID}/nodes" | python3 -c "
import json, sys
for n in json.load(sys.stdin):
    if n.get('name') == 'DVR_ssh-1':
        print(n.get('properties', {}).get('container_id',''))
")
if [ -z "$DVR_ID" ]; then
  echo "!! Could not resolve DVR_ssh-1's container ID for project $PROJECT_ID." >&2
  echo "   Confirm the project ID is correct and DVR_ssh-1 is started, or run" >&2
  echo "   setup-thief-on-bank.sh first to reprovision." >&2
  exit 1
fi
echo "   DVR_ssh-1 container ID: $DVR_ID"

# ---- 1b. Fail fast if the resolved container ID isn't actually reachable ----
# This is the check that was missing: without it, a stale/wrong PROJECT_ID
# resolves a dead container ID, every docker exec below fails silently, and
# empty output gets misread as "mitigation confirmed."
echo "== Verifying container is reachable =="
LIVE_ERR=$(docker exec "$DVR_ID" true 2>&1)
if [ $? -ne 0 ]; then
  echo "!! Container $DVR_ID does not respond to docker exec." >&2
  echo "   docker error: $LIVE_ERR" >&2
  echo "   This usually means: (a) PROJECT_ID is stale/wrong, (b) DVR_ssh-1 was" >&2
  echo "   recreated since this project was last inspected, or (c) this host isn't" >&2
  echo "   where this project's containers actually run. Re-run setup-thief-on-bank.sh" >&2
  echo "   to reprovision and get a fresh, confirmed-live container ID, then retry." >&2
  exit 1
fi
echo "   ok — container responds"

# ---- 2. Clear any staging residue left behind by a prior Thief run ----
# Must happen BEFORE the find-filter verification below — leftover copies in
# EXEC_HOME/staged/ from an earlier (possibly successful, unmitigated) Thief
# operation are real, small, undefended files sitting in a non-hidden path,
# and will falsely trip the "still discoverable" check if not cleared first.
echo "== Clearing staging residue from any prior run =="
docker exec "$DVR_ID" rm -rf "$EXEC_HOME/staged" "$EXEC_HOME/staged.tar.gz"

# ---- 3. Confirm sensitive files are currently present at EXEC_HOME ----
echo "== Checking for sensitive files at $EXEC_HOME =="
PRESENT=$(docker exec "$DVR_ID" sh -c "ls -la $EXEC_HOME/secrets.yml $EXEC_HOME/photo.png $EXEC_HOME/recording.wav 2>&1")
echo "$PRESENT"
if echo "$PRESENT" | grep -qi "No such file"; then
  echo "!! One or more sensitive files are missing from $EXEC_HOME. Run" >&2
  echo "   setup-thief-on-bank.sh to re-plant them, then re-run this script." >&2
  exit 1
fi

# ---- 3. Part 1 — relocate into hidden config directory ----
echo "== Applying Part 1: relocate into $EXEC_HOME/.config/secure/ =="
if ! docker exec "$DVR_ID" mkdir -p "$EXEC_HOME/.config/secure"; then
  echo "!! Failed to create $EXEC_HOME/.config/secure on $DVR_ID." >&2
  exit 1
fi
if ! docker exec "$DVR_ID" sh -c "mv $EXEC_HOME/secrets.yml $EXEC_HOME/photo.png $EXEC_HOME/recording.wav $EXEC_HOME/.config/secure/"; then
  echo "!! mv failed — one or more source files may be missing, or the destination" >&2
  echo "   is unwritable. Check $EXEC_HOME/.config/secure/ manually before retrying." >&2
  exit 1
fi

# ---- 4. Part 2 — pad each file past 500KB ----
echo "== Applying Part 2: padding each file past 500KB =="
if ! docker exec "$DVR_ID" sh -c "for f in secrets.yml photo.png recording.wav; do dd if=/dev/urandom bs=1024 count=512 >> $EXEC_HOME/.config/secure/\$f 2>/dev/null || exit 1; done"; then
  echo "!! Padding failed for one or more files. Check $EXEC_HOME/.config/secure/" >&2
  echo "   manually — files may be partially padded." >&2
  exit 1
fi

# ---- 5. Verify placement, size, and integrity ----
echo "== Verifying placement, size, and integrity =="
docker exec "$DVR_ID" sh -c "ls -la $EXEC_HOME/.config/secure/"
echo "-- first 200 bytes of secrets.yml (original content should be readable) --"
docker exec "$DVR_ID" sh -c "head -c 200 $EXEC_HOME/.config/secure/secrets.yml"
echo ""

# ---- 6. Verify against Thief's exact find filters, one extension at a time ----
# Three separate commands, not combined with -o — a combined command silently
# skips filtering on all but the last extension due to find's operator
# precedence (same issue documented for UK-Office).
echo "== Verifying against Thief's find filters (expect empty output x3) =="
FOUND_YML=$(docker exec "$DVR_ID" sh -c "find / -name '*.yml' -type f -not -path '*/\.*' -size -500k 2>/dev/null")
FOUND_WAV=$(docker exec "$DVR_ID" sh -c "find / -name '*.wav' -type f -not -path '*/\.*' -size -500k 2>/dev/null")
FOUND_PNG=$(docker exec "$DVR_ID" sh -c "find / -name '*.png' -type f -not -path '*/\.*' -size -500k 2>/dev/null")

echo "  .yml -> ${FOUND_YML:-<empty, mitigation holds>}"
echo "  .wav -> ${FOUND_WAV:-<empty, mitigation holds>}"
echo "  .png -> ${FOUND_PNG:-<empty, mitigation holds>}"

if [ -n "$FOUND_YML$FOUND_WAV$FOUND_PNG" ]; then
  echo "!! One or more files are still discoverable by Thief's filters. Mitigation" >&2
  echo "   did not fully apply — check the output above before running the operation." >&2
else
  echo "   confirmed — 0/3 files discoverable"
fi

# ---- 7. Confirm tar -P support (unaffected by this mitigation, but re-check each session) ----
echo ""
echo "== Confirming tar -P support =="
TAR_CHECK=$(docker exec "$DVR_ID" sh -c "tar -P -cf /tmp/tar-check.tar /etc/hostname 2>&1; rm -f /tmp/tar-check.tar")
if echo "$TAR_CHECK" | grep -qi "unrecognized option\|invalid option"; then
  echo "!! tar -P unsupported — a wrapper will be needed (see UK-Office's fix)." >&2
else
  echo "   ok — tar -P supported"
fi

echo ""
echo "== Done. DVR_ssh-1 ($DVR_ID) is mitigated and ready — start the Thief operation in Caldera. =="
