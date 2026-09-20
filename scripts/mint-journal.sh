#!/usr/bin/env bash
#
# mint-journal.sh — mint a systemd .journal test fixture with DOCUMENTED ground truth.
#
# WHY THIS EXISTS
#   The journald-forensic parser is validated Tier-1 against real systemd journals.
#   This script produces such a journal on a Linux host, logging a KNOWN set of
#   events so the ground truth is documented (not guessed), then copies the raw
#   binary `.journal` out for use as a test corpus and by the journalctl
#   differential-oracle test (JOURNALD_TEST_CORPUS).
#
# WHERE TO RUN
#   A Linux host (or container) with systemd + `logger` + `journalctl`. This script
#   is written for an operator to run ON LINUX; it CANNOT run on macOS (no systemd).
#
# CLASSIC vs COMPACT FORMAT — READ THIS
#   The reader currently decodes the *classic* on-disk layout only. systemd v252+
#   writes journals with the COMPACT (+ KEYED_HASH) incompatible flags, which use
#   32-bit entry-item offsets the reader does not yet decode. To mint a journal the
#   reader can parse end-to-end, run this INSIDE a systemd-239-era container (the
#   provenance of the committed `tests/data/classic-system.journal` fixture):
#
#     podman run --rm -it \
#       -v "$PWD/out:/out:Z" \
#       registry.access.redhat.com/ubi8/ubi-init \
#       bash -c '/usr/lib/systemd/systemd --system & sleep 2;
#                bash /out/mint-journal.sh /out/system.journal'
#
#   (ubi8 ships systemd 239 → classic layout, Incompatible Flags: <none>.)
#
#   On a MODERN host the mint still succeeds, but the resulting file will carry the
#   COMPACT flag; the journalctl oracle still decodes it (systemd reads its own
#   format), yet the crate's `parse_entries` will not — the differential test
#   detects the flag and SKIPS rather than failing. The script warns you when it
#   detects systemd >= 252.
#
# USAGE
#   scripts/mint-journal.sh [OUTPUT_PATH]
#     OUTPUT_PATH  where to write the minted .journal (default: ./minted-system.journal)
#
# OUTPUT
#   <OUTPUT_PATH>            the raw binary journal (copy of the live system.journal)
#   <OUTPUT_PATH>.truth.txt  the documented ground truth (events logged + oracle facts)
#
set -euo pipefail

OUT="${1:-./minted-system.journal}"
TRUTH="${OUT}.truth.txt"
TAG="jd4n6-mint"

# --- Preconditions -----------------------------------------------------------
command -v logger      >/dev/null || { echo "FATAL: 'logger' not found (util-linux)." >&2; exit 1; }
command -v journalctl  >/dev/null || { echo "FATAL: 'journalctl' not found — is this a systemd host?" >&2; exit 1; }
command -v systemctl   >/dev/null || echo "WARN: 'systemctl' absent; continuing." >&2

SD_VERSION="$(journalctl --version 2>/dev/null | awk 'NR==1{print $2}')"
echo "systemd version: ${SD_VERSION:-unknown}"
if [ -n "${SD_VERSION:-}" ] && [ "${SD_VERSION}" -ge 252 ] 2>/dev/null; then
  cat >&2 <<'WARN'
WARN: systemd >= 252 detected. The minted journal will use the COMPACT layout,
      which the current reader cannot decode. journalctl (the oracle) still reads
      it, and the differential-oracle test will SKIP on it. To mint a
      classic-format fixture, run inside a systemd-239 container (see header).
WARN
fi

# --- 1. Log a KNOWN set of events -------------------------------------------
# Each logged line's identifier + priority + message is recorded below so the
# fixture's ground truth is documented, not inferred. We use a distinct SYSLOG
# identifier (tag) so the events are unambiguously findable via `search`.
declare -a MESSAGES=(
  "mint event ALPHA login-marker"
  "mint event BRAVO service-start"
  "mint event CHARLIE user-command whoami"
  "mint event DELTA config-change"
  "mint event ECHO shutdown-marker"
)

echo "Logging ${#MESSAGES[@]} events with tag '${TAG}' (priority info=6)..."
for msg in "${MESSAGES[@]}"; do
  logger -t "${TAG}" -p user.info -- "${msg}"
done

# One elevated-priority event (priority err=3) so PRIORITY reconciliation has a
# non-default value to check.
ERR_MSG="mint event FOXTROT auth-failure simulated"
logger -t "${TAG}" -p user.err -- "${ERR_MSG}"
echo "Logging 1 error event (priority err=3)."

# systemd-cat marks a second identifier so field enumeration has variety.
if command -v systemd-cat >/dev/null; then
  echo "mint event GOLF systemd-cat-marker" | systemd-cat -t "${TAG}-cat" -p info
  CAT_LOGGED=1
else
  CAT_LOGGED=0
fi

# --- 2. Flush + sync so the events are durable on disk -----------------------
echo "Syncing journal to disk..."
journalctl --sync  2>/dev/null || true
journalctl --flush 2>/dev/null || true
sync

# --- 3. Locate and copy the live system.journal -----------------------------
MACHINE_ID="$(cat /etc/machine-id 2>/dev/null || true)"
SRC=""
if [ -n "${MACHINE_ID}" ] && [ -f "/var/log/journal/${MACHINE_ID}/system.journal" ]; then
  SRC="/var/log/journal/${MACHINE_ID}/system.journal"
else
  # Fall back to the first system.journal under /var/log/journal (persistent) or
  # /run/log/journal (volatile).
  SRC="$(find /var/log/journal /run/log/journal -name 'system.journal' 2>/dev/null | head -n1 || true)"
fi
[ -n "${SRC}" ] && [ -f "${SRC}" ] || { echo "FATAL: no system.journal found (persistent storage disabled?)." >&2; exit 1; }
echo "Source journal: ${SRC}"

mkdir -p "$(dirname "${OUT}")"
cp -f "${SRC}" "${OUT}"
echo "Copied journal → ${OUT}"

# --- 4. Record the documented ground truth -----------------------------------
MD5="$( (md5sum "${OUT}" 2>/dev/null || md5 -q "${OUT}") | awk '{print $1}')"
SHA="$( (sha256sum "${OUT}" 2>/dev/null || shasum -a 256 "${OUT}") | awk '{print $1}')"
INCOMPAT="$(journalctl --file "${OUT}" --header 2>/dev/null | awk -F': *' '/Incompatible Flags/{print $2; exit}')"
N_ENTRIES="$(journalctl --file "${OUT}" -o json 2>/dev/null | wc -l | tr -d ' ')"

{
  echo "# Ground truth for ${OUT}"
  echo "# Minted by scripts/mint-journal.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "systemd_version: ${SD_VERSION:-unknown}"
  echo "machine_id:      ${MACHINE_ID:-unknown}"
  echo "source_path:     ${SRC}"
  echo "md5:             ${MD5}"
  echo "sha256:          ${SHA}"
  echo "incompatible_flags: ${INCOMPAT:-unknown}   # '<none>' == classic (reader-parseable)"
  echo "journalctl_entry_count: ${N_ENTRIES}   # oracle count for the differential test"
  echo
  echo "## Logged events (ground truth)"
  echo "tag: ${TAG}    (SYSLOG_IDENTIFIER)"
  i=1
  for msg in "${MESSAGES[@]}"; do
    echo "  [${i}] PRIORITY=6 SYSLOG_IDENTIFIER=${TAG}  MESSAGE=${msg}"
    i=$((i+1))
  done
  echo "  [${i}] PRIORITY=3 SYSLOG_IDENTIFIER=${TAG}  MESSAGE=${ERR_MSG}"
  if [ "${CAT_LOGGED}" = "1" ]; then
    echo "  [+] PRIORITY=6 SYSLOG_IDENTIFIER=${TAG}-cat  MESSAGE=mint event GOLF systemd-cat-marker"
  fi
  echo
  echo "## Verify with the oracle"
  echo "  journalctl --file ${OUT} --header"
  echo "  journalctl --file ${OUT} -o json | wc -l"
  echo "  JOURNALD_TEST_CORPUS=${OUT} cargo test -p journald-binary --test journalctl_oracle -- --nocapture"
} > "${TRUTH}"

echo
echo "Done."
echo "  journal:      ${OUT}"
echo "  ground truth: ${TRUTH}"
echo "  md5:          ${MD5}"
echo
echo "Use it as the differential-oracle corpus:"
echo "  JOURNALD_TEST_CORPUS=${OUT} cargo test -p journald-binary --test journalctl_oracle"
