# Test data — journald-forensic

Single repo-root corpus (see `ronin-issen/docs/test-data-catalog.md` for the fleet
index — this README is the co-located human-facing detail; cross-reference, never
duplicate).

## `classic-system.journal`

- **Classification:** REAL-self (generated on a real systemd host, not synthetic)
- **Source:** produced by real `systemd-journald` (systemd 239, RHEL 8) running as
  PID 1 inside a `registry.access.redhat.com/ubi8/ubi-init` container under Podman.
  journald was configured `Storage=persistent`, `Compress=no`,
  `SystemMaxFileSize=512K`; 21 messages were logged via `logger -t jdtest`, then
  `journalctl --sync && --flush`. The resulting
  `/var/log/journal/<machine-id>/system.journal` was copied out verbatim.
- **Why systemd 239 (classic format):** systemd v252+ writes journals with the
  `COMPACT` + `KEYED_HASH` incompatible flags (32-bit entry-item offsets), which
  this reader does not yet decode. systemd 239 predates both, so the file uses the
  classic layout (`Incompatible Flags: <none>`, verified by `journalctl --header`).
- **MD5:** `cb1b9af3366d6d3e4f1470e3c7d203a4`
- **Size:** 524288 bytes (journald's minimum file size; ~18 KB non-zero, the rest is
  the preallocated arena — gzips to ~10 KB, so it is cheap in git).
- **Ground truth (independent oracle = `journalctl --header` / `journalctl --file`):**
  - State: OFFLINE (state byte 0)
  - Machine ID: `e7d87b83baf96ba14eb77adc0a769ed2`
  - Boot ID: `e00a23d431394d0ca22d6e3ebc10dd74`
  - Sequential Number ID: `799abeca5ffa46fcb51552ab9afb90cc`
  - Objects: 319 · Entry objects: 30 · Data objects: 160
  - Head sequential number: 1 · Tail sequential number: 64
  - 21 entries with `SYSLOG_IDENTIFIER=jdtest` (`MESSAGE` values
    `fixture message NUM <n> ALPHA BRAVO`, plus one `fixture ERROR message CHARLIE`).
- **Redistribution:** the file contains only the fixture log lines above plus
  journald's own housekeeping records (no proprietary content); freely
  redistributable.
- **Consumed by:**
  - `journald-binary` unit tests — `parse_header` / `parse_object_header` against a
    real header (Tier-1, cross-checked against the `journalctl` oracle values above).
  - `journald-cli` integration tests (`tests/cli_tests.rs`) — `timeline` / `fields`
    / `search` happy paths must find all 30 entries / 21 `jdtest` matches.

The remaining coverage fixtures (empty file, wrong magic, truncated / huge
header_size buffers) are constructed byte-exact inside the test sources, so the
coverage gate is satisfiable from committed bytes alone.

## Minting additional oracle corpora — `scripts/mint-journal.sh`

- **Classification:** REAL-self (minted on a real systemd host; ground truth
  documented, not inferred).
- **Generator (verbatim):** `scripts/mint-journal.sh [OUTPUT_PATH]` — run on a
  Linux/systemd host. It logs a KNOWN event set (`logger -t jd4n6-mint` at
  priorities info=6 and err=3, plus a `systemd-cat` marker), runs
  `journalctl --sync && --flush`, copies
  `/var/log/journal/<machine-id>/system.journal` to `OUTPUT_PATH`, and writes
  `OUTPUT_PATH.truth.txt` (md5/sha256, incompatible-flags, `journalctl` entry
  count, and the exact messages logged). For a **classic-format** file the reader
  can parse end-to-end, run it inside a systemd-239 container (recipe in the
  script header) — the same provenance as `classic-system.journal` above.
- **Not committed by default:** minted journals are operator-produced and
  environment-specific; they are consumed via the env-gated oracle test
  (`JOURNALD_TEST_CORPUS=<path> cargo test -p journald-binary --test
  journalctl_oracle`), not committed to git. Record any journal you *do* commit
  here with its `.truth.txt` values and this catalog's fields.

## Deliberately NOT committed: systemd fuzz seeds

systemd ships journal fuzz/seed corpora, but systemd is **LGPL-2.1-or-later**;
committing those binaries into this **Apache-2.0** repo would attach copyleft to
part of the tree. Malformed-input hardening therefore uses **synthetic in-source
buffers** (`crates/journald-binary/tests/malformed_input.rs`) plus the
`fuzz_parse_entries` cargo-fuzz target's generated corpus — no LGPL seeds. See
`docs/validation.md`.
