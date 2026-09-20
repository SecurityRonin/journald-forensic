# Validation

How the journald-forensic parser's correctness is established, and how to
reproduce it. The load-bearing evidence is a **differential-oracle** check: the
crate's decode is reconciled against `journalctl` — systemd decoding its *own*
on-disk format — over a real `.journal` file.

## Evidence tiers

| Tier | What vouches for the ground truth | Where |
|---|---|---|
| **T1** | `journalctl` (systemd's own decoder) on a real journal | `journalctl_oracle.rs` · `parse_header` real-header asserts |
| **T3** | synthetic buffers we authored (robustness: "never panic") | `malformed_input.rs` · `fuzz_parse_entries` |

The reader currently decodes the **classic** on-disk layout. systemd v252+ writes
journals with the `COMPACT` (+ `KEYED_HASH`) incompatible flags (32-bit
entry-item offsets), which are not yet decoded — the oracle test detects that flag
and skips such a corpus cleanly.

## The journalctl differential oracle (T1)

`journalctl` reads the same binary format the crate parses, so it is an
independent authority on both the entry count and each field's value. The test
`crates/journald-binary/tests/journalctl_oracle.rs`:

1. runs the crate's `parse_entries` over the journal bytes;
2. runs `journalctl --file <f> -o json --no-pager` and parses the JSONL;
3. **reconciles** the two —
   - **entry count** must be equal (we neither missed nor invented entries), and
   - for each sampled field (`MESSAGE`, `SYSLOG_IDENTIFIER`, `_PID`, `PRIORITY`,
     `_COMM`), every value the crate produced must be corroborated by the oracle
     (multiset subset). The count check guards the other direction.

The pure reconciliation helpers (`parse_oracle_jsonl`, `field_multiset`,
`reconcile`, `entry_to_text_map`) are unit-tested unconditionally with synthetic
inputs, so the reconciliation logic is exercised in every CI run. The end-to-end
oracle call is **env-gated**: it runs only when `JOURNALD_TEST_CORPUS` points at a
real `.journal` **and** `journalctl` is on `PATH`; otherwise it prints a `SKIP`
line and returns green (the fleet env-gated-oracle pattern).

### Reproducing it

On any Linux host with systemd (`journalctl` present):

```bash
JOURNALD_TEST_CORPUS=/path/to/system.journal \
  cargo test -p journald-binary --test journalctl_oracle -- --nocapture
```

Point `JOURNALD_TEST_CORPUS` at a **classic-format** journal (systemd 239-era, or
one minted by `scripts/mint-journal.sh` inside a systemd-239 container — see that
script's header). The committed `tests/data/classic-system.journal` fixture is
such a file.

Confirmed run (Linux container, real `journalctl`) against the committed fixture:

```
OK: reconciled 30 entries against journalctl oracle
    (fields: MESSAGE, SYSLOG_IDENTIFIER, _PID, PRIORITY, _COMM).
```

This matches the fixture's documented oracle ground truth (30 entry objects; see
`tests/data/README.md`).

### Minting a fresh oracle corpus

`scripts/mint-journal.sh` (Linux/systemd operator script) logs a **known** set of
events, syncs/flushes the journal, copies the live `system.journal` out, and
writes a `<out>.truth.txt` ground-truth sidecar (md5/sha256, incompatible-flags,
`journalctl` entry count, and the exact messages logged). The reader parses the
result only when it is classic-format; the script warns when the host's systemd is
≥ 252 (COMPACT layout).

## Malformed-input hardening (T3)

`parse_entries` accepts a raw `&[u8]` (a whole `.journal`) whose every size,
offset, and item count is attacker-controllable. The invariant is: **never panic,
never read out of bounds** — degrade to a (possibly empty) `Vec`. Two backstops:

- **`crates/journald-binary/tests/malformed_input.rs`** — deterministic,
  committed regression buffers: empty and every truncation point below the minimum
  header; extreme `header_size`; all-`0xFF` arena; LCG pseudo-random garbage of
  many lengths; `Entry`/`Data` objects declaring `size = u64::MAX`; item
  `data_offset` swept across every boundary (EOF, `u64::MAX`, self-reference).
  These lock in the fix for the `align8` overflow panic (commit `aff68e7`).
- **`fuzz/fuzz_targets/fuzz_parse_entries.rs`** — a `cargo-fuzz` target driving the
  full arena walk. `fuzz.yml` runs a 45s smoke pass on every PR and a 10-minute
  scheduled deep run, seeded from the committed journal. Local confirmation:
  **1.45M executions in 91s with zero crashes**.

### Why no systemd fuzz seeds are committed

systemd ships journal seed/fuzz corpora, but systemd is **LGPL-2.1-or-later**;
committing those binary files into this **Apache-2.0** repository would attach a
copyleft license to part of the tree. The hardening therefore uses **synthetic
in-source buffers** (byte-exact, reproducible, coverage-gate-satisfiable from
committed bytes) plus the fuzz target's own generated corpus — keeping the repo
license clean. Real classic-format journals for the T1 oracle come from the
committed fixture or an operator mint, not from LGPL seeds.
