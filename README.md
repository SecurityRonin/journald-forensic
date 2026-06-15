# journald-forensic

[![journald-core](https://img.shields.io/crates/v/journald-core.svg?label=journald-core)](https://crates.io/crates/journald-core)
[![Docs.rs](https://img.shields.io/docsrs/journald-core)](https://docs.rs/journald-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Read a systemd `.journal` file directly — no `journalctl`, no running systemd, no live host — and surface the sequence gaps, timestamp regressions, and truncation that say a log was tampered with.**

A DFIR analyst handed a disk image (or a single carved `.journal`) needs the journal's contents and its integrity story without booting the suspect system. `journalctl` refuses files it didn't write and needs a matching systemd; this reads the on-disk binary format from scratch in pure Rust over any byte slice.

## Timeline a journal in 30 seconds

```bash
cargo install --git https://github.com/SecurityRonin/journald-forensic jd-cli
```

```bash
# Chronological timeline as JSONL — one entry per line, every field preserved
jd timeline system.journal

# Every field name present across the file (know what you can pivot on)
jd fields system.journal

# Pull every entry matching a field filter
jd search system.journal PRIORITY=3
```

```jsonl
{"seqnum":1042,"realtime_us":1718900000000000,"_PID":"1","MESSAGE":"Started Session 3 of user root.","PRIORITY":"6","_SYSTEMD_UNIT":"session-3.scope"}
```

## The integrity signals

`journald-integrity` walks the parsed entries and flags what a clean, append-only journal should never show. Each is an **observation** — the examiner draws the conclusion.

| `IntegrityKind` | What it observes |
|---|---|
| `SequenceGap` | A break `[A, B]` with `B > A + 1` — `B − A − 1` entries deleted between two surviving records |
| `TimestampRegression` | A realtime timestamp that moves backwards, where the journal guarantees monotonic non-decrease (clock rollback or splice) |
| `Truncation` | The file ends before `tail_object_offset` + the last object's size — a journal cut short |
| `InvalidState` | The header `state` is `ONLINE` — an unclean shutdown or a file still being written |

```rust
use journald_integrity::{detect_sequence_gaps, detect_timestamp_regressions};

for gap in detect_sequence_gaps(&seqnums) {
    println!("{:?}: {}", gap.kind, gap.detail);
}
```

## The crates

A reader stack plus an analyzer, one workspace:

| Crate | Role |
|---|---|
| [`journald-core`](https://crates.io/crates/journald-core) | Domain types — `JournalEntry`, `JournalField`, `JournalCursor` — with field accessors (`message`, `priority`, `pid`, `syslog_identifier`, `realtime_as_datetime`) |
| `journald-binary` | The on-disk reader: `parse_journal_magic`, `parse_header`, `parse_object_header`, and the eight `JournalObjectType`s (Data / Field / Entry / EntryArray / hash tables / Tag) |
| `journald-carver` | Recovery: `scan_for_journal_magic` and `scan_for_entry_objects` carve journal structures from unallocated space and corrupt files |
| `journald-integrity` | The auditor: `detect_sequence_gaps` / `detect_timestamp_regressions` / `detect_truncation` / `detect_online_state` → `IntegrityIndicator` |
| `jd` (`jd-cli`) | The end-user CLI: `timeline`, `fields`, `search` |

## Trust, but verify

`journald-forensic` is built to read untrusted journal files from potentially compromised hosts:

- **No `journalctl`, no systemd, no live host** — it parses the binary format itself over any `&[u8]`, so it works on carved fragments and disk-image extractions that `journalctl` rejects.
- **Bounds-checked parsing** — every length and offset from the file is range-checked before use; malformed input yields a structured `JournalError`, not a panic.
- **No network, no telemetry** — analysis is entirely local; see [Privacy Policy](https://securityronin.github.io/journald-forensic/privacy/).

```bash
cargo test
```

## Where this fits

`journald-forensic` is the systemd-journal LOG-FORMAT reader for the SecurityRonin forensic family: it navigates a journal stream by cursor (sequence number + boot id) → structured entry fields, the Linux counterpart to [`winevt-forensic`](https://github.com/SecurityRonin/winevt-forensic) on Windows. Findings normalize onto the shared [`forensicnomicon`](https://crates.io/crates/forensicnomicon) reporting vocabulary so they aggregate with the rest of the fleet.

---

[Privacy Policy](https://securityronin.github.io/journald-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/journald-forensic/terms/) · © 2026 Security Ronin Ltd
