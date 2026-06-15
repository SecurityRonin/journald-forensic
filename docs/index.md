# journald-forensic

**Read the systemd journal binary format directly — no `journalctl`, no systemd, no live host.**

`journald-forensic` parses the systemd-journal binary format over any `&[u8]`, so it works on carved fragments and disk-image extractions that `journalctl` rejects. It navigates a journal stream by cursor (sequence number + boot id) to structured entry fields, recovers journal structures from unallocated space, and audits the file for tampering signals.

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

## The crates

A reader stack plus an analyzer, in one workspace:

- `journald-core` — domain types (`JournalEntry`, `JournalField`, `JournalCursor`) with field accessors
- `journald-binary` — the on-disk reader: `parse_journal_magic`, `parse_header`, `parse_object_header`, and the eight `JournalObjectType`s
- `journald-carver` — recovery: `scan_for_journal_magic` and `scan_for_entry_objects` carve journal structures from unallocated space and corrupt files
- `journald-integrity` — the auditor: `detect_sequence_gaps` / `detect_timestamp_regressions` / `detect_truncation` / `detect_online_state` to `IntegrityIndicator`
- `jd` (`jd-cli`) — the end-user CLI: `timeline`, `fields`, `search`

## Trust, but verify

`journald-forensic` is built to read untrusted journal files from potentially compromised hosts: bounds-checked parsing (every length and offset is range-checked before use; malformed input yields a structured `JournalError`, not a panic), and no network or telemetry — analysis is entirely local.

## Where this fits

`journald-forensic` is the systemd-journal LOG-FORMAT reader for the SecurityRonin forensic family, the Linux counterpart to [`winevt-forensic`](https://github.com/SecurityRonin/winevt-forensic) on Windows. Findings normalize onto the shared [`forensicnomicon`](https://crates.io/crates/forensicnomicon) reporting vocabulary so they aggregate with the rest of the fleet.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/journald-forensic) · © 2026 Security Ronin Ltd
