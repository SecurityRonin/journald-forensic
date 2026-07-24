# 1. Multi-crate reader-stack + analyzer workspace

Date: 2026-07-24

Status: Accepted

## Context

Reading a systemd `.journal` file for forensic purposes spans several distinct
concerns: the domain vocabulary (entries, fields, cursors), the on-disk binary
decoder, recovery of structures from unallocated or damaged bytes, integrity
auditing, and a user-facing CLI. Folding these into one crate would force a
downstream Rust tool that only wants the domain types or the binary reader to
compile the auditor and the `clap`/`anyhow` CLI surface, and would couple the
medium-agnostic parser to the binary. The fleet naming grammar
(`~/src/ronin-issen/CLAUDE.md`, "Crate naming grammar") classifies a
decompose-by-concern PARSER suite as **Pattern B**: an umbrella repo whose name is
not itself a crate, with role-suffixed members under a distinctive prefix.

## Decision

Split the repo into five members under the distinctive `journald-` prefix, arranged
in dependency layers (`crates/*/Cargo.toml`):

- `journald-core` — domain types (`JournalEntry`, `JournalField`, `JournalCursor`,
  `JournalError`) with field accessors; depends only on `chrono`/`thiserror`/`serde`.
- `journald-binary` — the on-disk reader (`parse_journal_magic`, `parse_header`,
  `parse_object_header`, the eight `JournalObjectType`s); depends on `journald-core`
  and `forensicnomicon`.
- `journald-carver` — recovery (`scan_for_journal_magic`, `scan_for_entry_objects`,
  `is_plausible_object_header`) over raw bytes; depends on `journald-core` +
  `journald-binary`.
- `journald-integrity` — the auditor (`detect_sequence_gaps`,
  `detect_timestamp_regressions`, `detect_truncation`, `detect_online_state` →
  `IntegrityIndicator`); depends on `journald-core` + `journald-binary`.
- `journald-cli` — the `jd4n6` binary; depends on all four.

The umbrella repo is `journald-forensic`; there is no `journald-forensic` crate,
per Pattern B. The layering is acyclic. Scaffolded in commit `8dcc0f6` and grown
one member at a time under strict red/green TDD (commits `9f05ac6`/`1faa2af`,
`c629cd1`/`196fce5`, `a5f0a55`/`53cb7db`, `ba6d777`/`1b13ef1`, `78dc099`/`6e95bd7`).

## Consequences

A downstream tool depends on exactly the layer it needs — the domain types or the
binary reader without the auditor or the CLI. The medium-agnostic reader and carver
are reusable outside this suite. The `journald-` prefix is distinctive enough to
stand alone on crates.io, so no `<repo>-*` widening is required (unlike the
generic-word `browser-forensic-*` case). The acyclic layering constrains where
shared helpers live: they belong in `journald-core`.
