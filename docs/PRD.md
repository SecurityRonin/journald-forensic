# journald-forensic — Product Requirements

*Reverse-written from the shipped code, README, and git history (read 2026-07-24).
Every current-state claim below is grounded in a same-session read of `crates/` and
`README.md`; the load-bearing decisions live as ADRs under
[`docs/decisions/`](decisions/). This documents what the tool **is today**, not a
roadmap.*

## Executive Summary

`journald-forensic` reads a systemd `.journal` file directly — with no `journalctl`,
no running systemd, and no live host — and surfaces both its contents and its
integrity story. The product an examiner runs is **`jd4n6`**, a CLI that turns a
binary `.journal` file into a chronological JSONL timeline, enumerates its field
names, and filters entries by field match. Underneath sit four publishable library
crates: a domain-type core, an on-disk binary reader, a carver for damaged or
unallocated bytes, and an integrity auditor that flags the sequence gaps, timestamp
regressions, truncation, and unclean-state markers an append-only journal should
never show.

The differentiator is reach: `journalctl` refuses files it did not write and needs a
matching systemd, so it is useless on a disk image, a mounted evidence volume, or a
single carved fragment. `jd4n6` parses the binary format itself over any byte slice,
so it works exactly where the live tool refuses.

## 1. Problem

A DFIR analyst holding a Linux disk image (or one `.journal` carved from unallocated
space) needs two things from the journal: **what it says** and **whether it was
tampered with** — without booting the suspect system. The standard tool fails both:

- `journalctl` will not open a `.journal` it did not itself write, and requires a
  running systemd of a compatible version; it cannot read a file lifted out of an
  image, and it silently declines carved fragments and truncated tails.
- Even when it reads a file, `journalctl` is a *log viewer*, not a forensic tool: it
  presents entries but does not flag deleted-entry sequence gaps, backwards
  timestamps, or a truncated file as anomalies for an examiner to weigh.

## 2. Users and use cases

- **DFIR / incident-response analyst** — has a disk image or extracted `.journal`
  files, needs a timeline and an integrity read without a matching live host.
- **Forensic examiner** — needs neutral, defensible observations (a sequence gap, a
  timestamp regression) to weigh against context, not a "tampered" verdict.
- **Rust tool author** — links `journald-core` (domain types) or `journald-binary`
  (the reader) into a larger analyzer, without pulling in the CLI.

## 3. What it does (the `jd4n6` surface)

From `crates/journald-cli/src/main.rs` — three subcommands, JSONL/line output, exit
`0` on success (including when a file is valid but no entries match — an empty result
is not an error) and `1` only when the file cannot be opened/read, its magic is
invalid (parse error), or the search filter is malformed:

- **`jd4n6 timeline <path>`** — emit a chronological timeline of journal entries as
  JSONL, one object per line, every field key=value preserved (machine-faithful and
  pipeline-friendly).
- **`jd4n6 fields <path>`** — list every field name present across the file, so the
  analyst knows what they can pivot on.
- **`jd4n6 search <path> FIELD=VALUE`** — emit every entry matching a field filter.

The integrity signals are produced by the `journald-integrity` library
(`IntegrityKind`: `SequenceGap`, `TimestampRegression`, `Truncation`,
`InvalidState`), each a neutral observation (ADR 0004).

## 4. Artifact family

- **Format:** systemd journal on-disk binary format (`.journal` files), magic
  `LPKSHHRH`, little-endian, eight object types (Data / Field / Entry / EntryArray /
  Data-hash-table / Field-hash-table / Tag). Format constants come from
  `forensicnomicon::journald` (ADR 0003).
- **Inputs:** a `.journal` file on disk, a `.journal` extracted from an image, or raw
  bytes containing journal structures (carver path). Everything is parsed over `&[u8]`
  (ADR 0002).
- **Fleet placement:** the systemd-journal LOG-FORMAT reader of the SecurityRonin
  forensic family — navigating a journal stream by cursor (sequence number + boot id)
  → structured entry fields — the Linux counterpart to `winevt-forensic` on Windows.
  Integrity anomalies are currently emitted as `journald-integrity`'s own
  `IntegrityIndicator` struct; normalizing them onto the shared
  `forensicnomicon::report` vocabulary is future work, not yet wired (only
  `journald-binary` depends on `forensicnomicon`, and solely for `::journald` format
  constants, never `::report`).

## 5. Scope

- Read the journal binary format from raw bytes: header, object headers, entries,
  fields, cursors.
- Extract a chronological timeline, enumerate field names, and search by field.
- Detect the four integrity invariant-breaks as neutral observations.
- Carve journal magic and plausible entry objects from unallocated/damaged bytes.
- Ship both a runnable CLI (`jd4n6`) and independently linkable libraries.

## 6. Non-goals

- **Not a `journalctl` replacement for live systems** — no live tailing, no journal
  writing, no systemd integration; it reads static files/bytes.
- **No verdicts** — the auditor reports observations; the examiner draws conclusions
  (ADR 0004). It never asserts that a gap *was* a deletion.
- **No image/filesystem decoding** — a PARSER, it takes `&[u8]`; extracting a
  `.journal` from an E01/ext4 image is the job of the CONTAINER/FILESYSTEM layers and
  orchestration, not this repo.
- **No cryptographic FSS seal *verification*** — `InvalidState` observes the header
  state; validating Forward-Secure-Sealing Tag objects against sealing keys is not
  implemented.
- **No streaming of multi-gigabyte journals** — the current CLI reads the whole file
  into memory before parsing (ADR 0002 consequences).

## 7. Validation approach (current state, stated honestly)

Correctness is currently exercised by **in-crate unit tests** across the four
libraries (magic/header/object-header parsing pinned to the `forensicnomicon`
constants, sequence-gap / timestamp-regression / truncation / online-state detectors,
carver magic and entry scans) plus **one CLI integration test**
(`crates/journald-cli/tests/cli_tests.rs`). These are author-written tests over
synthetic fixtures.

There is **no** independent-oracle or real-artifact validation yet: no `docs/validation.md`,
no differential run against `journalctl`/`libsystemd` output on real journals, and no
committed real-world corpus. Reaching the fleet Doer-Checker bar requires validating
`timeline`/`fields`/`search` and the integrity detectors against genuine `.journal`
files (e.g. produced by a real systemd host and cross-checked with `journalctl -o
json`), reconciling entry counts and field contents, and writing the result up in
`docs/validation.md`. That is outstanding work, not a claim already met.
