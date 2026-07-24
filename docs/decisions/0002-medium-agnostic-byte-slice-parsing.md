# 2. Medium-agnostic parsing over `&[u8]`, no `journalctl`/systemd/file-I/O

Date: 2026-07-24

Status: Accepted

## Context

`journalctl` refuses to read a `.journal` file it did not write and requires a
matching, running systemd — useless when a DFIR analyst holds a disk image, a
mounted evidence volume, or a single `.journal` carved out of unallocated space on
a foreign host. The bytes an examiner must inspect frequently arrive as a fragment,
a truncated tail, or an extraction from an image, none of which a live tool will
open. In the fleet layer model (`~/src/ronin-issen/CLAUDE.md`, "Multi-Repo
Architecture") a PARSER/LOG-FORMAT reader is medium-agnostic by design: it accepts
`Path` or `&[u8]` and never imports a CONTAINER or FILESYSTEM crate, so the source
of the bytes is decided in orchestration, not baked into the reader.

## Decision

The reader and carver operate purely on in-memory byte slices and perform no file
I/O. `crates/journald-binary/src/lib.rs` and `crates/journald-carver/src/lib.rs`
both open with the module doc "All functions accept `&[u8]` slices — no file I/O."
Every public parser (`parse_journal_magic`, `parse_header`, `parse_object_header`)
and every carver entry (`scan_for_journal_magic`, `scan_for_entry_objects`) takes a
`&[u8]` and returns a structured result. File reading lives only at the CLI edge
(`journald-cli`'s `read_and_validate`), which slurps a path into a `Vec<u8>` before
handing the slice to the library.

## Consequences

The library works on carved fragments and disk-image extractions that `journalctl`
rejects, and it has zero runtime dependency on systemd or a live host. A caller can
feed it bytes from any source — a mounted image, a memory extraction, a network
stream — without the library knowing or caring. The cost is that the library does no
streaming: a caller wanting to parse a multi-gigabyte journal must supply the bytes
(today, by reading the whole file into memory at the CLI), and bounded/streamed
reads over very large journals are future work.
