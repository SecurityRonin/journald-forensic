# 3. Format constants sourced from `forensicnomicon`, not hand-coded

Date: 2026-07-24

Status: Accepted

## Context

The binary reader needs the journal magic (`LPKSHHRH`), the header field offsets,
and the object-type byte values. Hard-coding these as literals in `journald-binary`
would duplicate knowledge that the fleet already centralizes: `forensicnomicon` is
the zero-dependency KNOWLEDGE leaf that owns magic bytes, header offsets, and format
constants for the whole family (`~/src/ronin-issen/CLAUDE.md`, "forensicnomicon" +
"Dependency Preference — prefer our own crates"). A private copy would drift the
moment the spec understanding is refined in one place and not the other.

## Decision

Source all journal format constants from `forensicnomicon::journald` rather than
defining them locally. `crates/journald-binary/src/lib.rs` re-exports
`forensicnomicon::journald::JOURNAL_MAGIC` for downstream crates and drives
`parse_header`/`parse_object_header` off `header_offset::*`,
`object_header_offset::*`, and `object_type::*` from the same module. A unit test
(`binary_magic_matches_forensicnomicon_constant`) pins the reader's behavior to the
KNOWLEDGE constant. This was introduced under TDD in commits `17b26d9` (RED) and
`0140d5a` (GREEN), and `forensicnomicon` was moved from a path dependency to the
published registry crate in commit `209eccf` (with the workspace pinning
`forensicnomicon = "1"`). The dependency arrow points strictly down onto the
KNOWLEDGE leaf; `journald-core` itself takes no `forensicnomicon` dependency.

## Consequences

Format facts live in one audited place; refining an offset or adding an object type
happens once in `forensicnomicon` and every reader inherits it. The reader keeps no
magic literals of its own beyond the re-export. The cost is a dependency on the
published `forensicnomicon` crate and its release cadence, accepted as the fleet
default (prefer our own crates; published registry version over a path dep).
