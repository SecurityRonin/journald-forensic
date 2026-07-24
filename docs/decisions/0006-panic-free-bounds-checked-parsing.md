# 6. Length-guarded parsing with structured errors over untrusted journal bytes

Date: 2026-07-24

Status: Accepted

## Context

Every byte this suite parses is attacker-controllable: a `.journal` file from a
potentially compromised host, or a fragment carved from unallocated space. A length
field that lies, a truncated header, or a malformed object must never crash the tool
or produce silently wrong output — a forensic parser that panics on a crafted
artifact is a denial-of-service on the investigation. The fleet "Paranoid Gatekeeper"
standard (`~/src/ronin-issen/CLAUDE.md`) sets the target posture: bounds-checked
reads, structured errors, and — in its full form — a `forbid(unsafe)` /
`unwrap_used = deny` lint wall plus a fuzz target per parsed structure.

## Decision

Guard every parse with an up-front length check against a minimum size, then read
fixed-width fields at known offsets, returning a structured `JournalError` (never a
panic) on any shortfall. In `crates/journald-binary/src/lib.rs`, `parse_journal_magic`
checks `buf.len() < 8`, `parse_header` checks `header_offset::MIN_HEADER_SIZE`, and
`parse_object_header` checks `object_header_offset::HEADER_SIZE`, each returning
`JournalError::BufferTooShort { needed, got }` before touching the bytes. The
`try_into().unwrap()` calls that follow operate on fixed-width sub-slices whose bounds
are dominated by the preceding length guard, so they are infallible by construction.
Unknown enum bytes are handled explicitly (`object_type_from_byte` returns an error;
an unknown header `state` is treated as the suspicious `Online`). No `unsafe` appears
anywhere in the workspace.

## Consequences

Malformed evidence degrades to a typed `JournalError` or a partial result, never a
crash. The parser is written against real journal offsets documented inline in the
source.

**Known deviation from the full fleet standard, stated honestly:** the workspace lint
posture is lighter than the Paranoid Gatekeeper target. `[workspace.lints]` sets only
`clippy::pedantic` with a few pragmatic allows (`Cargo.toml`); it does **not** yet
declare `unsafe_code = "forbid"` in `[workspace.lints.rust]`, nor
`clippy::unwrap_used`/`expect_used = "deny"`, and there is **no `cargo-fuzz` target**.
The current panic-free property therefore rests on the hand-written length guards and
tests, not on a static lint wall or a fuzzing invariant. Closing this gap — adding the
`unsafe_code`/`unwrap_used`/`expect_used` denies (with `#[allow]` in tests), routing
integer reads through the `safe-read` crate, and adding a fuzz target per parsed
structure — is outstanding work to reach full compliance.
