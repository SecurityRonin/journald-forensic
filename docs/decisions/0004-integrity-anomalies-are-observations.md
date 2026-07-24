# 4. Integrity anomalies are observations, never verdicts

Date: 2026-07-24

Status: Accepted

## Context

The journal format is append-only and monotonic by construction: sequence numbers
increase, realtime timestamps do not go backwards, and the file ends where the
header says the last object ends. A break in any of these invariants is forensically
interesting — but it is *evidence consistent with* tampering, not proof of it. A
sequence gap can mean deletion or a benign rotation boundary; a timestamp regression
can mean a splice or an NTP clock correction. The fleet forensic epistemology
(`~/src/ronin-issen/CLAUDE.md`, "Findings are observations, never legal
conclusions"; `docs/glossary.md`) requires naming the *observable*, not the
conclusion, and leaving the conclusion to the examiner/tribunal.

## Decision

`journald-integrity` reports each anomaly as a neutral `IntegrityIndicator { kind,
description, seqnum_start, seqnum_end }` describing what was observed, with an
`IntegrityKind` enumerating the four detectable invariant breaks
(`crates/journald-integrity/src/lib.rs`):

- `SequenceGap` — a break `[A, B]` with `B > A + 1`, i.e. `B − A − 1` entries absent
  between two surviving records.
- `TimestampRegression` — a realtime timestamp that decreases where the format
  guarantees monotonic non-decrease.
- `Truncation` — the file ends before `tail_object_offset` + the last object's size.
- `InvalidState` — the header `state` is `ONLINE` (unclean shutdown or active write).

The README states the discipline explicitly: "Each is an **observation** — the
examiner draws the conclusion." The detectors surface the raw span (start/end
seqnums, the byte shortfall) rather than a severity label or a "tampered" verdict.

## Consequences

Output states facts about the evidence and stops there; it never asserts that a gap
*was* a deletion or that a regression *was* a splice. Each anomaly is emitted as the
crate's own `IntegrityIndicator` struct (`kind`, `description`, `seqnum_start`,
`seqnum_end`); `journald-integrity` does not yet depend on `forensicnomicon`, so
normalizing these indicators onto the shared `forensicnomicon::report` vocabulary
("consistent with", never a verdict) so they aggregate with the rest of the fleet is
outstanding work, not a property already met. The examiner must still interpret each
indicator against context (rotation policy, clock discipline) — which is the
intended division of labor, not a gap in the tool.
