# 5. Low MSRV floor (1.75) decoupled from the pinned dev toolchain (1.96)

Date: 2026-07-24

Status: Accepted

## Context

The workspace publishes four library crates (`journald-core`, `journald-binary`,
`journald-carver`, `journald-integrity`) that external Rust tools may link, plus one
binary crate (`journald-cli`). The fleet MSRV policy (`~/.claude/CLAUDE.core.md`,
"Rust MSRV & Toolchain Policy"; `~/.claude/CLAUDE.personal.md`, fleet specifics)
separates the *dev toolchain* — pinned to the current stable so contributors and CI
never drift — from the *declared MSRV*, a downstream-facing compatibility promise
that published libraries keep deliberately low.

## Decision

Pin the dev toolchain to the fleet's current stable in `rust-toolchain.toml`
(`channel = "1.96.0"`, components `clippy`/`rustfmt`; set in commit `c422a3a`), and
declare a separate low MSRV floor `rust-version = "1.75"` in
`[workspace.package]` (`Cargo.toml`), inherited by every member via
`rust-version.workspace = true`. The two numbers are intentionally different: 1.96 is
what the code is built and linted with; 1.75 is the oldest toolchain the published
libraries promise to compile on.

## Consequences

The reader/analyzer libraries stay broadly consumable by older toolchains — a
deliberate compatibility feature and trust signal for a published crate — while
development happens on current stable. Raising the 1.75 floor is a near-breaking
change requiring a real newer-Rust need, not a reflexive bump to match the toolchain.
The `journald-cli` binary inherits the same 1.75 floor from the workspace rather than
declaring the toolchain version; this keeps one MSRV across all members at the cost of
a lower declared MSRV on the binary than strictly required (harmless, since nothing
pins a library dependency against the CLI).
