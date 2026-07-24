# 8. `jd4n6` binary name and the `journald-cli` crate rename

Date: 2026-07-24

Status: Accepted

## Context

The CLI and its crate were first built as `jd-cli` shipping a binary named `jd`
(commits `78dc099`/`6e95bd7`). Two fleet conventions apply
(`~/src/ronin-issen/CLAUDE.md`, "Crate naming grammar"): front-end binaries follow
the `<x>4n6` convention (`br4n6`, `ev4n6`, `sqlite4n6`, `mem4n6`, `disk4n6`), and a
Pattern B suite's CLI crate is named `<prefix>-cli`, not an abbreviated form. A bare
`jd` binary also collides trivially in `$PATH` and does not self-identify as a
forensic tool.

## Decision

Rename the crate `jd-cli` → `journald-cli` and the binary `jd` → `jd4n6`, in commit
`63d7150` ("refactor(naming): jd-cli -> journald-cli, binary jd -> jd4n6"). The crate
declares `[[bin]] name = "jd4n6"` (`crates/journald-cli/Cargo.toml`) with
`#[command(name = "jd4n6", version)]` (`crates/journald-cli/src/main.rs`), so
`jd4n6 --version` prints the conventional `jd4n6 X.Y.Z`. The crate name carries the
distinctive `journald-` suite prefix; the binary carries the `<x>4n6` DFIR-tool
identity.

## Consequences

The binary is discoverable and self-identifying (`jd4n6`), consistent with every
other fleet CLI, and the crate name matches the suite prefix used by its four
sibling libraries. The rename happened before any publish, so no crates.io orphan
was created (the crates.io 72-hour rename window was not even in play). A future
`release.yml` tag pipeline for the binary must key its Homebrew/winget package on
`jd4n6`; note that binary release automation is not yet wired in this repo (only
`release-plz` for the library crates is present).
