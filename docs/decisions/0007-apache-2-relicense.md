# 7. Relicense MIT → Apache-2.0

Date: 2026-07-24

Status: Accepted

## Context

The repo was first published under MIT (added alongside the README in commit
`f8d23b9`, "add README + MIT LICENSE + privacy/terms; relicense workspace MIT"). The
fleet subsequently standardized on Apache-2.0 for its explicit patent grant, and the
fleet README standard (`~/src/ronin-issen/CLAUDE.md`; `~/.claude/CLAUDE.personal.md`)
requires every repo to carry Apache-2.0 with the badge linking to `LICENSE` as the
single source of truth and no `## License` prose section.

## Decision

Relicense the whole workspace to Apache-2.0. Commit `315f929` ("relicense MIT →
Apache-2.0 (fleet standard)") switched `[workspace.package] license = "Apache-2.0"`
(`Cargo.toml`), and commit `41b354e` replaced the `LICENSE` file with the verbatim
Apache-2.0 text. The README carries the Apache-2.0 badge and no License heading.

## Consequences

Contributors and downstream users receive the Apache-2.0 patent grant, matching the
rest of the fleet so crates compose without license friction (the `deny.toml`
allowlist admits Apache-2.0). MIT compatibility is not lost for prior tags, but all
current and future releases are Apache-2.0. This is a one-time migration recorded
here so the license history is discoverable without spelunking git.
