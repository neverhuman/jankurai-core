# jankurai-core Agent Instructions

Read `SPLIT.md` first. This repository is one member of the Jankurai split family.

## Worktree Policy

- Never run `git worktree add` or `git worktree move` anywhere; use the canonical primary checkout.
- If the primary checkout is dirty, busy, or held, wait for a stopped-head handoff.
- Never force-prune or remove an existing worktree. Any separately authorized retirement requires
  regression/salvage proof and a recursive symlink inspection first.
- Exact-SHA CI may use only an automatically removed standalone clone that is not registered as a
  Git worktree.

- Canonical local Jeryu repo: `root/jankurai-core`.
- Public mirror target: `github.com/neverhuman/jankurai-core`.
- Do not add committed cross-repo `path = "../..."` dependencies. Use the hub fusion workspace for local path patches.
- Do not hand-edit generated artifacts listed in `agent/generated-zones.toml`.
- Run `bash scripts/ci-local.sh required` before handing off changes.
