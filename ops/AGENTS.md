# Jankurai Core Operations

This directory owns local, offline-reproducible proof lanes for the split core.

- Keep each CI entrypoint in `ops/ci/` and expose it through `scripts/ci-local.sh`.
- Required and security lanes must run from the canonical checkout without fetching source.
- Security scans fail closed for required tools and write evidence only under `target/`.
- Never publish, mirror, tag, or mutate forge state from a proof lane.

Proof: `bash scripts/ci-local.sh required` and `bash scripts/ci-local.sh security`.
