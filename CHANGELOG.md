# Changelog

All notable changes to jankurai-core are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The authoritative version string lives in [`VERSION`](VERSION).

## [Unreleased]

### Added

- Root `Justfile` command surface with `setup`, `fast`, `check`, `security`, and
  `audit` lanes for one-command setup and validation.
- GitHub Actions CI (`.github/workflows/ci.yml`) with build, security, and
  jankurai audit jobs, all third-party actions pinned to commit SHAs.
- Agent-readable documentation: `README.md`, `docs/boundaries.md`,
  `docs/release.md`, and `docs/exceptions.md`.

### Changed

- Re-scoped `agent/boundaries.toml`, `agent/owner-map.json`,
  `agent/test-map.json`, `agent/generated-zones.toml`, and
  `agent/proof-lanes.toml` to the paths that exist in this single-purpose repo.

## [1.6.10] - 2026-06-12

### Added

- Initial split-family extraction of the jankurai auditor Rust crate.
