# Changelog — Baysöz Labs <baysozlabs@proton.me>

All notable changes to `baysoz-reachoracle` are documented here. The format follows Keep a Changelog.

## [1.0.0] — 2026-11-23

### Added

- Offline SBOM ingestion for CycloneDX JSON, SPDX JSON and `==`-pinned requirements/lockfiles.
- Symbol-aware advisory feed validation with PEP 440 affected-version matching.
- Deterministic AST analyzer with import/from-import/module/assignment alias resolution, taint source
  propagation, inactive-guard detection and dynamic-dispatch evidence.
- Five-valued verdict algebra: `REACHED`, `UNRESOLVED`, `GUARDED`, `NOT_REACHED`, `NOT_AFFECTED`.
- Stable `RO-` finding identifiers, suppression baselines and configurable CI `--fail-on` thresholds.
- SARIF 2.1.0 output with rule metadata, fingerprints, source regions and Baysöz Labs attribution.
- `scan`, `explain` and `selftest` CLI commands; attribution on `--version` and every `--help`.
- Embedded 10-case adversarial corpus covering taint, aliases, guards, star imports, `getattr`,
  `eval` and dynamic subscripts.
- Enterprise documentation, MIT license, pinned-SHA GitHub Actions CI, 64 tests and zero-finding
  Ruff/Semgrep gates.
- Supreme Grand Jury Tribunal record: UNANIMOUS PASS (see `docs/TRIBUNAL.md`).

### Security

- GitHub Actions pinned to full commit SHAs after Semgrep flagged mutable tags during development.
- No network, subprocess, dynamic code execution or local LLM in the runtime path.

Baysöz Labs <baysozlabs@proton.me>
