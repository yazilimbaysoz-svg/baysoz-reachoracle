# Plan — Baysöz Labs <baysozlabs@proton.me>

**Project:** `baysoz-reachoracle` · **Status:** 1.0.0 released after unanimous Supreme Grand Jury Tribunal

## Phase 0 — Market validation (complete)

- Inspected `/home/runner/work/_temp/existing-repos.json` (21 existing Baysöz Labs repositories).
- Mined live GitHub data with `gh search repos`, `gh search issues` and `gh api`; see
  [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md).
- Selected the SBOM/CVE reachability seam: high-star ecosystem, observable false-positive pain, no
  portfolio overlap, no services, no local LLM.

## Phase 1 — Enterprise scaffold (complete)

- `docs/MARKET_RESEARCH.md`, `docs/ARCHITECTURE.md`, `PLAN.md`, `SECURITY.md`, `CHANGELOG.md`,
  `README.md`, MIT `LICENSE`, `pyproject.toml`, `.github/workflows/ci.yml`, `.gitignore`.
- Python 3.13+ package under `src/baysoz_reachoracle/` and adversarial suite under `tests/`.
- Explicit Baysöz Labs (`baysozlabs@proton.me`) attribution in every public file and CLI surface.

## Phase 2 — Core engine (complete)

- Advisory feed validation + PEP 440 matching (`advisories.py`).
- CycloneDX / SPDX / pinned-requirements ingestion (`sbom.py`).
- AST alias resolution, taint, guards, dynamic dispatch and verdict algebra (`analyzer.py`).
- Orchestration, stable IDs, baselines and text reporting (`report.py`).
- SARIF 2.1.0 with fingerprints and attribution (`sarif.py`).

## Phase 3 — CLI and corpus (complete)

- `scan` (json/sarif/text, output file, baseline, write-baseline, fail-on, sarif-all).
- `explain` (per-finding evidence narrative), `selftest` (10 adversarial cases), `--version`, `--help`.
- Every help/version surface attributes Baysöz Labs.

## Phase 4 — Quality gates (complete)

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

Acceptance: **64 tests passed**, **0 Ruff findings**, **0 Semgrep findings**. All actions in CI are
pinned to full commit SHAs after a Semgrep supply-chain finding was eliminated.

## Phase 5 — Supreme Grand Jury Tribunal (complete)

Three justices (Correctness, Security, Adversarial Realism) executed the built CLI against the fixture
application, the embedded adversarial corpus, malformed inputs, a suppression baseline round-trip and
SARIF output. Verdict: **UNANIMOUS PASS**. Evidence recorded in `docs/TRIBUNAL.md`.

## Phase 6 — Publication (complete)

- Public repository `yazilimbaysoz-svg/baysoz-reachoracle` with crisp description and security topics.
- Showcase result written to the designated `.factory-result.json` only.

## Phase 7 — Forward backlog (not in 1.0.0)

- uv.lock / Poetry lock ingestion; CWE-to-SARIF taxonomy enrichment; diff-aware scans;
  `--confidence` reporting; additional registry advisory adapters; optional CycloneDX VEX export.

Baysöz Labs <baysozlabs@proton.me>
