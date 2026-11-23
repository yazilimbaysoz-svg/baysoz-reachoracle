<!-- Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle -->
# baysoz-reachoracle

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-reachoracle/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-reachoracle/actions/workflows/ci.yml)
![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-purple.svg)
![Offline](https://img.shields.io/badge/runtime-offline-orange.svg)

**Offline white-box vulnerability reachability oracle for Python.** By **Baysöz Labs** (`baysozlabs@proton.me`).

Trivy, osv-scanner, Syft and Dependabot tell you *which packages* are vulnerable. `baysoz-reachoracle`
answers the red-team question that actually decides exploitability: **is the vulnerable symbol reachable
from this source tree, is it guarded, is it behind dynamic dispatch, and is attacker-controlled data flowing
into it?** It compiles an SBOM, a symbol-aware advisory feed and Python AST evidence into deterministic
verdicts, stable finding identifiers and SARIF 2.1.0 for CI enforcement. No network, no services, no LLM.

- **Attribution:** Baysöz Labs <baysozlabs@proton.me>
- **License:** MIT
- **Requires:** Python 3.13+, `packaging`

## Install

```bash
uv venv
uv pip install -e .
# or, once published:
uv tool install baysoz-reachoracle
```

## Verify

```bash
uv pip install pytest ruff semgrep
uv run pytest -q
uv run ruff check --select E,F,W,S,B .
uv run semgrep --config p/default --error .
uv run python -m baysoz_reachoracle selftest
```

## Inputs

| Input | Accepted formats |
| --- | --- |
| `--sbom` | CycloneDX 1.x JSON, SPDX 2.x JSON, or a `==`-pinned requirements/lock file |
| `--advisories` | Offline OSV-style JSON with `modules`, `vulnerable_versions` (PEP 440) and dotted `symbols` |
| `--source` | A Python file or a source directory (`.venv`, `build`, `dist`, caches are skipped) |

An advisory entry declares the exact vulnerable API surface, for example:

```json
{
  "id": "PYSEC-RO-2026-0001",
  "package": "PyYAML",
  "modules": ["yaml"],
  "vulnerable_versions": ["<6.0.1"],
  "fixed_version": "6.0.1",
  "symbols": ["yaml.load"],
  "severity": "HIGH",
  "title": "Unsafe deserialization via yaml.load",
  "cwe": ["CWE-502"]
}
```

## Verdict algebra

| Verdict | Meaning | CI level |
| --- | --- | --- |
| `REACHED` | Vulnerable symbol is called/referenced on an unguarded path | error |
| `UNRESOLVED` | Dynamic dispatch, star import or evaluator smuggling prevents an offline proof | warning |
| `GUARDED` | Every use sits behind a statically inactive guard (`if False`, `TYPE_CHECKING`, `__debug__`) | warning |
| `NOT_REACHED` | Package installed, vulnerable symbol never referenced | note (JSON only by default) |
| `NOT_AFFECTED` | Installed version outside the advisory range | omitted from findings |

A `REACHED` finding is marked `TAINTED` when attacker-controlled sources (`request.*`, `input()`,
`os.environ`, `sys.argv`) flow into the call. Stable IDs are SHA-256-derived from advisory, component,
symbol and source locations, so baselines and SARIF fingerprints survive re-runs.

## Architecture

```text
SBOM / lockfile ──► component + PEP 440 version ──┐
advisory feed ────► package, ranges, symbols ─────┼──► per-component matching
Python sources ───► AST aliases, taint, guards ───┘          │
                                                             ▼
                                     REACHED / UNRESOLVED / GUARDED / NOT_REACHED
                                                             │
                                          JSON · SARIF 2.1.0 · text · CI exit code
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full data flow, verdict precedence, deterministic
design and limitations, and [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md) for the GitHub ecosystem
analysis behind the project.

## Real CLI output

```console
$ python -m baysoz_reachoracle --version
baysoz-reachoracle 1.0.0 — Baysöz Labs <baysozlabs@proton.me>

$ python -m baysoz_reachoracle --help
usage: baysoz-reachoracle [-h] [--version] COMMAND ...

Offline white-box vulnerability reachability oracle for Python. Compiles SBOM components, symbol-aware advisories and AST evidence into deterministic verdicts and SARIF. By Baysöz Labs <baysozlabs@proton.me>.

positional arguments:
  COMMAND
    scan      scan a source tree for reachable vulnerable symbols
    explain   explain one finding from a saved JSON report
    selftest  run the built-in adversarial corpus

options:
  -h, --help  show this help message and exit
  --version   show version and Baysöz Labs attribution

Baysöz Labs <baysozlabs@proton.me>

$ python -m baysoz_reachoracle scan --sbom tests/fixtures/bom.json \
    --advisories tests/fixtures/advisories.json \
    --source tests/fixtures/source --format text
baysoz-reachoracle 1.0.0 — Baysöz Labs <baysozlabs@proton.me>

sources: tests/fixtures/source
sbom:    tests/fixtures/bom.json
advisories: tests/fixtures/advisories.json

[REACHED] RO-f5ada91409a31891 GHSA-RO-2026-0002 urllib3==2.2.3 urllib3.util.ssl_.create_urllib3_context
    Vulnerable symbol urllib3.util.ssl_.create_urllib3_context is used at sample_app.py:24
    - sample_app.py:24:11 call: urllib3.util.ssl_.create_urllib3_context | return build_context()
[REACHED] RO-0b881a8d887e3407 PYSEC-RO-2026-0001 PyYAML==6.0 yaml.load TAINTED
    Vulnerable symbol yaml.load is used at sample_app.py:19 with attacker-controlled data
    - sample_app.py:19:11 call: yaml.load | return yaml.load(payload, Loader=yaml.Loader) | attacker-controlled
[NOT_REACHED] RO-652c7e3bfa911240 GHSA-RO-2026-0003 requests==2.31.0 requests.get
    No source reference to requests.get; the vulnerable component is installed only

summary: GUARDED=0 NOT_AFFECTED=0 NOT_REACHED=1 REACHED=2 UNRESOLVED=0
echo $?  # 1 — CI gate fires on REACHED
```

`--format json` (default) emits the complete report including non-actionable verdicts;
`--format sarif` emits actionable findings only unless `--sarif-all` is supplied.

## CI gating

```yaml
- run: uv run python -m baysoz_reachoracle scan --sbom bom.json --advisories advisories.json --source . --format sarif --output reach.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reach.sarif
```

Exit codes: `0` clean (or below `--fail-on` threshold), `1` actionable findings, `2` invalid input.
`--fail-on` accepts `reached` (default), `unresolved`, `guarded`, `any`, `none`. Use `--write-baseline`
and `--baseline` to ratify existing findings and prevent regressions.

## Compliance and authorship

Every source file, document, manifest, license and CLI help/version surface attributes
**Baysöz Labs <baysozlabs@proton.me>**. Security reports: see [SECURITY.md](SECURITY.md).
No legal entity suffix is used anywhere in this project.
