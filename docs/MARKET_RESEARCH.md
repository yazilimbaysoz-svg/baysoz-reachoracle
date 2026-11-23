# Market Research — Baysöz Labs <baysozlabs@proton.me>

**Project:** `baysoz-reachoracle` · **Research date:** 2026-11-23 · **Analyst:** AppSec Red Team Division, Baysöz Labs (`baysozlabs@proton.me`)

## 1. Method

Live GitHub discovery was executed with an authenticated `gh` CLI session (account `yazilimbaysoz-svg`):

```bash
gh search repos --topic appsec --sort stars --order desc --limit 20 \
  --json fullName,stargazersCount,description,updatedAt
gh search repos --topic sarif --sort stars --order desc --limit 20 \
  --json fullName,stargazersCount,description,updatedAt
gh search repos "MCP security scanner" --sort stars --order desc --limit 20 \
  --json fullName,stargazersCount,description,updatedAt
gh search repos --topic graphql-security --sort stars --order desc --limit 15 \
  --json fullName,stargazersCount,description,updatedAt
gh search issues "MCP tool poisoning" --limit 20 --json title,repository,state,url
gh search issues repo:google/osv-scanner "false positive" --limit 10 --json title,state,url
gh api repos/<owner>/<repo> --jq '.stargazers_count'
```

The 21 repositories already published by Baysöz Labs were inventoried from
`/home/runner/work/_temp/existing-repos.json` and treated as a hard exclusion set.

## 2. Measured high-star ecosystem (live `gh api` counts, 2026-11-23)

| Repository | Stars | What it solves | Unchanged gap |
| --- | ---: | --- | --- |
| `aquasecurity/trivy` | 39,624 | Container/repo CVE, SBOM and secret scanning | Reports installed vulnerable packages, not symbol-level reachability in application source |
| `google/osv-scanner` | 11,599 | Lockfile/SBOM → OSV advisories | Version matching only; consumers must manually triage whether the vulnerable API is used |
| `anchore/syft` | 9,950 | SBOM generation | Inventory only; no exploitability evidence |
| `DependencyTrack/dependency-track` | 4,499 | Continuous component analysis platform | Heavy service; no offline source-level decision proof |
| `pypa/pip-audit` | 1,412 | Python environment audit + upgrade | No AST, no taint, no per-symbol evidence, no SARIF gate |
| `CycloneDX/cyclonedx-python-lib` | 119 | CycloneDX object model | Library primitive, not a red-team oracle |

Adjacent high-star appsec demand confirmed by `gh search repos --topic appsec`: `KeygraphHQ/shannon`
(52,191), `sqlmapproject/sqlmap` (39,013), `zaproxy/zaproxy` (16,244), `OWASP/CheatSheetSeries` (34,162).
The SARIF topic confirms that machine-readable CI evidence is a first-class delivery requirement:
`kucherenko/jscpd` (6,595, Rust engine + SARIF reporter), `Trusera/ai-bom` (367),
`sbom-tool/sbom-tools` (270, SBOM/CBOM diff + compliance), `XiantingWu/PQCensus` (263, evidence-grounded
crypto inventory with SARIF/CycloneDX output).

## 3. Live pain-point evidence from open issues

`gh search issues repo:google/osv-scanner "false positive"` surfaced real triage problems that epitomize
the ecosystem gap:

- [google/osv-scanner#3018](https://github.com/google/osv-scanner/issues/3018) — PyPI transitive
  dependency resolution produces outdated-version false positives.
- [google/osv-scanner#2898](https://github.com/google/osv-scanner/issues/2898) — CycloneDX SBOM
  namespace/qualifier handling produces false positives.
- [google/osv-scanner#2881](https://github.com/google/osv-scanner/issues/2881) — npm lockfile entry
  reported as vulnerable although the package is not actually in scope.
- [google/osv-scanner#2978](https://github.com/google/osv-scanner/issues/2978) — CycloneDX scanning
  dropped a namespace, changing the matched component identity.

The pattern is consistent: component identity/version matching is necessary but insufficient. Teams still
need to answer: **"does this repository actually execute the vulnerable API with data an attacker can
control?"** A scanner that cannot answer that forces either noisy blocking gates or manual red-team
triage — both expensive at 2026 dependency churn rates.

## 4. Rejected alternatives (and why)

| Candidate | Live signal | Rejection reason |
| --- | --- | --- |
| Another MCP tool-poisoning scanner | `gh search repos "MCP security scanner"` returns 15+ near-identical projects in the first 20 results, almost all under 30 stars; `gh search issues "MCP tool poisoning"` is dominated by cross-promotional spam and low-signal requests | Saturated and redundant; trivial differentiators would violate the no-toy rule |
| GraphQL alias-batching DoS oracle | `doyensec/inql` 1,814, `dolevf/Damn-Vulnerable-GraphQL-Application` 1,720 | Valuable, but requires an HTTP target or a full GraphQL parser; less deterministic offline value than source-level reachability |
| Generic AI-agent red-team probe runner | `gy15901580825/Argus` 218 (320 probes, SARIF), `guardana/guardana` 224, `KeygraphHQ/shannon` 52,191 | Requires model/browser/payment surfaces or an LLM; explicitly excluded by the brief |
| Env/config drift tooling | Already present in Baysöz Labs portfolio (`envpair`, `envlens`) | Direct redundancy |
| JOSE/JWT, HTTP desync, BOLA, Terraform, NetworkPolicy, Gateway API, OTel, cardinality, SLO, ATR/Sigma, GitHub Actions pinning | Already present (`baysoz-josegate`, `baysoz-desyncforge`, `bolaforge`, `planradius`, `baysoz-netpol-oracle`, `baysoz-routegate`, `baysoz-otelgate`, `baysoz-cardinalis`, `baysoz-burnlattice`, `atr-parity-gate`, `baysoz-actionlock`) | Direct portfolio redundancy |

## 5. Product thesis

`baysoz-reachoracle` occupies an empty, high-value seam between SBOM/CVE scanners and human exploit
verification. It is a **deterministic, offline, zero-service white-box oracle** that:

1. Ingests the outputs of the ecosystem's standard tools (CycloneDX/SPDX/pinned lockfiles) plus a
   symbol-aware advisory feed — no network calls at runtime.
2. Resolves import aliases, from-imports, module aliases, assignment chains, taint sources
   (`request.*`, `input()`, `os.environ`, `sys.argv`), inactive guards and dynamic dispatch
   (`getattr`, `eval`, `importlib`, star imports, dynamic subscripts) using Python's own AST.
3. Emits a five-valued verdict (`REACHED`, `UNRESOLVED`, `GUARDED`, `NOT_REACHED`, `NOT_AFFECTED`)
   with file/line/column evidence rather than a binary "vulnerable" assertion.
4. Produces SARIF 2.1.0 with stable SHA-256 fingerprints and baselines for ratcheted CI enforcement.

This is a **library-quality CLI**, not a wrapper: it implements its own advisory validation, PEP 440
matching, alias resolution, taint propagation, guard analysis, verdict algebra, report schema and
serializers. Its only dependency is `packaging`.

## 6. 2026–2027 tailwinds

- SBOM/CBOM evidence is becoming a procurement and regulatory norm; SARIF is the standard CI exchange
  format (confirmed by the SARIF topic results above).
- AI-assisted code generation increases dependency volume and therefore CVE noise; exploitability
  triage is the scarce skill, and automating the *proof* (not the judgment) is high leverage.
- Red teams need offline tooling for air-gapped or client-controlled engagements; no external API key,
  no service, no LLM is a deployment advantage, not a limitation.

## 7. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Advisory feeds must declare `symbols` | Explicit schema validation; a module root can be declared as a symbol for broad matching; unknown dynamic behaviour is `UNRESOLVED`, never silently "safe" |
| Aliasing through decorators/closures is not fully interprocedural | Conservative `UNRESOLVED` on dynamic constructs; documented limitations in `docs/ARCHITECTURE.md` |
| Suppression baselines can hide regressions | Stable IDs include source location and verdict; moving or changing a call site creates a new ID |
| SARIF noise | Actionable-only by default; `--sarif-all` opts into complete evidence |

**Conclusion:** a genuinely needed, non-redundant, high-signal appsec-redteam engineering project for
2026–2027, justified by high-star ecosystem demand and observable false-positive pain in live issues.

Baysöz Labs <baysozlabs@proton.me>
