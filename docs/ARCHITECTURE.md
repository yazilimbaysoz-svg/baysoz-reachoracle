# Architecture — Baysöz Labs <baysozlabs@proton.me>

**Project:** `baysoz-reachoracle` · **Version:** 1.0.0 · **Owner:** Baysöz Labs (`baysozlabs@proton.me`)

## 1. Purpose and boundaries

The system answers one question deterministically and offline:

> Given installed Python components and an offline advisory feed, is the vulnerable API actually
> reachable from a source tree, is it guarded, is it hidden behind dynamic dispatch, and does
> attacker-controlled data reach the call?

It does **not** fetch advisories, execute code, send network traffic, use an LLM, or claim that a
`NOT_REACHED` verdict is a formal proof of safety. It produces evidence-backed verdicts with explicit
uncertainty, designed for CI enforcement and red-team triage.

## 2. Module map

| Module | Responsibility |
| --- | --- |
| `src/baysoz_reachoracle/models.py` | Immutable domain types (`Advisory`, `Component`, `Evidence`, `Finding`, `Report`, `Verdict`) and PEP 503 name normalization |
| `src/baysoz_reachoracle/advisories.py` | Feed schema validation, PEP 440 range matching with `packaging` |
| `src/baysoz_reachoracle/sbom.py` | CycloneDX JSON, SPDX JSON and pinned-requirements ingestion |
| `src/baysoz_reachoracle/analyzer.py` | AST alias resolution, taint origins, inactive-guard detection, dynamic dispatch events, verdict algebra |
| `src/baysoz_reachoracle/report.py` | Orchestration, stable `RO-` identifiers, baselines, summary, text renderer, CI exit code |
| `src/baysoz_reachoracle/sarif.py` | SARIF 2.1.0 log/rule/result construction with fingerprints |
| `src/baysoz_reachoracle/corpus.py` | Embedded adversarial corpus (`selftest`) |
| `src/baysoz_reachoracle/cli.py` | `scan`, `explain`, `selftest`, `--version`, `--help`, attribution on every surface |

## 3. Data flow

```text
CycloneDX / SPDX / requirements ─► load_components ─► Component(name, version, ecosystem)
Offline advisory JSON ──────────► parse_advisories ─► Advisory(package, ranges, modules, symbols)
Python source tree ─────────────► collect_sources ──► (relative_path, text) pairs
                                                          │
                                                          ▼
                                              ast.parse + two-pass visitor
                                                          │
                       ┌──────────────────────────────────┴───────────────────────────────┐
                       │ ReferenceEvent(symbol, kind, guarded, tainted, location)          │
                       │ DynamicEvent(target, kind, guarded, location)                     │
                       └──────────────────────────────────┬───────────────────────────────┘
                                                          ▼
                          is_affected(component, advisory) ? ── no ─► omitted
                                                          │ yes
                                                          ▼
                                      resolve_advisory → SymbolVerdict + Evidence
                                                          │
                       ┌──────────────────────────────────┴───────────────────────────────┐
                       │ Report (JSON)      SARIF 2.1.0 (actionable only)   text summary   │
                       │ stable RO-id       baseline fingerprints           CI exit code   │
                       └──────────────────────────────────────────────────────────────────┘
```

## 4. Analyzer design

### 4.1 Two-pass visitors

1. **Alias collector** walks the whole module once and maps every local binding to an absolute dotted
   path: `import yaml as y` → `y → yaml`; `from yaml import load as unsafe` → `unsafe → yaml.load`.
   Collecting globally first handles functions defined before their imports.
2. **Event collector** walks again with those aliases and collects:
   - `call`/`attribute`/`name` references to resolved dotted symbols;
   - taint-propagating assignments (`payload = request.args.get(...)`);
   - dynamic events (`getattr`, `eval`, `exec`, `__import__`, `importlib.import_module`, star imports,
     dynamic subscripts).

Events are frozen dataclasses stored in sets, then sorted. Duplicate visits therefore cannot change
output — a core determinism invariant.

### 4.2 Taint model

A local name is tainted if assigned from `request.*` (including `flask.request.*`), `input()`,
`os.environ`, `os.getenv`, or `sys.argv`. Taint propagates through simple assignments and aliases;
it is consumed when a call receives a tainted positional or keyword argument. A tainted `REACHED`
finding is flagged `TAINTED` in JSON, text and SARIF properties.

### 4.3 Guards

`if False:`, `if 0:`, `if TYPE_CHECKING:` (including `typing.TYPE_CHECKING`) and `if __debug__:` mark the
body as statically inactive. Only inactive branches increment guard depth; `else` branches and normal
`try/except` remain unguarded. A verdict is `GUARDED` only when *every* matching reference is inactive
and no unguarded dynamic event exists.

### 4.4 Dynamic dispatch is never silently safe

A literal `getattr(yaml, "load")`, `eval("yaml.load")` or `importlib.import_module("yaml")` produces a
targeted dynamic event matched to advisory symbols/modules. A non-literal dispatch combined with any use
of the advisory's module produces an untargeted dynamic event. Any unguarded dynamic event outranks
`GUARDED` and `NOT_REACHED` evidence, producing `UNRESOLVED`.

### 4.5 Verdict precedence

| Priority | Condition | Verdict |
| ---: | --- | --- |
| 1 | Any unguarded matching reference | `REACHED` |
| 2 | Any unguarded matching dynamic event | `UNRESOLVED` |
| 3 | Matching references exist, all guarded | `GUARDED` |
| 4 | Matching dynamic events exist | `UNRESOLVED` |
| 5 | No matching evidence | `NOT_REACHED` |
| pre-filter | Installed version outside advisory range | not reported (`NOT_AFFECTED`) |

## 5. Stable identifiers and baselines

`RO-<16 hex>` = SHA-256 over advisory id, normalized package, installed version, resolved symbol and the
sorted `(path, line, column, kind)` tuple of source evidence. Version evidence is intentionally excluded
so a version bump alone does not invalidate an accepted finding; adding, moving or changing a call site
does. `--write-baseline` emits actionable IDs with Baysöz Labs attribution; `--baseline` suppresses only
IDs that still match current findings and reports them in `suppressed`.

## 6. SARIF contract

- `runs[0].tool.driver.properties.attribution` and every result property carry Baysöz Labs attribution.
- `ruleId` is the advisory id; `partialFingerprints.baysozReachOracleId` is the stable `RO-` id.
- `level`: `error` for `REACHED` (and tainted), `warning` for `UNRESOLVED`/`GUARDED`.
- Every non-version evidence item becomes a physical location with `startLine`, `startColumn` and snippet.
- Default output contains actionable findings only; `--sarif-all` includes `NOT_REACHED` as `note`.
- No timestamps, hostnames, absolute build identifiers or random IDs are emitted.

## 7. Complexity and performance

- Parsing is linear in source size; visitors are single-pass per AST.
- Matching is `O(components × advisories × references)`, with sets of immutable events and early
  version filtering. Typical repository scans complete in milliseconds for the built-in corpus.
- Memory is bounded by the number of unique evidence events, which are deduplicated by value.

## 8. Explicit limitations

- No cross-module interprocedural data-flow or type inference; aliases crossing module boundaries are
  treated as unresolved only when dynamic syntax is present.
- `getattr` with a runtime-computed name and no module usage is not attributed to any advisory; the tool
  avoids speculative findings rather than inventing evidence.
- Decorators, metaclasses, C extensions and runtime code generation are outside the static model.
- An advisory that omits `symbols` is rejected; the feed must describe the vulnerable API surface.
- These limitations bias toward `UNRESOLVED` (honest uncertainty), never toward a false "safe" verdict.

## 9. Extension points

Additional ingestors (Poetry/uv lockfiles, Conda), additional dynamic sinks, and additional report
formats can be added without changing the verdict algebra: each contributes immutable evidence to
`resolve_advisory`, and serialization is isolated in `report.py` / `sarif.py`.

Baysöz Labs <baysozlabs@proton.me>
