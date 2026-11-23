# Supreme Grand Jury Tribunal — Baysöz Labs <baysozlabs@proton.me>

**Project:** `baysoz-reachoracle` 1.0.0 · **Session:** 2026-11-23 · **Convener:** AppSec Red Team Division, Baysöz Labs (`baysozlabs@proton.me`)

## Justices

| Justice | Mandate |
| --- | --- |
| Justice Correctness | Tests, deterministic verdicts, evidence integrity, no stubs/hallucinations |
| Justice Security | Static/security gates, input validation, SARIF fingerprints, baseline discipline |
| Justice Adversarial Realism | Live execution against newly authored hostile sources not present in the repository |

## Evidence heard

### 1. Quality gates ( Justice Correctness + Justice Security )

```text
$ uv venv && uv pip install -e . && uv pip install pytest
$ uv run pytest -q
................................................................         [100%]  (64 tests)

$ ruff check --select E,F,W,S,B .
All checks passed!

$ semgrep --config p/default --error .
✅ Scan completed successfully.
 • Findings: 0 (0 blocking)
 • Rules run: 325
```

A source audit for `TODO`, `FIXME`, `NotImplemented`, `placeholder`, `stub` and bare `pass` in
`src/` and `tests/` returned no matches. An attribution audit of all 34 public files found zero files
missing `Baysöz Labs` / `baysozlabs@proton.me`. No stubs, no fabricated output, no unattributed file.

### 2. Embedded corpus ( Justice Correctness )

```text
$ uv run python -m baysoz_reachoracle selftest
PASS direct-tainted-call: expected=REACHED actual=REACHED tainted=True
PASS alias-chain: expected=REACHED actual=REACHED tainted=False
PASS nested-module-alias: expected=REACHED actual=REACHED tainted=False
PASS getattr-dynamic-dispatch: expected=UNRESOLVED actual=UNRESOLVED tainted=False
PASS type-checking-guard: expected=GUARDED actual=GUARDED tainted=False
PASS explicit-false-guard: expected=GUARDED actual=GUARDED tainted=False
PASS import-and-safe-loader-only: expected=NOT_REACHED actual=NOT_REACHED tainted=False
PASS star-import: expected=UNRESOLVED actual=UNRESOLVED tainted=False
PASS dynamic-subscript: expected=UNRESOLVED actual=UNRESOLVED tainted=False
PASS evaluator-smuggling: expected=UNRESOLVED actual=UNRESOLVED tainted=False

10/10 cases passed
Baysöz Labs <baysozlabs@proton.me>
```

### 3. Fresh hostile source, mixed controls ( Justice Adversarial Realism )

Inputs were authored outside the repository in `/tmp/opencode/tribunal-baysoz/`: a pinned lockfile
(`PyYAML==5.4.1`, `urllib3==1.26.0`), an advisory feed with `GHSA-TRIB-2026-0001/-0002`, and an
application combining `os.environ`/`request.form` taint, a module alias, an assignment alias,
`getattr` dispatch, `TYPE_CHECKING`, `if False`, and a safe loader.

```text
$ uv run python -m baysoz_reachoracle scan --sbom .../lock.txt \
    --advisories .../advisories.json --source .../src_mixed --format text
[REACHED] RO-c0cd9a71b1d18d6b GHSA-TRIB-2026-0001 PyYAML==5.4.1 yaml.load TAINTED
    Vulnerable symbol yaml.load is used at app.py:15 with attacker-controlled data
    - app.py:15:11 call: yaml.load | return y.load(data) | attacker-controlled
    - app.py:19:13 attribute: yaml.load | loader = y.load
    - app.py:20:11 call: yaml.load | return loader("!!python/object/apply:os.system")
    - app.py:24:11 dynamic-call: yaml.load | return getattr(y, "load")("payload")
    - app.py:29:8 call: yaml.load | y.load("type-only")
[GUARDED] RO-aad227f618f9296f GHSA-TRIB-2026-0002 urllib3==1.26.0 urllib3.request
    Every use of urllib3.request is behind a statically inactive guard
    - app.py:31:8 call: urllib3.request | urllib3.request("GET", "http://example.invalid")

summary: GUARDED=1 NOT_AFFECTED=0 NOT_REACHED=0 REACHED=1 UNRESOLVED=0
exit=1
```

The tribunal initially observed that taint was missed when the source used
`os.environ.get(...) or request.form[...]` (a `BoolOp`). This was a **real defect**, not a test
artifact: `ast.BoolOp` and `ast.IfExp` were added to the taint model, covered by a new regression test,
and the live re-run produced the `TAINTED` verdict shown above.

A second observation — duplicated dynamic evidence for one `getattr` site — was likewise fixed by
suppressing untargeted dynamic events at locations already carrying a targeted event.

### 4. Dynamic-only source and strict gating ( Justice Adversarial Realism )

```text
$ uv run python -m baysoz_reachoracle scan ... --source .../src_dynamic --format text --fail-on unresolved
[UNRESOLVED] RO-d9d8c8c210ad7ba8 GHSA-TRIB-2026-0001 PyYAML==5.4.1 yaml.load
    Dynamic dispatch at app.py:7 prevents proving yaml.load unreachable
    - app.py:7:11 dynamic-call: yaml.load | return getattr(y, "load")("payload")
[NOT_REACHED] RO-df016f7881be105c GHSA-TRIB-2026-0002 urllib3==1.26.0 urllib3.request
    No source reference to urllib3.request; the vulnerable component is installed only

summary: GUARDED=0 NOT_AFFECTED=0 NOT_REACHED=1 REACHED=0 UNRESOLVED=1
exit=1
```

Dynamic dispatch was not silently declared safe, and the strict gate fired as required.

### 5. SARIF, fingerprints and baseline ratchet ( Justice Security )

```text
$ uv run python -m baysoz_reachoracle scan ... --format sarif --output reach.sarif \
    --write-baseline baseline.json
sarif_exit=1
SARIF version: 2.1.0, results: 2, levels: ['error', 'warning']
fingerprints: ['RO-c0cd9a71b1d18d6b', 'RO-aad227f618f9296f']
baseline: Baysöz Labs <baysozlabs@proton.me>

$ uv run python -m baysoz_reachoracle scan ... --baseline baseline.json --format text
No affected component/source pairings found.
summary: GUARDED=0 NOT_AFFECTED=0 NOT_REACHED=0 REACHED=0 UNRESOLVED=0
suppressed: RO-aad227f618f9296f, RO-c0cd9a71b1d18d6b
baseline_rescan_exit=0
```

### 6. Malformed input ( Justice Security )

```text
$ uv run python -m baysoz_reachoracle scan --advisories bad-advisories.json ...
baysoz-reachoracle: error: advisories[0].id must be an uppercase advisory identifier
Baysöz Labs <baysozlabs@proton.me>
exit=2
```

## Findings and Disposition

Two genuine analyzer defects were found (BoolOp taint, duplicate dynamic evidence). Both were fixed,
regression-tested, and the complete quality-gate and tribunal sequence was re-run afterwards. No
stubs, fabricated features, hallucinated outputs or unattributed files remain.

## Verdicts

| Justice | Verdict |
| --- | --- |
| Justice Correctness | **PASS** — 64 tests, 10/10 corpus, deterministic evidence |
| Justice Security | **PASS** — zero Ruff/Semgrep findings, validated inputs, SARIF fingerprints, baseline ratchet |
| Justice Adversarial Realism | **PASS** — fresh hostile sources correctly classified; defects found and remediated |

**Tribunal result: UNANIMOUS PASS — release authorized.**

Baysöz Labs <baysozlabs@proton.me>
