"""Built-in adversarial corpus for live validator runs.

Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle.
"""

from __future__ import annotations

from dataclasses import dataclass

from .advisories import parse_advisories
from .analyzer import resolve_advisory, scan_source
from .models import Evidence, Verdict

_CORPUS_ADVISORY = {
    "advisories": [
        {
            "id": "PYSEC-RO-0001",
            "package": "PyYAML",
            "modules": ["yaml"],
            "vulnerable_versions": ["<6.0.1"],
            "fixed_version": "6.0.1",
            "symbols": ["yaml.load"],
            "severity": "HIGH",
            "title": "Unsafe deserialization through yaml.load",
            "cwe": ["CWE-502"],
        }
    ]
}


@dataclass(frozen=True)
class Case:
    name: str
    source: str
    expected: Verdict
    expected_tainted: bool = False


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected: str
    actual: str
    tainted: bool
    passed: bool
    detail: str


_CASES = (
    Case(
        name="direct-tainted-call",
        source=(
            "import yaml\n"
            "from flask import request\n\n"
            "def load_config():\n"
            "    payload = request.args.get('payload')\n"
            "    return yaml.load(payload)\n"
        ),
        expected=Verdict.REACHED,
        expected_tainted=True,
    ),
    Case(
        name="alias-chain",
        source=("import yaml as y\nunsafe = y.load\nresult = unsafe(open('config.yml').read())\n"),
        expected=Verdict.REACHED,
    ),
    Case(
        name="nested-module-alias",
        source=(
            "import yaml\nholder = yaml\nvalue = holder.load('!!python/object/apply:os.system')\n"
        ),
        expected=Verdict.REACHED,
    ),
    Case(
        name="getattr-dynamic-dispatch",
        source="import yaml\nvalue = getattr(yaml, 'load')('payload')\n",
        expected=Verdict.UNRESOLVED,
    ),
    Case(
        name="type-checking-guard",
        source=(
            "from typing import TYPE_CHECKING\n"
            "import yaml\n\n"
            "if TYPE_CHECKING:\n"
            "    yaml.load('never executed at runtime')\n"
        ),
        expected=Verdict.GUARDED,
    ),
    Case(
        name="explicit-false-guard",
        source="import yaml\nif False:\n    yaml.load('dead code')\n",
        expected=Verdict.GUARDED,
    ),
    Case(
        name="import-and-safe-loader-only",
        source="import yaml\nsafe = yaml.safe_load\n",
        expected=Verdict.NOT_REACHED,
    ),
    Case(
        name="star-import",
        source="from yaml import *\n",
        expected=Verdict.UNRESOLVED,
    ),
    Case(
        name="dynamic-subscript",
        source="import yaml\nname = 'load'\nyaml[name]('payload')\n",
        expected=Verdict.UNRESOLVED,
    ),
    Case(
        name="evaluator-smuggling",
        source="import yaml\ncall = eval('yaml.load')\ncall('payload')\n",
        expected=Verdict.UNRESOLVED,
    ),
)


def run_corpus() -> tuple[CaseResult, ...]:
    """Run the full adversarial corpus and return one verdict per case."""
    advisory = parse_advisories(_CORPUS_ADVISORY)[0]
    version_evidence = Evidence("<corpus>", 0, 0, "PyYAML==6.0 satisfies <6.0.1", "version-match")
    results: list[CaseResult] = []
    for index, case in enumerate(_CASES):
        source_path = f"corpus/case_{index:02d}.py"
        events = scan_source(case.source, source_path)
        resolved = resolve_advisory(advisory, events, version_evidence)
        passed = resolved.verdict is case.expected
        if case.expected_tainted:
            passed = passed and resolved.tainted
        results.append(
            CaseResult(
                name=case.name,
                expected=case.expected.value,
                actual=resolved.verdict.value,
                tainted=resolved.tainted,
                passed=passed,
                detail=resolved.message,
            )
        )
    return tuple(results)
