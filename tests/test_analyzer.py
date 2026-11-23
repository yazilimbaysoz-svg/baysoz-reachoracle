"""AST analyzer tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import pytest

from baysoz_reachoracle.advisories import parse_advisories
from baysoz_reachoracle.analyzer import SymbolVerdict, resolve_advisory, scan_source
from baysoz_reachoracle.models import Evidence, Verdict

_FEED = {
    "attribution": "Baysöz Labs <baysozlabs@proton.me>",
    "advisories": [
        {
            "id": "PYSEC-RO-2026-0001",
            "package": "PyYAML",
            "modules": ["yaml"],
            "vulnerable_versions": ["<6.0.1"],
            "symbols": ["yaml.load"],
            "severity": "HIGH",
            "title": "Unsafe deserialization",
        }
    ],
}
_VERSION = Evidence("<feed>", 0, 0, "PyYAML==6.0 satisfies <6.0.1", "version-match")


def _resolve(source: str) -> SymbolVerdict:
    advisory = parse_advisories(_FEED)[0]
    return resolve_advisory(advisory, scan_source(source, "sample.py"), _VERSION)


def test_direct_tainted_call() -> None:
    result = _resolve(
        "import yaml\nfrom flask import request\n\n"
        "def run():\n"
        "    data = request.args.get('payload')\n"
        "    return yaml.load(data)\n"
    )
    assert result.verdict is Verdict.REACHED
    assert result.tainted is True
    assert any(item.kind == "call" and item.path == "sample.py" for item in result.evidence)


def test_taint_through_boolop_and_subscript() -> None:
    result = _resolve(
        "import os\nimport yaml\nfrom flask import request\n\n"
        "def run():\n"
        "    data = os.environ.get('PAYLOAD') or request.form['x']\n"
        "    return yaml.load(data)\n"
    )
    assert result.verdict is Verdict.REACHED
    assert result.tainted is True


def test_from_import_and_assignment_alias() -> None:
    result = _resolve("from yaml import load as unsafe\nrunner = unsafe\nrunner('payload')\n")
    assert result.verdict is Verdict.REACHED
    assert result.symbol == "yaml.load"


def test_module_alias_chain() -> None:
    result = _resolve("import yaml as y\nmod = y\nmod.load('payload')\n")
    assert result.verdict is Verdict.REACHED


def test_getattr_is_unresolved() -> None:
    result = _resolve("import yaml\ngetattr(yaml, 'load')('payload')\n")
    assert result.verdict is Verdict.UNRESOLVED
    assert any(item.kind == "dynamic-call" for item in result.evidence)


def test_generic_dynamic_does_not_duplicate_targeted_evidence() -> None:
    result = _resolve("import yaml\ngetattr(yaml, 'load')('payload')\n")
    dynamic_items = [item for item in result.evidence if item.kind == "dynamic-call"]
    assert len(dynamic_items) == 1


def test_constant_guard_is_guarded() -> None:
    result = _resolve("import yaml\nif False:\n    yaml.load('dead')\n")
    assert result.verdict is Verdict.GUARDED


def test_type_checking_guard_is_guarded() -> None:
    result = _resolve(
        "from typing import TYPE_CHECKING\nimport yaml\nif TYPE_CHECKING:\n    yaml.load('dead')\n"
    )
    assert result.verdict is Verdict.GUARDED


def test_safe_loader_only_is_not_reached() -> None:
    result = _resolve("import yaml\nsafe_load = yaml.safe_load\n")
    assert result.verdict is Verdict.NOT_REACHED


def test_star_import_is_unresolved() -> None:
    result = _resolve("from yaml import *\n")
    assert result.verdict is Verdict.UNRESOLVED


def test_dynamic_subscript_is_unresolved() -> None:
    result = _resolve("import yaml\nname = 'load'\nyaml[name]('payload')\n")
    assert result.verdict is Verdict.UNRESOLVED


def test_references_are_deduplicated_and_sorted() -> None:
    events = scan_source("import yaml\nyaml.load('a')\nyaml.load('b')\n", "sample.py")
    assert len(events.references) == len(set(events.references))
    assert [event.line for event in events.references] == sorted(
        event.line for event in events.references
    )


def test_syntax_error_raises() -> None:
    with pytest.raises(ValueError, match="cannot parse sample.py:2"):
        scan_source("import yaml\nthis is not python(\n", "sample.py")


def test_unguarded_call_outranks_dynamic_dispatch() -> None:
    result = _resolve("import yaml\nyaml.load('direct')\ngetattr(yaml, 'load')('dynamic')\n")
    assert result.verdict is Verdict.REACHED
    assert any(item.kind == "dynamic-call" for item in result.evidence)
