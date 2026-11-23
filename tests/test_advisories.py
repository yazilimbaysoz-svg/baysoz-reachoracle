"""Advisory parsing and version matching tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from baysoz_reachoracle.advisories import (
    AdvisoryError,
    is_affected,
    load_advisories,
    parse_advisories,
)
from baysoz_reachoracle.models import Component

_VALID = {
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


def test_feed_fixture_parses_and_sorts(advisory_path: Path) -> None:
    advisories = load_advisories(advisory_path)
    assert [item.id for item in advisories] == [
        "GHSA-RO-2026-0002",
        "GHSA-RO-2026-0003",
        "PYSEC-RO-2026-0001",
    ]
    assert all(item.ecosystem == "PyPI" for item in advisories)


def test_valid_feed_defaults() -> None:
    advisory = parse_advisories(_VALID)[0]
    assert advisory.fixed_version == ""
    assert advisory.description == ""
    assert advisory.ecosystem == "PyPI"
    assert advisory.cwe == ()


def test_version_boundaries() -> None:
    advisory = parse_advisories(_VALID)[0]
    assert is_affected(advisory, Component("PyYAML", "6.0"))
    assert not is_affected(advisory, Component("PyYAML", "6.0.1"))
    assert not is_affected(advisory, Component("requests", "6.0"))
    assert not is_affected(advisory, Component("PyYAML", "6.0", ecosystem="npm"))


@pytest.mark.parametrize(
    ("mutator", "expected"),
    [
        (lambda data: data.pop("advisories"), "non-empty"),
        (lambda data: data["advisories"][0].update({"severity": "WEIRD"}), "severity"),
        (
            lambda data: data["advisories"][0].update({"vulnerable_versions": ["not a spec"]}),
            "vulnerable_versions",
        ),
        (lambda data: data["advisories"][0].update({"symbols": ["bad symbol!"]}), "symbols"),
        (lambda data: data["advisories"][0].update({"id": "lower"}), "uppercase"),
        (lambda data: data["advisories"][0].update({"fixed_version": "nope"}), "fixed_version"),
    ],
)
def test_invalid_feeds_raise(mutator: Callable[[dict[str, Any]], None], expected: str) -> None:
    payload = json.loads(json.dumps(_VALID))
    mutator(payload)
    with pytest.raises(AdvisoryError, match=expected):
        parse_advisories(payload)


def test_duplicate_advisory_ids_raise() -> None:
    payload = json.loads(json.dumps(_VALID))
    payload["advisories"].append(dict(payload["advisories"][0]))
    with pytest.raises(AdvisoryError, match="duplicate"):
        parse_advisories(payload)


def test_missing_feed_file_raises(tmp_path: Path) -> None:
    with pytest.raises(AdvisoryError, match="cannot read advisory feed"):
        load_advisories(tmp_path / "missing.json")


def test_invalid_component_version_raises() -> None:
    advisory = parse_advisories(_VALID)[0]
    with pytest.raises(AdvisoryError, match="invalid PEP 440"):
        is_affected(advisory, Component("PyYAML", "not-a-version"))
