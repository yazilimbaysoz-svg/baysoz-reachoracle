"""SBOM ingestion tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from pathlib import Path

import pytest

from baysoz_reachoracle.models import normalize_name
from baysoz_reachoracle.sbom import SbomError, load_components
from conftest import FIXTURES


def test_all_supported_sbom_formats_agree() -> None:
    expected = tuple(
        sorted(
            [
                ("pyyaml", "6.0", "PyPI"),
                ("requests", "2.31.0", "PyPI"),
                ("urllib3", "2.2.3", "PyPI"),
            ]
        )
    )
    for filename in ("bom.json", "spdx.json", "requirements.txt"):
        components = load_components(FIXTURES / filename)
        actual = tuple(sorted((item.key, item.version, item.ecosystem) for item in components))
        assert actual == expected


def test_cyclonedx_purl_sets_ecosystem() -> None:
    components = load_components(FIXTURES / "bom.json")
    assert all(component.purl.startswith("pkg:pypi/") for component in components)


def test_normalize_name_follows_pep_503() -> None:
    assert normalize_name("PyYAML") == "pyyaml"
    assert normalize_name("zope.interface") == "zope-interface"
    assert normalize_name("a__b--c") == "a-b-c"


def test_missing_sbom_raises(tmp_path: Path) -> None:
    with pytest.raises(SbomError, match="cannot read SBOM"):
        load_components(tmp_path / "absent.json")


def test_invalid_json_sbom_raises(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text('{"components": [', encoding="utf-8")
    with pytest.raises(SbomError, match="invalid JSON"):
        load_components(path)


def test_unknown_json_sbom_raises(tmp_path: Path) -> None:
    path = tmp_path / "unknown.json"
    path.write_text('{"attribution": "Baysöz Labs <baysozlabs@proton.me>"}', encoding="utf-8")
    with pytest.raises(SbomError, match="unrecognized"):
        load_components(path)


def test_unpinned_requirements_raises(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("# Baysöz Labs <baysozlabs@proton.me>\nPyYAML>=6.0\n", encoding="utf-8")
    with pytest.raises(SbomError, match="pin exactly one version"):
        load_components(path)


def test_malformed_requirements_line_raises(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("Baysöz Labs <baysozlabs@proton.me>\n", encoding="utf-8")
    with pytest.raises(SbomError, match="invalid"):
        load_components(path)


def test_empty_cyclonedx_components_raises(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_text(
        '{"attribution": "Baysöz Labs <baysozlabs@proton.me>", '
        '"bomFormat": "CycloneDX", "components": []}',
        encoding="utf-8",
    )
    with pytest.raises(SbomError, match="no components"):
        load_components(path)
