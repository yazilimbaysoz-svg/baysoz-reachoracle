"""SARIF serialization tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from pathlib import Path

from baysoz_reachoracle import ATTRIBUTION
from baysoz_reachoracle.report import report_to_dict, run_scan
from baysoz_reachoracle.sarif import build_sarif


def test_sarif_shape_and_attribution(
    sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    report = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    sarif = build_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["properties"]["attribution"] == ATTRIBUTION
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["properties"]["attribution"] == ATTRIBUTION
    assert {rule["id"] for rule in driver["rules"]} == {
        finding.advisory_id for finding in report.findings
    }
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    assert all(result["properties"]["attribution"] == ATTRIBUTION for result in results)
    assert all(result["level"] == "error" for result in results)
    assert all(result["partialFingerprints"]["baysozReachOracleId"] for result in results)
    assert all(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in results
    )


def test_sarif_all_includes_non_actionable(
    sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    report = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    sarif = build_sarif(report, include_all=True)
    results = sarif["runs"][0]["results"]
    assert len(results) == len(report.findings)
    assert any(result["properties"]["verdict"] == "NOT_REACHED" for result in results)


def test_sarif_is_deterministic(sbom_path: Path, advisory_path: Path, source_path: Path) -> None:
    report = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    encoded = json.dumps(build_sarif(report))
    repeated = json.dumps(build_sarif(report))
    assert encoded == repeated
    assert json.dumps(report_to_dict(report)) == json.dumps(report_to_dict(report))
