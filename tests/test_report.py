"""End-to-end report, baseline, and gate tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from baysoz_reachoracle import ATTRIBUTION
from baysoz_reachoracle.models import Verdict
from baysoz_reachoracle.report import (
    BaselineError,
    collect_sources,
    format_text_report,
    gate_exit_code,
    load_baseline,
    report_to_dict,
    run_scan,
)
from baysoz_reachoracle.sbom import SbomError


def test_end_to_end_verdicts(sbom_path: Path, advisory_path: Path, source_path: Path) -> None:
    report = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    by_advisory = {finding.advisory_id: finding for finding in report.findings}
    assert set(by_advisory) == {
        "PYSEC-RO-2026-0001",
        "GHSA-RO-2026-0002",
        "GHSA-RO-2026-0003",
    }
    yaml_finding = by_advisory["PYSEC-RO-2026-0001"]
    assert yaml_finding.verdict is Verdict.REACHED
    assert yaml_finding.tainted is True
    assert by_advisory["GHSA-RO-2026-0002"].verdict is Verdict.REACHED
    assert by_advisory["GHSA-RO-2026-0003"].verdict is Verdict.NOT_REACHED
    assert report.summary["REACHED"] == 2
    assert report.summary["NOT_REACHED"] == 1
    assert report.attribution == ATTRIBUTION


def test_scan_is_deterministic(sbom_path: Path, advisory_path: Path, source_path: Path) -> None:
    first = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    second = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    assert json.dumps(report_to_dict(first)) == json.dumps(report_to_dict(second))


def test_finding_identifiers_are_stable(
    sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    report = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    assert len({finding.id for finding in report.findings}) == len(report.findings)
    assert all(
        finding.id.startswith("RO-") and len(finding.id) == 19 for finding in report.findings
    )


def test_baseline_suppresses_actionable_findings(
    tmp_path: Path, sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    baseline = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    identifiers = sorted(finding.id for finding in baseline.findings)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"attribution": ATTRIBUTION, "suppressed": identifiers}),
        encoding="utf-8",
    )
    assert load_baseline(baseline_path) == tuple(identifiers)
    report = run_scan(
        sbom_path=sbom_path,
        advisory_path=advisory_path,
        source_root=source_path,
        suppressed_ids=tuple(identifiers),
    )
    assert report.findings == ()
    assert report.suppressed == tuple(identifiers)
    assert gate_exit_code(report, "reached") == 0


def test_baseline_requires_ro_identifiers(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text('{"suppressed": ["not-an-id"]}', encoding="utf-8")
    with pytest.raises(BaselineError, match="RO-"):
        load_baseline(path)


def test_baseline_requires_array(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text('{"suppressed": "RO-123"}', encoding="utf-8")
    with pytest.raises(BaselineError, match="array"):
        load_baseline(path)


def test_gate_thresholds(sbom_path: Path, advisory_path: Path, source_path: Path) -> None:
    report = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    assert gate_exit_code(report, "reached") == 1
    assert gate_exit_code(report, "any") == 1
    assert gate_exit_code(report, "none") == 0


def test_collect_sources_excludes_virtualenvs(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("# Baysöz Labs <baysozlabs@proton.me>\n", encoding="utf-8")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "ignored.py").write_text("import yaml\n", encoding="utf-8")
    sources = collect_sources(tmp_path)
    assert [path for path, _ in sources] == ["app.py"]


def test_collect_sources_rejects_empty_directory(tmp_path: Path) -> None:
    with pytest.raises(SbomError, match="no Python sources"):
        collect_sources(tmp_path)


def test_text_report_contains_attribution(
    sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    report = run_scan(sbom_path=sbom_path, advisory_path=advisory_path, source_root=source_path)
    text = format_text_report(report)
    assert ATTRIBUTION in text
    assert "REACHED" in text
    assert "summary:" in text
