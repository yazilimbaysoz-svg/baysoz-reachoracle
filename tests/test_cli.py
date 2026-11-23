"""CLI contract tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from baysoz_reachoracle import ATTRIBUTION, __version__
from baysoz_reachoracle.cli import build_parser, main


def _scan_args(sbom_path: Path, advisory_path: Path, source_path: Path) -> list[str]:
    return [
        "scan",
        "--sbom",
        str(sbom_path),
        "--advisories",
        str(advisory_path),
        "--source",
        str(source_path),
    ]


def test_version_output_attributes_baysöz_labs(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--version"])
    assert error.value.code == 0
    output = capsys.readouterr().out
    assert __version__ in output
    assert ATTRIBUTION in output


@pytest.mark.parametrize(
    "argv", [["--help"], ["scan", "--help"], ["explain", "--help"], ["selftest", "--help"]]
)
def test_every_help_surface_attributes_baysöz_labs(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as error:
        main(argv)
    assert error.value.code == 0
    assert ATTRIBUTION in capsys.readouterr().out


def test_parser_has_all_commands() -> None:
    parser = build_parser()
    assert "scan" in parser.format_help()
    assert "explain" in parser.format_help()
    assert "selftest" in parser.format_help()


def test_scan_json_to_stdout(
    capsys: pytest.CaptureFixture[str], sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    exit_code = main(_scan_args(sbom_path, advisory_path, source_path))
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["attribution"] == ATTRIBUTION
    assert payload["summary"]["REACHED"] == 2


def test_scan_sarif_to_file(
    tmp_path: Path, sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    output = tmp_path / "report.sarif"
    argv = [
        *_scan_args(sbom_path, advisory_path, source_path),
        "--format",
        "sarif",
        "--output",
        str(output),
    ]
    assert main(argv) == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["properties"]["attribution"] == ATTRIBUTION


def test_scan_text_format(
    capsys: pytest.CaptureFixture[str], sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    argv = [*_scan_args(sbom_path, advisory_path, source_path), "--format", "text"]
    assert main(argv) == 1
    assert ATTRIBUTION in capsys.readouterr().out


def test_fail_on_none_returns_zero(sbom_path: Path, advisory_path: Path, source_path: Path) -> None:
    argv = [*_scan_args(sbom_path, advisory_path, source_path), "--fail-on", "none"]
    assert main(argv) == 0


def test_baseline_round_trip_via_cli(
    tmp_path: Path, sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    baseline = tmp_path / "baseline.json"
    argv = [*_scan_args(sbom_path, advisory_path, source_path), "--write-baseline", str(baseline)]
    assert main(argv) == 1
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert payload["attribution"] == ATTRIBUTION
    assert len(payload["suppressed"]) == 2
    rerun = [*_scan_args(sbom_path, advisory_path, source_path), "--baseline", str(baseline)]
    assert main(rerun) == 0


def test_explain_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sbom_path: Path,
    advisory_path: Path,
    source_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    argv = [*_scan_args(sbom_path, advisory_path, source_path), "--output", str(report_path)]
    assert main(argv) == 1
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    finding_id = payload["findings"][0]["id"]
    assert main(["explain", "--report", str(report_path), "--finding", finding_id]) == 0
    output = capsys.readouterr().out
    assert finding_id in output
    assert "Evidence:" in output
    assert ATTRIBUTION in output


def test_explain_unknown_finding_returns_error(
    tmp_path: Path, sbom_path: Path, advisory_path: Path, source_path: Path
) -> None:
    report_path = tmp_path / "report.json"
    argv = [*_scan_args(sbom_path, advisory_path, source_path), "--output", str(report_path)]
    assert main(argv) == 1
    assert main(["explain", "--report", str(report_path), "--finding", "RO-0000000000000000"]) == 2


def test_selftest_all_pass(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["selftest"]) == 0
    output = capsys.readouterr().out
    assert "10/10 cases passed" in output
    assert ATTRIBUTION in output
    assert "FAIL" not in output


def test_selftest_json_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["selftest", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] == payload["total"] == 10
    assert payload["attribution"] == ATTRIBUTION
    assert all(case["passed"] for case in payload["cases"])


def test_missing_sbom_returns_error_with_attribution(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, advisory_path: Path, source_path: Path
) -> None:
    argv = [
        "scan",
        "--sbom",
        str(tmp_path / "absent.json"),
        "--advisories",
        str(advisory_path),
        "--source",
        str(source_path),
    ]
    assert main(argv) == 2
    assert ATTRIBUTION in capsys.readouterr().err
