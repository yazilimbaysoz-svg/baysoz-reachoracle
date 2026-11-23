"""Command-line interface for Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import ATTRIBUTION, PROJECT, __version__
from .advisories import AdvisoryError
from .corpus import run_corpus
from .report import (
    BaselineError,
    format_text_report,
    gate_exit_code,
    load_baseline,
    report_to_dict,
    run_scan,
)
from .sarif import build_sarif
from .sbom import SbomError
from .models import Report

_FAIL_ON_CHOICES = ("reached", "unresolved", "guarded", "any", "none")
_FORMAT_CHOICES = ("json", "sarif", "text")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser with attribution on every help surface."""
    description = (
        "Offline white-box vulnerability reachability oracle for Python. "
        "Compiles SBOM components, symbol-aware advisories and AST evidence "
        f"into deterministic verdicts and SARIF. By {ATTRIBUTION}."
    )
    parser = argparse.ArgumentParser(
        prog=PROJECT,
        description=description,
        epilog=ATTRIBUTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROJECT} {__version__} — {ATTRIBUTION}",
        help="show version and Baysöz Labs attribution",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = commands.add_parser(
        "scan",
        help="scan a source tree for reachable vulnerable symbols",
        description=f"Run an offline reachability scan. By {ATTRIBUTION}.",
        epilog=ATTRIBUTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument(
        "--sbom", required=True, type=Path, help="CycloneDX/SPDX JSON or pinned requirements file"
    )
    scan.add_argument(
        "--advisories", required=True, type=Path, help="offline OSV-style advisory JSON feed"
    )
    scan.add_argument("--source", required=True, type=Path, help="Python source file or directory")
    scan.add_argument(
        "--format", choices=_FORMAT_CHOICES, default="json", help="report format (default: json)"
    )
    scan.add_argument("--output", type=Path, help="write report to this file instead of stdout")
    scan.add_argument("--baseline", type=Path, help="JSON file of suppressed RO- identifiers")
    scan.add_argument(
        "--write-baseline",
        type=Path,
        help="write actionable finding identifiers as a new baseline",
    )
    scan.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="reached",
        help="minimum verdict that fails CI (default: reached)",
    )
    scan.add_argument(
        "--sarif-all",
        action="store_true",
        help="include non-actionable verdicts in SARIF output",
    )

    explain = commands.add_parser(
        "explain",
        help="explain one finding from a saved JSON report",
        description=f"Render a deterministic explanation for a finding. By {ATTRIBUTION}.",
        epilog=ATTRIBUTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    explain.add_argument("--report", required=True, type=Path, help="JSON report produced by scan")
    explain.add_argument(
        "--finding", required=True, help="finding identifier, e.g. RO-0123456789abcdef"
    )

    selftest = commands.add_parser(
        "selftest",
        help="run the built-in adversarial corpus",
        description=f"Execute the embedded adversarial reachability corpus. By {ATTRIBUTION}.",
        epilog=ATTRIBUTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    selftest.add_argument(
        "--json", action="store_true", help="emit machine-readable corpus results"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning a deterministic process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "explain":
            return _run_explain(args)
        if args.command == "selftest":
            return _run_selftest(args)
    except (AdvisoryError, BaselineError, SbomError, OSError, ValueError) as exc:
        sys.stderr.write(f"{PROJECT}: error: {exc}\n{ATTRIBUTION}\n")
        return 2
    sys.stderr.write(f"{PROJECT}: unknown command\n{ATTRIBUTION}\n")
    return 2


def _run_scan(args: argparse.Namespace) -> int:
    baseline_ids = load_baseline(args.baseline) if args.baseline else ()
    report = run_scan(
        sbom_path=args.sbom,
        advisory_path=args.advisories,
        source_root=args.source,
        suppressed_ids=baseline_ids,
    )
    if args.write_baseline:
        identifiers = sorted(
            finding.id
            for finding in report.findings
            if finding.verdict.value in {"REACHED", "UNRESOLVED", "GUARDED"}
        )
        _write_text(
            args.write_baseline,
            json.dumps(
                {"attribution": ATTRIBUTION, "suppressed": identifiers},
                indent=2,
            )
            + "\n",
        )
    rendered = _render_report(report, args.format, args.sarif_all)
    if args.output:
        _write_text(args.output, rendered)
    else:
        sys.stdout.write(rendered)
    return gate_exit_code(report, args.fail_on)


def _render_report(report: Report, output_format: str, sarif_all: bool) -> str:
    if output_format == "json":
        payload = report_to_dict(report)
    elif output_format == "sarif":
        payload = build_sarif(report, include_all=sarif_all)
    else:
        return format_text_report(report) + "\n"
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _run_explain(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(args.report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        message = f"invalid JSON report {args.report}: {exc}"
        raise ValueError(message) from exc
    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        raise ValueError(f"{args.report} is not a reachoracle JSON report")
    for finding in findings:
        if isinstance(finding, dict) and finding.get("id") == args.finding:
            lines = [
                f"{PROJECT} {__version__} — {ATTRIBUTION}",
                "",
                f"Finding: {finding['id']} ({finding['verdict']})",
                f"Advisory: {finding['advisory_id']} — {finding['title']}",
                f"Component: {finding['package']}=={finding['installed_version']}",
                f"Symbol: {finding['symbol']}",
                f"Explanation: {finding['message']}",
                f"Tainted: {finding['tainted']}",
                "Evidence:",
            ]
            for item in finding["evidence"]:
                location = f"{item['path']}:{item['line']}:{item['column']}"
                lines.append(f"  - {item['kind']} {location} {item['snippet']}")
            lines.append("")
            lines.append(ATTRIBUTION)
            sys.stdout.write("\n".join(lines) + "\n")
            return 0
    raise ValueError(f"finding {args.finding} not present in {args.report}")


def _run_selftest(args: argparse.Namespace) -> int:
    results = run_corpus()
    passed = sum(1 for result in results if result.passed)
    if args.json:
        payload: dict[str, Any] = {
            "attribution": ATTRIBUTION,
            "passed": passed,
            "total": len(results),
            "cases": [
                {
                    "name": result.name,
                    "expected": result.expected,
                    "actual": result.actual,
                    "tainted": result.tainted,
                    "passed": result.passed,
                    "detail": result.detail,
                }
                for result in results
            ],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        lines = [f"{PROJECT} adversarial corpus — {ATTRIBUTION}", ""]
        for result in results:
            status = "PASS" if result.passed else "FAIL"
            lines.append(
                f"{status} {result.name}: expected={result.expected} actual={result.actual} "
                f"tainted={result.tainted}"
            )
        lines.extend(["", f"{passed}/{len(results)} cases passed", ATTRIBUTION])
        sys.stdout.write("\n".join(lines) + "\n")
    return 0 if passed == len(results) else 1


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
