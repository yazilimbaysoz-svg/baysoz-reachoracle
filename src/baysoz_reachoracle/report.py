"""Scan orchestration, stable identifiers, baselines, and serialization.

Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import ATTRIBUTION, PROJECT, __version__
from .advisories import is_affected, load_advisories
from .analyzer import resolve_advisory, scan_paths
from .models import VERDICT_RANK, Advisory, Component, Evidence, Finding, Report, Verdict
from .sbom import SbomError, load_components

_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".github",
        ".venv",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
        "venv",
    }
)
_SCHEMA_VERSION = "1.0.0"
_ACTIONABLE = frozenset({Verdict.REACHED, Verdict.UNRESOLVED, Verdict.GUARDED})
_FAIL_ON_RANK = {"none": 4, "guarded": 1, "any": 1, "unresolved": 2, "reached": 3}


class BaselineError(ValueError):
    """Raised when a suppression baseline is malformed."""


def collect_sources(root: Path) -> tuple[tuple[str, str], ...]:
    """Read Python sources under a file or directory, excluding virtualenvs."""
    if root.is_file():
        if root.suffix != ".py":
            message = f"source path must be a .py file or a directory: {root}"
            raise SbomError(message)
        paths = [root]
    else:
        paths = sorted(path for path in root.rglob("*.py") if not _excluded(path))
    if not paths:
        raise SbomError(f"no Python sources found under {root}")
    sources: list[tuple[str, str]] = []
    for path in paths:
        relative = path.relative_to(root).as_posix() if root.is_dir() else path.name
        sources.append((relative, path.read_text(encoding="utf-8")))
    return tuple(sources)


def _excluded(path: Path) -> bool:
    return any(part in _EXCLUDED_DIRS for part in path.parts)


def load_baseline(path: Path) -> tuple[str, ...]:
    """Load stable finding identifiers that CI may suppress."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"invalid JSON in baseline {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("suppressed"), list):
        raise BaselineError("baseline requires a 'suppressed' array")
    result: list[str] = []
    for identifier in payload["suppressed"]:
        if not isinstance(identifier, str) or not identifier.startswith("RO-"):
            raise BaselineError("baseline identifiers must start with 'RO-'")
        result.append(identifier)
    return tuple(sorted(set(result)))


def run_scan(
    *,
    sbom_path: Path,
    advisory_path: Path,
    source_root: Path,
    suppressed_ids: tuple[str, ...] = (),
) -> Report:
    """Execute a complete deterministic scan."""
    components = load_components(sbom_path)
    advisories = load_advisories(advisory_path)
    sources = collect_sources(source_root)
    events = scan_paths(sources)
    findings: list[Finding] = []
    for component in components:
        for advisory in advisories:
            if not is_affected(advisory, component):
                continue
            version_evidence = _version_evidence(component, advisory, sbom_path)
            resolved = resolve_advisory(advisory, events, version_evidence)
            finding_id = _stable_id(advisory.id, component, resolved.symbol, resolved.evidence)
            findings.append(
                Finding(
                    id=finding_id,
                    advisory_id=advisory.id,
                    package=component.name,
                    installed_version=component.version,
                    symbol=resolved.symbol,
                    verdict=resolved.verdict,
                    severity=advisory.severity,
                    title=advisory.title,
                    cwe=advisory.cwe,
                    tainted=resolved.tainted,
                    message=resolved.message,
                    evidence=resolved.evidence,
                )
            )
    findings.sort(
        key=lambda item: (-VERDICT_RANK[item.verdict], item.advisory_id, item.package, item.id)
    )
    active = tuple(item for item in findings if item.id not in suppressed_ids)
    actually_suppressed = tuple(sorted({item.id for item in findings if item.id in suppressed_ids}))
    summary = {verdict.value: 0 for verdict in Verdict}
    for finding in active:
        summary[finding.verdict.value] += 1
    return Report(
        attribution=ATTRIBUTION,
        schema_version=_SCHEMA_VERSION,
        source_root=str(source_root),
        sbom_path=str(sbom_path),
        advisory_path=str(advisory_path),
        components=components,
        findings=active,
        suppressed=actually_suppressed,
        summary=summary,
    )


def _version_evidence(component: Component, advisory: Advisory, sbom_path: Path) -> Evidence:
    specifier = ",".join(advisory.vulnerable_versions)
    text = f"{component.name}=={component.version} satisfies {specifier}"
    return Evidence(str(sbom_path), 0, 0, text, "version-match")


def _stable_id(
    advisory_id: str, component: Component, symbol: str, evidence: tuple[Evidence, ...]
) -> str:
    locations = [
        f"{item.path}:{item.line}:{item.column}:{item.kind}"
        for item in evidence
        if item.kind != "version-match"
    ]
    payload = "\x1f".join(
        [advisory_id, component.key, component.version, symbol, ";".join(locations)]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"RO-{digest}"


def gate_exit_code(report: Report, fail_on: str) -> int:
    """Translate a report into a deterministic CI exit code."""
    threshold = _FAIL_ON_RANK[fail_on]
    ranks = [
        VERDICT_RANK[finding.verdict]
        for finding in report.findings
        if finding.verdict in _ACTIONABLE
    ]
    highest = max(ranks, default=0)
    return 1 if highest >= threshold else 0


def report_to_dict(report: Report) -> dict[str, Any]:
    """Serialize a report to a stable JSON-compatible dictionary."""
    return {
        "attribution": report.attribution,
        "schema_version": report.schema_version,
        "generator": f"{PROJECT} {__version__}",
        "source_root": report.source_root,
        "sbom_path": report.sbom_path,
        "advisory_path": report.advisory_path,
        "components": [
            {
                "name": component.name,
                "version": component.version,
                "ecosystem": component.ecosystem,
                "purl": component.purl,
            }
            for component in report.components
        ],
        "summary": dict(sorted(report.summary.items())),
        "suppressed": list(report.suppressed),
        "findings": [
            {
                "id": finding.id,
                "advisory_id": finding.advisory_id,
                "package": finding.package,
                "installed_version": finding.installed_version,
                "symbol": finding.symbol,
                "verdict": finding.verdict.value,
                "severity": finding.severity,
                "title": finding.title,
                "cwe": list(finding.cwe),
                "tainted": finding.tainted,
                "message": finding.message,
                "evidence": [
                    {
                        "path": item.path,
                        "line": item.line,
                        "column": item.column,
                        "snippet": item.snippet,
                        "kind": item.kind,
                    }
                    for item in finding.evidence
                ],
            }
            for finding in report.findings
        ],
    }


def format_text_report(report: Report) -> str:
    """Render a compact, human-readable report."""
    lines = [f"{PROJECT} {__version__} — {ATTRIBUTION}", ""]
    lines.append(f"sources: {report.source_root}")
    lines.append(f"sbom:    {report.sbom_path}")
    lines.append(f"advisories: {report.advisory_path}")
    lines.append("")
    if not report.findings:
        lines.append("No affected component/source pairings found.")
    for finding in report.findings:
        flag = " TAINTED" if finding.tainted else ""
        lines.append(
            f"[{finding.verdict.value}] {finding.id} {finding.advisory_id} "
            f"{finding.package}=={finding.installed_version} {finding.symbol}{flag}"
        )
        lines.append(f"    {finding.message}")
        for item in finding.evidence:
            if item.kind == "version-match":
                continue
            lines.append(f"    - {item.path}:{item.line}:{item.column} {item.snippet}")
    lines.append("")
    counts = " ".join(f"{key}={value}" for key, value in sorted(report.summary.items()))
    lines.append(f"summary: {counts}")
    if report.suppressed:
        lines.append(f"suppressed: {', '.join(report.suppressed)}")
    return "\n".join(lines)
