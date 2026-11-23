"""Deterministic SARIF 2.1.0 serialization.

Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle.
"""

from __future__ import annotations

from typing import Any

from . import ATTRIBUTION, PROJECT, __version__
from .models import Finding, Report, Verdict

_LEVELS = {
    Verdict.REACHED: "error",
    Verdict.UNRESOLVED: "warning",
    Verdict.GUARDED: "warning",
    Verdict.NOT_REACHED: "note",
    Verdict.NOT_AFFECTED: "none",
}
_ACTIONABLE = frozenset({Verdict.REACHED, Verdict.UNRESOLVED, Verdict.GUARDED})
_HOMEPAGE = "https://github.com/yazilimbaysoz-svg/baysoz-reachoracle"


def build_sarif(report: Report, *, include_all: bool = False) -> dict[str, Any]:
    """Build a SARIF log from a report with stable ordering and fingerprints."""
    findings = [
        finding for finding in report.findings if include_all or finding.verdict in _ACTIONABLE
    ]
    rules = _build_rules(report)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "properties": {
            "attribution": ATTRIBUTION,
            "generator": f"{PROJECT} {__version__}",
            "summary": dict(sorted(report.summary.items())),
        },
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": PROJECT,
                        "version": __version__,
                        "informationUri": _HOMEPAGE,
                        "fullName": f"{PROJECT} — {ATTRIBUTION}",
                        "properties": {"attribution": ATTRIBUTION},
                        "rules": rules,
                    }
                },
                "results": [_build_result(finding) for finding in findings],
                "properties": {"attribution": ATTRIBUTION},
            }
        ],
    }


def _build_rules(report: Report) -> list[dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for finding in report.findings:
        if finding.advisory_id in rules:
            continue
        rules[finding.advisory_id] = {
            "id": finding.advisory_id,
            "name": finding.advisory_id.replace("-", "_"),
            "shortDescription": {"text": finding.title[:128]},
            "fullDescription": {"text": f"{finding.title} — {ATTRIBUTION}"},
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "attribution": ATTRIBUTION,
                "security-severity": _security_severity(finding.severity),
                "tags": ["security", "reachability", *finding.cwe],
            },
        }
    return [rules[key] for key in sorted(rules)]


def _build_result(finding: Finding) -> dict[str, Any]:
    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": item.path, "uriBaseId": "%SRCROOT%"},
                "region": {
                    "startLine": max(item.line, 1),
                    "startColumn": max(item.column + 1, 1),
                    "snippet": {"text": item.snippet},
                },
            },
            "logicalLocations": [{"name": finding.symbol, "kind": "function"}],
        }
        for item in finding.evidence
        if item.kind != "version-match"
    ]
    if not locations:
        first = finding.evidence[0]
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": first.path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "snippet": {"text": first.snippet},
                    },
                }
            }
        )
    level = _LEVELS[finding.verdict]
    if finding.verdict is Verdict.REACHED and finding.tainted:
        level = "error"
    return {
        "ruleId": finding.advisory_id,
        "level": level,
        "message": {"text": finding.message},
        "partialFingerprints": {"baysozReachOracleId": finding.id},
        "properties": {
            "attribution": ATTRIBUTION,
            "verdict": finding.verdict.value,
            "package": finding.package,
            "installedVersion": finding.installed_version,
            "symbol": finding.symbol,
            "tainted": finding.tainted,
            "cwe": list(finding.cwe),
        },
        "locations": locations,
    }


def _security_severity(severity: str) -> str:
    return {
        "CRITICAL": "9.5",
        "HIGH": "8.0",
        "MEDIUM": "5.0",
        "LOW": "2.0",
    }.get(severity, "5.0")
