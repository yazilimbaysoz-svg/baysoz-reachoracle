"""Immutable domain models for Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    """Reachability verdicts ordered from strongest to weakest evidence."""

    REACHED = "REACHED"
    UNRESOLVED = "UNRESOLVED"
    GUARDED = "GUARDED"
    NOT_REACHED = "NOT_REACHED"
    NOT_AFFECTED = "NOT_AFFECTED"


VERDICT_RANK = {
    Verdict.REACHED: 3,
    Verdict.UNRESOLVED: 2,
    Verdict.GUARDED: 1,
    Verdict.NOT_REACHED: 0,
    Verdict.NOT_AFFECTED: 0,
}


@dataclass(frozen=True, order=True)
class Evidence:
    """A deterministic, source-located proof fragment."""

    path: str
    line: int
    column: int
    snippet: str
    kind: str


@dataclass(frozen=True, order=True)
class Component:
    """An installed distribution from an SBOM or lockfile."""

    name: str
    version: str
    ecosystem: str = "PyPI"
    purl: str = ""

    @property
    def key(self) -> str:
        return normalize_name(self.name)


def normalize_name(name: str) -> str:
    """Normalize a Python distribution name per PEP 503."""
    result: list[str] = []
    previous_separator = False
    for char in name:
        if char in "-_.":
            if not previous_separator:
                result.append("-")
            previous_separator = True
        else:
            result.append(char.lower())
            previous_separator = False
    return "".join(result)


@dataclass(frozen=True)
class Advisory:
    """An offline OSV-style advisory with symbol-level exploitability metadata."""

    id: str
    package: str
    modules: tuple[str, ...]
    vulnerable_versions: tuple[str, ...]
    symbols: tuple[str, ...]
    severity: str
    title: str
    description: str = ""
    fixed_version: str = ""
    cwe: tuple[str, ...] = ()
    ecosystem: str = "PyPI"

    @property
    def key(self) -> str:
        return normalize_name(self.package)


@dataclass(frozen=True)
class Finding:
    """An advisory/component pairing with a deterministic reachability verdict."""

    id: str
    advisory_id: str
    package: str
    installed_version: str
    symbol: str
    verdict: Verdict
    severity: str
    title: str
    cwe: tuple[str, ...]
    tainted: bool
    message: str
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class Report:
    """A complete, reproducible scan result."""

    attribution: str
    schema_version: str
    source_root: str
    sbom_path: str
    advisory_path: str
    components: tuple[Component, ...]
    findings: tuple[Finding, ...]
    suppressed: tuple[str, ...]
    summary: dict[str, int]
