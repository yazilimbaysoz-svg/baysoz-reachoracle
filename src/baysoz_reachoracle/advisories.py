"""Offline advisory feed loading and version matching.

Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .models import Advisory, Component, normalize_name

_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9._-]*$")
_SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})


class AdvisoryError(ValueError):
    """Raised when an advisory feed is malformed."""


def load_advisories(path: Path) -> tuple[Advisory, ...]:
    """Load and validate an offline OSV-style advisory feed."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        message = f"cannot read advisory feed {path}: {exc}"
        raise AdvisoryError(message) from exc
    except json.JSONDecodeError as exc:
        message = f"invalid JSON in advisory feed {path}: {exc}"
        raise AdvisoryError(message) from exc
    return parse_advisories(payload)


def parse_advisories(payload: object) -> tuple[Advisory, ...]:
    """Parse an advisory feed from an already-decoded JSON object."""
    if not isinstance(payload, dict):
        raise AdvisoryError("advisory feed must be a JSON object")
    entries = payload.get("advisories")
    if not isinstance(entries, list) or not entries:
        raise AdvisoryError("advisory feed requires a non-empty 'advisories' array")
    advisories: list[Advisory] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        advisory = _parse_advisory(entry, index)
        if advisory.id in seen:
            raise AdvisoryError(f"duplicate advisory id: {advisory.id}")
        seen.add(advisory.id)
        advisories.append(advisory)
    return tuple(sorted(advisories, key=lambda item: item.id))


def _parse_advisory(entry: object, index: int) -> Advisory:
    label = f"advisories[{index}]"
    if not isinstance(entry, dict):
        raise AdvisoryError(f"{label} must be an object")
    advisory_id = _required_string(entry, "id", label)
    if not _ID_PATTERN.fullmatch(advisory_id):
        raise AdvisoryError(f"{label}.id must be an uppercase advisory identifier")
    package = _required_string(entry, "package", label)
    modules = _string_tuple(entry, "modules", label, required=True)
    versions = _string_tuple(entry, "vulnerable_versions", label, required=True)
    symbols = _string_tuple(entry, "symbols", label, required=True)
    for specifier in versions:
        try:
            SpecifierSet(specifier)
        except InvalidSpecifier as exc:
            raise AdvisoryError(
                f"{label}.vulnerable_versions contains {specifier!r}: {exc}"
            ) from exc
    for symbol in symbols:
        if not _SYMBOL_PATTERN.fullmatch(symbol):
            raise AdvisoryError(f"{label}.symbols contains invalid dotted path {symbol!r}")
    for module in modules:
        if not _SYMBOL_PATTERN.fullmatch(module):
            raise AdvisoryError(f"{label}.modules contains invalid module name {module!r}")
    severity = _required_string(entry, "severity", label).upper()
    if severity not in _SEVERITIES:
        raise AdvisoryError(f"{label}.severity must be one of {sorted(_SEVERITIES)}")
    cwe = _string_tuple(entry, "cwe", label, required=False)
    fixed_version = entry.get("fixed_version", "")
    if not isinstance(fixed_version, str):
        raise AdvisoryError(f"{label}.fixed_version must be a string")
    if fixed_version:
        _parse_version(fixed_version, f"{label}.fixed_version")
    description = entry.get("description", "")
    if not isinstance(description, str):
        raise AdvisoryError(f"{label}.description must be a string")
    ecosystem = entry.get("ecosystem", "PyPI")
    if not isinstance(ecosystem, str) or not ecosystem:
        raise AdvisoryError(f"{label}.ecosystem must be a non-empty string")
    return Advisory(
        id=advisory_id,
        package=package,
        modules=tuple(sorted(set(modules))),
        vulnerable_versions=tuple(versions),
        symbols=tuple(sorted(set(symbols))),
        severity=severity,
        title=_required_string(entry, "title", label),
        description=description,
        fixed_version=fixed_version,
        cwe=tuple(cwe),
        ecosystem=ecosystem,
    )


def _required_string(entry: dict[str, object], key: str, label: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AdvisoryError(f"{label}.{key} must be a non-empty string")
    return value.strip()


def _string_tuple(
    entry: dict[str, object], key: str, label: str, *, required: bool
) -> tuple[str, ...]:
    value = entry.get(key, [])
    if not isinstance(value, list) or (required and not value):
        expectation = "non-empty array" if required else "array"
        raise AdvisoryError(f"{label}.{key} must be a {expectation} of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise AdvisoryError(f"{label}.{key} must contain only non-empty strings")
        result.append(item.strip())
    return tuple(result)


def _parse_version(value: str, label: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as exc:
        raise AdvisoryError(f"{label} contains invalid PEP 440 version {value!r}") from exc


def is_affected(advisory: Advisory, component: Component) -> bool:
    """Return True when the installed version satisfies the advisory range."""
    if normalize_name(advisory.package) != component.key:
        return False
    if advisory.ecosystem.lower() != component.ecosystem.lower():
        return False
    installed = _parse_version(component.version, f"component {component.name}")
    specifier = SpecifierSet(",".join(advisory.vulnerable_versions))
    return installed in specifier
