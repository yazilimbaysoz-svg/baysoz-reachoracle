"""SBOM and lockfile ingestion for Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle."""

from __future__ import annotations

import json
import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from .models import Component

_PURL_PATTERN = re.compile(r"^pkg:([^/@]+)/[^@]+@([^?]+)")


class SbomError(ValueError):
    """Raised when an SBOM or lockfile cannot be interpreted."""


def load_components(path: Path) -> tuple[Component, ...]:
    """Load components from CycloneDX JSON, SPDX JSON, or a pinned requirements file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        message = f"cannot read SBOM {path}: {exc}"
        raise SbomError(message) from exc
    if raw.lstrip().startswith("{"):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            message = f"invalid JSON in SBOM {path}: {exc}"
            raise SbomError(message) from exc
        if not isinstance(payload, dict):
            raise SbomError(f"SBOM {path} must contain a JSON object")
        if payload.get("bomFormat") == "CycloneDX" or "components" in payload:
            components = _from_cyclonedx(payload)
        elif "spdxVersion" in payload or "packages" in payload:
            components = _from_spdx(payload)
        else:
            raise SbomError(f"unrecognized JSON SBOM format in {path}")
    else:
        components = _from_requirements(raw)
    if not components:
        raise SbomError(f"SBOM {path} contains no components")
    unique = {
        (component.key, component.version, component.ecosystem): component
        for component in components
    }
    return tuple(sorted(unique.values(), key=lambda item: (item.key, item.version)))


def _from_cyclonedx(payload: dict[str, object]) -> tuple[Component, ...]:
    entries = payload.get("components")
    if not isinstance(entries, list):
        raise SbomError("CycloneDX SBOM requires a 'components' array")
    components: list[Component] = []
    for index, entry in enumerate(entries):
        label = f"components[{index}]"
        if not isinstance(entry, dict):
            raise SbomError(f"{label} must be an object")
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not name:
            raise SbomError(f"{label}.name must be a non-empty string")
        if not isinstance(version, str) or not version:
            raise SbomError(f"{label}.version must be a non-empty string")
        purl = entry.get("purl", "")
        if not isinstance(purl, str):
            raise SbomError(f"{label}.purl must be a string")
        ecosystem = "PyPI"
        match = _PURL_PATTERN.match(purl)
        if match and match.group(1).lower() != "pypi":
            ecosystem = match.group(1).upper()
        components.append(Component(name=name, version=version, ecosystem=ecosystem, purl=purl))
    return tuple(components)


def _from_spdx(payload: dict[str, object]) -> tuple[Component, ...]:
    entries = payload.get("packages")
    if not isinstance(entries, list):
        raise SbomError("SPDX SBOM requires a 'packages' array")
    components: list[Component] = []
    for index, entry in enumerate(entries):
        label = f"packages[{index}]"
        if not isinstance(entry, dict):
            raise SbomError(f"{label} must be an object")
        name = entry.get("name")
        version = entry.get("versionInfo")
        if not isinstance(name, str) or not name:
            raise SbomError(f"{label}.name must be a non-empty string")
        if not isinstance(version, str) or not version:
            raise SbomError(f"{label}.versionInfo must be a non-empty string")
        components.append(Component(name=name, version=version))
    return tuple(components)


def _from_requirements(raw: str) -> tuple[Component, ...]:
    components: list[Component] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("#") or text.startswith("-"):
            continue
        try:
            requirement = Requirement(text)
        except InvalidRequirement as exc:
            raise SbomError(f"requirements line {line_number} is invalid: {exc}") from exc
        versions = [
            specifier.version
            for specifier in requirement.specifier
            if specifier.operator in {"==", "==="}
        ]
        if len(versions) != 1:
            message = f"requirements line {line_number} must pin exactly one version with '=='"
            raise SbomError(message)
        components.append(Component(name=requirement.name, version=versions[0]))
    return tuple(components)
