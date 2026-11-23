"""Shared fixtures for Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle."""

from __future__ import annotations

from pathlib import Path

import pytest

from baysoz_reachoracle import ATTRIBUTION

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def advisory_path() -> Path:
    return FIXTURES / "advisories.json"


@pytest.fixture
def sbom_path() -> Path:
    return FIXTURES / "bom.json"


@pytest.fixture
def source_path() -> Path:
    return FIXTURES / "source" / "sample_app.py"


@pytest.fixture
def attribution() -> str:
    return ATTRIBUTION
