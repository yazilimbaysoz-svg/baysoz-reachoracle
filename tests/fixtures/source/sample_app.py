"""Adversarial fixture application.

Baysöz Labs <baysozlabs@proton.me> — baysoz-reachoracle.
"""

from __future__ import annotations

from typing import Any

import requests
import yaml
from flask import request
from urllib3.util.ssl_ import create_urllib3_context as build_context


def load_policy() -> dict[str, Any]:
    """Reachable unsafe deserialization fed by user-controlled input."""
    payload = request.args.get("policy")
    return yaml.load(payload, Loader=yaml.Loader)


def build_tls_context() -> object:
    """Reachable TLS context construction through a from-import alias."""
    return build_context()


def unused_http_helper(url: str) -> object:
    """The imported requests package is never called here."""
    return url
