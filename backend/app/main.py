"""Compatibility import for local tooling.

Phase A deploys ``app.control_api:app`` directly.  This module intentionally
does not retain the former monolith startup/shutdown lifecycle; it only
re-exports the pure Control API application for callers that still import
``app.main`` during the repository transition.
"""

from app.control_api import app

__all__ = ["app"]
