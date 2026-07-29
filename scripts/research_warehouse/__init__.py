"""Research-only warehouse infrastructure.

The package is intentionally independent from ``backend.app`` and execution
services.  Subsystems are added by their own issue instead of a shared god
module.
"""

from .errors import RegistryError
from .registry import load_registry

__all__ = ["RegistryError", "load_registry"]
