"""Static guard against coupling Research code to execution authority."""

from __future__ import annotations

import ast
from pathlib import Path

from .errors import RegistryError

FORBIDDEN_IMPORT_PREFIXES = (
    "backend.app",
    "psycopg",
    "questdb",
    "vnpy",
    "zmq",
)
FORBIDDEN_ENV_NAMES = frozenset(
    {
        "COMMODITY_C_FAST_SIMNOW_RPC_REQUEST_ADDRESS",
        "COMMODITY_C_FAST_SIMNOW_RPC_SUBSCRIBE_ADDRESS",
        "WEB_TRADE_ENABLED",
    }
)


def _imports(tree: ast.AST) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module)
    return result


def _environment_reads(tree: ast.AST) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "getenv"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            result.add(node.args[0].value)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "environ"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            result.add(node.slice.value)
    return result


def assert_research_source_boundary(paths: list[Path]) -> None:
    """Prove that scoped Research modules have no execution-side imports/env."""
    violations: list[str] = []
    for path in sorted(paths):
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise RegistryError(f"cannot inspect Research source: {path}") from exc
        for imported in sorted(_imports(tree)):
            if imported.startswith(FORBIDDEN_IMPORT_PREFIXES):
                violations.append(f"{path}: forbidden import {imported}")
        for name in _environment_reads(tree):
            if name in FORBIDDEN_ENV_NAMES:
                violations.append(f"{path}: forbidden execution environment {name}")
    if violations:
        raise RegistryError("; ".join(violations))
