"""Static guard against coupling Research code to execution authority."""

from __future__ import annotations

import ast
from pathlib import Path

from .errors import RegistryError

FORBIDDEN_IMPORT_ROOTS = (
    "backend",
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
            result.update(f"{node.module}.{alias.name}" for alias in node.names)
    return result


def _constant_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _environment_reads(tree: ast.AST) -> set[str]:
    result: set[str] = set()
    os_aliases = {"os"}
    getenv_aliases: set[str] = set()
    environ_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    os_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                local_name = alias.asname or alias.name
                if alias.name == "getenv":
                    getenv_aliases.add(local_name)
                elif alias.name == "environ":
                    environ_aliases.add(local_name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            name = _constant_string(node.args[0])
            if name is None:
                continue
            if isinstance(node.func, ast.Name) and node.func.id in getenv_aliases or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "getenv"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in os_aliases
            ) or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and (
                    (
                        isinstance(node.func.value, ast.Attribute)
                        and node.func.value.attr == "environ"
                        and isinstance(node.func.value.value, ast.Name)
                        and node.func.value.value.id in os_aliases
                    )
                    or (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id in environ_aliases
                    )
                )
            ):
                result.add(name)
        if isinstance(node, ast.Subscript):
            name = _constant_string(node.slice)
            if name is None:
                continue
            if (
                isinstance(node.value, ast.Attribute)
                and node.value.attr == "environ"
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id in os_aliases
            ) or (
                isinstance(node.value, ast.Name)
                and node.value.id in environ_aliases
            ):
                result.add(name)
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
            if any(
                imported == root or imported.startswith(f"{root}.")
                for root in FORBIDDEN_IMPORT_ROOTS
            ):
                violations.append(f"{path}: forbidden import {imported}")
        for name in _environment_reads(tree):
            if name in FORBIDDEN_ENV_NAMES:
                violations.append(f"{path}: forbidden execution environment {name}")
    if violations:
        raise RegistryError("; ".join(violations))
