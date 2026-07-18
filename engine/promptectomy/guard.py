"""Static purity guard for generated engine modules.

The synthesis prompt asks Codex for pure, stdlib-only code with no IO. That is a request, not a
control. This module makes it a control: before any generated module is imported and executed, its
AST is checked and dangerous imports/calls are rejected. It is defense-in-depth, not a real sandbox
(that needs out-of-process isolation + rlimits for untrusted input), but it removes the obvious RCE
vectors and enforces the purity the verdict depends on.
"""

from __future__ import annotations

import ast
from pathlib import Path

_FORBIDDEN_MODULES = frozenset({
    "os", "sys", "subprocess", "socket", "shutil", "pathlib", "requests", "urllib", "http",
    "importlib", "ctypes", "multiprocessing", "threading", "asyncio", "pickle", "marshal",
    "builtins", "io", "tempfile", "glob", "resource", "signal", "gc", "inspect", "webbrowser",
})
_FORBIDDEN_CALLS = frozenset({"eval", "exec", "compile", "open", "__import__", "input", "globals", "vars", "getattr"})
_FORBIDDEN_NAMES = (_FORBIDDEN_CALLS - {"input"}) | {"__builtins__"}
_FORBIDDEN_ATTRS = frozenset({"system", "popen", "spawn", "spawnl", "spawnv", "fork", "call", "run", "Popen"})


class ImpureEngine(Exception):
    """A generated module used a construct that a pure deterministic engine may not use."""


def assert_pure(module_path: str | Path) -> None:
    """Raise ImpureEngine if the module imports dangerous stdlib or calls IO/eval-style builtins."""
    path = Path(module_path)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _FORBIDDEN_MODULES:
                    raise ImpureEngine(f"{path.name} imports forbidden module {alias.name!r}")
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if top in _FORBIDDEN_MODULES:
                raise ImpureEngine(f"{path.name} imports from forbidden module {node.module!r}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_CALLS:
            raise ImpureEngine(f"{path.name} calls forbidden builtin {node.func.id!r}")
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            raise ImpureEngine(f"{path.name} references forbidden builtin {node.id!r}")
        elif isinstance(node, ast.Attribute) and (
            node.attr in _FORBIDDEN_ATTRS or node.attr.startswith("__") and node.attr.endswith("__")
        ):
            raise ImpureEngine(f"{path.name} uses forbidden attribute {node.attr!r}")
