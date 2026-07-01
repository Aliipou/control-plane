"""Rules A & B on the control-plane source (stdlib-only, no deps needed).

Runs in the deps-free CI job. Rule A: control-plane imports no research/agent
layer (it MAY import the kernel — runtime can use core). Rule B: it constructs no
Decision (it routes and verifies; it never decides).
"""

from __future__ import annotations

import ast
from pathlib import Path

_PKG = Path(__file__).resolve().parent.parent / "control_plane"
_FORBIDDEN = {"research", "fdk_research", "agent_runtime", "sklearn", "torch", "tensorflow"}
_VERDICTS = {"ALLOW", "DENY", "LIMIT", "CONTAIN", "DEFER"}
_DYNAMIC = {"__import__", "import_module"}


def _files():
    return list(_PKG.rglob("*.py"))


def test_rule_a_no_forbidden_layer_and_no_dynamic_import() -> None:
    bad = []
    for py in _files():
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in _FORBIDDEN:
                        bad.append(f"{py.name}: import {a.name}")
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                if node.module.split(".")[0] in _FORBIDDEN:
                    bad.append(f"{py.name}: from {node.module}")
            elif isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                if name in _DYNAMIC:
                    bad.append(f"{py.name}:{node.lineno}: dynamic import")
    assert not bad, bad


def test_rule_b_emits_no_decision() -> None:
    bad = []
    for py in _files():
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                if name == "Decision":
                    bad.append(f"{py.name}:{node.lineno}: constructs Decision(...)")
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values, strict=False):
                    if (
                        isinstance(k, ast.Constant)
                        and k.value == "verdict"
                        and isinstance(v, ast.Constant)
                        and v.value in _VERDICTS
                    ):
                        bad.append(f"{py.name}:{node.lineno}: builds a decision dict")
    assert not bad, bad
