# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Every query must use bound parameters: no f-strings, concatenation or % formatting in SQL."""

import ast
from pathlib import Path

import pytest

DB = Path(__file__).parents[2] / "src" / "vexledger"
SQL_CALLS = {"text", "execute", "exec_driver_sql"}


def _is_built_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(
            isinstance(n, ast.Constant) and isinstance(n.value, str)
            for n in (node.left, node.right)
        )
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


@pytest.mark.parametrize("path", sorted(DB.rglob("*.py")), ids=lambda p: str(p.relative_to(DB)))
def test_no_dynamic_sql(path: Path) -> None:
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Call):
            name = (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else getattr(node.func, "id", "")
            )
            if name in SQL_CALLS and node.args:
                assert not _is_built_string(node.args[0]), (
                    f"{path.name}:{node.lineno} builds SQL from a string"
                )
