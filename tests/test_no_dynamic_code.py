"""Keep the installed package free of dynamic code execution."""

import ast
import inspect
from pathlib import Path

import probity_observer
from probity_observer.selection_profile import (
    ALTERNATE_CHECKER,
    CHECKER,
    _check_above,
    _check_at_least,
)

FORBIDDEN = {"exec", "eval", "compile", "__import__"}


def _calls(tree: ast.AST) -> list[str]:
    return [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in FORBIDDEN
    ]


def test_package_source_has_no_dynamic_execution():
    root = Path(probity_observer.__file__).parent
    found = {
        str(path.relative_to(root)): _calls(ast.parse(path.read_bytes()))
        for path in sorted(root.rglob("*.py"))
    }
    assert {name: calls for name, calls in found.items() if calls} == {}


def test_guard_sees_a_dynamic_call():
    assert _calls(ast.parse(b"exec(compile(x, 'n', 'exec'))")) == ["exec", "compile"]


def _body(tree: ast.Module) -> str:
    function = tree.body[0]
    assert isinstance(function, ast.FunctionDef)
    statements = [
        statement
        for statement in function.body
        if not (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant))
    ]
    return ast.dump(ast.Module(body=statements, type_ignores=[]))


def test_bundled_functions_match_the_retained_checker_text():
    for raw, function in ((CHECKER, _check_at_least), (ALTERNATE_CHECKER, _check_above)):
        source = inspect.getsource(function).encode()
        assert _body(ast.parse(raw)) == _body(ast.parse(source))
    assert _body(ast.parse(CHECKER)) != _body(ast.parse(ALTERNATE_CHECKER))
