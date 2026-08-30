import ast
import inspect

from ad_enum import cli
from ad_enum.core.console import Console


def _main_tree():
    return ast.parse(inspect.getsource(cli.main))


def _first_line(tree, predicate):
    return min(node.lineno for node in ast.walk(tree) if predicate(node))


def test_scan_coverage_is_initialized_before_any_coverage_add():
    tree = _main_tree()
    initialized = _first_line(tree, lambda n: isinstance(n, ast.Assign) and
                               any(isinstance(t, ast.Name) and t.id == "coverage" for t in n.targets))
    first_add = _first_line(tree, lambda n: isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                            and n.func.attr == "add" and isinstance(n.func.value, ast.Name)
                            and n.func.value.id == "coverage")
    assert initialized < first_add


def test_privileged_context_is_ready_before_fgpp_resultant_rendering():
    source = inspect.getsource(cli.main)
    assert source.index("privileged_sids = privileged_account_sids(inventory)") < source.index("resultants = []")


def test_progress_status_semantics_are_distinct():
    from io import StringIO
    stream = StringIO()
    console = Console(stream=stream, no_color=True)
    console.complete("successful check")
    console.complete("degraded check", "WARNING")
    output = stream.getvalue()
    assert "[ + ] successful check" in output
    assert "[ ! ] degraded check" in output


def test_scan_metadata_has_honest_incomplete_and_complete_states():
    source = inspect.getsource(cli.main)
    assert source.index('"status": "INCOMPLETE"') < source.index('"status": "COMPLETE"')
