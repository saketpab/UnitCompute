from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest


def guards_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/check_guards.py"
    spec = importlib.util.spec_from_file_location("guards_calibration", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "names", [[], ["definitely-not-an-existing-mutant"], ["owner-scoping", "missing"]]
)
def test_mutation_selection_refuses_empty_or_unknown(names: list[str]) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_guards.py", "--only", *names],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires one or more known mutation names" in result.stderr
    assert "guards proven" not in result.stdout


def test_real_postgresql_error_is_not_a_behavioral_mutation_kill(tmp_path: Path) -> None:
    guards = guards_module()
    mutation = guards.Mutation(
        "calibration-db-arithmetic",
        (
            (
                "services/deployments.py",
                '"SELECT * FROM deployments WHERE id = %s AND owner_id = %s",',
                '"SELECT * FROM deployments WHERE id = %s AND owner_id = %s '
                'AND 1/(length(id)-length(id))=1",',
            ),
        ),
        ("tests/test_authorization.py::test_cross_user_access_is_non_enumerating",),
    )
    assert guards.run(mutation, tmp_path) == "BROKEN-MUTANT(DivisionByZero)"
    evidence = tmp_path / mutation.name
    assert "DivisionByZero" in (evidence / "pytest.log").read_text()
    assert (evidence / "reports.jsonl").is_file()


def test_real_ownership_assertion_kills_only_the_behavioral_mutation(tmp_path: Path) -> None:
    guards = guards_module()
    mutation = next(m for m in guards.MUTATIONS if m.name == "owner-scoping")
    assert guards.run(mutation, tmp_path) == "KILLED"
    reports = (tmp_path / mutation.name / "reports.jsonl").read_text()
    assert "assert 200 == 404" in reports


@pytest.mark.parametrize("error", ["SyntaxError", "DivisionByZero"])
def test_contention_allowance_does_not_hide_unrelated_logged_sql_faults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    guards = guards_module()
    mutation = next(m for m in guards.MUTATIONS if m.name == "r2-write-retry")
    real_run = guards.subprocess.run

    def with_unrelated_diagnostic(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        # Run the real PostgreSQL contention case, then calibrate its diagnostic veto.
        result = real_run(*args, **kwargs)
        result.stderr += f"\npsycopg.errors.{error}: unrelated calibration SQL fault\n"
        return result

    monkeypatch.setattr(guards.subprocess, "run", with_unrelated_diagnostic)
    assert guards.run(mutation, tmp_path) == f"BROKEN-MUTANT({error})"
    output = (tmp_path / mutation.name / "pytest.log").read_text()
    assert "LockNotAvailable: canceling statement due to lock timeout" in output
    assert "assert 'recovery_required' == 'succeeded'" in output
