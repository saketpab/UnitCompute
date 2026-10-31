from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql

from conftest import make_settings
from test_postgresql import empty_target, legacy_fixture
from unitcompute.api.app import build_container, create_app
from unitcompute.auth import Principal
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.db.import_sqlite import import_snapshot
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.services.deployments import unresolved_create_obligation
from unitcompute.worker import Worker

A, B = "dep_" + "b" * 32, "dep_" + "1" * 32
P, J = "plan_" + "2" * 32, "job_" + "3" * 32
ISSUER = "https://old.test"
AUTH = {"Authorization": "Bearer dev:legacy"}


def legacy_source(path: Path) -> None:
    legacy_fixture(path)
    with sqlite3.connect(path) as c:
        for table in ("deployments", "plans", "jobs", "idempotency_records"):
            c.execute(f"UPDATE {table} SET owner_id='dev:legacy' WHERE owner_id='legacy-subject'")  # noqa: S608 - fixed tables
        c.execute("UPDATE plans SET approved_by='dev:legacy'")


def other_history(c: Any, owner: str, marker: str = "?") -> None:
    # Same data against SQLite source and the published-nine PostgreSQL corruption fixture.
    c.execute(
        "INSERT INTO deployments(id,owner_id,name,disk_gib,region,instance_type,provisioner,"
        "status,current_plan_id,created_at,updated_at) VALUES(" + ",".join([marker] * 11) + ")",
        (
            B,
            owner,
            "other",
            8,
            "us-east-1",
            "t3.micro",
            "simulated",
            "deleted",
            None,
            "2026-10-30T00:00:00+00:00",
            "2026-10-30T00:00:00+00:00",
        ),
    )
    c.execute(
        "INSERT INTO plans(id,deployment_id,owner_id,kind,status,provisioner,config_hash,region,"
        "state_key,template_version,created_at,preview_json) VALUES("
        + ",".join([marker] * 12)
        + ")",
        (
            P,
            B,
            owner,
            "destroy",
            "apply_failed",
            "simulated",
            "h",
            "us-east-1",
            "k",
            "ec2-vm/v1",
            "2026-10-30T00:00:00+00:00",
            '{"changes":[]}',
        ),
    )
    c.execute(
        "INSERT INTO jobs(id,owner_id,deployment_id,plan_id,kind,status,payload_hash,created_at) "
        "VALUES(" + ",".join([marker] * 8) + ")",
        (J, owner, B, P, "apply", "failed", "h", "2026-10-30T00:00:00+00:00"),
    )


def cross_source(path: Path, owner: str, field: str = "source") -> None:
    with sqlite3.connect(path) as c:
        other_history(c, owner)
        definition = c.execute(
            "SELECT sql FROM sqlite_master WHERE name='recovery_obligations_forward_only'"
        ).fetchone()[0]
        c.execute("DROP TRIGGER recovery_obligations_forward_only")
        if field == "source":
            c.execute(
                "UPDATE recovery_obligations SET job_id=?,plan_id=? WHERE discharged_at IS NULL",
                (J, P),
            )
        else:
            c.execute(
                "UPDATE recovery_obligations SET discharged_by_job_id=? "
                "WHERE discharged_at IS NOT NULL",
                (J,),
            )
        c.execute(definition)
        assert c.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("owner", ["dev:other", "dev:legacy"])
@pytest.mark.parametrize("field", ["source", "discharge"])
def test_import_rejects_cross_bound_recovery_atomically(
    db: Database, tmp_path: Path, owner: str, field: str
) -> None:
    path = tmp_path / "source.sqlite3"
    legacy_source(path)
    cross_source(path, owner, field)
    empty_target(db)
    original = path.read_bytes()
    with pytest.raises(ValueError, match="recovery_obligations"):
        import_snapshot(db, path, issuer=ISSUER, source_auth="development")
    assert path.read_bytes() == original
    with db.read() as c:
        for table in (
            "deployments",
            "jobs",
            "plans",
            "recovery_obligations",
            "offline_imports",
            "users",
        ):
            assert (
                c.execute(
                    sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))
                ).fetchone()[0]
                == 0
            )
    with sqlite3.connect(path) as c:
        definition = c.execute(
            "SELECT sql FROM sqlite_master WHERE name='recovery_obligations_forward_only'"
        ).fetchone()[0]
        c.execute("DROP TRIGGER recovery_obligations_forward_only")
        c.execute(
            "UPDATE recovery_obligations SET job_id=?,plan_id=? WHERE discharged_at IS NULL",
            ("job_" + "d" * 32, "plan_" + "c" * 32),
        )
        c.execute(
            "UPDATE recovery_obligations SET discharged_by_job_id=NULL "
            "WHERE discharged_at IS NOT NULL"
        )
        c.execute(definition)
    assert import_snapshot(db, path, issuer=ISSUER, source_auth="development")["deployments"] == 2


@pytest.mark.parametrize("owner", ["dev:other", "dev:legacy"])
def test_existing_nine_corruption_never_clears_obligation_or_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner: str
) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    files = database._migration_files()
    path = tmp_path / "source.sqlite3"
    legacy_source(path)
    with monkeypatch.context() as old:
        old.setattr(database, "_migration_files", lambda: files[:9])
        old.setattr(database, "LATEST_SCHEMA_VERSION", 9)
        db.migrate()
        empty_target(db)
        import_snapshot(db, path, issuer=ISSUER, source_auth="development")
        with db.transaction() as c:
            db.ensure_user(c, Principal(owner, "dev"))
            other_history(c, owner, "%s")
            definition = c.execute(
                "SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid='recovery_ob"
                "ligations'::regclass AND tgname='recovery_obligations_forward_only'"
            ).fetchone()[0]
            c.execute("DROP TRIGGER recovery_obligations_forward_only ON recovery_obligations")
            c.execute(
                "UPDATE recovery_obligations SET job_id=%s,plan_id=%s WHERE discharged_at IS NULL",
                (J, P),
            )
            c.execute(definition)
        with db.read() as c:
            before = c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall()

        class Counting(SimulatedProvisioner):
            applies = 0

            def apply(self, *args: Any, **kwargs: Any) -> Any:
                self.applies += 1
                return super().apply(*args, **kwargs)

        provisioner = Counting(settings.data_dir)
        worker = Worker(settings, db, provisioner)
        worker._retry_uncaptured(A)
        with db.read() as c:
            assert c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall() == before
            assert unresolved_create_obligation(c, "dev:legacy") == A
        with TestClient(create_app(settings, build_container(settings))) as client:
            assert client.post(f"/deployments/{A}/plan", headers=AUTH).status_code == 202
            assert worker.run_once()
            detail = client.get(f"/deployments/{A}", headers=AUTH).json()
            assert detail["current_plan"]["error"]["code"] == "recovery_evidence_missing"
            refused = client.post(
                f"/deployments/{A}/approve",
                headers=AUTH,
                json={"plan_id": detail["current_plan"]["plan_id"], "plan_hash": "a" * 64},
            )
            assert refused.status_code == 409
            with db.transaction() as c:
                c.execute("UPDATE deployments SET status='deleted' WHERE id=%s", (A,))
            response = client.post(
                "/deployments", headers=AUTH, json={"name": "blocked", "disk_gib": 8}
            )
            assert response.status_code == 409
            assert response.json()["error"]["code"] == "recovery_required"
        assert provisioner.applies == 0
    with pytest.raises(psycopg.IntegrityError):
        db.migrate()
    assert db.schema_version() == 9
    with db.read() as c:
        assert c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall() == before


@pytest.mark.parametrize(
    ("table", "column", "payload"),
    [
        ("jobs", "result_json", []),
        ("jobs", "result_json", "scalar"),
        ("jobs", "result_json", 7),
        ("plans", "preview_json", []),
        ("plans", "preview_json", None),
        ("plans", "preview_json", {"changes": {}}),
        ("plans", "preview_json", {"changes": [1]}),
        ("plans", "preview_json", {"changes": [{"action": "create", "address": "x"}]}),
        ("plans", "preview_json", {"warnings": [1]}),
        ("plans", "cost_json", {}),
        ("plans", "provider_versions_json", []),
        ("plans", "provider_versions_json", {"aws": 1}),
        ("plans", "prior_resource_ids_json", {}),
        ("plans", "prior_resource_ids_json", [{}]),
        ("worker_heartbeats", "checks_json", []),
        ("audit_events", "detail_json", []),
        ("idempotency_records", "response_json", []),
        ("idempotency_records", "response_json", {}),
        ("agent_attempts", "response_json", []),
    ],
)
def test_import_rejects_wrong_json_shapes_and_corrected_source_is_usable(
    db: Database, tmp_path: Path, table: str, column: str, payload: Any
) -> None:
    path = tmp_path / "source.sqlite3"
    legacy_source(path)
    empty_target(db)
    with sqlite3.connect(path) as c:
        original = c.execute(f"SELECT {column} FROM {table} LIMIT 1").fetchone()[0]  # noqa: S608 - fixed parameter inventory
        c.execute(f"UPDATE {table} SET {column}=?", (json.dumps(payload),))  # noqa: S608 - fixed parameter inventory
    snapshot = path.read_bytes()
    with pytest.raises(ValueError, match=rf"invalid historical JSON shape: {table}\.{column}"):
        import_snapshot(db, path, issuer=ISSUER, source_auth="development")
    assert path.read_bytes() == snapshot
    with db.read() as c:
        assert c.execute("SELECT count(*) FROM offline_imports").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM deployments").fetchone()[0] == 0
    with sqlite3.connect(path) as c:
        c.execute(f"UPDATE {table} SET {column}=?", (original,))  # noqa: S608 - fixed parameter inventory
    counts = import_snapshot(db, path, issuer=ISSUER, source_auth="development")
    assert import_snapshot(db, path, issuer=ISSUER, source_auth="development") == counts
    settings = make_settings(tmp_path)
    with TestClient(
        create_app(settings, build_container(settings)), raise_server_exceptions=False
    ) as client:
        for route in ("/jobs/job_" + "d" * 32, f"/deployments/{A}", "/deployments"):
            response = client.get(route, headers=AUTH)
            assert response.status_code == 200, response.text


@pytest.mark.parametrize("payload", [{}, None, {"retained": {"items": [1, "two", None]}}])
def test_valid_job_result_shapes_survive_import_and_api(
    db: Database, tmp_path: Path, payload: Any
) -> None:
    path = tmp_path / "source.sqlite3"
    legacy_source(path)
    empty_target(db)
    with sqlite3.connect(path) as c:
        c.execute("UPDATE jobs SET result_json=?", (json.dumps(payload),))
    import_snapshot(db, path, issuer=ISSUER, source_auth="development")
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings, build_container(settings))) as client:
        response = client.get("/jobs/job_" + "d" * 32, headers=AUTH)
        assert response.status_code == 200
        assert response.json()["result"] == payload


@pytest.mark.parametrize(
    ("job", "plan", "discharger"),
    [
        (None, P, None),
        (J, None, None),
        (J, P, None),
        ("job_" + "d" * 32, P, None),
        ("job_" + "f" * 32, "plan_" + "c" * 32, None),
        (None, None, J),
        (None, None, "job_" + "d" * 32),
        (None, None, "job_" + "f" * 32),
    ],
)
def test_postgresql_recovery_bindings_reject_invalid_apply_links(
    db: Database, tmp_path: Path, job: str | None, plan: str | None, discharger: str | None
) -> None:
    path = tmp_path / "source.sqlite3"
    legacy_source(path)
    empty_target(db)
    import_snapshot(db, path, issuer=ISSUER, source_auth="development")
    with db.transaction() as c:
        db.ensure_user(c, Principal("dev:other", "dev"))
        other_history(c, "dev:other", "%s")
        c.execute(
            (
                "INSERT INTO jobs(id,owner_id,deployment_id,plan_id,kind,status,payload_h"
                "ash,created_at) VALUES(%s,'dev:legacy',%s,%s,'plan','failed','x',now())"
            ),
            ("job_" + "f" * 32, A, "plan_" + "c" * 32),
        )
    with pytest.raises(psycopg.IntegrityError), db.transaction() as c:
        c.execute(
            (
                "INSERT INTO recovery_obligations(deployment_id,job_id,plan_id,reason,evi"
                "dence,created_at,discharged_at,discharged_by_job_id) VALUES(%s,%s,%s,'ne"
                "gative-control',%s,now(),%s,%s)"
            ),
            (
                A,
                job,
                plan,
                "captured" if discharger else "uncaptured",
                "2026-10-30T00:01:00+00:00" if discharger else None,
                discharger,
            ),
        )
    with db.read() as c:
        assert (
            c.execute(
                "SELECT count(*) FROM recovery_obligations WHERE reason='negative-control'"
            ).fetchone()[0]
            == 0
        )
        assert unresolved_create_obligation(c, "dev:legacy") == A


def test_null_unknown_references_remain_uncaptured_and_jobs_cannot_invalidate_history(
    db: Database, tmp_path: Path
) -> None:
    path = tmp_path / "source.sqlite3"
    legacy_source(path)
    empty_target(db)
    import_snapshot(db, path, issuer=ISSUER, source_auth="development")
    with db.transaction() as c:
        c.execute(
            (
                "INSERT INTO recovery_obligations(deployment_id,reason,evidence,created_a"
                "t) VALUES(%s,'unknown-reference','uncaptured',now())"
            ),
            (A,),
        )
    worker = Worker(make_settings(tmp_path), db, SimulatedProvisioner(tmp_path / "sim"))
    worker._retry_uncaptured(A)
    with db.read() as c:
        assert (
            c.execute(
                "SELECT evidence FROM recovery_obligations WHERE reason='unknown-reference'"
            ).fetchone()[0]
            == "uncaptured"
        )
    for job, column, value in [
        ("job_" + "d" * 32, "kind", "plan"),
        ("job_" + "e" * 32, "status", "failed"),
    ]:
        with pytest.raises(psycopg.errors.CheckViolation), db.transaction() as c:
            c.execute(
                sql.SQL("UPDATE jobs SET {}=%s WHERE id=%s").format(sql.Identifier(column)),
                (value, job),
            )


def test_signed_jwt_control_accepts_carol_and_rejects_reserved_dev_subject(
    tmp_path: Path, db: Database
) -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    from test_config_and_auth import JWT_SETTINGS, _authenticator, _token

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    settings = make_settings(tmp_path, **JWT_SETTINGS)
    container = build_container(settings, authenticator=_authenticator(tmp_path, private))
    with TestClient(create_app(settings, container)) as client:
        for subject, status in [("carol", 200), ("dev:carol", 401)]:
            response = client.get(
                "/me", headers={"Authorization": "Bearer " + _token(private, sub=subject)}
            )
            assert response.status_code == status


def test_completed_assistant_reply_shape_is_checked_without_rewriting_history(
    db: Database, tmp_path: Path
) -> None:
    from unitcompute.agent.service import _stored_reply

    path = tmp_path / "source.sqlite3"
    legacy_source(path)
    empty_target(db)
    with sqlite3.connect(path) as c:
        c.execute("UPDATE agent_attempts SET status='succeeded',response_json='{}'")
    with pytest.raises(
        ValueError, match=r"invalid historical JSON shape: agent_attempts\.response_json"
    ):
        import_snapshot(db, path, issuer=ISSUER, source_auth="development")
    reply = {
        "session_id": "chat_" + "a" * 32,
        "reply": "retained answer",
        "model": "legacy",
        "proposal": None,
        "clarifications": [],
        "tool_calls": [],
        "approval_note": "approval required",
    }
    with sqlite3.connect(path) as c:
        c.execute("UPDATE agent_attempts SET response_json=?", (json.dumps(reply),))
    import_snapshot(db, path, issuer=ISSUER, source_auth="development")
    with db.read() as c:
        stored = c.execute("SELECT response_json FROM agent_attempts").fetchone()[0]
    assert json.loads(stored) == reply
    assert _stored_reply(stored).reply == "retained answer"


def test_published_nine_upgrade_retains_receipt_hashes_and_all_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    path = tmp_path / "source.sqlite3"
    legacy_source(path)
    files = database._migration_files()
    tables = (
        "plans",
        "jobs",
        "audit_events",
        "deployment_resources",
        "recovery_obligations",
        "offline_imports",
    )
    with monkeypatch.context() as old:
        old.setattr(database, "_migration_files", lambda: files[:9])
        old.setattr(database, "LATEST_SCHEMA_VERSION", 9)
        db.migrate()
        empty_target(db)
        counts = import_snapshot(db, path, issuer=ISSUER, source_auth="development")
        with db.read() as c:
            checksums = c.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall()
            histories = {
                t: c.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(t))).fetchall()
                for t in tables
            }
    assert db.migrate() == [10]
    assert db.migrate() == []
    assert import_snapshot(db, path, issuer=ISSUER, source_auth="development") == counts
    with db.read() as c:
        assert (
            c.execute(
                "SELECT * FROM schema_migrations WHERE version<=9 ORDER BY version"
            ).fetchall()
            == checksums
        )
        assert {
            t: c.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(t))).fetchall()
            for t in tables
        } == histories
