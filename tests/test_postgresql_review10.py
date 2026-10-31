from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql

from conftest import make_settings
from pg_history import seed_history
from unitcompute.api.app import build_container, create_app
from unitcompute.auth import Principal
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.services.deployments import unresolved_create_obligation
from unitcompute.worker import Worker

A, B = "dep_" + "b" * 32, "dep_" + "1" * 32
P, J = "plan_" + "2" * 32, "job_" + "3" * 32
ISSUER = "https://old.test"
AUTH = {"Authorization": "Bearer dev:legacy"}


def other_history(c: Any, owner: str, marker: str = "%s") -> None:
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


@pytest.mark.parametrize("owner", ["dev:other", "dev:legacy"])
def test_existing_nine_corruption_upgrade_rejects_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner: str
) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    files = database._migration_files()
    with monkeypatch.context() as old:
        old.setattr(database, "_migration_files", lambda: files[:9])
        old.setattr(database, "LATEST_SCHEMA_VERSION", 9)
        db.migrate()
        seed_history(db)
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

    with pytest.raises(psycopg.IntegrityError):
        db.migrate()
    assert db.schema_version() == 9
    with db.read() as c:
        assert c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall() == before


@pytest.mark.parametrize("payload", [{}, None, {"retained": {"items": [1, "two", None]}}])
def test_valid_job_result_shapes_survive_api(db: Database, tmp_path: Path, payload: Any) -> None:
    seed_history(db)
    with db.transaction() as c:
        c.execute("UPDATE jobs SET result_json=%s", (json.dumps(payload),))
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
    seed_history(db)
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
    seed_history(db)
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


@pytest.mark.parametrize("version", [9, 10])
def test_published_prior_upgrade_retains_receipt_hashes_and_all_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: int
) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
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
        old.setattr(database, "_migration_files", lambda: files[:version])
        old.setattr(database, "LATEST_SCHEMA_VERSION", version)
        db.migrate()
        seed_history(db)
        with db.transaction() as c:
            c.execute(
                "INSERT INTO offline_imports(fingerprint,counts) "
                "VALUES('retained-receipt','{\"rows\":1}')"
            )
        with db.read() as c:
            checksums = c.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall()
            histories = {
                t: c.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(t))).fetchall()
                for t in tables
            }
    assert db.migrate() == list(range(version + 1, 12))
    assert db.migrate() == []
    with db.read() as c:
        assert (
            c.execute(
                "SELECT * FROM schema_migrations WHERE version<=%s ORDER BY version", (version,)
            ).fetchall()
            == checksums
        )
        assert {
            t: c.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(t))).fetchall()
            for t in tables
        } == histories
