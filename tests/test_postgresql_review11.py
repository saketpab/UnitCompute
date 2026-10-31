from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql

from conftest import make_settings
from pg_history import DEP, PLAN, SOURCE_JOB, SUCCESS_JOB, seed_history
from unitcompute.api.app import build_container, create_app
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.provisioning.simulated import SimulatedProvisioner
from unitcompute.services.deployments import canonical_hash, unresolved_create_obligation
from unitcompute.worker import Worker

AUTH = {"Authorization": "Bearer dev:legacy"}
CHAT = "chat_" + "a" * 32
REPLY = {
    "session_id": CHAT,
    "reply": "retained answer",
    "model": "recorded",
    "proposal": None,
    "clarifications": [],
    "tool_calls": [],
    "approval_note": "approval required",
}


def insert_obligation(
    c: Any, evidence: str, source: str | None, discharge: str | None, stamped: bool = True
) -> None:
    c.execute(
        "INSERT INTO recovery_obligations(deployment_id,job_id,plan_id,reason,evidence,"
        "created_at,discharged_at,discharged_by_job_id) VALUES(%s,%s,%s,'completion-test',%s,"
        "now(),CASE WHEN %s THEN now() END,%s)",
        (DEP, source, PLAN, evidence, stamped, discharge),
    )


@pytest.mark.parametrize(
    ("evidence", "source", "discharge", "stamped"),
    [
        ("uncaptured", SOURCE_JOB, None, True),
        ("uncaptured", SOURCE_JOB, SUCCESS_JOB, True),
        ("uncaptured", SOURCE_JOB, SUCCESS_JOB, False),
        ("captured", SUCCESS_JOB, SUCCESS_JOB, True),
        ("captured", SUCCESS_JOB, SOURCE_JOB, True),
    ],
)
def test_direct_completion_contradictions_are_atomic(
    db: Database, evidence: str, source: str | None, discharge: str | None, stamped: bool
) -> None:
    seed_history(db)
    with db.read() as c:
        before = c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall()
    with pytest.raises(psycopg.IntegrityError), db.transaction() as c:
        insert_obligation(c, evidence, source, discharge, stamped)
    with db.read() as c:
        assert c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall() == before
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction() as c:
        c.execute("UPDATE jobs SET sequence=-1 WHERE id=%s", (SUCCESS_JOB,))


@pytest.mark.parametrize("version", [9, 10])
@pytest.mark.parametrize("corruption", ["uncaptured", "ordering"])
def test_upgrade_rejects_corrupt_completion_without_rewriting_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: int, corruption: str
) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    files = database._migration_files()
    with monkeypatch.context() as old:
        old.setattr(database, "_migration_files", lambda: files[:version])
        old.setattr(database, "LATEST_SCHEMA_VERSION", version)
        db.migrate()
        seed_history(db)
        with db.transaction() as c:
            insert_obligation(
                c,
                "uncaptured" if corruption == "uncaptured" else "captured",
                SOURCE_JOB if corruption == "uncaptured" else SUCCESS_JOB,
                SUCCESS_JOB,
            )
            c.execute("INSERT INTO offline_imports(fingerprint,counts) VALUES('keep','{}')")
        with db.read() as c:
            before = {
                t: c.execute(
                    sql.SQL("SELECT * FROM {} ORDER BY 1").format(sql.Identifier(t))
                ).fetchall()
                for t in (
                    "schema_migrations",
                    "recovery_obligations",
                    "jobs",
                    "plans",
                    "offline_imports",
                )
            }
    with pytest.raises(psycopg.errors.CheckViolation):
        db.migrate()
    assert db.schema_version() == version
    with db.read() as c:
        assert {
            t: c.execute(
                sql.SQL("SELECT * FROM {} ORDER BY 1").format(sql.Identifier(t))
            ).fetchall()
            for t in before
        } == before


@pytest.mark.parametrize("status", ["apply_failed", "applied"])
@pytest.mark.parametrize("corruption", ["uncaptured", "ordering"])
def test_corrupt_completion_blocks_api_worker_and_retention(
    db: Database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
    corruption: str,
) -> None:
    seed_history(db)
    with db.transaction() as c:
        c.execute(
            "ALTER TABLE recovery_obligations DROP CONSTRAINT recovery_uncaptured_not_discharged"
        )
        c.execute("DROP TRIGGER recovery_apply_bindings ON recovery_obligations")
        c.execute("DROP TRIGGER recovery_obligations_forward_only ON recovery_obligations")
        c.execute(
            "INSERT INTO jobs(id,owner_id,deployment_id,plan_id,kind,status,payload_hash,"
            "created_at,sequence) SELECT 'job_older',owner_id,deployment_id,plan_id,'apply',"
            "'succeeded','h',now(),-1 FROM jobs WHERE id=%s",
            (SOURCE_JOB,),
        )
        c.execute(
            "UPDATE recovery_obligations SET evidence=%s,discharged_at=now(),"
            "discharged_by_job_id=%s",
            (
                "uncaptured" if corruption == "uncaptured" else "captured",
                SUCCESS_JOB if corruption == "uncaptured" else "job_older",
            ),
        )
        c.execute(
            "UPDATE plans SET status=%s,created_at=now()-interval '200 days' WHERE id=%s",
            (status, PLAN),
        )
    settings = make_settings(tmp_path)
    provisioner = SimulatedProvisioner(settings.data_dir)
    worker = Worker(settings, db, provisioner)
    worker.self_check()
    monkeypatch.setattr(worker, "_self_check_due", lambda: False)
    monkeypatch.setattr(worker, "refresh_readiness", lambda: None)
    directory = settings.workdir_root / DEP / PLAN
    directory.mkdir(parents=True)
    evidence = directory / "errored.tfstate"
    evidence.write_text("retained recovery evidence")
    with db.read() as c:
        before = c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall()
        assert unresolved_create_obligation(c, "dev:legacy") == DEP
    worker._retry_uncaptured(DEP)
    worker.housekeeping()
    from unitcompute import admin

    monkeypatch.setattr(admin, "load_settings", lambda: settings)
    capsys.readouterr()
    assert admin.main(["recovery-report"]) == 0
    entries = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert entries[0]["open_recovery_obligations"]
    assert evidence.read_text() == "retained recovery evidence"
    with db.read() as c:
        assert c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall() == before
    with TestClient(create_app(settings, build_container(settings))) as client:
        response = client.post(f"/deployments/{DEP}/plan", headers=AUTH)
        assert response.status_code == 202
        assert worker.run_once()
        detail = client.get(f"/deployments/{DEP}", headers=AUTH).json()
        assert detail["current_plan"]["error"]["code"] == "recovery_evidence_missing"
        assert (
            client.post(
                f"/deployments/{DEP}/approve",
                headers=AUTH,
                json={"plan_id": detail["current_plan"]["plan_id"], "plan_hash": "a" * 64},
            ).status_code
            == 409
        )
        with db.transaction() as c:
            c.execute("UPDATE deployments SET status='deleted' WHERE id=%s", (DEP,))
        response = client.post(
            "/deployments", headers=AUTH, json={"name": "blocked", "disk_gib": 8}
        )
        assert (
            response.status_code == 409 and response.json()["error"]["code"] == "recovery_required"
        )


def attempt(db: Database, status: str, payload: Any) -> dict[str, str]:
    body = {"session_id": CHAT, "message": "retained request"}
    with db.transaction() as c:
        c.execute(
            "INSERT INTO chat_sessions(id,owner_id,turns,created_at,updated_at) "
            "VALUES(%s,'dev:alice',1,now(),now())",
            (CHAT,),
        )
        c.execute(
            "INSERT INTO agent_attempts(owner_id,session_id,status,idempotency_key,"
            "payload_hash,response_json,created_at,lease_expires_at) "
            "VALUES('dev:alice',%s,%s,'retained-key-001',%s,%s,now(),now()+interval '1 hour')",
            (CHAT, status, canonical_hash(body), None if payload is None else json.dumps(payload)),
        )
    return body


@pytest.mark.parametrize(
    "payload",
    [None, [], {}, {"reply": "missing required fields"}, {**REPLY, "clarifications": [1]}],
)
def test_completed_reply_requires_readable_payload(db: Database, payload: Any) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        attempt(db, "succeeded", payload)
    with db.read() as c:
        assert c.execute("SELECT count(*) FROM agent_attempts").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM chat_sessions").fetchone()[0] == 0


@pytest.mark.parametrize("status", ["succeeded", "reserved", "failed", "corrupt"])
def test_assistant_replay_after_restart_never_reinvokes_model(
    db: Database, tmp_path: Path, status: str
) -> None:
    if status == "corrupt":
        with db.transaction() as c:
            c.execute("ALTER TABLE agent_attempts DROP CONSTRAINT completed_assistant_reply")
    body = attempt(
        db, "succeeded" if status == "corrupt" else status, REPLY if status == "succeeded" else None
    )
    settings = make_settings(tmp_path)
    for _ in range(2):
        container = build_container(settings)

        def no_model() -> Any:
            raise AssertionError("model must not be invoked for replay/in-flight refusal")

        container.agent._model_factory = no_model
        with TestClient(create_app(settings, container), raise_server_exceptions=False) as client:
            response = client.post(
                "/agent/messages",
                headers={
                    "Authorization": "Bearer dev:alice",
                    "Idempotency-Key": "retained-key-001",
                },
                json=body,
            )
            expected = {"succeeded": 200, "corrupt": 503, "reserved": 409, "failed": 409}[status]
            assert response.status_code == expected, response.text
            if status == "corrupt":
                assert response.json()["error"]["code"] == "stored_reply_invalid"
            if status == "succeeded":
                assert response.json()["reply"] == REPLY["reply"]
        with db.read() as c:
            assert c.execute("SELECT count(*) FROM agent_attempts").fetchone()[0] == 1


@pytest.mark.parametrize("payload", [None, []])
def test_upgrade_rejects_unreadable_success_without_rewriting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: Any
) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    files = database._migration_files()
    with monkeypatch.context() as old:
        old.setattr(database, "_migration_files", lambda: files[:10])
        db.migrate()
        attempt(db, "succeeded", payload)
        with db.read() as c:
            before = c.execute("SELECT * FROM agent_attempts").fetchall()
    with pytest.raises(psycopg.errors.CheckViolation):
        db.migrate()
    assert db.schema_version() == 10
    with db.read() as c:
        assert c.execute("SELECT * FROM agent_attempts").fetchall() == before


@pytest.mark.parametrize("final_state", [True, False])
def test_restarted_worker_preserves_uncertainty_or_repairs_and_discharges(
    db: Database, tmp_path: Path, final_state: bool
) -> None:
    from test_worker_recovery import FailingApply
    from unitcompute.provisioning.base import ProvisioningError

    settings = make_settings(tmp_path)
    headers = {"Authorization": "Bearer dev:alice"}
    with TestClient(create_app(settings, build_container(settings))) as client:
        dep = client.post(
            "/deployments", headers=headers, json={"name": "restart", "disk_gib": 8}
        ).json()["deployment_id"]
        healthy = Worker(settings, db, SimulatedProvisioner(settings.data_dir))
        assert healthy.run_once()
        plan = client.get("/deployments/" + dep, headers=headers).json()["current_plan"]
        assert (
            client.post(
                f"/deployments/{dep}/approve",
                headers=headers,
                json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
            ).status_code
            == 202
        )
        partial = Worker(
            settings,
            db,
            FailingApply(
                settings.data_dir,
                ProvisioningError("controlled_partial", "controlled partial outcome"),
                True,
                final_state=final_state,
            ),
        )
        assert partial.run_once()
    restarted_db = Database(db.dsn, db.schema)
    worker = Worker(settings, restarted_db, SimulatedProvisioner(settings.data_dir))
    assert not worker.run_once()
    with TestClient(create_app(settings, build_container(settings))) as client:
        assert client.post(f"/deployments/{dep}/plan", headers=headers).status_code == 202
        assert worker.run_once()
        detail = client.get("/deployments/" + dep, headers=headers).json()
        with db.read() as c:
            obligation = c.execute("SELECT * FROM recovery_obligations").fetchone()
            assert obligation["discharged_at"] is None
        if not final_state:
            assert obligation["evidence"] == "uncaptured"
            assert detail["current_plan"]["error"]["code"] == "recovery_evidence_missing"
            return
        assert obligation["evidence"] == "captured"
        plan = detail["current_plan"]
        assert (
            client.post(
                f"/deployments/{dep}/approve",
                headers=headers,
                json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
            ).status_code
            == 202
        )
        assert worker.run_once()
        with db.read() as c:
            row = c.execute(
                "SELECT o.*,src.sequence AS source_sequence,dst.sequence AS discharge_sequence, "
                "dst.status AS discharge_status FROM recovery_obligations o "
                "JOIN jobs src ON src.id=o.job_id "
                "JOIN jobs dst ON dst.id=o.discharged_by_job_id"
            ).fetchone()
            assert row["discharged_at"] is not None and row["discharge_status"] == "succeeded"
            assert row["discharge_sequence"] > row["source_sequence"]
        assert client.post(f"/deployments/{dep}/deletion-plan", headers=headers).status_code == 202
        assert worker.run_once()
        plan = client.get("/deployments/" + dep, headers=headers).json()["current_plan"]
        assert (
            client.post(
                f"/deployments/{dep}/approve",
                headers=headers,
                json={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]},
            ).status_code
            == 202
        )
        assert worker.run_once()
        assert client.get("/deployments/" + dep, headers=headers).json()["status"] == "deleted"


@pytest.mark.parametrize(
    ("evidence", "stamped"), [("captured", False), ("captured", True), ("not_needed", True)]
)
def test_supported_unknown_recovery_references_remain_valid(
    db: Database, evidence: str, stamped: bool
) -> None:
    seed_history(db)
    with db.transaction() as c:
        insert_obligation(c, evidence, None, None, stamped)
    with db.read() as c:
        row = c.execute(
            "SELECT * FROM recovery_obligations WHERE reason='completion-test'"
        ).fetchone()
        assert row["job_id"] is None and row["discharged_by_job_id"] is None
        assert row["evidence"] == evidence
