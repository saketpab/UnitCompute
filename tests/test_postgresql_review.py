from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from conftest import Harness, auth, create_and_plan, make_settings
from pg_history import seed_history
from unitcompute.api.app import build_container, create_app
from unitcompute.auth import JwtAuthenticator, Principal
from unitcompute.db.database import Database
from unitcompute.provisioning.base import NetworkTargets, owner_tag
from unitcompute.provisioning.terraform import build_tfvars
from unitcompute.services.catalog import CatalogService
from unitcompute.services.deployments import DeploymentService
from unitcompute.worker import Worker

DEP = "dep_" + "b" * 32
PLAN = "plan_" + "c" * 32
ISSUER = "https://old.test"


@pytest.mark.parametrize("kind", ["create", "destroy"])
def test_native_resource_replan_preserves_identity_and_approval(
    db: Database, tmp_path: Path, kind: str
) -> None:
    seed_history(db, native=True)
    settings = make_settings(
        tmp_path,
        provisioner="terraform",
        auth_mode="jwt",
        auth_issuer=ISSUER,
        auth_audience="review",
        auth_jwks_url=ISSUER + "/jwks",
        auth_required_group="review",
        aws_account_id="123456789012",
        vpc_id="vpc-0123456789abcdef0",
        subnet_id="subnet-0123456789abcdef0",
        instance_profile_name="review",
        state_bucket="review-only-bucket",
        plan_role_arn="arn:aws:iam::123456789012:role/ReviewPlan",
        apply_role_arn="arn:aws:iam::123456789012:role/ReviewApply",
    )
    svc = DeploymentService(db, settings)
    principal = Principal("legacy-subject", "jwt", ISSUER)
    with db.read() as c:
        before = c.execute(
            "SELECT account_scope,provider_resource_id,approved_config,approved_at FROM resources"
        ).fetchone()
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    authenticator = JwtAuthenticator(settings, key_resolver=lambda _token: private.public_key())
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "review",
            "sub": principal.subject,
            "iat": now,
            "exp": now + 300,
            "groups": ["review"],
        },
        private,
        algorithm="RS256",
    )
    container = build_container(settings, authenticator=authenticator, deployments=svc)
    with TestClient(create_app(settings, container)) as client:
        route = "plan" if kind == "create" else "deletion-plan"
        response = client.post(
            f"/deployments/{DEP}/{route}", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 202, response.text
    with db.read() as c:
        assert (
            c.execute(
                "SELECT account_scope,provider_resource_id,approved_config,approved_at "
                "FROM resources"
            ).fetchone()
            == before
        )
    assert svc.get_deployment(principal, DEP).current_plan.status == "pending"


@pytest.mark.parametrize("status", ["pending", "ready", "failed"])
def test_native_projection_with_unapproved_current_plan(
    db: Database, tmp_path: Path, status: str
) -> None:
    seed_history(db, native=True)
    principal = Principal("legacy-subject", "jwt", ISSUER)
    pending = "plan_" + "f" * 32
    with db.transaction() as c:
        c.execute(
            "INSERT INTO plans(id,deployment_id,owner_id,kind,status,provisioner,config_hash,"
            "region,state_key,template_version,created_at) SELECT %s,deployment_id,owner_id,"
            "kind,%s,provisioner,config_hash,region,state_key,template_version,created_at "
            "FROM plans WHERE id=%s",
            (pending, status, PLAN),
        )
        c.execute(
            "UPDATE deployments SET current_plan_id=%s WHERE owner_id=%s",
            (pending, principal.owner_id),
        )
    with db.read() as c:
        row = c.execute(
            "SELECT account_scope,provider_resource_id,approved_config FROM resources"
        ).fetchone()
        assert row["account_scope"] == "123456789012"
        assert row["provider_resource_id"] == "i-0123456789abcdef0"
        assert json.loads(row["approved_config"])["plan_id"] == PLAN


def test_worker_tfvars_use_immutable_cloud_marker(db: Database, tmp_path: Path) -> None:
    seed_history(db, native=True)
    with db.read() as c:
        row = c.execute("SELECT * FROM deployments").fetchone()
    spec = Worker._spec(row)
    assert spec.owner_tag == owner_tag("legacy-subject")
    assert spec.owner_tag != owner_tag(row["owner_id"])
    assert build_tfvars(
        spec, NetworkTargets("123456789012", "vpc-x", "subnet-x", "profile"), "ami-x"
    )["owner_tag"] == owner_tag("legacy-subject")


@pytest.mark.parametrize("user", ["alice", "bob"])
def test_current_plan_constraint_rejects_other_deployment(harness: Harness, user: str) -> None:
    first = create_and_plan(harness)
    with harness.db.transaction() as c:
        c.execute("UPDATE deployments SET status='deleted' WHERE id=%s", (first["id"],))
    second = create_and_plan(harness, user=user)
    with pytest.raises(psycopg.errors.ForeignKeyViolation), harness.db.transaction() as c:
        c.execute(
            "UPDATE deployments SET current_plan_id=%s WHERE id=%s",
            (first["current_plan"]["plan_id"], second["id"]),
        )
    assert (
        harness.client.get(f"/deployments/{second['id']}", headers=auth(user)).json()[
            "current_plan"
        ]["plan_id"]
        == second["current_plan"]["plan_id"]
    )


@pytest.mark.parametrize(
    "config",
    [
        {"schema_version": 1},
        {"schema_version": 1, "settings": {}},
        {"schema_version": 1, "kind": "storage"},
        {"schema_version": 1, "kind": None, "settings": {}},
        {"schema_version": 1, "kind": "storage", "settings": None},
        {"schema_version": None, "kind": "storage", "settings": {}},
    ],
)
def test_provider_required_structure(db: Database, config: dict[str, Any]) -> None:
    with db.read() as c:
        user = c.execute("SELECT id FROM users WHERE owner_id='dev:alice'").fetchone()[0]
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction() as c:
        c.execute(
            (
                "INSERT INTO resources(user_id,owner_id,name,provider,native_type,execution_"
                "mechanism,status,created_at,updated_at,provider_config) VALUES(%s,'dev:alic"
                "e','x','aws','storage:bucket','sdk','observed',now(),now(),%s)"
            ),
            (user, json.dumps(config)),
        )


def test_job_and_resource_reads_redact_structured_values(harness: Harness) -> None:
    detail = create_and_plan(harness)
    job = detail["latest_job"]["id"]
    with harness.db.transaction() as c:
        c.execute(
            "UPDATE jobs SET result_json=%s WHERE id=%s",
            (r'{"pass\u0077ord":"synthetic-review-only"}', job),
        )
        c.execute(
            "UPDATE resources SET provider_config=%s",
            (
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "storage",
                        "settings": {"name": "password=synthetic-review-only"},
                    }
                ),
            ),
        )
    assert harness.client.get(f"/jobs/{job}", headers=auth()).json()["result"] == {
        "password": "[REDACTED]"
    }
    result = harness.client.get("/resources", headers=auth()).json()
    assert "synthetic-review-only" not in json.dumps(result)
    assert (
        CatalogService(harness.db).resources(Principal("dev:alice", "dev"), 50, None)["items"][0][
            "provider_config"
        ]["settings"]["name"]
        == "password=[REDACTED]"
    )


def test_patch_cors_preflight_and_authenticated_updates(db: Database, tmp_path: Path) -> None:
    settings = make_settings(tmp_path, cors_origins=("https://review.example",))
    with TestClient(create_app(settings, build_container(settings))) as c:
        chat = c.post("/chats", headers=auth(), json={"title": "before"}).json()
        for path, body in (
            ("/me", {"name": "new name"}),
            (f"/chats/{chat['id']}", {"title": "after"}),
        ):
            preflight = c.options(
                path,
                headers={
                    "Origin": "https://review.example",
                    "Access-Control-Request-Method": "PATCH",
                    "Access-Control-Request-Headers": "Authorization,Content-Type",
                },
            )
            assert preflight.status_code == 200
            assert preflight.headers["access-control-allow-origin"] == "https://review.example"
            response = c.patch(
                path, headers={**auth(), "Origin": "https://review.example"}, json=body
            )
            assert response.status_code == 200, response.text
            assert response.headers["access-control-allow-origin"] == "https://review.example"
        assert (
            c.options(
                "/me",
                headers={
                    "Origin": "https://other.example",
                    "Access-Control-Request-Method": "PATCH",
                },
            ).status_code
            == 400
        )


def test_upgrade_from_published_eight_preserves_history_and_checksums(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unitcompute.db import database

    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    files = database._migration_files()
    with monkeypatch.context() as old:
        old.setattr(database, "_migration_files", lambda: files[:8])
        old.setattr(database, "LATEST_SCHEMA_VERSION", 8)
        db.migrate()
        seed_history(db, native=True)
        with db.read() as c:
            checksums = c.execute(
                "SELECT version,checksum FROM schema_migrations ORDER BY version"
            ).fetchall()
            history = c.execute(
                "SELECT * FROM deployment_resources ORDER BY resource_id,source,parent_id"
            ).fetchall()
            obligations = c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall()
    assert db.migrate() == [9, 10, 11]
    assert db.migrate() == []
    with db.read() as c:
        assert (
            c.execute(
                "SELECT version,checksum FROM schema_migrations WHERE version<=8 ORDER BY version"
            ).fetchall()
            == checksums
        )
        assert (
            c.execute(
                "SELECT * FROM deployment_resources ORDER BY resource_id,source,parent_id"
            ).fetchall()
            == history
        )
        assert c.execute("SELECT * FROM recovery_obligations ORDER BY id").fetchall() == obligations
        assert c.execute("SELECT account_scope FROM resources").fetchone()[0] == "123456789012"


def test_upgrade_rejects_invalid_provider_rows_without_rewriting_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unitcompute.db import database

    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    files = database._migration_files()
    with monkeypatch.context() as old:
        old.setattr(database, "_migration_files", lambda: files[:8])
        db.migrate()
        with db.transaction() as c:
            c.execute(
                "INSERT INTO resources(user_id,owner_id,name,provider,native_type,"
                "execution_mechanism,"
                "status,created_at,updated_at,provider_config) SELECT id,owner_id,'x','aws',"
                "'storage:bucket','sdk','observed',now(),now(),'{\"schema_version\":1}' "
                "FROM users WHERE owner_id='dev:alice'"
            )
    with pytest.raises(psycopg.errors.CheckViolation):
        db.migrate()
    assert db.schema_version() == 8
    with db.read() as c:
        assert json.loads(c.execute("SELECT provider_config FROM resources").fetchone()[0]) == {
            "schema_version": 1
        }


def test_projection_keeps_last_approval_when_approval_timestamps_tie(harness: Harness) -> None:
    from psycopg import sql

    from conftest import launch

    detail = launch(harness)
    with harness.db.transaction() as c:
        original = c.execute(
            "SELECT * FROM plans WHERE id=%s", (detail["current_plan"]["plan_id"],)
        ).fetchone()
        next_plan = dict(original)
        next_plan.update(id="plan_" + "0" * 32, plan_hash="b" * 64, status="applied")
        names = list(next_plan)
        c.execute(
            sql.SQL("INSERT INTO plans ({}) VALUES ({})").format(
                sql.SQL(",").join(map(sql.Identifier, names)),
                sql.SQL(",").join(sql.Placeholder() for _ in names),
            ),
            tuple(next_plan[n] for n in names),
        )
        c.execute(
            "UPDATE deployments SET current_plan_id=%s WHERE id=%s", (next_plan["id"], detail["id"])
        )
    with harness.db.read() as c:
        approved = json.loads(c.execute("SELECT approved_config FROM resources").fetchone()[0])
    assert approved["plan_id"] == next_plan["id"]
    assert approved["plan_hash"] == next_plan["plan_hash"]
    with harness.db.transaction() as c:
        pending = dict(next_plan)
        pending.update(
            id="plan_" + "1" * 32,
            approved_at=None,
            approved_by=None,
            plan_hash=None,
            status="pending",
        )
        c.execute(
            sql.SQL("INSERT INTO plans ({}) VALUES ({})").format(
                sql.SQL(",").join(map(sql.Identifier, names)),
                sql.SQL(",").join(sql.Placeholder() for _ in names),
            ),
            tuple(pending[n] for n in names),
        )
        c.execute(
            "UPDATE deployments SET current_plan_id=%s WHERE id=%s", (pending["id"], detail["id"])
        )
    with harness.db.read() as c:
        assert (
            json.loads(c.execute("SELECT approved_config FROM resources").fetchone()[0]) == approved
        )
