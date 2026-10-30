from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg
import pytest

from conftest import Harness, auth, create_and_plan, make_settings
from unitcompute.auth import Principal
from unitcompute.db import database
from unitcompute.db.database import Database
from unitcompute.db.import_sqlite import import_snapshot


def test_fresh_repeated_concurrent_migrations(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: db.migrate(), range(4)))
    assert sorted(len(r) for r in results) == [0, 0, 0, 8]
    assert db.migrate() == []


def test_failed_migration_rolls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = make_settings(tmp_path)
    db = Database(settings.database_url, settings.database_schema)
    files = database._migration_files()
    monkeypatch.setattr(
        database,
        "_migration_files",
        lambda: [*files, (9, "CREATE TABLE rollback_probe (id int); SELECT nonexistent_column;")],
    )
    with pytest.raises(psycopg.errors.UndefinedColumn):
        db.migrate()
    assert db.schema_version() is None
    monkeypatch.setattr(database, "_migration_files", lambda: files)
    assert db.migrate() == list(range(1, 9))


def test_migration_checksum_rejects_rewrite(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    files = database._migration_files()
    monkeypatch.setattr(
        database, "_migration_files", lambda: [(1, files[0][1] + "\n-- changed"), *files[1:]]
    )
    with pytest.raises(RuntimeError, match="checksum"):
        db.migrate()


def test_same_subject_different_issuers_are_different_users(db: Database) -> None:
    a, b = (
        Principal("same-sub", "jwt", "https://a.test"),
        Principal("same-sub", "jwt", "https://b.test"),
    )
    assert a.owner_id != b.owner_id
    with db.transaction() as conn:
        first = db.ensure_user(conn, a)
        assert db.ensure_user(conn, a) == first
        assert db.ensure_user(conn, b) != first
        conn.execute(
            "UPDATE users SET email='same@example.test' WHERE owner_id IN (%s,%s)",
            (a.owner_id, b.owner_id),
        )
    with db.read() as conn:
        assert (
            conn.execute("SELECT count(*) FROM users WHERE email='same@example.test'").fetchone()[0]
            == 2
        )


def test_owned_chat_titles_and_stable_pagination(harness: Harness) -> None:
    client = harness.client
    ids = [
        client.post("/chats", json={"title": f"chat {i}"}, headers=auth()).json()["id"]
        for i in range(3)
    ]
    first = client.get("/chats?limit=2", headers=auth()).json()
    assert [r["id"] for r in first["items"]] == ids[:0:-1]
    assert (
        client.patch("/chats/" + ids[0], json={"title": "Renamed"}, headers=auth()).json()["title"]
        == "Renamed"
    )
    client.post("/chats", json={"title": "new"}, headers=auth())
    second = client.get(
        "/chats", params={"limit": 2, "cursor": first["next_cursor"]}, headers=auth()
    ).json()
    assert [r["id"] for r in second["items"]] == ids[:1]
    assert second["next_cursor"] is None
    assert (
        client.get(
            "/chats", params={"cursor": first["next_cursor"]}, headers=auth("bob")
        ).status_code
        == 422
    )
    assert (
        client.patch("/chats/" + ids[0], json={"title": "stolen"}, headers=auth("bob")).status_code
        == 404
    )
    assert client.get("/chats/" + ids[0] + "/messages", headers=auth("bob")).status_code == 404


def test_resource_chat_link_and_api_alias(harness: Harness) -> None:
    c = harness.client
    chat = c.post("/chats", json={"title": "My VM"}, headers=auth()).json()
    response = c.post(
        "/deployments", json={"name": "demo", "disk_gib": 8, "chat_id": chat["id"]}, headers=auth()
    )
    assert response.status_code == 202
    rows = c.get("/resources", headers=auth()).json()["items"]
    assert len(rows) == 1
    r = rows[0]
    assert r["deployment_id"] == response.json()["deployment_id"]
    assert r["chat_id"] == chat["uuid"] and r["user_id"] == chat["user_id"]
    assert c.get("/resources/" + r["id"], headers=auth("bob")).status_code == 404
    assert (
        c.post(
            "/deployments",
            json={"name": "stolen", "disk_gib": 8, "chat_id": chat["id"]},
            headers=auth("bob"),
        ).status_code
        == 404
    )


def test_composite_chat_owner_fk_rejects_attack(harness: Harness) -> None:
    chat = harness.client.post("/chats", json={"title": "Alice"}, headers=auth()).json()
    d = create_and_plan(harness, "bob")
    with pytest.raises(psycopg.IntegrityError), harness.db.transaction() as conn:
        conn.execute("UPDATE deployments SET chat_id=%s WHERE id=%s", (chat["id"], d["id"]))
    with pytest.raises(psycopg.IntegrityError), harness.db.transaction() as conn:
        conn.execute("UPDATE resources SET chat_id=%s WHERE owner_id='dev:bob'", (chat["uuid"],))


def resource(
    db: Database,
    provider: str = "azure",
    scope: str = "project",
    native_id: str = "same",
    **changes: Any,
) -> str:
    with db.transaction() as conn:
        user = conn.execute("SELECT id FROM users WHERE owner_id='dev:alice'").fetchone()[0]
        row = conn.execute(
            (
                "INSERT INTO resources "
                "(user_id,owner_id,name,provider,account_scope,native_type,"
                "provider_resource_id,execution_mechanism,status,created_at,"
                "updated_at,provider_config) "
                "VALUES (%s,'dev:alice','fixture',%s,%s,'storage:bucket',%s,'sdk','observed',"
                "clock_timestamp(),clock_timestamp(),%s) RETURNING id"
            ),
            (
                user,
                provider,
                scope,
                native_id,
                json.dumps(
                    changes.get("config", {"schema_version": 1, "kind": "storage", "settings": {}})
                ),
            ),
        ).fetchone()
        return str(row[0])


def test_provider_neutral_identity_and_optional_compute(db: Database) -> None:
    a = resource(db)
    assert resource(db, provider="gcp") != a
    assert resource(db, scope="other") != a
    with pytest.raises(psycopg.IntegrityError):
        resource(db)
    with db.read() as conn:
        assert conn.execute(
            "SELECT cpu_count,memory_gb,storage_gb,region FROM resources WHERE id=%s", (a,)
        ).fetchone() == {"cpu_count": None, "memory_gb": None, "storage_gb": None, "region": None}


@pytest.mark.parametrize(
    "config",
    [
        {"schema_version": 2, "kind": "storage", "settings": {}},
        {"schema_version": 1, "kind": "storage", "settings": {"access_key": "secret"}},
        {"schema_version": 1, "kind": "storage", "settings": {}, "raw_state": {}},
    ],
)
def test_provider_config_rejects_unknown_version_or_secret_fields(
    db: Database, config: dict[str, Any]
) -> None:
    with pytest.raises(psycopg.IntegrityError):
        resource(db, config=config)


def test_resource_owner_and_history_constraints(db: Database) -> None:
    rid = resource(db)
    with pytest.raises(psycopg.IntegrityError), db.transaction() as conn:
        conn.execute("UPDATE resources SET owner_id='dev:bob' WHERE id=%s", (rid,))
    with pytest.raises(psycopg.IntegrityError), db.transaction() as conn:
        conn.execute("DELETE FROM resources WHERE id=%s", (rid,))
    with pytest.raises(psycopg.IntegrityError), db.transaction() as conn:
        conn.execute("DELETE FROM users WHERE owner_id='dev:alice'")


def legacy_fixture(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        for p in sorted((Path(__file__).parent / "fixtures/legacy_sqlite").glob("*.sql")):
            conn.executescript(p.read_text())
            conn.execute(
                "INSERT INTO schema_migrations VALUES (?,?)",
                (int(p.name[:4]), "2026-10-30T00:00:00+00:00"),
            )
        conn.execute(
            "INSERT INTO chat_sessions VALUES "
            "('chat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','dev:alice',1,'2026-10-30T00:00:00+00:00','2026-10-30T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO chat_messages(session_id,role,content,created_at) "
            "VALUES ('chat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','user','preserved',"
            "'2026-10-30T00:00:00+00:00')"
        )

        conn.executescript((Path(__file__).parent / "fixtures/legacy_history.sql").read_text())


def empty_target(db: Database) -> None:
    with db.transaction() as conn:
        conn.execute("DELETE FROM users")


def test_offline_import_restart_idempotence_and_ordering(db: Database, tmp_path: Path) -> None:
    source = tmp_path / "legacy.sqlite3"
    legacy_fixture(source)
    empty_target(db)
    counts = import_snapshot(db, source, issuer="https://old.test")
    assert counts["chat_messages"] == 1
    assert import_snapshot(Database(db.dsn, db.schema), source, issuer="https://old.test") == counts
    with db.read() as conn:
        assert (
            conn.execute("SELECT content FROM chat_messages ORDER BY id").fetchone()[0]
            == "preserved"
        )
        assert conn.execute("SELECT user_id FROM chat_sessions").fetchone()[0] is not None
        dep = conn.execute(
            "SELECT owner_id,cloud_owner_id,current_plan_id FROM deployments"
        ).fetchone()
        assert dep["owner_id"] == Principal("legacy-subject", "jwt", "https://old.test").owner_id
        assert dep["cloud_owner_id"] == "legacy-subject"
        assert dep["current_plan_id"] == "plan_" + "c" * 32
        assert [r[0] for r in conn.execute("SELECT payload_hash FROM jobs ORDER BY sequence")] == [
            "exact-payload-hash",
            "second-payload-hash",
        ]
        assert conn.execute("SELECT config_hash,plan_hash FROM plans").fetchone() == {
            "config_hash": "exact-config-hash",
            "plan_hash": "exact-plan-hash",
        }
        assert [
            r[0] for r in conn.execute("SELECT source FROM deployment_resources ORDER BY source")
        ] == ["launch_output", "terraform_state"]
        assert [
            r[0] for r in conn.execute("SELECT evidence FROM recovery_obligations ORDER BY id")
        ] == ["uncaptured", "captured"]
        assert conn.execute("SELECT actor FROM audit_events").fetchone()[0] == "legacy-subject"
        assert (
            conn.execute("SELECT payload_hash FROM agent_attempts").fetchone()[0]
            == "exact-chat-hash"
        )


def test_offline_import_unknown_data_rollback(db: Database, tmp_path: Path) -> None:
    source = tmp_path / "legacy.sqlite3"
    legacy_fixture(source)
    empty_target(db)
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE unknown_data(value TEXT)")
    with pytest.raises(ValueError, match="unknown"):
        import_snapshot(db, source, issuer="https://old.test")
    with db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM offline_imports").fetchone()[0] == 0


def test_transaction_survives_connection_restart(db: Database) -> None:
    principal = Principal("restart-subject", "jwt", "https://restart.test")
    with db.transaction(principal.owner_id) as conn:
        db.ensure_user(conn, principal)
    restarted = Database(db.dsn, db.schema)
    with restarted.read() as conn:
        row = conn.execute(
            "SELECT auth_provider_user_id FROM users WHERE owner_id=%s", (principal.owner_id,)
        ).fetchone()
    assert row is not None and row[0] == "restart-subject"


def test_concurrent_claims_are_durable_and_distinct(harness: Harness) -> None:
    for user in ("alice", "bob"):
        assert (
            harness.client.post(
                "/deployments", json={"name": "claim-demo", "disk_gib": 8}, headers=auth(user)
            ).status_code
            == 202
        )
    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = list(pool.map(lambda _: harness.worker().claim(), range(2)))
    assert all(row is not None for row in claimed)
    assert len({row["id"] for row in claimed}) == 2
    assert harness.worker().claim() is None
    restarted = Database(harness.db.dsn, harness.db.schema)
    with restarted.read() as conn:
        assert conn.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()[0] == 2


def test_concurrent_same_key_returns_one_committed_response(harness: Harness) -> None:
    def create(_: int) -> dict[str, Any]:
        result = harness.client.post(
            "/deployments",
            json={"name": "same-key", "disk_gib": 8},
            headers={**auth(), "Idempotency-Key": "postgres-same-key-0001"},
        )
        assert result.status_code == 202
        return result.json()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(create, range(4)))
    assert all(r == results[0] for r in results)
    with harness.db.read() as conn:
        assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1


def test_unknown_recovery_state_cannot_be_stored(harness: Harness) -> None:
    d = create_and_plan(harness)
    with pytest.raises(psycopg.IntegrityError), harness.db.transaction() as conn:
        conn.execute(
            "INSERT INTO recovery_obligations(deployment_id,reason,evidence,created_at) "
            "VALUES (%s,'unknown','assumed_safe',clock_timestamp())",
            (d["id"],),
        )
    with harness.db.read() as conn:
        assert conn.execute("SELECT count(*) FROM recovery_obligations").fetchone()[0] == 0


def test_import_partial_failure_is_atomic_and_retryable(db: Database, tmp_path: Path) -> None:
    source = tmp_path / "legacy.sqlite3"
    legacy_fixture(source)
    empty_target(db)
    with sqlite3.connect(source) as conn:
        conn.execute("UPDATE chat_messages SET created_at='unknown-time'")
    with pytest.raises(ValueError, match="Invalid isoformat"):
        import_snapshot(db, source, issuer="https://old.test")
    with db.read() as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM deployments").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM offline_imports").fetchone()[0] == 0
    with sqlite3.connect(source) as conn:
        conn.execute("UPDATE chat_messages SET created_at='2026-10-30T00:00:00+00:00'")
    assert import_snapshot(db, source, issuer="https://old.test")["deployments"] == 1


def test_message_history_redacts_legacy_credentials(harness: Harness) -> None:
    from conftest import FAKE_AWS_KEY_ID

    chat = harness.client.post("/chats", json={"title": "Legacy history"}, headers=auth()).json()
    with harness.db.transaction() as conn:
        conn.execute(
            "INSERT INTO chat_messages(session_id,role,content,created_at) "
            "VALUES (%s,%s,%s,clock_timestamp())",
            (chat["id"], "user", FAKE_AWS_KEY_ID),
        )
    response = harness.client.get("/chats/" + chat["id"] + "/messages", headers=auth())
    assert response.status_code == 200
    assert FAKE_AWS_KEY_ID not in response.text


def test_import_rejects_unredacted_source_without_rewriting_history(
    db: Database, tmp_path: Path
) -> None:
    from conftest import FAKE_AWS_KEY_ID

    source = tmp_path / "legacy.sqlite3"
    legacy_fixture(source)
    empty_target(db)
    with sqlite3.connect(source) as conn:
        conn.execute("UPDATE chat_messages SET content=?", (FAKE_AWS_KEY_ID,))
    with pytest.raises(ValueError, match="unredacted sensitive source data"):
        import_snapshot(db, source, issuer="https://old.test")
    with db.read() as conn:
        assert conn.execute("SELECT count(*) FROM chat_messages").fetchone()[0] == 0
    with sqlite3.connect(source) as conn:
        assert conn.execute("SELECT content FROM chat_messages").fetchone()[0] == FAKE_AWS_KEY_ID


def test_offline_import_restores_real_backend_identity_after_plan_history(
    db: Database, tmp_path: Path
) -> None:
    source = tmp_path / "legacy.sqlite3"
    legacy_fixture(source)
    empty_target(db)
    with sqlite3.connect(source) as conn:
        conn.execute("UPDATE deployments SET provisioner='terraform'")
        conn.execute("UPDATE plans SET provisioner='terraform',account_id='123456789012'")
    assert import_snapshot(db, source, issuer="https://old.test")["deployments"] == 1
    with db.read() as conn:
        row = conn.execute("SELECT account_scope,provider_resource_id FROM resources").fetchone()
        assert row == {
            "account_scope": "123456789012",
            "provider_resource_id": "i-0123456789abcdef0",
        }
