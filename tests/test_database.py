"""Database contracts against PostgreSQL; no cloud or notebook execution."""

import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

import database


@pytest.fixture
def target():
    dsn = os.environ.get("TEST_DATABASE_URL")
    if not dsn:
        pytest.fail(
            "Set TEST_DATABASE_URL to an existing disposable PostgreSQL database"
        )
    schema = "test_database_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        yield dsn, schema
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


def connection(target):
    dsn, schema = target
    conn = database.connect(dsn)
    conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
    conn.commit()
    return conn


@pytest.fixture
def db(target):
    with connection(target) as conn:
        database.migrate(conn)
        yield conn


def user(conn, subject="alice", issuer="https://issuer.test"):
    return conn.execute(
        "INSERT INTO users(auth_issuer, auth_provider_user_id, email) VALUES (%s,%s,%s) RETURNING id",
        (issuer, subject, "shared@example.test"),
    ).fetchone()[0]


def chat(conn, owner):
    return conn.execute(
        "INSERT INTO chats(user_id,title) VALUES (%s,'Project') RETURNING id", (owner,)
    ).fetchone()[0]


def resource(
    conn,
    owner,
    chat_id=None,
    provider="aws",
    account="account-a",
    region=None,
    native_type="storage:bucket",
    native_id="bucket-a",
):
    return conn.execute(
        "INSERT INTO resources(user_id,chat_id,name,provider,account_scope,region,native_type,"
        "provider_resource_id) VALUES (%s,%s,'Example',%s,%s,%s,%s,%s) RETURNING id",
        (owner, chat_id, provider, account, region, native_type, native_id),
    ).fetchone()[0]


def test_schema_fresh_repeat_and_concurrent_migration(target):
    def apply(_):
        with connection(target) as conn:
            return database.migrate(conn)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sorted(pool.map(apply, range(4))) == [[], [], [], [1]]
    with connection(target) as conn:
        assert database.migrate(conn) == []
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname=current_schema()"
            )
        }
        assert tables == {
            "users",
            "chats",
            "messages",
            "resources",
            "unitcompute_schema_migrations",
        }


def test_connection_requires_configuration(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="DATABASE_URL"):
        database.connect()


def test_configured_connection_commit_rollback_and_restart(target, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", target[0])
    with database.connect() as conn:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(target[1])))
        database.migrate(conn)
        owner = user(conn)
    with connection(target) as conn:
        assert conn.execute("SELECT id FROM users").fetchone()[0] == owner
        with pytest.raises(RuntimeError), conn.transaction():
            user(conn, "rolled-back")
            raise RuntimeError("abort transaction")
    with connection(target) as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 1


def test_failed_migration_is_atomic_and_retryable(target, tmp_path, monkeypatch):
    original = database.MIGRATIONS.joinpath("001_initial.sql").read_text()
    (tmp_path / "001_initial.sql").write_text(original)
    later = tmp_path / "002_example.sql"
    later.write_text("CREATE TABLE migration_probe(id integer); SELECT missing_column;")
    monkeypatch.setattr(database, "MIGRATIONS", tmp_path)
    with connection(target) as conn:
        with pytest.raises(psycopg.errors.UndefinedColumn):
            database.migrate(conn)
        assert conn.execute("SELECT to_regclass('users')").fetchone()[0] is None
        assert (
            conn.execute(
                "SELECT to_regclass('unitcompute_schema_migrations')"
            ).fetchone()[0]
            is None
        )
    later.write_text("CREATE TABLE migration_probe(id integer);")
    with connection(target) as conn:
        assert database.migrate(conn) == [1, 2]


def test_applied_history_is_never_rewritten(target, tmp_path, monkeypatch):
    with connection(target) as conn:
        database.migrate(conn)
        owner = user(conn)
    original = database.MIGRATIONS.joinpath("001_initial.sql").read_text()
    (tmp_path / "001_initial.sql").write_text(original + "\n-- changed\n")
    monkeypatch.setattr(database, "MIGRATIONS", tmp_path)
    with connection(target) as conn:
        before = conn.execute("SELECT * FROM unitcompute_schema_migrations").fetchall()
        with pytest.raises(ValueError, match="checksum"):
            database.migrate(conn)
        assert (
            conn.execute("SELECT * FROM unitcompute_schema_migrations").fetchall()
            == before
        )
        assert conn.execute("SELECT id FROM users").fetchone()[0] == owner


def test_older_checkout_refuses_unknown_migrations(db):
    db.execute(
        "INSERT INTO unitcompute_schema_migrations(version,checksum) VALUES(99,'unknown')"
    )
    with pytest.raises(ValueError, match="absent"):
        database.migrate(db)


def test_existing_tables_are_not_replaced(target):
    with connection(target) as conn:
        conn.execute("CREATE TABLE users(important_text text)")
        conn.execute("INSERT INTO users VALUES('retain this data')")
    with connection(target) as conn:
        with pytest.raises(psycopg.errors.DuplicateTable):
            database.migrate(conn)
        assert (
            conn.execute("SELECT important_text FROM users").fetchone()[0]
            == "retain this data"
        )
        assert (
            conn.execute(
                "SELECT to_regclass('unitcompute_schema_migrations')"
            ).fetchone()[0]
            is None
        )


def test_identity_is_issuer_and_subject_not_email(db):
    first = user(db)
    second = user(db, issuer="https://other-issuer.test")
    assert first != second
    with pytest.raises(psycopg.errors.UniqueViolation), db.transaction():
        user(db)
    assert (
        db.execute(
            "SELECT count(*) FROM users WHERE email='shared@example.test'"
        ).fetchone()[0]
        == 2
    )


def test_resource_chat_must_belong_to_its_owner(db):
    alice, bob = user(db), user(db, "bob")
    alice_chat = chat(db, alice)
    resource(db, alice, alice_chat)
    with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
        resource(db, bob, alice_chat, native_id="other")
    with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
        chat(db, uuid.uuid4())


@pytest.mark.parametrize("role", ["system", "tool"])
def test_messages_accept_only_user_and_assistant(db, role):
    cid = chat(db, user(db))
    for valid in ("user", "assistant"):
        db.execute(
            "INSERT INTO messages(chat_id,role,content) VALUES (%s,%s,'Hello')",
            (cid, valid),
        )
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "INSERT INTO messages(chat_id,role,content) VALUES (%s,%s,'No')",
            (cid, role),
        )
    assert (
        db.execute("SELECT count(*) FROM messages WHERE chat_id=%s", (cid,)).fetchone()[
            0
        ]
        == 2
    )


def test_provider_identity_and_global_noncompute_resources(db):
    owner = user(db)
    rid = resource(db, owner)
    with pytest.raises(psycopg.errors.UniqueViolation), db.transaction():
        resource(db, owner)
    for extra in (
        {"provider": "azure"},
        {"provider": "gcp"},
        {"account": "other-account"},
        {"region": "us-east-1"},
        {"native_type": "compute:instance"},
    ):
        resource(db, owner, **extra)
    assert (
        db.execute(
            "SELECT region,os,cpu_count,memory_gb,storage_gb FROM resources WHERE id=%s",
            (rid,),
        ).fetchone()
        == (None,) * 5
    )
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        resource(db, owner, account=None, native_id="needs-account")


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("cpu_count", 0),
        ("memory_gb", 0),
        ("storage_gb", 0),
        ("memory_gb", "NaN"),
        ("memory_gb", "Infinity"),
        ("storage_gb", "NaN"),
        ("storage_gb", "Infinity"),
    ],
)
def test_compute_capacity_is_optional_but_positive(db, column, value):
    rid = resource(db, user(db))
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            sql.SQL("UPDATE resources SET {}=%s WHERE id=%s").format(
                sql.Identifier(column)
            ),
            (value, rid),
        )


def test_approved_configuration_is_an_object_with_approval_time(db):
    rid = resource(db, user(db))
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "UPDATE resources SET approved_config=%s,approved_at=now() WHERE id=%s",
            (Jsonb([]), rid),
        )
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute("UPDATE resources SET approved_at=now() WHERE id=%s", (rid,))
    db.execute(
        "UPDATE resources SET approved_config=%s,approved_at=now() WHERE id=%s",
        (Jsonb({"name": "Example"}), rid),
    )


def test_referenced_owners_and_chats_cannot_cascade_away_resources(db):
    owner = user(db)
    cid = chat(db, owner)
    rid = resource(db, owner, cid)
    for statement, value in (
        ("DELETE FROM users WHERE id=%s", owner),
        ("DELETE FROM chats WHERE id=%s", cid),
    ):
        with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
            db.execute(statement, (value,))
    assert db.execute("SELECT id FROM resources").fetchone()[0] == rid


def test_duplicate_migration_versions_are_rejected(target, tmp_path, monkeypatch):
    (tmp_path / "001_first.sql").write_text("CREATE TABLE first_table(id integer)")
    (tmp_path / "001_duplicate.sql").write_text("CREATE TABLE second_table(id integer)")
    monkeypatch.setattr(database, "MIGRATIONS", tmp_path)
    with connection(target) as conn:
        with pytest.raises(ValueError, match="Duplicate"):
            database.migrate(conn)
        assert (
            conn.execute(
                "SELECT to_regclass('unitcompute_schema_migrations')"
            ).fetchone()[0]
            is None
        )
