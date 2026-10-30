"""PostgreSQL persistence and short, explicitly locked application transactions."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib import resources
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import set_json_loads

from unitcompute.auth import Principal
from unitcompute.errors import ServiceUnavailable

BUSY_TIMEOUT_MS = 5000


class Row(dict[str, Any]):
    """Named fields with positional access for scalar queries."""

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


def row_factory(cursor: psycopg.Cursor[Row]) -> Any:
    names = [c.name for c in cursor.description or ()]

    def make(values: Sequence[Any]) -> Row:
        return Row(zip(names, values, strict=True))

    return make


Connection = psycopg.Connection[Row]


def utcnow() -> datetime:
    return datetime.now(UTC)


def to_db_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def from_db_time(value: str | datetime) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def _migration_files() -> list[tuple[int, str]]:
    package = resources.files("unitcompute.db") / "migrations"
    return sorted(
        (int(p.name.split("_", 1)[0]), p.read_text(encoding="utf-8"))
        for p in package.iterdir()
        if p.name.endswith(".sql")
    )


LATEST_SCHEMA_VERSION = max(v for v, _ in _migration_files())


class Database:
    def __init__(self, dsn: str, schema: str = "public") -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("invalid database schema")
        self.dsn, self.schema = dsn, schema

    def connect(self) -> Connection:
        conn = psycopg.connect(self.dsn, autocommit=True, row_factory=row_factory)
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
        conn.execute("SET timezone TO 'UTC'")
        conn.execute("SELECT set_config('lock_timeout', %s, false)", (f"{BUSY_TIMEOUT_MS}ms",))
        # Existing domain boundaries consume canonical JSON text. JSONB is stored natively;
        # decoding happens exactly once in those owners rather than in every SQL caller.
        set_json_loads(lambda data: data.decode() if isinstance(data, bytes) else data, conn)
        return conn

    @contextmanager
    def read(self) -> Iterator[Connection]:
        with self.connect() as conn:
            yield conn

    @contextmanager
    def transaction(self, owner_id: str | None = None) -> Iterator[Connection]:
        try:
            with self.connect() as conn, conn.transaction():
                # Scoped requests can proceed concurrently for different owners. Unscoped
                # worker/recovery writes exclusively lock the same gate: no predicate write
                # can race an owner-wide quota or recovery decision.
                fn = "pg_advisory_xact_lock" if owner_id is None else "pg_advisory_xact_lock_shared"
                conn.execute(f"SELECT {fn}(hashtextextended(%s, 0))", (self.schema + ":writes",))
                if owner_id is not None:
                    conn.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                        (self.schema + ":owner:" + owner_id,),
                    )
                yield conn
        except (
            psycopg.errors.LockNotAvailable,
            psycopg.errors.DeadlockDetected,
            psycopg.errors.SerializationFailure,
        ) as exc:
            raise ServiceUnavailable(
                "The database is busy; retry the request.", code="database_busy"
            ) from exc

    @staticmethod
    def ensure_user(conn: Connection, principal: Principal) -> str:
        row = conn.execute(
            "INSERT INTO users (owner_id, auth_issuer, auth_provider_user_id) "
            "VALUES (%s, %s, %s) ON CONFLICT (auth_issuer, auth_provider_user_id) "
            "DO UPDATE SET auth_provider_user_id=EXCLUDED.auth_provider_user_id RETURNING id",
            (principal.owner_id, principal.issuer, principal.subject),
        ).fetchone()
        if row is None:
            raise RuntimeError("user reservation returned no row")
        return str(row["id"])

    def migrate(self) -> list[int]:
        applied: list[int] = []
        with self.connect() as conn, conn.transaction():
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (self.schema + ":migrations",),
            )
            conn.execute(
                sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema))
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, "
                "engine TEXT NOT NULL CHECK (engine = 'postgresql'), checksum TEXT NOT NULL, "
                "applied_at TIMESTAMPTZ NOT NULL)"
            )
            for version, script in _migration_files():
                checksum = hashlib.sha256(script.encode()).hexdigest()
                old = conn.execute(
                    "SELECT checksum FROM schema_migrations WHERE version=%s", (version,)
                ).fetchone()
                if old:
                    if old["checksum"] != checksum:
                        raise RuntimeError(f"migration {version} checksum changed")
                    continue
                conn.execute(script, prepare=False)
                conn.execute(
                    "INSERT INTO schema_migrations VALUES (%s, 'postgresql', %s, %s)",
                    (version, checksum, utcnow()),
                )
                applied.append(version)
        return applied

    def schema_version(self) -> int | None:
        with self.read() as conn:
            table = conn.execute("SELECT to_regclass('schema_migrations')").fetchone()
            if table is None or table[0] is None:
                return None
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            return int(row[0]) if row and row[0] is not None else None

    def require_current_schema(self) -> None:
        if self.schema_version() != LATEST_SCHEMA_VERSION:
            raise RuntimeError(
                "database schema is not current; run `unitcompute-admin migrate` first"
            )
