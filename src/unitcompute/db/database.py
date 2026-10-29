"""SQLite access shared by the API and the worker.

Both processes open the same file on persistent local storage. Writes use short
``BEGIN IMMEDIATE`` transactions so claims and quota reservations are serialised, and no
transaction is ever held while Terraform or a model call runs.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

from unitcompute.errors import ServiceUnavailable

BUSY_TIMEOUT_MS = 5000


def utcnow() -> datetime:
    return datetime.now(UTC)


def to_db_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def from_db_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _migration_files() -> list[tuple[int, str]]:
    package = resources.files("unitcompute.db") / "migrations"
    found: list[tuple[int, str]] = []
    for entry in package.iterdir():
        if entry.name.endswith(".sql"):
            version = int(entry.name.split("_", 1)[0])
            found.append((version, entry.read_text(encoding="utf-8")))
    return sorted(found)


LATEST_SCHEMA_VERSION = max(version for version, _ in _migration_files())


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Short write transaction; contention beyond the busy timeout becomes a 503."""
        conn = self.connect()
        try:
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc) or "busy" in str(exc):
                    raise ServiceUnavailable(
                        "The database is busy; retry the request.", code="database_busy"
                    ) from exc
                raise
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        finally:
            conn.close()

    def initialise_storage(self) -> None:
        """Create the data directory with private permissions and enable WAL."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode = WAL")
        finally:
            conn.close()
        os.chmod(self.path, 0o600)

    def migrate(self) -> list[int]:
        self.initialise_storage()
        applied: list[int] = []
        conn = self.connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            for version, sql in _migration_files():
                conn.execute("BEGIN IMMEDIATE")
                try:
                    done = conn.execute(
                        "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
                    ).fetchone()
                    if done is None:
                        for statement in _split_sql(sql):
                            conn.execute(statement)
                        conn.execute(
                            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                            (version, to_db_time(utcnow())),
                        )
                        applied.append(version)
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                conn.execute("COMMIT")
        finally:
            conn.close()
        return applied

    def schema_version(self) -> int | None:
        if not self.path.exists():
            return None
        with self.read() as conn:
            table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
            ).fetchone()
            if table is None:
                return None
            row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
            return int(row["v"]) if row and row["v"] is not None else None

    def require_current_schema(self) -> None:
        version = self.schema_version()
        if version != LATEST_SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema is at version {version}, expected {LATEST_SCHEMA_VERSION}; "
                "run `unitcompute-admin migrate` first"
            )


def _split_sql(sql: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        current.append(line)
        if stripped.endswith(";"):
            statements.append("\n".join(current))
            current = []
    if current:
        statements.append("\n".join(current))
    return statements
