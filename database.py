"""PostgreSQL connection and schema setup; no application or cloud execution."""

import hashlib
import os
from pathlib import Path

import psycopg

MIGRATIONS = Path(__file__).with_name("migrations")


def connect(dsn: str | None = None) -> psycopg.Connection:
    """Use DATABASE_URL unless a PostgreSQL connection string is supplied."""
    if dsn is None:
        dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise ValueError("Set DATABASE_URL to an existing PostgreSQL database")
    return psycopg.connect(dsn)


def migrate(connection: psycopg.Connection) -> list[int]:
    """Apply trusted SQL files atomically, refusing changed or unknown history."""
    files = sorted(MIGRATIONS.glob("*.sql"))
    scripts = {
        int(path.name.split("_", 1)[0]): path.read_text(encoding="utf-8")
        for path in files
    }
    if len(scripts) != len(files):
        raise ValueError("Duplicate migration versions")
    checksums = {v: hashlib.sha256(s.encode()).hexdigest() for v, s in scripts.items()}
    with connection.transaction():
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended("
            "'unitcompute-schema:' || current_schema(), 0))"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS unitcompute_schema_migrations ("
            "version integer PRIMARY KEY, checksum text NOT NULL, "
            "applied_at timestamptz NOT NULL DEFAULT now())"
        )
        applied: dict[int, str] = dict(
            connection.execute(
                "SELECT version, checksum FROM unitcompute_schema_migrations"
            ).fetchall()
        )
        if applied.keys() - scripts.keys():
            raise ValueError("Database contains migrations absent from this checkout")
        for version, checksum in applied.items():
            if checksum != checksums[version]:
                raise ValueError(f"Applied migration {version} checksum changed")
        pending = sorted(scripts.keys() - applied.keys())
        for version in pending:
            connection.execute(scripts[version], prepare=False)
            connection.execute(
                "INSERT INTO unitcompute_schema_migrations(version, checksum) VALUES (%s, %s)",
                (version, checksums[version]),
            )
    return pending


if __name__ == "__main__":
    with connect() as connection:
        print(f"Applied migrations: {migrate(connection)}")
