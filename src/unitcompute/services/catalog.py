"""Owned product views and stable sequence cursors over PostgreSQL persistence."""

from __future__ import annotations

import json
from typing import Any

from psycopg import sql

from unitcompute.auth import Principal
from unitcompute.db.database import Database, Row, to_db_time, utcnow
from unitcompute.errors import InvalidInput, NotFound
from unitcompute.logging_setup import redact
from unitcompute.pagination import cursor_scope, decode_cursor, encode_cursor
from unitcompute.services.deployments import new_id


def product_row(row: Row) -> dict[str, Any]:
    result = dict(row)
    result.pop("owner_id", None)
    result.pop("sequence", None)
    if "content" in result:
        result["content"] = redact(result["content"])
    for key in ("provider_config", "approved_config"):
        if result.get(key) is not None:
            result[key] = json.loads(result[key])
    return result


class CatalogService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def profile(
        self, principal: Principal, updates: dict[str, str] | None = None
    ) -> dict[str, Any]:
        with self.db.transaction(principal.owner_id) as conn:
            self.db.ensure_user(conn, principal)
            if updates:
                for field, value in updates.items():
                    if field not in {"name", "email"}:
                        raise InvalidInput("Invalid profile field.")
                    conn.execute(
                        sql.SQL("UPDATE users SET {}=%s WHERE owner_id=%s").format(
                            sql.Identifier(field)
                        ),
                        (redact(value), principal.owner_id),
                    )
            row = conn.execute(
                (
                    "SELECT id, name, email, auth_issuer, auth_provider_user_id, "
                    "created_at FROM users WHERE owner_id=%s"
                ),
                (principal.owner_id,),
            ).fetchone()
            return dict(row or {})

    def resources(self, principal: Principal, limit: int, cursor: str | None) -> dict[str, Any]:
        scope = cursor_scope(principal, "resources")
        before = decode_cursor(cursor, scope)
        with self.db.read() as conn:
            rows = conn.execute(
                (
                    "SELECT * FROM resources WHERE owner_id=%s AND sequence<%s ORDER "
                    "BY sequence DESC LIMIT %s"
                ),
                (principal.owner_id, before, limit + 1),
            ).fetchall()
        return self._page(rows, limit, scope, "sequence")

    def resource(self, principal: Principal, resource_id: str) -> dict[str, Any]:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT * FROM resources WHERE id=%s AND owner_id=%s",
                (resource_id, principal.owner_id),
            ).fetchone()
        if row is None:
            raise NotFound("Resource not found.")
        return product_row(row)

    @staticmethod
    def _page(rows: list[Row], limit: int, scope: str, sequence_key: str) -> dict[str, Any]:
        items = rows[:limit]
        return {
            "items": [product_row(r) for r in items],
            "next_cursor": encode_cursor(scope, items[-1][sequence_key])
            if len(rows) > limit
            else None,
        }

    def create_chat(self, principal: Principal, title: str) -> dict[str, Any]:
        with self.db.transaction(principal.owner_id) as conn:
            self.db.ensure_user(conn, principal)
            now = to_db_time(utcnow())
            row = conn.execute(
                (
                    "INSERT INTO chat_sessions (id, owner_id, title, created_at, "
                    "updated_at) VALUES (%s,%s,%s,%s,%s) RETURNING *"
                ),
                (new_id("chat"), principal.owner_id, redact(title), now, now),
            ).fetchone()
            return product_row(row or Row())

    def chats(self, principal: Principal, limit: int, cursor: str | None) -> dict[str, Any]:
        scope = cursor_scope(principal, "chats")
        with self.db.read() as conn:
            rows = conn.execute(
                (
                    "SELECT * FROM chat_sessions WHERE owner_id=%s AND sequence<%s "
                    "ORDER BY sequence DESC LIMIT %s"
                ),
                (principal.owner_id, decode_cursor(cursor, scope), limit + 1),
            ).fetchall()
        return self._page(rows, limit, scope, "sequence")

    def title(self, principal: Principal, chat_id: str, title: str) -> dict[str, Any]:
        with self.db.transaction(principal.owner_id) as conn:
            row = conn.execute(
                (
                    "UPDATE chat_sessions SET title=%s,updated_at=%s WHERE id=%s AND "
                    "owner_id=%s RETURNING *"
                ),
                (redact(title), to_db_time(utcnow()), chat_id, principal.owner_id),
            ).fetchone()
            if row is None:
                raise NotFound("Chat not found.")
            return product_row(row)

    def messages(
        self, principal: Principal, chat_id: str, limit: int, cursor: str | None
    ) -> dict[str, Any]:
        scope = cursor_scope(principal, "messages:" + chat_id)
        with self.db.read() as conn:
            if (
                conn.execute(
                    "SELECT 1 FROM chat_sessions WHERE id=%s AND owner_id=%s",
                    (chat_id, principal.owner_id),
                ).fetchone()
                is None
            ):
                raise NotFound("Chat not found.")
            rows = conn.execute(
                (
                    "SELECT * FROM chat_messages WHERE session_id=%s AND id<%s ORDER "
                    "BY id DESC LIMIT %s"
                ),
                (chat_id, decode_cursor(cursor, scope), limit + 1),
            ).fetchall()
        return self._page(rows, limit, scope, "id")
