"""Versioned, owner-bound sequence cursors for stable descending pages."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json

from unitcompute.auth import Principal
from unitcompute.errors import InvalidInput


def encode_cursor(scope: str, sequence: int) -> str:
    return base64.urlsafe_b64encode(json.dumps([1, scope, sequence]).encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None, scope: str) -> int:
    if cursor is None:
        return 2**63 - 1
    try:
        version, stored_scope, sequence = json.loads(
            base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        )
        if (
            version != 1
            or stored_scope != scope
            or type(sequence) is not int
            or not 0 < sequence < 2**63
        ):
            raise ValueError("invalid cursor")
        return int(sequence)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise InvalidInput("Invalid pagination cursor.") from exc


def cursor_scope(principal: Principal, collection: str) -> str:
    return hashlib.sha256((principal.owner_id + ":" + collection).encode()).hexdigest()
