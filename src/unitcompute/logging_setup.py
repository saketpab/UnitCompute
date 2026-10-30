"""Structured JSON logging and secret redaction."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from collections.abc import Iterable
from contextvars import ContextVar
from typing import Any

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

# Pattern-based, so bounded: it covers the listed credential names in name=value,
# name: value, export NAME="value", 'single-quoted' and JSON "name": "value" forms (the
# whole quoted value, spaces included), plus the token shapes below. It cannot recognise
# every secret.
_CREDENTIAL_FIELD_NAMES = (
    r"(?:aws_secret_access_key|secret_access_key|aws_session_token|session_token|password|"
    r"passwd|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)"
)
# Quoted values honour backslash escapes (JSON/shell), so an escaped quote does not end the
# value; an unterminated quoted value is redacted to the end of the line.
_ASSIGNMENT = re.compile(
    rf"(?i)(\b{_CREDENTIAL_FIELD_NAMES}[\"']?\s*[=:]\s*)"
    r"(\"(?:\\.|[^\"\\\n])*(?:\"|(?=\n)|$)|'(?:\\.|[^'\\\n])*(?:'|(?=\n)|$)|[^\s\"',;]+)"
)
_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
        re.DOTALL,
    ),
]
REDACTED = "[REDACTED]"


def _redact_assignment(match: re.Match[str]) -> str:
    value = match.group(2)
    quote = value[0] if value[0] in "\"'" else ""
    closed = bool(quote) and len(value) > 1 and value.endswith(quote)
    return f"{match.group(1)}{quote}{REDACTED}{quote if closed else ''}"


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    for secret in secrets:
        if secret and len(secret) >= 8:
            text = text.replace(secret, REDACTED)
    text = _ASSIGNMENT.sub(_redact_assignment, text)
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update({k: redact(str(v)) for k, v in fields.items()})
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, separators=(",", ":"))


def secure_process_defaults() -> None:
    """Owner-only permissions for everything the process creates (SQLite WAL/SHM files,
    Terraform work directories, logs)."""
    os.umask(0o077)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
