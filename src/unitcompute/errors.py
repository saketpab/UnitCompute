"""Domain errors that map to stable API error codes."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class Unauthenticated(AppError):
    status_code = 401
    code = "unauthenticated"


class Forbidden(AppError):
    status_code = 403
    code = "forbidden"


class NotFound(AppError):
    """Also used for resources owned by someone else, so IDs cannot be enumerated."""

    status_code = 404
    code = "not_found"


class Conflict(AppError):
    status_code = 409
    code = "conflict"

    def __init__(
        self, message: str, *, code: str = "conflict", details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message, details=details)
        self.code = code


class InvalidInput(AppError):
    status_code = 422
    code = "invalid_input"


class PayloadTooLarge(AppError):
    status_code = 413
    code = "payload_too_large"


class RateLimited(AppError):
    status_code = 429
    code = "rate_limited"


class ServiceUnavailable(AppError):
    status_code = 503
    code = "unavailable"

    def __init__(
        self, message: str, *, code: str = "unavailable", details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message, details=details)
        self.code = code
