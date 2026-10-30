"""Bearer-token authentication.

Production uses OIDC/JWT access tokens verified with PyJWT against the issuer's JWKS
(signature, issuer, audience, expiry and team membership). The development authenticator
exists only for local work and cannot be constructed outside development mode.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import jwt

from unitcompute.config import AuthMode, Environment, Settings
from unitcompute.errors import Forbidden, Unauthenticated

_SUBJECT = re.compile(r"^[A-Za-z0-9@._:|+-]{1,200}$")
_DEV_TOKEN = re.compile(r"^dev:([a-z][a-z0-9-]{0,31})$")
LEEWAY_SECONDS = 30


@dataclass(frozen=True)
class Principal:
    subject: str
    """Stable owner ID: the verified token subject (``dev:<name>`` in development)."""

    auth_method: str
    issuer: str = "unitcompute:development"

    @property
    def owner_id(self) -> str:
        if self.auth_method == "dev":
            return self.subject
        identity = json.dumps([self.issuer, self.subject], separators=(",", ":"))
        return "owner_" + hashlib.sha256(identity.encode()).hexdigest()


class Authenticator(Protocol):
    def authenticate(self, authorization: str | None) -> Principal: ...


def _bearer(authorization: str | None) -> str:
    if not authorization:
        raise Unauthenticated("Missing bearer token.")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token or " " in token.strip():
        raise Unauthenticated("Authorization header must be 'Bearer <token>'.")
    return token.strip()


KeyResolver = Callable[[str], Any]


class JwtAuthenticator:
    def __init__(self, settings: Settings, key_resolver: KeyResolver | None = None) -> None:
        if not (settings.auth_issuer and settings.auth_audience and settings.auth_jwks_url):
            raise ValueError("JWT authentication requires issuer, audience and JWKS URL")
        self._issuer = settings.auth_issuer
        self._audience = settings.auth_audience
        self._algorithms = list(settings.auth_algorithms)
        self._group = settings.auth_required_group
        self._groups_claim = settings.auth_groups_claim
        if key_resolver is None:
            # cache_keys=False: PyJWT's per-key cache never expires, so a key removed from the
            # issuer's JWKS would stay trusted until restart. The JWKS document cache below
            # is bounded, so removed keys stop working within auth_jwks_cache_seconds.
            client = jwt.PyJWKClient(
                settings.auth_jwks_url,
                cache_keys=False,
                cache_jwk_set=True,
                lifespan=settings.auth_jwks_cache_seconds,
                timeout=5,
            )

            def key_resolver(token: str) -> Any:
                return client.get_signing_key_from_jwt(token).key

        self._resolve_key = key_resolver

    def authenticate(self, authorization: str | None) -> Principal:
        token = _bearer(authorization)
        try:
            key = self._resolve_key(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, ValueError) as exc:
            raise Unauthenticated("Invalid or expired token.") from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not _SUBJECT.fullmatch(subject):
            raise Unauthenticated("Token subject is not acceptable.")
        if subject.startswith("dev:"):
            raise Unauthenticated("Token subject is not acceptable.")
        if self._group is not None:
            groups = claims.get(self._groups_claim)
            if isinstance(groups, str):
                groups = [groups]
            if not isinstance(groups, list) or self._group not in groups:
                raise Forbidden("Your account is not a member of the UnitCompute team.")
        return Principal(subject=subject, auth_method="jwt", issuer=self._issuer)


class DevAuthenticator:
    """Accepts ``Bearer dev:<name>``. Development only; refuses to exist in production."""

    def __init__(self, settings: Settings) -> None:
        if settings.environment is not Environment.DEVELOPMENT or (
            settings.auth_mode is not AuthMode.DEV
        ):
            raise RuntimeError("DevAuthenticator is only available in development auth mode")

    def authenticate(self, authorization: str | None) -> Principal:
        token = _bearer(authorization)
        match = _DEV_TOKEN.fullmatch(token)
        if match is None:
            raise Unauthenticated("Development tokens look like 'dev:<lowercase-name>'.")
        return Principal(subject=f"dev:{match.group(1)}", auth_method="dev")


def build_authenticator(settings: Settings) -> Authenticator:
    if settings.auth_mode is AuthMode.JWT:
        return JwtAuthenticator(settings)
    return DevAuthenticator(settings)
