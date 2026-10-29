from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from conftest import make_settings
from unitcompute.auth import DevAuthenticator, JwtAuthenticator, build_authenticator
from unitcompute.config import Settings, load_settings
from unitcompute.errors import Forbidden, Unauthenticated

ISSUER = "https://login.example.test/"
AUDIENCE = "unitcompute-api"
JWT_SETTINGS: dict[str, Any] = {
    "auth_mode": "jwt",
    "auth_issuer": ISSUER,
    "auth_audience": AUDIENCE,
    "auth_jwks_url": "https://login.example.test/.well-known/jwks.json",
    "auth_required_group": "unitcompute-team",
}
TERRAFORM_SETTINGS: dict[str, Any] = {
    "provisioner": "terraform",
    "aws_account_id": "123456789012",
    "vpc_id": "vpc-0123456789abcdef0",
    "subnet_id": "subnet-0123456789abcdef0",
    "instance_profile_name": "unitcompute-ssm",
    "state_bucket": "unitcompute-state-example",
    "plan_role_arn": "arn:aws:iam::123456789012:role/unitcompute-plan",
    "apply_role_arn": "arn:aws:iam::123456789012:role/unitcompute-apply",
}


def test_development_defaults_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load_settings()
    assert settings.environment == "development"
    assert settings.provisioner == "disabled"
    assert settings.agent_model is None
    assert settings.cors_origins == ()


def test_valid_production_configuration(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path, environment="production", **JWT_SETTINGS, **TERRAFORM_SETTINGS
    )
    assert isinstance(build_authenticator(settings), JwtAuthenticator)


@pytest.mark.parametrize(
    "override, message",
    [
        ({"auth_mode": "dev"}, "production requires auth_mode=jwt"),
        ({"auth_required_group": None}, "auth_required_group"),
        ({"auth_jwks_url": "http://login.example.test/jwks"}, "https"),
        ({"provisioner": "simulated"}, "production requires provisioner=terraform"),
        ({"provisioner": "disabled"}, "production requires provisioner=terraform"),
        ({"apply_role_arn": "arn:aws:iam::123456789012:role/unitcompute-plan"}, "distinct"),
        ({"subnet_id": "subnet-; rm -rf /"}, "subnet_id"),
        ({"state_bucket": None}, "state_bucket"),
        ({"aws_region": "eu-west-1"}, "us-east-1"),
        ({"cors_origins": "*"}, "cors_origins"),
        ({"auth_algorithms": "HS256"}, "asymmetric"),
        ({"auth_algorithms": "none"}, "asymmetric"),
        ({"agent_model": "fake:scripted"}, "development-only"),
        ({"agent_model": "shell:rm"}, "agent_model"),
    ],
)
def test_production_fails_closed(tmp_path: Path, override: dict[str, Any], message: str) -> None:
    values = {"environment": "production", **JWT_SETTINGS, **TERRAFORM_SETTINGS, **override}
    with pytest.raises(ValidationError, match=message):
        make_settings(tmp_path, **values)


def test_unknown_settings_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UNITCOMPUTE_SKIP_AUTH", "1")
    with pytest.raises(ValueError, match="UNITCOMPUTE_SKIP_AUTH"):
        load_settings()


def test_env_parsing_of_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "UNITCOMPUTE_CORS_ORIGINS", "https://app.example.test, http://localhost:5173"
    )
    assert load_settings().cors_origins == ("https://app.example.test", "http://localhost:5173")


def test_dev_authenticator_cannot_exist_in_production(tmp_path: Path) -> None:
    prod = make_settings(tmp_path, environment="production", **JWT_SETTINGS, **TERRAFORM_SETTINGS)
    with pytest.raises(RuntimeError):
        DevAuthenticator(prod)


# --------------------------------------------------------------------- JWT verification


@pytest.fixture(scope="module")
def keys() -> tuple[Any, Any]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, other


def _authenticator(tmp_path: Path, private: Any) -> JwtAuthenticator:
    settings = make_settings(tmp_path, **JWT_SETTINGS)
    public = private.public_key()
    return JwtAuthenticator(settings, key_resolver=lambda _token: public)


def _token(private: Any, **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "groups": ["unitcompute-team"],
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, private, algorithm="RS256")


def test_valid_jwt(tmp_path: Path, keys: tuple[Any, Any]) -> None:
    principal = _authenticator(tmp_path, keys[0]).authenticate(f"Bearer {_token(keys[0])}")
    assert principal.subject == "user-123"
    assert principal.auth_method == "jwt"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "other-api"},
        {"iss": "https://evil.example.test/"},
        {"exp": int(time.time()) - 3600},
        {"exp": None},
        {"sub": None},
        {"iat": None},
        {"sub": "dev:alice"},
        {"sub": "x" * 300},
    ],
)
def test_invalid_jwt_claims(
    tmp_path: Path, keys: tuple[Any, Any], overrides: dict[str, Any]
) -> None:
    with pytest.raises(Unauthenticated):
        _authenticator(tmp_path, keys[0]).authenticate(f"Bearer {_token(keys[0], **overrides)}")


def test_jwt_signed_by_other_key(tmp_path: Path, keys: tuple[Any, Any]) -> None:
    with pytest.raises(Unauthenticated):
        _authenticator(tmp_path, keys[0]).authenticate(f"Bearer {_token(keys[1])}")


def test_jwt_alg_none_and_hmac_confusion(tmp_path: Path, keys: tuple[Any, Any]) -> None:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "groups": ["unitcompute-team"],
    }
    unsigned = jwt.encode(claims, None, algorithm="none")
    public_pem = (
        keys[0]
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    header = jwt.utils.base64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = jwt.utils.base64url_encode(jwt.api_jws.json.dumps(claims).encode())
    import hashlib
    import hmac

    signing_input = header + b"." + payload
    sig = jwt.utils.base64url_encode(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    confused = (signing_input + b"." + sig).decode()
    authenticator = _authenticator(tmp_path, keys[0])
    for token in (unsigned, confused):
        with pytest.raises(Unauthenticated):
            authenticator.authenticate(f"Bearer {token}")


def test_jwt_requires_team_group(tmp_path: Path, keys: tuple[Any, Any]) -> None:
    authenticator = _authenticator(tmp_path, keys[0])
    for groups in (None, [], ["other-team"], "other-team"):
        with pytest.raises(Forbidden):
            authenticator.authenticate(f"Bearer {_token(keys[0], groups=groups)}")


def test_jwt_authenticator_rejects_dev_tokens(tmp_path: Path, keys: tuple[Any, Any]) -> None:
    with pytest.raises(Unauthenticated):
        _authenticator(tmp_path, keys[0]).authenticate("Bearer dev:alice")


def test_production_app_rejects_dev_tokens(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from unitcompute.api.app import create_app
    from unitcompute.db.database import Database

    settings: Settings = make_settings(
        tmp_path, environment="production", **JWT_SETTINGS, **TERRAFORM_SETTINGS
    )
    Database(settings.database_path).migrate()
    with TestClient(create_app(settings)) as client:
        response = client.get("/deployments", headers={"Authorization": "Bearer dev:alice"})
    assert response.status_code == 401
