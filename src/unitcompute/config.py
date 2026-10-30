"""Validated runtime configuration.

Everything is read from ``UNITCOMPUTE_*`` environment variables. Development mode is the
default and never provisions real infrastructure; production refuses to start unless real
authentication and the Terraform provisioner are fully configured.
"""

from __future__ import annotations

import os
import re
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from typing import Annotated, Self
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

DEFAULT_REGION = "us-east-1"
# One region per installation (SPEC). A region is supported only when it has a reviewed price
# snapshot (pricing.PRICE_SNAPSHOTS), a bootstrapped network/IAM/state environment and
# regional IAM policies filled from docs/iam. Adding one is a code change that adds its
# snapshot here and there; the configured value is checked against this set at startup.
SUPPORTED_REGIONS = frozenset({DEFAULT_REGION})
_REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]$")
INSTANCE_TYPE = "t3.micro"
AL2023_AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
AGENT_PROVIDERS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}

_ROLE_ARN = re.compile(r"^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


class AuthMode(StrEnum):
    JWT = "jwt"
    DEV = "dev"


class ProvisionerKind(StrEnum):
    DISABLED = "disabled"
    SIMULATED = "simulated"
    TERRAFORM = "terraform"


class ConfigError(ValueError):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="UNITCOMPUTE_", extra="forbid", frozen=True)

    environment: Environment = Environment.DEVELOPMENT
    data_dir: Path = Path("data")

    auth_mode: AuthMode = AuthMode.DEV
    auth_issuer: str | None = None
    auth_audience: str | None = None
    auth_jwks_url: str | None = None
    auth_algorithms: Annotated[tuple[str, ...], NoDecode] = ("RS256",)
    auth_required_group: str | None = None
    auth_groups_claim: str = "groups"
    auth_jwks_cache_seconds: int = Field(default=300, ge=30, le=3600)

    cors_origins: Annotated[tuple[str, ...], NoDecode] = ()
    max_request_bytes: int = Field(default=16 * 1024, ge=1024, le=1024 * 1024)

    provisioner: ProvisionerKind = ProvisionerKind.DISABLED
    aws_region: str = DEFAULT_REGION
    aws_account_id: str | None = None
    vpc_id: str | None = None
    subnet_id: str | None = None
    instance_profile_name: str | None = None
    state_bucket: str | None = None
    plan_role_arn: str | None = None
    apply_role_arn: str | None = None

    terraform_binary: Path = Path("terraform")
    terraform_plugin_cache_dir: Path | None = None
    plan_timeout_seconds: int = Field(default=600, ge=30, le=3600)
    apply_timeout_seconds: int = Field(default=1800, ge=60, le=7200)
    plan_ttl_seconds: int = Field(default=900, ge=60, le=900)
    workdir_retention_days: int = Field(default=7, ge=1, le=90)
    worker_poll_seconds: float = Field(default=2.0, ge=0.1, le=60)
    worker_stale_seconds: int = Field(default=120, ge=30, le=3600)
    worker_self_check_seconds: int = Field(default=300, ge=30, le=86400)
    readiness_timeout_seconds: float = Field(default=300, ge=0, le=1800)
    readiness_poll_seconds: float = Field(default=15, ge=0, le=300)
    readiness_refresh_seconds: int = Field(default=300, ge=30, le=86400)

    agent_model: str | None = None
    agent_timeout_seconds: float = Field(default=45, ge=1, le=120)
    agent_max_model_calls: int = Field(default=6, ge=1, le=12)
    agent_max_tool_calls: int = Field(default=8, ge=1, le=16)
    agent_max_output_tokens: int = Field(default=1024, ge=64, le=4096)
    agent_max_message_chars: int = Field(default=2000, ge=100, le=8000)
    agent_history_messages: int = Field(default=12, ge=0, le=40)
    agent_max_session_turns: int = Field(default=50, ge=1, le=500)
    agent_max_messages_per_day: int = Field(default=200, ge=1, le=10000)

    @field_validator("auth_algorithms", "cors_origins", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("auth_algorithms")
    @classmethod
    def _asymmetric_only(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {"RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384", "EdDSA"}
        bad = [alg for alg in value if alg not in allowed]
        if bad or not value:
            raise ValueError(
                f"auth_algorithms must be asymmetric algorithms from {sorted(allowed)}"
            )
        return value

    @field_validator("cors_origins")
    @classmethod
    def _explicit_origins(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for origin in value:
            parsed = urlparse(origin)
            if origin == "*" or parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(
                    "cors_origins must be explicit http(s) origins; '*' is not allowed"
                )
            if parsed.path not in {"", "/"}:
                raise ValueError("cors_origins must not contain paths")
        return value

    @model_validator(mode="after")
    def _fail_closed(self) -> Self:
        problems: list[str] = []
        production = self.environment is Environment.PRODUCTION
        if not _REGION.fullmatch(self.aws_region):
            problems.append("aws_region must look like an AWS region name such as us-east-1")
        elif self.aws_region not in SUPPORTED_REGIONS:
            problems.append(
                "aws_region must be one of the supported regions: "
                + ", ".join(sorted(SUPPORTED_REGIONS))
            )
        if production and self.auth_mode is not AuthMode.JWT:
            problems.append("production requires auth_mode=jwt")
        if self.provisioner is ProvisionerKind.TERRAFORM and (
            self.auth_mode is not AuthMode.JWT or not self.auth_required_group
        ):
            # Real infrastructure is never driven by forgeable development identities.
            problems.append("provisioner=terraform requires auth_mode=jwt with auth_required_group")
        if self.auth_mode is AuthMode.JWT:
            for field in ("auth_issuer", "auth_audience", "auth_jwks_url"):
                if not getattr(self, field):
                    problems.append(f"auth_mode=jwt requires {field}")
            if self.auth_jwks_url and urlparse(self.auth_jwks_url).scheme != "https":
                problems.append("auth_jwks_url must use https")
            if production and not self.auth_required_group:
                problems.append("production requires auth_required_group (team membership)")
        if production and self.provisioner is not ProvisionerKind.TERRAFORM:
            problems.append("production requires provisioner=terraform")
        if self.provisioner is ProvisionerKind.TERRAFORM:
            problems.extend(self._terraform_problems())
        if self.agent_model is not None:
            provider, _, model = self.agent_model.partition(":")
            if provider == "fake":
                if production:
                    problems.append("the fake agent model is development-only")
            elif provider not in AGENT_PROVIDERS or not model:
                problems.append(
                    "agent_model must be '<provider>:<model>' with provider in "
                    f"{sorted(AGENT_PROVIDERS)}"
                )
        if problems:
            raise ConfigError("; ".join(problems))
        return self

    def _terraform_problems(self) -> list[str]:
        problems: list[str] = []
        checks: list[tuple[str, re.Pattern[str]]] = [
            ("aws_account_id", re.compile(r"^\d{12}$")),
            ("vpc_id", re.compile(r"^vpc-[0-9a-f]{8,17}$")),
            ("subnet_id", re.compile(r"^subnet-[0-9a-f]{8,17}$")),
            ("instance_profile_name", re.compile(r"^[A-Za-z0-9+=,.@_-]{1,128}$")),
            ("state_bucket", _BUCKET),
            ("plan_role_arn", _ROLE_ARN),
            ("apply_role_arn", _ROLE_ARN),
        ]
        for field, pattern in checks:
            value = getattr(self, field)
            if not value or not pattern.fullmatch(value):
                problems.append(f"provisioner=terraform requires a valid {field}")
        if self.plan_role_arn and self.plan_role_arn == self.apply_role_arn:
            problems.append("plan_role_arn and apply_role_arn must be distinct roles")
        return problems

    @cached_property
    def database_path(self) -> Path:
        return self.data_dir / "unitcompute.sqlite3"

    @cached_property
    def workdir_root(self) -> Path:
        return self.data_dir / "work"

    @cached_property
    def worker_lock_path(self) -> Path:
        return self.data_dir / "worker.lock"


def load_settings() -> Settings:
    known = {f"UNITCOMPUTE_{name.upper()}" for name in Settings.model_fields}
    unknown = sorted(k for k in os.environ if k.startswith("UNITCOMPUTE_") and k not in known)
    if unknown:
        # A misspelt security setting must not silently fall back to a default.
        raise ConfigError(f"unknown settings: {', '.join(unknown)}")
    try:
        return Settings()
    except ConfigError:
        raise
    except ValueError as exc:  # pydantic ValidationError is a ValueError subclass
        raise ConfigError(str(exc)) from exc
