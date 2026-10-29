"""ASGI entry point.

Run with ``unitcompute-api`` or ``uvicorn --factory unitcompute.api.main:app_factory``.
"""

from __future__ import annotations

import argparse
import ipaddress

import uvicorn
from fastapi import FastAPI

from unitcompute.api.app import create_app
from unitcompute.config import AuthMode, load_settings
from unitcompute.logging_setup import configure_logging, secure_process_defaults


def app_factory() -> FastAPI:
    secure_process_defaults()
    configure_logging()
    return create_app(load_settings())


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def run() -> None:
    parser = argparse.ArgumentParser(description="Run the UnitCompute API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    settings = load_settings()
    if settings.auth_mode is AuthMode.DEV and not _is_loopback(args.host):
        raise SystemExit("development auth may only listen on a loopback address")
    uvicorn.run(
        "unitcompute.api.main:app_factory",
        factory=True,
        host=args.host,
        port=args.port,
        proxy_headers=False,
        server_header=False,
        log_config=None,
    )
