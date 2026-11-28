"""Shared pytest fixtures for HostGrid Control Plane tests."""

from __future__ import annotations

import base64
import secrets
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import hash_password
from app.db.base import init_schema
from app.db.models import User
from app.main import create_app
from app.services.eol.detector import seed_eol_catalog

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def generate_ed25519_pair_b64() -> tuple[str, str]:
    """Generate an ephemeral Ed25519 keypair encoded as raw 32-byte base64 strings."""
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(priv_raw).decode("ascii"),
        base64.b64encode(pub_raw).decode("ascii"),
    )


@pytest.fixture
def ed25519_keys() -> tuple[str, str]:
    """Return ephemeral (privkey_b64, pubkey_b64) pair for signing tests."""
    return generate_ed25519_pair_b64()


@pytest.fixture
def test_settings(tmp_path: Path, ed25519_keys: tuple[str, str]) -> Settings:
    """Create isolated testing settings backed by a temporary SQLite DB."""
    priv_b64, pub_b64 = ed25519_keys
    db_file = tmp_path / "test_hostgrid.db"
    bundles_dir = tmp_path / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    return Settings(
        HOSTGRID_ENV="testing",
        HOSTGRID_JWT_SECRET=secrets.token_hex(32),
        DATABASE_URL=f"sqlite+aiosqlite:///{db_file}",
        HOSTGRID_BUNDLES_DIR=str(bundles_dir),
        HOSTGRID_BUNDLE_SIGNING_PRIVKEY_B64=priv_b64,
        HOSTGRID_BUNDLE_SIGNING_PUBKEY_B64=pub_b64,
        HOSTGRID_MAX_BUNDLE_SIZE_MB=2,
        HOSTGRID_MAX_BUNDLE_UNCOMPRESSED_MB=4,
    )


@pytest.fixture
async def app_instance(test_settings: Settings) -> AsyncIterator[FastAPI]:
    """Build initialized FastAPI app with seeded EOL catalog and RBAC test users."""
    app = create_app(test_settings)
    await init_schema(app.state.engine)
    async with app.state.session_factory() as session:
        await seed_eol_catalog(session)
        users = [
            User(
                username="admin_u",
                email="admin@example.local",
                password_hash=hash_password("AdminPass!123"),
                role="admin",
                is_active=True,
            ),
            User(
                username="operator_u",
                email="operator@example.local",
                password_hash=hash_password("OperPass!123"),
                role="operator",
                is_active=True,
            ),
            User(
                username="viewer_u",
                email="viewer@example.local",
                password_hash=hash_password("ViewPass!123"),
                role="viewer",
                is_active=True,
            ),
            User(
                username="inactive_u",
                email="inactive@example.local",
                password_hash=hash_password("InactPass!123"),
                role="viewer",
                is_active=False,
            ),
        ]
        session.add_all(users)
        await session.commit()
    yield app
    await app.state.engine.dispose()


@pytest.fixture
async def db_session(app_instance: FastAPI) -> AsyncIterator[AsyncSession]:
    """Provide direct AsyncSession for unit/service tests."""
    async with app_instance.state.session_factory() as session:
        yield session


@pytest.fixture
async def api_client(app_instance: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Return AsyncClient bound to the FastAPI ASGI app."""
    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


async def login_as(client: httpx.AsyncClient, username: str, password: str) -> str:
    """Authenticate test user and return Bearer JWT."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    token: str = resp.json()["access_token"]
    return token
