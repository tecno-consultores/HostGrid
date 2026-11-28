"""Cryptographic primitives: Argon2id, JWT, SHA-256, HMAC, and Ed25519."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.core.errors import DomainError

_PASSWORD_HASHER = PasswordHasher()


def utc_now() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(UTC)


def format_rfc3339(dt: datetime) -> str:
    """Format datetime as UTC RFC 3339 with millisecond precision."""
    normalized = dt.astimezone(UTC) if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    ms = normalized.microsecond // 1000
    return f"{normalized.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize payload into deterministic sorted-key UTF-8 JSON bytes."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    """Compute lowercase hexadecimal SHA-256 digest."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def generate_prefixed_token(prefix: str) -> str:
    """Generate a cryptographically secure token with prefix and 32 random bytes."""
    return f"{prefix}{secrets.token_hex(32)}"


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def create_access_token(
    *,
    user_id: UUID,
    username: str,
    role: str,
    secret: str,
    expire_minutes: int,
) -> tuple[str, datetime]:
    """Create a signed HS256 JWT access token and return (token, expires_at)."""
    now = utc_now()
    expires_at = now + timedelta(minutes=expire_minutes)
    claims = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": str(uuid4()),
    }
    token = jwt.encode(claims, secret, algorithm="HS256")
    return token, expires_at


def decode_access_token(token: str, secret: str) -> dict[str, Any]:
    """Decode and validate an HS256 JWT access token."""
    try:
        decoded: dict[str, Any] = jwt.decode(token, secret, algorithms=["HS256"])
        return decoded
    except jwt.PyJWTError as exc:
        raise DomainError(
            status_code=401,
            title="Unauthorized",
            detail="Invalid or expired authentication token.",
            error_type="urn:hostgrid:error:auth",
        ) from exc


def sign_ed25519_b64(privkey_b64: str, message: bytes) -> str:
    """Sign message bytes using a raw 32-byte base64-encoded Ed25519 private key."""
    raw = base64.b64decode(privkey_b64, validate=True)
    key = Ed25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(key.sign(message)).decode("ascii")


def verify_ed25519_b64(pubkey_b64: str, message: bytes, signature_b64: str) -> bool:
    """Verify a base64 Ed25519 signature over message bytes."""
    try:
        pub_raw = base64.b64decode(pubkey_b64, validate=True)
        sig_raw = base64.b64decode(signature_b64.strip(), validate=True)
        pubkey = Ed25519PublicKey.from_public_bytes(pub_raw)
        pubkey.verify(sig_raw, message)
        return True
    except (ValueError, InvalidSignature):
        return False


def verify_hmac_sha256_b64(key_material: str, message: bytes, signature_b64: str) -> bool:
    """Verify a base64 HMAC-SHA256 digest in constant time."""
    expected = hmac.new(key_material.encode("utf-8"), message, hashlib.sha256).digest()
    try:
        provided = base64.b64decode(signature_b64.strip(), validate=True)
    except ValueError:
        return False
    return hmac.compare_digest(expected, provided)
