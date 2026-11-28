"""TLS/mTLS-aware container healthcheck helper for HostGrid Control Plane."""

from __future__ import annotations

import os
import ssl
import sys
import urllib.request
from collections.abc import Mapping


def _is_tls_enabled(env: Mapping[str, str]) -> bool:
    cert = env.get("HOSTGRID_TLS_CERTFILE", "").strip()
    key = env.get("HOSTGRID_TLS_KEYFILE", "").strip()
    return bool(cert) and bool(key)


def _resolve_ca_path(env: Mapping[str, str]) -> str | None:
    for key in ("HOSTGRID_HEALTH_CA", "HOSTGRID_TLS_CA_CERTS", "HOSTGRID_TLS_CERTFILE"):
        value = env.get(key, "").strip()
        if value:
            return value
    return None


def _build_ssl_context(env: Mapping[str, str]) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=_resolve_ca_path(env))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    client_cert = env.get("HOSTGRID_HEALTH_CLIENT_CERT", "").strip()
    client_key = env.get("HOSTGRID_HEALTH_CLIENT_KEY", "").strip()
    if bool(client_cert) != bool(client_key):
        raise ValueError(
            "Both HOSTGRID_HEALTH_CLIENT_CERT and HOSTGRID_HEALTH_CLIENT_KEY must be set together."
        )
    if client_cert and client_key:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return ctx


def _default_health_url(env: Mapping[str, str]) -> str:
    tls_enabled = _is_tls_enabled(env)
    port = env.get("HOSTGRID_SERVER_PORT", "").strip()
    if not port:
        port = "8443" if tls_enabled else "8000"
    scheme = "https" if tls_enabled else "http"
    return f"{scheme}://127.0.0.1:{port}/healthz"


def resolve_healthcheck_target(env: Mapping[str, str]) -> tuple[str, ssl.SSLContext | None]:
    """Resolve local /healthz URL and optional SSL context from container environment."""
    override = env.get("HOSTGRID_HEALTH_URL", "").strip()
    url = override or _default_health_url(env)
    if not url.startswith(("http://", "https://")):
        raise ValueError("Healthcheck URL must use http:// or https://.")
    ctx = _build_ssl_context(env) if url.startswith("https://") else None
    return url, ctx


def check_health(env: Mapping[str, str] | None = None, *, timeout: float = 3.0) -> int:
    """Execute /healthz probe returning 0 when HTTP 200 is received, 1 otherwise."""
    resolved_env = os.environ if env is None else env
    try:
        url, ctx = resolve_healthcheck_target(resolved_env)
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:  # noqa: S310
            return 0 if int(getattr(resp, "status", 0)) == 200 else 1
    except Exception:
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(check_health())
