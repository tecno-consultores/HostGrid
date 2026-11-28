#!/bin/sh
set -eu

cert="${HOSTGRID_TLS_CERTFILE:-}"
key="${HOSTGRID_TLS_KEYFILE:-}"
ca="${HOSTGRID_TLS_CA_CERTS:-}"

if [ -n "$cert" ] && [ -z "$key" ]; then
  echo "ERROR: HOSTGRID_TLS_CERTFILE requires HOSTGRID_TLS_KEYFILE." >&2
  exit 2
fi
if [ -z "$cert" ] && [ -n "$key" ]; then
  echo "ERROR: HOSTGRID_TLS_KEYFILE requires HOSTGRID_TLS_CERTFILE." >&2
  exit 2
fi
if [ -n "$ca" ] && [ -z "$cert" ]; then
  echo "ERROR: HOSTGRID_TLS_CA_CERTS requires HOSTGRID_TLS_CERTFILE and HOSTGRID_TLS_KEYFILE." >&2
  exit 2
fi

alembic upgrade head

if [ -n "$cert" ]; then
  port="${HOSTGRID_SERVER_PORT:-8443}"
  if [ -n "$ca" ]; then
    exec uvicorn app.main:get_asgi_app --factory --host 0.0.0.0 --port "$port" \
      --ssl-certfile "$cert" \
      --ssl-keyfile "$key" \
      --ssl-ca-certs "$ca" \
      --ssl-cert-reqs 2
  fi
  exec uvicorn app.main:get_asgi_app --factory --host 0.0.0.0 --port "$port" \
    --ssl-certfile "$cert" \
    --ssl-keyfile "$key"
fi

port="${HOSTGRID_SERVER_PORT:-8000}"
exec uvicorn app.main:get_asgi_app --factory --host 0.0.0.0 --port "$port"
