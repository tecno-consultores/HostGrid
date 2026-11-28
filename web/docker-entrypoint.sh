#!/bin/sh
set -eu

upstream="${HOSTGRID_WEB_UPSTREAM_URL:-http://server:8000}"
upstream="${upstream%/}"
ca="${HOSTGRID_WEB_UPSTREAM_CA:-}"
client_cert="${HOSTGRID_WEB_UPSTREAM_CLIENT_CERT:-}"
client_key="${HOSTGRID_WEB_UPSTREAM_CLIENT_KEY:-}"

validate_safe_value() {
  case "$1" in
    *[!A-Za-z0-9._:/-]*)
      echo "ERROR: Invalid character in $2." >&2
      exit 2
      ;;
  esac
}

validate_safe_value "$upstream" "HOSTGRID_WEB_UPSTREAM_URL"
case "$upstream" in
  http://*|https://*) ;;
  *)
    echo "ERROR: HOSTGRID_WEB_UPSTREAM_URL must start with http:// or https://." >&2
    exit 2
    ;;
esac

if [ -n "$client_cert" ] && [ -z "$client_key" ]; then
  echo "ERROR: HOSTGRID_WEB_UPSTREAM_CLIENT_CERT requires HOSTGRID_WEB_UPSTREAM_CLIENT_KEY." >&2
  exit 2
fi
if [ -z "$client_cert" ] && [ -n "$client_key" ]; then
  echo "ERROR: HOSTGRID_WEB_UPSTREAM_CLIENT_KEY requires HOSTGRID_WEB_UPSTREAM_CLIENT_CERT." >&2
  exit 2
fi

if [ -n "$ca" ]; then
  validate_safe_value "$ca" "HOSTGRID_WEB_UPSTREAM_CA"
fi
if [ -n "$client_cert" ]; then
  validate_safe_value "$client_cert" "HOSTGRID_WEB_UPSTREAM_CLIENT_CERT"
  validate_safe_value "$client_key" "HOSTGRID_WEB_UPSTREAM_CLIENT_KEY"
fi

is_https=0
case "$upstream" in
  https://*) is_https=1 ;;
esac

if [ "$is_https" -eq 0 ] && { [ -n "$ca" ] || [ -n "$client_cert" ]; }; then
  echo "ERROR: HOSTGRID_WEB_UPSTREAM_CA/CLIENT_CERT require an https:// HOSTGRID_WEB_UPSTREAM_URL." >&2
  exit 2
fi

write_ssl_directives() {
  if [ "$is_https" -eq 1 ]; then
    printf '        proxy_ssl_server_name on;\n'
    printf '        proxy_ssl_protocols TLSv1.2 TLSv1.3;\n'
    if [ -n "$ca" ]; then
      printf '        proxy_ssl_verify on;\n'
      printf '        proxy_ssl_verify_depth 2;\n'
      printf '        proxy_ssl_trusted_certificate %s;\n' "$ca"
    fi
    if [ -n "$client_cert" ]; then
      printf '        proxy_ssl_certificate %s;\n' "$client_cert"
      printf '        proxy_ssl_certificate_key %s;\n' "$client_key"
    fi
  fi
}

{
  cat <<'EOF'
client_body_temp_path /tmp/client_temp;
proxy_temp_path /tmp/proxy_temp;
fastcgi_temp_path /tmp/fastcgi_temp;
uwsgi_temp_path /tmp/uwsgi_temp;
scgi_temp_path /tmp/scgi_temp;

server {
    listen 8080;
    server_name _;

    root /usr/share/nginx/html;
    index index.html;

    client_max_body_size 55m;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location /api/ {
EOF
  printf '        proxy_pass %s;\n' "$upstream"
  cat <<'EOF'
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
EOF
  write_ssl_directives
  cat <<'EOF'
    }

    location = /healthz {
EOF
  printf '        proxy_pass %s/healthz;\n' "$upstream"
  write_ssl_directives
  cat <<'EOF'
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF
} > /tmp/nginx-default.conf

exec nginx -g "daemon off;"
