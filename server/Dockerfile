FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml ./
COPY app ./app
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install .

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    HOME="/tmp"

RUN addgroup --system --gid 10001 hostgrid \
    && adduser --system --uid 10001 --ingroup hostgrid --home /tmp --no-create-home hostgrid \
    && mkdir -p /var/lib/hostgrid/bundles /var/lib/hostgrid/cve-cache \
    && chown -R hostgrid:hostgrid /var/lib/hostgrid

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER 10001:10001
EXPOSE 8000 8443

CMD ["/usr/local/bin/docker-entrypoint.sh"]
