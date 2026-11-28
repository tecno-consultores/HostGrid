"""Initial HostGrid schema migration.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-19 00:00:00
"""

from __future__ import annotations

from alembic import op

from app.db import models as _models  # noqa: F401
from app.db.base import Base

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all initial HostGrid tables."""
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    """Drop all initial HostGrid tables."""
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
