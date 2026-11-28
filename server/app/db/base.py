"""Async SQLAlchemy 2.0 base class and session lifecycle helpers."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all HostGrid ORM models."""


def create_engine_and_sessionmaker(
    database_url: str,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Build an async SQLAlchemy engine and session factory for PG or SQLite."""
    engine = create_async_engine(
        database_url,
        pool_pre_ping=True,
        future=True,
    )
    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    return engine, session_factory


async def init_schema(engine: AsyncEngine) -> None:
    """Create all tables (used for SQLite development/testing initialization)."""
    from app.db import models as _models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def yield_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Yield a managed AsyncSession."""
    async with session_factory() as session:
        yield session
