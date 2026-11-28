"""HostGrid Control Plane FastAPI application factory and entrypoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.v1 import api_v1_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.db.base import create_engine_and_sessionmaker, init_schema
from app.services.auth_service import ensure_bootstrap_admin
from app.services.eol.detector import seed_eol_catalog


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure a HostGrid FastAPI application instance."""
    resolved_settings = settings or get_settings()
    engine, session_factory = create_engine_and_sessionmaker(resolved_settings.database_url)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if resolved_settings.database_url.startswith("sqlite"):
            await init_schema(engine)
        async with session_factory() as session:
            await seed_eol_catalog(session)
            await session.commit()
            await ensure_bootstrap_admin(session, resolved_settings)
        yield
        await engine.dispose()

    app = FastAPI(
        title="HostGrid Control Plane",
        version="0.1.0",
        docs_url=None if resolved_settings.hostgrid_env == "production" else "/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.engine = engine
    app.state.session_factory = session_factory

    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
    )
    register_exception_handlers(app, is_production=resolved_settings.hostgrid_env == "production")
    app.include_router(api_v1_router)

    @app.get("/healthz", tags=["health"])
    async def healthz(request: Request) -> JSONResponse:
        factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
        try:
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            return JSONResponse(status_code=200, content={"status": "ok", "db": "connected"})
        except Exception:
            return JSONResponse(status_code=503, content={"status": "degraded", "db": "error"})

    return app


def get_asgi_app() -> FastAPI:
    """ASGI factory entrypoint for uvicorn --factory."""
    return create_app()
