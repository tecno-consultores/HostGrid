"""RFC 9457 Problem Details error model and FastAPI exception handlers."""

from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

PROBLEM_MEDIA_TYPE = "application/problem+json"


class DomainError(Exception):
    """Structured domain error rendered as RFC 9457 Problem Details."""

    def __init__(
        self,
        status_code: int,
        title: str,
        detail: str,
        error_type: str = "about:blank",
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.title = title
        self.detail = detail
        self.error_type = error_type


def build_problem_response(
    *,
    status_code: int,
    title: str,
    detail: str,
    instance: str,
    error_type: str = "about:blank",
) -> JSONResponse:
    """Create a JSONResponse conforming to RFC 9457."""
    return JSONResponse(
        status_code=status_code,
        media_type=PROBLEM_MEDIA_TYPE,
        content={
            "type": error_type,
            "title": title,
            "status": status_code,
            "detail": detail,
            "instance": instance,
            "trace_id": str(uuid4()),
        },
    )


def register_exception_handlers(app: FastAPI, is_production: bool) -> None:
    """Attach RFC 9457 handlers for domain, validation, and unexpected errors."""

    @app.exception_handler(DomainError)
    async def handle_domain_error(request: Request, exc: DomainError) -> JSONResponse:
        return build_problem_response(
            status_code=exc.status_code,
            title=exc.title,
            detail=exc.detail,
            instance=str(request.url.path),
            error_type=exc.error_type,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        detail = (
            "Request payload validation failed."
            if is_production
            else f"Validation error: {exc.errors()}"
        )
        return build_problem_response(
            status_code=422,
            title="Unprocessable Entity",
            detail=detail,
            instance=str(request.url.path),
            error_type="urn:hostgrid:error:validation",
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        detail = (
            "An internal error occurred while processing the request."
            if is_production
            else f"Unhandled error: {exc}"
        )
        return build_problem_response(
            status_code=500,
            title="Internal Server Error",
            detail=detail,
            instance=str(request.url.path),
            error_type="urn:hostgrid:error:internal",
        )
