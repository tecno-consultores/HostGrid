"""Service-layer Role-Based Access Control (RBAC) primitives."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from app.core.errors import DomainError


class Role(StrEnum):
    """HostGrid user roles."""

    ADMIN = "admin"
    APPROVER = "approver"
    OPERATOR = "operator"
    VIEWER = "viewer"


ALL_USER_ROLES: frozenset[Role] = frozenset(
    {Role.ADMIN, Role.APPROVER, Role.OPERATOR, Role.VIEWER}
)
OPERATOR_OR_ADMIN: frozenset[Role] = frozenset({Role.OPERATOR, Role.ADMIN})
APPROVER_OR_ADMIN: frozenset[Role] = frozenset({Role.APPROVER, Role.ADMIN})
ADMIN_ONLY: frozenset[Role] = frozenset({Role.ADMIN})


@dataclass(frozen=True)
class ActorContext:
    """Authenticated principal (human user or enrolled agent)."""

    actor_id: UUID | None
    username: str
    role: Role | None = None
    is_agent: bool = False
    host_id: UUID | None = None


def require_roles(actor: ActorContext, allowed: Iterable[Role]) -> None:
    """Enforce role authorization inside the domain service layer."""
    if actor.is_agent or actor.role is None or actor.role not in set(allowed):
        raise DomainError(
            status_code=403,
            title="Forbidden",
            detail="Insufficient permissions for this operation.",
            error_type="urn:hostgrid:error:forbidden",
        )


def require_agent_host(actor: ActorContext, target_host_id: UUID) -> None:
    """Verify the authenticated agent matches the target host identifier."""
    if not actor.is_agent or actor.host_id != target_host_id:
        raise DomainError(
            status_code=403,
            title="Forbidden",
            detail="Agent credential does not match the target host.",
            error_type="urn:hostgrid:error:agent_host_mismatch",
        )
