"""Strict Pydantic schemas for Phase 3 governed patching workflows and agent patch jobs."""

from __future__ import annotations

import re
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.schemas.common import StrictBaseModel, sanitize_single_line

_VALID_PKG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,127}$")


class PatchPlanCreateRequest(StrictBaseModel):
    """Request payload to create a governed patch plan and run repository precheck."""

    title: str = Field(min_length=3, max_length=255)
    target_host_ids: list[UUID] = Field(min_length=1, max_length=200)
    packages: list[str] = Field(min_length=1, max_length=100)
    canary_percent: int = Field(default=10, ge=1, le=100)
    max_wave_percent: int = Field(default=50, ge=1, le=100)
    safe_mode_enabled: bool = True
    max_failed_hosts: int = Field(default=0, ge=0, le=100)
    rollback_on_unreachable: bool = True

    @field_validator("title")
    @classmethod
    def _clean_title(cls, value: str) -> str:
        cleaned = sanitize_single_line(value).strip()
        if len(cleaned) < 3:
            raise ValueError("Patch plan title must be at least 3 visible characters.")
        return cleaned

    @field_validator("packages")
    @classmethod
    def _validate_packages(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in values:
            pkg = sanitize_single_line(raw).strip()
            if not _VALID_PKG_RE.match(pkg):
                raise ValueError(f"Invalid package name '{pkg}'.")
            if pkg not in seen:
                seen.add(pkg)
                cleaned.append(pkg)
        return cleaned


class DryRunOutcomeIn(StrictBaseModel):
    """Per-host non-mutating dry-run simulation outcome."""

    host_id: UUID
    succeeded: bool
    repo_verified: bool
    planned_changes_count: int = Field(default=0, ge=0)
    warnings: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("warnings")
    @classmethod
    def _clean_warnings(cls, values: list[str]) -> list[str]:
        return [sanitize_single_line(w).strip()[:255] for w in values]


class PatchDryRunSubmitRequest(StrictBaseModel):
    """Submit dry-run results for target hosts to unlock Maker-Checker approval."""

    outcomes: list[DryRunOutcomeIn] = Field(min_length=1, max_length=200)


class PatchDecisionRequest(StrictBaseModel):
    """Maker-Checker approval or rejection decision."""

    decision: Literal["approved", "rejected"]
    rationale: str = Field(min_length=3, max_length=1000)

    @field_validator("rationale")
    @classmethod
    def _clean_rationale(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class WaveHealthReportRequest(StrictBaseModel):
    """Safe Mode health telemetry for an active rollout wave."""

    wave_number: int = Field(ge=1, le=200)
    healthy_hosts: int = Field(ge=0)
    failed_hosts: int = Field(ge=0)
    unreachable_hosts: int = Field(default=0, ge=0)


class PatchApprovalResponse(StrictBaseModel):
    """Serialized Maker-Checker decision record."""

    id: UUID
    patch_plan_id: UUID
    approver_id: UUID
    approver_username: str
    decision: Literal["approved", "rejected"]
    rationale: str
    decided_at: str


class CanaryWaveResponse(StrictBaseModel):
    """Deterministic progressive rollout wave."""

    wave_number: int
    is_canary: bool
    host_ids: list[UUID]


class PatchPlanResponse(StrictBaseModel):
    """Full governed patch plan representation."""

    id: UUID
    title: str
    target_host_ids: list[UUID]
    packages: list[str]
    canary_percent: int
    status: str
    created_by: UUID
    created_by_username: str
    created_at: str
    updated_at: str
    precheck: dict[str, Any]
    policy: dict[str, Any]
    waves: list[CanaryWaveResponse]
    active_wave_number: int | None
    dry_run_report: dict[str, Any] | None
    wave_reports: list[dict[str, Any]]
    approvals: list[PatchApprovalResponse]


class AgentPatchJobResponse(StrictBaseModel):
    """Pull-based patch job dispatched to an enrolled agent."""

    plan_id: UUID
    title: str
    mode: Literal["dry_run", "apply"]
    wave_number: int | None
    packages: list[str]
    safe_mode_enabled: bool
    rollback_on_failure: bool


class AgentPatchJobResultRequest(StrictBaseModel):
    """Agent execution or dry-run result posted back over outbound TLS 1.3."""

    mode: Literal["dry_run", "apply"]
    status: Literal[
        "dry_run_only",
        "blocked_repo_precheck",
        "failed_dry_run",
        "failed_healthcheck",
        "rolled_back",
        "completed",
    ]
    succeeded: bool
    repo_verified: bool = False
    planned_changes_count: int = Field(default=0, ge=0)
    healthy_after_patch: bool | None = None
    rolled_back: bool = False
    detail: str = Field(default="", max_length=500)
    warnings: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("detail")
    @classmethod
    def _clean_detail(cls, value: str) -> str:
        return sanitize_single_line(value).strip()

    @field_validator("warnings")
    @classmethod
    def _clean_warnings(cls, values: list[str]) -> list[str]:
        return [sanitize_single_line(w).strip()[:255] for w in values]
