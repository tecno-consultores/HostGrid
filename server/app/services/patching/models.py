"""Typed domain models for Phase 3 governed patching workflows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class PatchPlanStatus(StrEnum):
    """State machine statuses for governed patch plans (ARCHITECTURE.md section 6)."""

    DRAFT = "DRAFT"
    REPO_PRECHECK = "REPO_PRECHECK"
    FAILED_PRECHECK = "FAILED_PRECHECK"
    DRY_RUN_READY = "DRY_RUN_READY"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CANARY_WAVE = "CANARY_WAVE"
    ROLLOUT_IN_PROGRESS = "ROLLOUT_IN_PROGRESS"
    COMPLETED = "COMPLETED"
    ROLLED_BACK = "ROLLED_BACK"


class ApprovalDecision(StrEnum):
    """Maker-Checker approval outcomes (SPEC.md section 2.2)."""

    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True)
class RepoPrecheckTarget:
    """Repository verification status reported by a candidate host."""

    host_id: UUID
    repo_access_ok: bool | None
    gpg_verified: bool = True


@dataclass(frozen=True)
class RepoPrecheckSummary:
    """Aggregate result of pre-verifying signed repository reachability."""

    passed: bool
    eligible_host_ids: tuple[UUID, ...]
    blocked_host_ids: tuple[UUID, ...]
    next_status: PatchPlanStatus


@dataclass(frozen=True)
class DryRunHostOutcome:
    """Deterministic simulation result returned by an agent for a single host."""

    host_id: UUID
    succeeded: bool
    repo_verified: bool
    planned_changes_count: int = 0
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class DryRunGateResult:
    """Verification gate determining whether all target hosts passed dry-run."""

    ready_for_approval: bool
    failed_host_ids: tuple[UUID, ...]
    missing_host_ids: tuple[UUID, ...]


@dataclass(frozen=True)
class CanaryPolicy:
    """Wave slicing configuration for progressive canary rollout."""

    canary_percent: int = 10
    max_wave_percent: int = 50
    halt_on_any_failure: bool = True


@dataclass(frozen=True)
class CanaryWave:
    """Ordered rollout wave containing target host identifiers."""

    wave_number: int
    is_canary: bool
    host_ids: tuple[UUID, ...]


@dataclass(frozen=True)
class SafeModeThreshold:
    """Safe Mode guardrails controlling automatic post-patch rollback."""

    enabled: bool = True
    max_failed_hosts: int = 0
    rollback_on_unreachable: bool = True


@dataclass(frozen=True)
class WaveHealthReport:
    """Post-patch health telemetry aggregated across a rollout wave."""

    healthy_hosts: int
    failed_hosts: int
    unreachable_hosts: int = 0
