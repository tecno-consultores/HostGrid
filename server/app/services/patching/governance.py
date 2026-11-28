"""Governed patching state machine, repo precheck, dry-run, maker-checker, and canary logic."""

from __future__ import annotations

import math
from collections.abc import Sequence
from uuid import UUID

from app.core.errors import DomainError
from app.core.rbac import APPROVER_OR_ADMIN, ActorContext, require_roles
from app.schemas.common import sanitize_single_line
from app.services.patching.models import (
    ApprovalDecision,
    CanaryPolicy,
    CanaryWave,
    DryRunGateResult,
    DryRunHostOutcome,
    PatchPlanStatus,
    RepoPrecheckSummary,
    RepoPrecheckTarget,
    SafeModeThreshold,
    WaveHealthReport,
)

ALLOWED_TRANSITIONS: dict[PatchPlanStatus, frozenset[PatchPlanStatus]] = {
    PatchPlanStatus.DRAFT: frozenset({PatchPlanStatus.REPO_PRECHECK}),
    PatchPlanStatus.REPO_PRECHECK: frozenset(
        {PatchPlanStatus.FAILED_PRECHECK, PatchPlanStatus.DRY_RUN_READY}
    ),
    PatchPlanStatus.DRY_RUN_READY: frozenset({PatchPlanStatus.PENDING_APPROVAL}),
    PatchPlanStatus.PENDING_APPROVAL: frozenset(
        {PatchPlanStatus.APPROVED, PatchPlanStatus.REJECTED}
    ),
    PatchPlanStatus.APPROVED: frozenset({PatchPlanStatus.CANARY_WAVE}),
    PatchPlanStatus.CANARY_WAVE: frozenset(
        {PatchPlanStatus.ROLLOUT_IN_PROGRESS, PatchPlanStatus.ROLLED_BACK}
    ),
    PatchPlanStatus.ROLLOUT_IN_PROGRESS: frozenset(
        {PatchPlanStatus.COMPLETED, PatchPlanStatus.ROLLED_BACK}
    ),
    PatchPlanStatus.FAILED_PRECHECK: frozenset(),
    PatchPlanStatus.REJECTED: frozenset(),
    PatchPlanStatus.ROLLED_BACK: frozenset(),
    PatchPlanStatus.COMPLETED: frozenset(),
}


def validate_status_transition(current: PatchPlanStatus, target: PatchPlanStatus) -> None:
    """Enforce the ARCHITECTURE.md section 6 patching state machine."""
    if target not in ALLOWED_TRANSITIONS[current]:
        raise DomainError(
            status_code=409,
            title="Conflict",
            detail=f"Invalid patch plan status transition from {current.value} to {target.value}.",
            error_type="urn:hostgrid:error:invalid_patch_transition",
        )


def _ensure_unique_host_ids(host_ids: Sequence[UUID], *, context: str) -> None:
    if not host_ids:
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail=f"At least one target host is required for {context}.",
            error_type="urn:hostgrid:error:empty_patch_targets",
        )
    if len(set(host_ids)) != len(host_ids):
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail=f"Duplicate target host IDs are not permitted in {context}.",
            error_type="urn:hostgrid:error:duplicate_patch_targets",
        )


def _is_repo_eligible(target: RepoPrecheckTarget) -> bool:
    return target.repo_access_ok is True and target.gpg_verified


def evaluate_repo_precheck(targets: Sequence[RepoPrecheckTarget]) -> RepoPrecheckSummary:
    """Block patching if any target host lacks reachable signed repositories."""
    _ensure_unique_host_ids(
        [item.host_id for item in targets],
        context="repository pre-verification",
    )
    eligible = tuple(item.host_id for item in targets if _is_repo_eligible(item))
    blocked = tuple(item.host_id for item in targets if not _is_repo_eligible(item))
    passed = len(blocked) == 0
    next_status = PatchPlanStatus.DRY_RUN_READY if passed else PatchPlanStatus.FAILED_PRECHECK
    return RepoPrecheckSummary(
        passed=passed,
        eligible_host_ids=eligible,
        blocked_host_ids=blocked,
        next_status=next_status,
    )


def _dry_run_passed(outcome: DryRunHostOutcome) -> bool:
    return outcome.succeeded and outcome.repo_verified


def _index_dry_run_outcomes(
    outcomes: Sequence[DryRunHostOutcome],
) -> dict[UUID, DryRunHostOutcome]:
    by_host: dict[UUID, DryRunHostOutcome] = {}
    for item in outcomes:
        if item.planned_changes_count < 0:
            raise DomainError(
                status_code=422,
                title="Unprocessable Entity",
                detail="planned_changes_count cannot be negative.",
                error_type="urn:hostgrid:error:invalid_dry_run_outcome",
            )
        if item.host_id in by_host:
            raise DomainError(
                status_code=422,
                title="Unprocessable Entity",
                detail="Duplicate dry-run outcomes for the same host are not permitted.",
                error_type="urn:hostgrid:error:duplicate_patch_targets",
            )
        by_host[item.host_id] = item
    return by_host


def _classify_dry_run_hosts(
    target_host_ids: Sequence[UUID],
    by_host: dict[UUID, DryRunHostOutcome],
) -> tuple[tuple[UUID, ...], tuple[UUID, ...]]:
    missing: list[UUID] = []
    failed: list[UUID] = []
    for host_id in target_host_ids:
        outcome = by_host.get(host_id)
        if outcome is None:
            missing.append(host_id)
        elif not _dry_run_passed(outcome):
            failed.append(host_id)
    return tuple(failed), tuple(missing)


def evaluate_dry_run_gate(
    target_host_ids: Sequence[UUID],
    outcomes: Sequence[DryRunHostOutcome],
) -> DryRunGateResult:
    """Require verified successful dry-run simulation on every target host."""
    _ensure_unique_host_ids(target_host_ids, context="dry-run evaluation")
    by_host = _index_dry_run_outcomes(outcomes)
    failed, missing = _classify_dry_run_hosts(target_host_ids, by_host)
    return DryRunGateResult(
        ready_for_approval=(len(failed) == 0 and len(missing) == 0),
        failed_host_ids=failed,
        missing_host_ids=missing,
    )


def _ensure_distinct_approver(actor: ActorContext, plan_created_by: UUID) -> None:
    if actor.actor_id is None or actor.actor_id == plan_created_by:
        raise DomainError(
            status_code=403,
            title="Forbidden",
            detail="Maker-Checker violation: the patch plan creator cannot decide its approval.",
            error_type="urn:hostgrid:error:maker_checker_violation",
        )


def _validate_rationale(rationale: str) -> None:
    try:
        cleaned = sanitize_single_line(rationale).strip()
    except ValueError as exc:
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail="Approval or rejection rationale contains disallowed control characters.",
            error_type="urn:hostgrid:error:invalid_rationale",
        ) from exc
    if not cleaned:
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail="A non-empty approval or rejection rationale is required.",
            error_type="urn:hostgrid:error:missing_rationale",
        )


def validate_maker_checker_decision(
    *,
    actor: ActorContext,
    plan_created_by: UUID,
    current_status: PatchPlanStatus,
    decision: ApprovalDecision,
    rationale: str,
) -> PatchPlanStatus:
    """Validate RBAC, plan state, Maker-Checker separation of duties, and rationale."""
    require_roles(actor, APPROVER_OR_ADMIN)
    if current_status != PatchPlanStatus.PENDING_APPROVAL:
        raise DomainError(
            status_code=409,
            title="Conflict",
            detail="Patch plan must be in PENDING_APPROVAL status to record a decision.",
            error_type="urn:hostgrid:error:invalid_patch_transition",
        )
    _ensure_distinct_approver(actor, plan_created_by)
    _validate_rationale(rationale)
    return (
        PatchPlanStatus.APPROVED
        if decision == ApprovalDecision.APPROVED
        else PatchPlanStatus.REJECTED
    )


def _validate_canary_policy(policy: CanaryPolicy) -> None:
    if not 1 <= policy.canary_percent <= 100:
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail="canary_percent must be between 1 and 100.",
            error_type="urn:hostgrid:error:invalid_canary_policy",
        )
    if not 1 <= policy.max_wave_percent <= 100:
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail="max_wave_percent must be between 1 and 100.",
            error_type="urn:hostgrid:error:invalid_canary_policy",
        )
    if policy.canary_percent > policy.max_wave_percent:
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail="canary_percent cannot exceed max_wave_percent.",
            error_type="urn:hostgrid:error:invalid_canary_policy",
        )


def _slice_rollout_waves(
    remaining: Sequence[UUID],
    wave_size: int,
) -> list[CanaryWave]:
    waves: list[CanaryWave] = []
    for offset in range(0, len(remaining), wave_size):
        waves.append(
            CanaryWave(
                wave_number=len(waves) + 2,
                is_canary=False,
                host_ids=tuple(remaining[offset : offset + wave_size]),
            )
        )
    return waves


def build_canary_waves(
    host_ids: Sequence[UUID],
    policy: CanaryPolicy,
) -> tuple[CanaryWave, ...]:
    """Partition hosts deterministically into Wave 1 (canary) and subsequent rollout waves."""
    _validate_canary_policy(policy)
    _ensure_unique_host_ids(host_ids, context="canary wave planning")

    total = len(host_ids)
    canary_size = max(1, math.ceil(total * policy.canary_percent / 100))
    wave_size = max(1, math.ceil(total * policy.max_wave_percent / 100))

    first_wave = CanaryWave(
        wave_number=1,
        is_canary=True,
        host_ids=tuple(host_ids[:canary_size]),
    )
    rest = _slice_rollout_waves(host_ids[canary_size:], wave_size)
    return (first_wave, *rest)


def _validate_wave_health_inputs(
    report: WaveHealthReport,
    threshold: SafeModeThreshold,
) -> None:
    if min(report.healthy_hosts, report.failed_hosts, report.unreachable_hosts) < 0:
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail="Wave health counts cannot be negative.",
            error_type="urn:hostgrid:error:invalid_wave_health",
        )
    if threshold.max_failed_hosts < 0:
        raise DomainError(
            status_code=422,
            title="Unprocessable Entity",
            detail="max_failed_hosts cannot be negative.",
            error_type="urn:hostgrid:error:invalid_safe_mode_threshold",
        )


def should_trigger_rollback(
    report: WaveHealthReport,
    threshold: SafeModeThreshold,
) -> bool:
    """Decide whether Safe Mode must halt rollout and trigger rollback."""
    _validate_wave_health_inputs(report, threshold)
    if not threshold.enabled:
        return False
    if report.failed_hosts > threshold.max_failed_hosts:
        return True
    return threshold.rollback_on_unreachable and report.unreachable_hosts > 0
