"""Persistent governed patching service layer with WORM audit and agent pull jobs (Phase 3)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import DomainError
from app.core.rbac import (
    ALL_USER_ROLES,
    APPROVER_OR_ADMIN,
    OPERATOR_OR_ADMIN,
    ActorContext,
    require_agent_host,
    require_roles,
)
from app.core.security import format_rfc3339, utc_now
from app.db.models import Host, IdempotencyRecord, PatchApproval, PatchPlan, User
from app.schemas.common import PaginatedResponse
from app.schemas.patching import (
    AgentPatchJobResponse,
    AgentPatchJobResultRequest,
    CanaryWaveResponse,
    PatchApprovalResponse,
    PatchDecisionRequest,
    PatchDryRunSubmitRequest,
    PatchPlanCreateRequest,
    PatchPlanResponse,
    WaveHealthReportRequest,
)
from app.services.patching.governance import (
    build_canary_waves,
    evaluate_dry_run_gate,
    evaluate_repo_precheck,
    should_trigger_rollback,
    validate_maker_checker_decision,
    validate_status_transition,
)
from app.services.patching.models import (
    ApprovalDecision,
    CanaryPolicy,
    DryRunHostOutcome,
    PatchPlanStatus,
    RepoPrecheckTarget,
    SafeModeThreshold,
    WaveHealthReport,
)
from app.services.worm import append_audit_log


def _parse_plan_meta(plan: PatchPlan) -> dict[str, Any]:
    raw = plan.dry_run_report_json
    return dict(raw) if isinstance(raw, dict) else {}


def _validate_idempotency_key(raw_key: str | None) -> str | None:
    if raw_key is None or not raw_key.strip():
        return None
    try:
        return str(UUID(raw_key.strip()))
    except ValueError as exc:
        raise DomainError(
            status_code=422,
            title="Invalid Idempotency-Key",
            detail="Idempotency-Key header must be a valid UUID.",
            error_type="urn:hostgrid:error:invalid_idempotency_key",
        ) from exc


async def _load_plan_or_404(
    session: AsyncSession,
    plan_id: UUID,
    *,
    for_update: bool = False,
) -> PatchPlan:
    stmt = select(PatchPlan).where(PatchPlan.id == plan_id)
    if for_update and session.get_bind().dialect.name == "postgresql":
        stmt = stmt.with_for_update()
    plan = (await session.execute(stmt)).scalar_one_or_none()
    if plan is None:
        raise DomainError(
            status_code=404,
            title="Not Found",
            detail="Patch plan not found.",
            error_type="urn:hostgrid:error:not_found",
        )
    return plan


async def _load_usernames(session: AsyncSession, user_ids: set[UUID]) -> dict[UUID, str]:
    if not user_ids:
        return {}
    rows = (
        await session.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
    ).all()
    return {uid: uname for uid, uname in rows}


def _serialize_waves(meta: dict[str, Any]) -> list[CanaryWaveResponse]:
    waves_raw = meta.get("waves", [])
    return [
        CanaryWaveResponse(
            wave_number=int(w["wave_number"]),
            is_canary=bool(w["is_canary"]),
            host_ids=[UUID(str(hid)) for hid in w["host_ids"]],
        )
        for w in waves_raw
        if isinstance(w, dict)
    ]


async def _serialize_plan(session: AsyncSession, plan: PatchPlan) -> PatchPlanResponse:
    approval_rows = (
        await session.execute(
            select(PatchApproval)
            .where(PatchApproval.patch_plan_id == plan.id)
            .order_by(PatchApproval.decided_at.asc())
        )
    ).scalars().all()
    user_ids = {plan.created_by, *(row.approver_id for row in approval_rows)}
    usernames = await _load_usernames(session, user_ids)
    meta = _parse_plan_meta(plan)
    approvals = [
        PatchApprovalResponse(
            id=row.id,
            patch_plan_id=row.patch_plan_id,
            approver_id=row.approver_id,
            approver_username=usernames.get(row.approver_id, "unknown"),
            decision=row.decision,  # type: ignore[arg-type]
            rationale=row.rationale,
            decided_at=format_rfc3339(row.decided_at),
        )
        for row in approval_rows
    ]
    return PatchPlanResponse(
        id=plan.id,
        title=plan.title,
        target_host_ids=[UUID(str(hid)) for hid in plan.target_host_ids_json],
        packages=list(plan.packages_json),
        canary_percent=plan.canary_percent,
        status=plan.status,
        created_by=plan.created_by,
        created_by_username=usernames.get(plan.created_by, "unknown"),
        created_at=format_rfc3339(plan.created_at),
        updated_at=format_rfc3339(plan.updated_at),
        precheck=dict(meta.get("precheck", {})),
        policy=dict(meta.get("policy", {})),
        waves=_serialize_waves(meta),
        active_wave_number=meta.get("active_wave_number"),
        dry_run_report=meta.get("dry_run"),
        wave_reports=list(meta.get("wave_reports", [])),
        approvals=approvals,
    )


async def _load_target_hosts_ordered(
    session: AsyncSession,
    target_host_ids: list[UUID],
) -> list[Host]:
    rows = (
        await session.execute(select(Host).where(Host.id.in_(target_host_ids)))
    ).scalars().all()
    by_id = {host.id: host for host in rows}
    missing = [str(hid) for hid in target_host_ids if hid not in by_id]
    if missing:
        raise DomainError(
            status_code=404,
            title="Unknown Target Host",
            detail=f"Target host(s) not found: {', '.join(missing[:5])}.",
            error_type="urn:hostgrid:error:unknown_target_host",
        )
    return [by_id[hid] for hid in target_host_ids]


def _build_initial_plan_meta(
    payload: PatchPlanCreateRequest,
    hosts: list[Host],
) -> tuple[PatchPlanStatus, dict[str, Any]]:
    policy = CanaryPolicy(
        canary_percent=payload.canary_percent,
        max_wave_percent=payload.max_wave_percent,
    )
    waves = build_canary_waves(payload.target_host_ids, policy)
    targets = [
        RepoPrecheckTarget(
            host_id=host.id,
            repo_access_ok=host.repo_access_ok,
            gpg_verified=(host.repo_access_ok is True),
        )
        for host in hosts
    ]
    precheck = evaluate_repo_precheck(targets)
    meta: dict[str, Any] = {
        "precheck": {
            "passed": precheck.passed,
            "eligible_host_ids": [str(hid) for hid in precheck.eligible_host_ids],
            "blocked_host_ids": [str(hid) for hid in precheck.blocked_host_ids],
        },
        "policy": {
            "canary_percent": payload.canary_percent,
            "max_wave_percent": payload.max_wave_percent,
            "safe_mode_enabled": payload.safe_mode_enabled,
            "max_failed_hosts": payload.max_failed_hosts,
            "rollback_on_unreachable": payload.rollback_on_unreachable,
        },
        "waves": [
            {
                "wave_number": w.wave_number,
                "is_canary": w.is_canary,
                "host_ids": [str(hid) for hid in w.host_ids],
            }
            for w in waves
        ],
        "active_wave_number": None,
        "dry_run": None,
        "dry_run_outcomes_by_host": {},
        "wave_host_results": {},
        "wave_reports": [],
    }
    return precheck.next_status, meta


def _plan_request_fingerprint(payload: PatchPlanCreateRequest) -> dict[str, Any]:
    return {
        "title": payload.title,
        "target_host_ids": [str(hid) for hid in payload.target_host_ids],
        "packages": list(payload.packages),
        "canary_percent": payload.canary_percent,
        "max_wave_percent": payload.max_wave_percent,
        "safe_mode_enabled": payload.safe_mode_enabled,
        "max_failed_hosts": payload.max_failed_hosts,
        "rollback_on_unreachable": payload.rollback_on_unreachable,
    }


def _cached_plan_fingerprint(plan: PatchPlanResponse) -> dict[str, Any]:
    pol = plan.policy
    return {
        "title": plan.title,
        "target_host_ids": [str(hid) for hid in plan.target_host_ids],
        "packages": list(plan.packages),
        "canary_percent": int(pol.get("canary_percent", plan.canary_percent)),
        "max_wave_percent": int(pol.get("max_wave_percent", 50)),
        "safe_mode_enabled": bool(pol.get("safe_mode_enabled", True)),
        "max_failed_hosts": int(pol.get("max_failed_hosts", 0)),
        "rollback_on_unreachable": bool(pol.get("rollback_on_unreachable", True)),
    }


async def _lookup_idempotent_plan(
    session: AsyncSession,
    *,
    key: str,
    actor_scope: str,
    payload: PatchPlanCreateRequest,
) -> PatchPlanResponse | None:
    existing = (
        await session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.idempotency_key == key,
                IdempotencyRecord.endpoint == "POST /api/v1/patching/plans",
                IdempotencyRecord.actor_scope == actor_scope,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        return None
    cached = PatchPlanResponse.model_validate(existing.response_json)
    if _cached_plan_fingerprint(cached) != _plan_request_fingerprint(payload):
        raise DomainError(
            status_code=409,
            title="Idempotency Conflict",
            detail="Idempotency-Key was already used with a different patch plan payload.",
            error_type="urn:hostgrid:error:idempotency_conflict",
        )
    return cached


async def _commit_plan_with_idempotency(
    session: AsyncSession,
    *,
    clean_key: str | None,
    actor_scope: str,
    payload: PatchPlanCreateRequest,
    response: PatchPlanResponse,
) -> PatchPlanResponse:
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        if clean_key is None:
            raise
        cached = await _lookup_idempotent_plan(
            session, key=clean_key, actor_scope=actor_scope, payload=payload
        )
        if cached is None:
            raise
        return cached
    return response


async def _resolve_creator_id(actor: ActorContext) -> UUID:
    if actor.actor_id is None:
        raise DomainError(
            status_code=403,
            title="Forbidden",
            detail="Human actor identity is required for this operation.",
            error_type="urn:hostgrid:error:forbidden",
        )
    return actor.actor_id


async def create_patch_plan(
    session: AsyncSession,
    *,
    actor: ActorContext,
    payload: PatchPlanCreateRequest,
    idempotency_key: str | None = None,
) -> PatchPlanResponse:
    """Create a PatchPlan and run repo precheck (DRAFT -> REPO_PRECHECK -> DRY_RUN_READY|FAILED)."""
    require_roles(actor, OPERATOR_OR_ADMIN)
    creator_id = await _resolve_creator_id(actor)
    clean_key = _validate_idempotency_key(idempotency_key)
    actor_scope = f"user:{creator_id}"
    cached = (
        await _lookup_idempotent_plan(
            session, key=clean_key, actor_scope=actor_scope, payload=payload
        )
        if clean_key is not None
        else None
    )
    if cached is not None:
        return cached

    hosts = await _load_target_hosts_ordered(session, payload.target_host_ids)
    next_status, meta = _build_initial_plan_meta(payload, hosts)
    validate_status_transition(PatchPlanStatus.DRAFT, PatchPlanStatus.REPO_PRECHECK)
    validate_status_transition(PatchPlanStatus.REPO_PRECHECK, next_status)

    plan = PatchPlan(
        title=payload.title,
        target_host_ids_json=[str(hid) for hid in payload.target_host_ids],
        packages_json=list(payload.packages),
        canary_percent=payload.canary_percent,
        status=next_status.value,
        dry_run_report_json=meta,
        created_by=creator_id,
    )
    session.add(plan)
    await session.flush()

    await append_audit_log(
        session,
        actor_id=creator_id,
        actor_username=actor.username,
        action="patch_plan.created",
        resource_type="patch_plan",
        resource_id=str(plan.id),
        details={
            "title": plan.title,
            "status": plan.status,
            "target_count": len(payload.target_host_ids),
            "packages": payload.packages,
            "precheck_passed": meta["precheck"]["passed"],
        },
    )
    response = await _serialize_plan(session, plan)
    if clean_key is not None:
        session.add(
            IdempotencyRecord(
                idempotency_key=clean_key,
                endpoint="POST /api/v1/patching/plans",
                actor_scope=actor_scope,
                status_code=201,
                response_json=response.model_dump(mode="json"),
            )
        )
    return await _commit_plan_with_idempotency(
        session,
        clean_key=clean_key,
        actor_scope=actor_scope,
        payload=payload,
        response=response,
    )


async def list_patch_plans(
    session: AsyncSession,
    *,
    actor: ActorContext,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> PaginatedResponse[PatchPlanResponse]:
    """List patch plans ordered newest first with optional status filter."""
    require_roles(actor, ALL_USER_ROLES)
    clauses: list[Any] = []
    if status_filter:
        clauses.append(PatchPlan.status == status_filter.strip().upper())
    total = int(
        (await session.execute(select(func.count(PatchPlan.id)).where(*clauses))).scalar_one()
    )
    rows = (
        await session.execute(
            select(PatchPlan)
            .where(*clauses)
            .order_by(desc(PatchPlan.created_at), desc(PatchPlan.id))
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    items = [await _serialize_plan(session, row) for row in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


async def get_patch_plan(
    session: AsyncSession,
    *,
    actor: ActorContext,
    plan_id: UUID,
) -> PatchPlanResponse:
    """Fetch single governed patch plan with approvals, waves, and dry-run details."""
    require_roles(actor, ALL_USER_ROLES)
    plan = await _load_plan_or_404(session, plan_id)
    return await _serialize_plan(session, plan)


def _apply_dry_run_outcomes(
    plan: PatchPlan,
    outcomes: list[DryRunHostOutcome],
) -> tuple[bool, dict[str, Any]]:
    target_ids = [UUID(str(hid)) for hid in plan.target_host_ids_json]
    gate = evaluate_dry_run_gate(target_ids, outcomes)
    meta = _parse_plan_meta(plan)
    outcomes_by_host = {
        str(item.host_id): {
            "host_id": str(item.host_id),
            "succeeded": item.succeeded,
            "repo_verified": item.repo_verified,
            "planned_changes_count": item.planned_changes_count,
            "warnings": list(item.warnings),
        }
        for item in outcomes
    }
    meta["dry_run_outcomes_by_host"] = outcomes_by_host
    meta["dry_run"] = {
        "ready_for_approval": gate.ready_for_approval,
        "failed_host_ids": [str(hid) for hid in gate.failed_host_ids],
        "missing_host_ids": [str(hid) for hid in gate.missing_host_ids],
        "outcomes": list(outcomes_by_host.values()),
        "evaluated_at": format_rfc3339(utc_now()),
    }
    if gate.ready_for_approval:
        validate_status_transition(PatchPlanStatus(plan.status), PatchPlanStatus.PENDING_APPROVAL)
        plan.status = PatchPlanStatus.PENDING_APPROVAL.value
    plan.dry_run_report_json = meta
    plan.updated_at = utc_now()
    return gate.ready_for_approval, meta["dry_run"]


async def submit_dry_run(
    session: AsyncSession,
    *,
    actor: ActorContext,
    plan_id: UUID,
    payload: PatchDryRunSubmitRequest,
) -> PatchPlanResponse:
    """Record dry-run simulation outcomes and transition DRY_RUN_READY -> PENDING_APPROVAL."""
    require_roles(actor, OPERATOR_OR_ADMIN)
    plan = await _load_plan_or_404(session, plan_id, for_update=True)
    if PatchPlanStatus(plan.status) != PatchPlanStatus.DRY_RUN_READY:
        raise DomainError(
            status_code=409,
            title="Conflict",
            detail="Dry-run results can only be recorded while plan is in DRY_RUN_READY status.",
            error_type="urn:hostgrid:error:invalid_patch_transition",
        )
    outcomes = [
        DryRunHostOutcome(
            host_id=o.host_id,
            succeeded=o.succeeded,
            repo_verified=o.repo_verified,
            planned_changes_count=o.planned_changes_count,
            warnings=tuple(o.warnings),
        )
        for o in payload.outcomes
    ]
    ready, dry_run_summary = _apply_dry_run_outcomes(plan, outcomes)
    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="patch_plan.dry_run_recorded",
        resource_type="patch_plan",
        resource_id=str(plan.id),
        details={"ready_for_approval": ready, "status": plan.status, "summary": dry_run_summary},
    )
    await session.commit()
    return await _serialize_plan(session, plan)


async def decide_patch_plan(
    session: AsyncSession,
    *,
    actor: ActorContext,
    plan_id: UUID,
    payload: PatchDecisionRequest,
) -> PatchPlanResponse:
    """Enforce Maker-Checker approval or rejection (approver_id != created_by) and audit WORM."""
    require_roles(actor, APPROVER_OR_ADMIN)
    plan = await _load_plan_or_404(session, plan_id, for_update=True)
    next_status = validate_maker_checker_decision(
        actor=actor,
        plan_created_by=plan.created_by,
        current_status=PatchPlanStatus(plan.status),
        decision=ApprovalDecision(payload.decision),
        rationale=payload.rationale,
    )
    validate_status_transition(PatchPlanStatus(plan.status), next_status)
    approver_id = await _resolve_creator_id(actor)

    approval = PatchApproval(
        patch_plan_id=plan.id,
        approver_id=approver_id,
        decision=payload.decision,
        rationale=payload.rationale,
    )
    session.add(approval)
    plan.status = next_status.value
    plan.updated_at = utc_now()
    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action=f"patch_plan.{payload.decision}",
        resource_type="patch_plan",
        resource_id=str(plan.id),
        details={"decision": payload.decision, "rationale": payload.rationale},
    )
    await session.commit()
    return await _serialize_plan(session, plan)


async def start_canary_execution(
    session: AsyncSession,
    *,
    actor: ActorContext,
    plan_id: UUID,
) -> PatchPlanResponse:
    """Transition an APPROVED plan into CANARY_WAVE (Wave 1)."""
    require_roles(actor, OPERATOR_OR_ADMIN)
    plan = await _load_plan_or_404(session, plan_id, for_update=True)
    validate_status_transition(PatchPlanStatus(plan.status), PatchPlanStatus.CANARY_WAVE)
    meta = _parse_plan_meta(plan)
    meta["active_wave_number"] = 1
    plan.status = PatchPlanStatus.CANARY_WAVE.value
    plan.dry_run_report_json = meta
    plan.updated_at = utc_now()
    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action="patch_plan.canary_started",
        resource_type="patch_plan",
        resource_id=str(plan.id),
        details={"active_wave_number": 1},
    )
    await session.commit()
    return await _serialize_plan(session, plan)


def _safe_mode_from_meta(meta: dict[str, Any]) -> SafeModeThreshold:
    pol = meta.get("policy", {})
    return SafeModeThreshold(
        enabled=bool(pol.get("safe_mode_enabled", True)),
        max_failed_hosts=int(pol.get("max_failed_hosts", 0)),
        rollback_on_unreachable=bool(pol.get("rollback_on_unreachable", True)),
    )


def _complete_plan(plan: PatchPlan, meta: dict[str, Any], current: PatchPlanStatus) -> str:
    if current == PatchPlanStatus.CANARY_WAVE:
        validate_status_transition(current, PatchPlanStatus.ROLLOUT_IN_PROGRESS)
        current = PatchPlanStatus.ROLLOUT_IN_PROGRESS
    validate_status_transition(current, PatchPlanStatus.COMPLETED)
    plan.status = PatchPlanStatus.COMPLETED.value
    meta["active_wave_number"] = None
    return "patch_plan.completed"


def _advance_plan_after_wave(
    plan: PatchPlan,
    meta: dict[str, Any],
    wave_number: int,
    report: WaveHealthReport,
) -> tuple[str, bool]:
    rollback = should_trigger_rollback(report, _safe_mode_from_meta(meta))
    current = PatchPlanStatus(plan.status)
    if rollback:
        validate_status_transition(current, PatchPlanStatus.ROLLED_BACK)
        plan.status = PatchPlanStatus.ROLLED_BACK.value
        meta["active_wave_number"] = None
        return "patch_plan.rolled_back", True
    if wave_number >= len(meta.get("waves", [])):
        return _complete_plan(plan, meta, current), False
    if current == PatchPlanStatus.CANARY_WAVE:
        validate_status_transition(current, PatchPlanStatus.ROLLOUT_IN_PROGRESS)
        plan.status = PatchPlanStatus.ROLLOUT_IN_PROGRESS.value
    meta["active_wave_number"] = wave_number + 1
    return "patch_plan.wave_advanced", False


async def report_wave_health(
    session: AsyncSession,
    *,
    actor: ActorContext,
    plan_id: UUID,
    payload: WaveHealthReportRequest,
) -> PatchPlanResponse:
    """Evaluate Safe Mode wave health and advance rollout or trigger automatic rollback."""
    require_roles(actor, OPERATOR_OR_ADMIN)
    plan = await _load_plan_or_404(session, plan_id, for_update=True)
    if PatchPlanStatus(plan.status) not in {
        PatchPlanStatus.CANARY_WAVE,
        PatchPlanStatus.ROLLOUT_IN_PROGRESS,
    }:
        raise DomainError(
            status_code=409,
            title="Conflict",
            detail="Wave health can only be reported during CANARY_WAVE or ROLLOUT_IN_PROGRESS.",
            error_type="urn:hostgrid:error:invalid_patch_transition",
        )
    meta = _parse_plan_meta(plan)
    active_wave = meta.get("active_wave_number")
    if active_wave is not None and payload.wave_number != active_wave:
        raise DomainError(
            status_code=409,
            title="Wave Mismatch",
            detail=(
                f"Expected health report for active wave {active_wave}, "
                f"got {payload.wave_number}."
            ),
            error_type="urn:hostgrid:error:wave_mismatch",
        )
    report = WaveHealthReport(
        healthy_hosts=payload.healthy_hosts,
        failed_hosts=payload.failed_hosts,
        unreachable_hosts=payload.unreachable_hosts,
    )
    action, rolled_back = _advance_plan_after_wave(plan, meta, payload.wave_number, report)
    wave_reports = list(meta.get("wave_reports", []))
    wave_reports.append(
        {
            "wave_number": payload.wave_number,
            "healthy_hosts": payload.healthy_hosts,
            "failed_hosts": payload.failed_hosts,
            "unreachable_hosts": payload.unreachable_hosts,
            "rollback_triggered": rolled_back,
            "reported_at": format_rfc3339(utc_now()),
        }
    )
    meta["wave_reports"] = wave_reports
    plan.dry_run_report_json = meta
    plan.updated_at = utc_now()
    await append_audit_log(
        session,
        actor_id=actor.actor_id,
        actor_username=actor.username,
        action=action,
        resource_type="patch_plan",
        resource_id=str(plan.id),
        details={
            "wave_number": payload.wave_number,
            "status": plan.status,
            "rollback_triggered": rolled_back,
        },
    )
    await session.commit()
    return await _serialize_plan(session, plan)


def _find_active_wave(meta: dict[str, Any]) -> dict[str, Any] | None:
    active_num = meta.get("active_wave_number")
    for wave in meta.get("waves", []):
        if isinstance(wave, dict) and wave.get("wave_number") == active_num:
            return wave
    return None


def _build_dry_run_job(
    plan: PatchPlan,
    meta: dict[str, Any],
    host_id_str: str,
) -> AgentPatchJobResponse | None:
    pol = meta.get("policy", {})
    recorded = meta.get("dry_run_outcomes_by_host", {})
    if host_id_str not in plan.target_host_ids_json or host_id_str in recorded:
        return None
    return AgentPatchJobResponse(
        plan_id=plan.id,
        title=plan.title,
        mode="dry_run",
        wave_number=None,
        packages=list(plan.packages_json),
        safe_mode_enabled=bool(pol.get("safe_mode_enabled", True)),
        rollback_on_failure=bool(pol.get("rollback_on_unreachable", True)),
    )


def _build_apply_job(
    plan: PatchPlan,
    meta: dict[str, Any],
    host_id_str: str,
) -> AgentPatchJobResponse | None:
    pol = meta.get("policy", {})
    wave = _find_active_wave(meta)
    wave_key = str(meta.get("active_wave_number"))
    recorded_wave = meta.get("wave_host_results", {}).get(wave_key, {})
    if not wave or host_id_str not in wave.get("host_ids", []) or host_id_str in recorded_wave:
        return None
    return AgentPatchJobResponse(
        plan_id=plan.id,
        title=plan.title,
        mode="apply",
        wave_number=int(wave["wave_number"]),
        packages=list(plan.packages_json),
        safe_mode_enabled=bool(pol.get("safe_mode_enabled", True)),
        rollback_on_failure=bool(pol.get("rollback_on_unreachable", True)),
    )


def _build_agent_job_for_plan(plan: PatchPlan, host_id_str: str) -> AgentPatchJobResponse | None:
    meta = _parse_plan_meta(plan)
    if plan.status == PatchPlanStatus.DRY_RUN_READY.value:
        return _build_dry_run_job(plan, meta, host_id_str)
    return _build_apply_job(plan, meta, host_id_str)


async def get_agent_patch_jobs(
    session: AsyncSession,
    *,
    actor: ActorContext,
    host_id: UUID,
) -> list[AgentPatchJobResponse]:
    """Return pending pull-based dry-run or active-wave apply jobs for an enrolled agent."""
    require_agent_host(actor, host_id)
    active_statuses = (
        PatchPlanStatus.DRY_RUN_READY.value,
        PatchPlanStatus.CANARY_WAVE.value,
        PatchPlanStatus.ROLLOUT_IN_PROGRESS.value,
    )
    rows = (
        await session.execute(
            select(PatchPlan)
            .where(PatchPlan.status.in_(active_statuses))
            .order_by(PatchPlan.created_at.asc())
        )
    ).scalars().all()
    host_str = str(host_id)
    jobs: list[AgentPatchJobResponse] = []
    for plan in rows:
        job = _build_agent_job_for_plan(plan, host_str)
        if job is not None:
            jobs.append(job)
    return jobs


def _record_agent_dry_run_outcome(
    plan: PatchPlan,
    host_id: UUID,
    payload: AgentPatchJobResultRequest,
) -> tuple[str, dict[str, Any]]:
    if PatchPlanStatus(plan.status) != PatchPlanStatus.DRY_RUN_READY:
        raise DomainError(
            status_code=409,
            title="Conflict",
            detail="Plan is not awaiting dry-run simulation.",
            error_type="urn:hostgrid:error:invalid_patch_transition",
        )
    meta = _parse_plan_meta(plan)
    recorded = dict(meta.get("dry_run_outcomes_by_host", {}))
    recorded[str(host_id)] = {
        "host_id": str(host_id),
        "succeeded": payload.succeeded,
        "repo_verified": payload.repo_verified,
        "planned_changes_count": payload.planned_changes_count,
        "warnings": list(payload.warnings),
    }
    outcomes = [
        DryRunHostOutcome(
            host_id=UUID(str(item["host_id"])),
            succeeded=bool(item["succeeded"]),
            repo_verified=bool(item["repo_verified"]),
            planned_changes_count=int(item["planned_changes_count"]),
            warnings=tuple(item.get("warnings", [])),
        )
        for item in recorded.values()
    ]
    ready, _ = _apply_dry_run_outcomes(plan, outcomes)
    return "patch_plan.agent_dry_run_reported", {"host_id": str(host_id), "ready": ready}


def _finalize_wave_if_ready(
    plan: PatchPlan,
    meta: dict[str, Any],
    wave: dict[str, Any],
    wave_results: dict[str, dict[str, Any]],
) -> str:
    wave_num = int(wave["wave_number"])
    healthy_cnt = sum(1 for v in wave_results.values() if v["healthy"])
    failed_cnt = len(wave_results) - healthy_cnt
    report = WaveHealthReport(healthy_hosts=healthy_cnt, failed_hosts=failed_cnt)
    all_reported = len(wave_results) >= len(wave["host_ids"])
    if not all_reported and not should_trigger_rollback(report, _safe_mode_from_meta(meta)):
        return "patch_plan.agent_apply_reported"
    action, rolled_back = _advance_plan_after_wave(plan, meta, wave_num, report)
    wave_reports = list(meta.get("wave_reports", []))
    wave_reports.append(
        {
            "wave_number": wave_num,
            "healthy_hosts": healthy_cnt,
            "failed_hosts": failed_cnt,
            "unreachable_hosts": 0,
            "rollback_triggered": rolled_back,
            "reported_at": format_rfc3339(utc_now()),
        }
    )
    meta["wave_reports"] = wave_reports
    return action


def _record_agent_apply_outcome(
    plan: PatchPlan,
    host_id: UUID,
    payload: AgentPatchJobResultRequest,
) -> tuple[str, dict[str, Any]]:
    meta = _parse_plan_meta(plan)
    wave = _find_active_wave(meta)
    host_str = str(host_id)
    if wave is None or host_str not in wave.get("host_ids", []):
        raise DomainError(
            status_code=409,
            title="Conflict",
            detail="Host is not part of the active rollout wave for this patch plan.",
            error_type="urn:hostgrid:error:invalid_patch_transition",
        )
    wave_num = int(wave["wave_number"])
    wave_key = str(wave_num)
    all_results = dict(meta.get("wave_host_results", {}))
    wave_results = dict(all_results.get(wave_key, {}))
    healthy = (
        payload.succeeded
        and (payload.healthy_after_patch is not False)
        and not payload.rolled_back
    )
    wave_results[host_str] = {
        "status": payload.status,
        "healthy": healthy,
        "rolled_back": payload.rolled_back,
        "detail": payload.detail,
        "reported_at": format_rfc3339(utc_now()),
    }
    all_results[wave_key] = wave_results
    meta["wave_host_results"] = all_results
    action = _finalize_wave_if_ready(plan, meta, wave, wave_results)
    plan.dry_run_report_json = meta
    plan.updated_at = utc_now()
    return action, {"host_id": host_str, "wave_number": wave_num, "status": plan.status}


async def report_agent_patch_job_result(
    session: AsyncSession,
    *,
    actor: ActorContext,
    host_id: UUID,
    plan_id: UUID,
    payload: AgentPatchJobResultRequest,
) -> PatchPlanResponse:
    """Ingest a pull-based agent dry-run or wave execution outcome and advance state machine."""
    require_agent_host(actor, host_id)
    plan = await _load_plan_or_404(session, plan_id, for_update=True)
    if str(host_id) not in plan.target_host_ids_json:
        raise DomainError(
            status_code=403,
            title="Forbidden",
            detail="Host is not a target of this patch plan.",
            error_type="urn:hostgrid:error:forbidden",
        )
    if payload.mode == "dry_run":
        action, details = _record_agent_dry_run_outcome(plan, host_id, payload)
    else:
        action, details = _record_agent_apply_outcome(plan, host_id, payload)

    await append_audit_log(
        session,
        actor_id=None,
        actor_username=actor.username,
        action=action,
        resource_type="patch_plan",
        resource_id=str(plan.id),
        details=details,
    )
    await session.commit()
    return await _serialize_plan(session, plan)
