"""Unit tests for Phase 3 governed patching base contracts and governance rules."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.core.errors import DomainError
from app.core.rbac import ActorContext, Role
from app.services.patching import (
    ApprovalDecision,
    CanaryPolicy,
    DryRunHostOutcome,
    PatchPlanStatus,
    RepoPrecheckTarget,
    SafeModeThreshold,
    WaveHealthReport,
    build_canary_waves,
    evaluate_dry_run_gate,
    evaluate_repo_precheck,
    should_trigger_rollback,
    validate_maker_checker_decision,
    validate_status_transition,
)


def test_patch_plan_status_transitions() -> None:
    """Verify allowed state transitions pass and illegal transitions raise 409."""
    validate_status_transition(PatchPlanStatus.DRAFT, PatchPlanStatus.REPO_PRECHECK)
    validate_status_transition(PatchPlanStatus.REPO_PRECHECK, PatchPlanStatus.DRY_RUN_READY)
    validate_status_transition(PatchPlanStatus.DRY_RUN_READY, PatchPlanStatus.PENDING_APPROVAL)
    validate_status_transition(PatchPlanStatus.PENDING_APPROVAL, PatchPlanStatus.APPROVED)
    validate_status_transition(PatchPlanStatus.APPROVED, PatchPlanStatus.CANARY_WAVE)
    validate_status_transition(PatchPlanStatus.CANARY_WAVE, PatchPlanStatus.ROLLOUT_IN_PROGRESS)
    validate_status_transition(PatchPlanStatus.ROLLOUT_IN_PROGRESS, PatchPlanStatus.COMPLETED)

    with pytest.raises(DomainError) as exc_info:
        validate_status_transition(PatchPlanStatus.DRAFT, PatchPlanStatus.APPROVED)
    assert exc_info.value.status_code == 409

    with pytest.raises(DomainError) as terminal_exc:
        validate_status_transition(PatchPlanStatus.COMPLETED, PatchPlanStatus.ROLLED_BACK)
    assert terminal_exc.value.status_code == 409


def test_repo_precheck_blocks_inaccessible_or_unsigned_hosts() -> None:
    """Any host with unreachable or unsigned repo blocks transition to DRY_RUN_READY."""
    h1, h2, h3 = uuid4(), uuid4(), uuid4()

    passed = evaluate_repo_precheck(
        [
            RepoPrecheckTarget(host_id=h1, repo_access_ok=True, gpg_verified=True),
            RepoPrecheckTarget(host_id=h2, repo_access_ok=True, gpg_verified=True),
        ]
    )
    assert passed.passed is True
    assert passed.next_status == PatchPlanStatus.DRY_RUN_READY
    assert passed.eligible_host_ids == (h1, h2)
    assert passed.blocked_host_ids == ()

    blocked = evaluate_repo_precheck(
        [
            RepoPrecheckTarget(host_id=h1, repo_access_ok=True, gpg_verified=True),
            RepoPrecheckTarget(host_id=h2, repo_access_ok=False, gpg_verified=True),
            RepoPrecheckTarget(host_id=h3, repo_access_ok=True, gpg_verified=False),
        ]
    )
    assert blocked.passed is False
    assert blocked.next_status == PatchPlanStatus.FAILED_PRECHECK
    assert blocked.eligible_host_ids == (h1,)
    assert blocked.blocked_host_ids == (h2, h3)

    with pytest.raises(DomainError) as empty_exc:
        evaluate_repo_precheck([])
    assert empty_exc.value.status_code == 422

    with pytest.raises(DomainError) as dup_exc:
        evaluate_repo_precheck(
            [
                RepoPrecheckTarget(host_id=h1, repo_access_ok=True, gpg_verified=True),
                RepoPrecheckTarget(host_id=h1, repo_access_ok=False, gpg_verified=True),
            ]
        )
    assert dup_exc.value.status_code == 422


def test_dry_run_gate_requires_complete_verified_outcomes() -> None:
    """Dry-run gate fails on missing hosts, failed simulation, or unverified repos."""
    h1, h2, h3 = uuid4(), uuid4(), uuid4()

    ok = evaluate_dry_run_gate(
        [h1, h2],
        [
            DryRunHostOutcome(
                host_id=h1, succeeded=True, repo_verified=True, planned_changes_count=2
            ),
            DryRunHostOutcome(
                host_id=h2, succeeded=True, repo_verified=True, planned_changes_count=1
            ),
        ],
    )
    assert ok.ready_for_approval is True
    assert ok.failed_host_ids == ()
    assert ok.missing_host_ids == ()

    incomplete = evaluate_dry_run_gate(
        [h1, h2, h3],
        [
            DryRunHostOutcome(host_id=h1, succeeded=False, repo_verified=True),
            DryRunHostOutcome(host_id=h2, succeeded=True, repo_verified=False),
        ],
    )
    assert incomplete.ready_for_approval is False
    assert incomplete.failed_host_ids == (h1, h2)
    assert incomplete.missing_host_ids == (h3,)


def test_dry_run_gate_rejects_invalid_and_duplicate_inputs() -> None:
    """Reject empty targets, duplicate targets, conflicting duplicate outcomes, and negatives."""
    h1 = uuid4()

    with pytest.raises(DomainError) as empty_exc:
        evaluate_dry_run_gate([], [])
    assert empty_exc.value.status_code == 422

    with pytest.raises(DomainError) as dup_target_exc:
        evaluate_dry_run_gate(
            [h1, h1],
            [DryRunHostOutcome(host_id=h1, succeeded=True, repo_verified=True)],
        )
    assert dup_target_exc.value.status_code == 422

    # Conflicting duplicate outcomes must NEVER allow last-wins bypass.
    with pytest.raises(DomainError) as dup_outcome_exc:
        evaluate_dry_run_gate(
            [h1],
            [
                DryRunHostOutcome(host_id=h1, succeeded=False, repo_verified=True),
                DryRunHostOutcome(host_id=h1, succeeded=True, repo_verified=True),
            ],
        )
    assert dup_outcome_exc.value.status_code == 422

    with pytest.raises(DomainError) as neg_exc:
        evaluate_dry_run_gate(
            [h1],
            [
                DryRunHostOutcome(
                    host_id=h1, succeeded=True, repo_verified=True, planned_changes_count=-1
                )
            ],
        )
    assert neg_exc.value.status_code == 422


def test_maker_checker_approval_enforcement() -> None:
    """Enforce approver/admin RBAC, PENDING_APPROVAL state, distinct actor, and rationale."""
    creator_id = uuid4()
    approver_id = uuid4()
    approver = ActorContext(actor_id=approver_id, username="approver1", role=Role.APPROVER)
    creator_admin = ActorContext(actor_id=creator_id, username="admin1", role=Role.ADMIN)
    operator = ActorContext(actor_id=approver_id, username="op1", role=Role.OPERATOR)

    assert (
        validate_maker_checker_decision(
            actor=approver,
            plan_created_by=creator_id,
            current_status=PatchPlanStatus.PENDING_APPROVAL,
            decision=ApprovalDecision.APPROVED,
            rationale="Dry-run verified in staging window.",
        )
        == PatchPlanStatus.APPROVED
    )

    assert (
        validate_maker_checker_decision(
            actor=approver,
            plan_created_by=creator_id,
            current_status=PatchPlanStatus.PENDING_APPROVAL,
            decision=ApprovalDecision.REJECTED,
            rationale="Deferred until after freeze.",
        )
        == PatchPlanStatus.REJECTED
    )

    # Creator cannot self-approve even with admin role.
    with pytest.raises(DomainError) as self_exc:
        validate_maker_checker_decision(
            actor=creator_admin,
            plan_created_by=creator_id,
            current_status=PatchPlanStatus.PENDING_APPROVAL,
            decision=ApprovalDecision.APPROVED,
            rationale="Self-approval attempt",
        )
    assert self_exc.value.status_code == 403

    # Operator lacks approval role.
    with pytest.raises(DomainError) as rbac_exc:
        validate_maker_checker_decision(
            actor=operator,
            plan_created_by=creator_id,
            current_status=PatchPlanStatus.PENDING_APPROVAL,
            decision=ApprovalDecision.APPROVED,
            rationale="Unauthorized",
        )
    assert rbac_exc.value.status_code == 403

    # Plan must be PENDING_APPROVAL.
    with pytest.raises(DomainError) as state_exc:
        validate_maker_checker_decision(
            actor=approver,
            plan_created_by=creator_id,
            current_status=PatchPlanStatus.DRAFT,
            decision=ApprovalDecision.APPROVED,
            rationale="Premature",
        )
    assert state_exc.value.status_code == 409

    # Rationale cannot be blank or contain ASCII control characters.
    with pytest.raises(DomainError) as rationale_exc:
        validate_maker_checker_decision(
            actor=approver,
            plan_created_by=creator_id,
            current_status=PatchPlanStatus.PENDING_APPROVAL,
            decision=ApprovalDecision.APPROVED,
            rationale="   ",
        )
    assert rationale_exc.value.status_code == 422

    with pytest.raises(DomainError) as ctrl_exc:
        validate_maker_checker_decision(
            actor=approver,
            plan_created_by=creator_id,
            current_status=PatchPlanStatus.PENDING_APPROVAL,
            decision=ApprovalDecision.APPROVED,
            rationale="Approved\r\nFAKE_AUDIT",
        )
    assert ctrl_exc.value.status_code == 422


def test_canary_wave_planning_and_validation() -> None:
    """Verify deterministic canary + rollout wave slicing and input validation."""
    hosts = [uuid4() for _ in range(10)]
    waves = build_canary_waves(hosts, CanaryPolicy(canary_percent=10, max_wave_percent=40))
    assert len(waves) == 4
    assert waves[0].wave_number == 1 and waves[0].is_canary is True and len(waves[0].host_ids) == 1
    assert waves[1].wave_number == 2 and waves[1].is_canary is False and len(waves[1].host_ids) == 4
    assert waves[2].wave_number == 3 and len(waves[2].host_ids) == 4
    assert waves[3].wave_number == 4 and len(waves[3].host_ids) == 1
    flattened = [hid for w in waves for hid in w.host_ids]
    assert flattened == hosts

    single = build_canary_waves([hosts[0]], CanaryPolicy(canary_percent=10, max_wave_percent=50))
    assert len(single) == 1 and single[0].is_canary is True

    for bad_policy in (
        CanaryPolicy(canary_percent=0, max_wave_percent=50),
        CanaryPolicy(canary_percent=10, max_wave_percent=101),
        CanaryPolicy(canary_percent=80, max_wave_percent=20),
    ):
        with pytest.raises(DomainError) as pol_exc:
            build_canary_waves(hosts, bad_policy)
        assert pol_exc.value.status_code == 422

    with pytest.raises(DomainError) as empty_exc:
        build_canary_waves([], CanaryPolicy())
    assert empty_exc.value.status_code == 422

    with pytest.raises(DomainError) as dup_exc:
        build_canary_waves([hosts[0], hosts[0]], CanaryPolicy())
    assert dup_exc.value.status_code == 422


def test_safe_mode_rollback_thresholds() -> None:
    """Verify Safe Mode rollback decisions on failed or unreachable wave hosts."""
    strict = SafeModeThreshold(enabled=True, max_failed_hosts=0, rollback_on_unreachable=True)
    assert (
        should_trigger_rollback(WaveHealthReport(healthy_hosts=5, failed_hosts=0), strict) is False
    )
    assert (
        should_trigger_rollback(WaveHealthReport(healthy_hosts=4, failed_hosts=1), strict) is True
    )
    assert (
        should_trigger_rollback(
            WaveHealthReport(healthy_hosts=4, failed_hosts=0, unreachable_hosts=1),
            strict,
        )
        is True
    )

    disabled = SafeModeThreshold(enabled=False, max_failed_hosts=0, rollback_on_unreachable=True)
    assert (
        should_trigger_rollback(
            WaveHealthReport(healthy_hosts=0, failed_hosts=5, unreachable_hosts=2),
            disabled,
        )
        is False
    )


def test_safe_mode_rejects_negative_counts() -> None:
    """Negative wave telemetry or threshold counts must raise 422."""
    strict = SafeModeThreshold(enabled=True, max_failed_hosts=0, rollback_on_unreachable=True)
    with pytest.raises(DomainError) as neg_report:
        should_trigger_rollback(
            WaveHealthReport(healthy_hosts=-1, failed_hosts=0),
            strict,
        )
    assert neg_report.value.status_code == 422

    with pytest.raises(DomainError) as neg_threshold:
        should_trigger_rollback(
            WaveHealthReport(healthy_hosts=5, failed_hosts=0),
            SafeModeThreshold(enabled=True, max_failed_hosts=-1),
        )
    assert neg_threshold.value.status_code == 422
