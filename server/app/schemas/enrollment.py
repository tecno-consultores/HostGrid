"""Agent enrollment and heartbeat schemas."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.schemas.common import StrictBaseModel, sanitize_single_line

EnvironmentType = Literal["prod", "staging", "dev", "dmz"]
ConnectivityMode = Literal["lan", "relay", "airgapped", "agentless"]
OsFamilyType = Literal["debian", "ubuntu", "rhel", "centos", "alpine", "suse", "other"]
ArchType = Literal["amd64", "arm64", "386"]
InitSystemType = Literal["systemd", "sysvinit", "upstart", "openrc", "unknown"]


class EnrollmentTokenCreateRequest(StrictBaseModel):
    """Operator request to generate a single-use enrollment token."""

    label: str = Field(min_length=1, max_length=128)
    environment: EnvironmentType = "prod"
    ttl_minutes: int = Field(default=60, ge=5, le=10080)

    @field_validator("label")
    @classmethod
    def _clean_label(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class EnrollmentTokenResponse(StrictBaseModel):
    """Issued single-use enrollment token (plaintext returned only once)."""

    id: UUID
    enrollment_token: str
    label: str
    environment: EnvironmentType
    expires_at: str


class EnrollmentRegisterRequest(StrictBaseModel):
    """Agent registration payload using a single-use enrollment token."""

    enrollment_token: str = Field(min_length=16, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    machine_id_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    os_family: OsFamilyType = "other"
    os_name: str = Field(min_length=1, max_length=128)
    os_version: str = Field(min_length=1, max_length=64)
    kernel_version: str = Field(min_length=1, max_length=128)
    arch: ArchType = "amd64"
    init_system: InitSystemType = "unknown"
    connectivity_mode: ConnectivityMode = "lan"
    environment: EnvironmentType | None = None

    @field_validator("enrollment_token", "hostname", "os_name", "os_version", "kernel_version")
    @classmethod
    def _clean_text(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class EnrollmentRegisterResponse(StrictBaseModel):
    """Agent identity and signing public key returned on successful registration."""

    host_id: UUID
    agent_credential: str
    bundle_signing_pubkey_b64: str
    heartbeat_interval_sec: int = 300
    scan_interval_sec: int = 3600


class HeartbeatRequest(StrictBaseModel):
    """Periodic agent heartbeat payload."""

    agent_version: str = Field(min_length=1, max_length=32)
    lynis_version: str | None = Field(default=None, max_length=32)
    uptime_sec: int = Field(default=0, ge=0)
    last_scan_at: str | None = Field(default=None, max_length=64)
    repo_access_ok: bool | None = None

    @field_validator("agent_version")
    @classmethod
    def _clean_agent_version(cls, value: str) -> str:
        return sanitize_single_line(value).strip()


class HeartbeatResponse(StrictBaseModel):
    """Heartbeat acknowledgment."""

    host_id: UUID
    status: Literal["ok"] = "ok"
    server_time: str
