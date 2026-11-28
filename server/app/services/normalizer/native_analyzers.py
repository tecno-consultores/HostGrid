"""Native host network, sysctl, and service posture analyzers."""

from __future__ import annotations

from app.schemas.snapshot import ListeningSocket, NetworkPayload
from app.services.normalizer.scoring import NormalizedFinding, compute_fingerprint

WILDCARD_ADDRS: frozenset[str] = frozenset({"0.0.0.0", "::", "*", "[::]"})  # noqa: S104
LOOPBACK_ADDRS: frozenset[str] = frozenset({"127.0.0.1", "::1", "[::1]"})

UNENCRYPTED_PORTS: dict[int, str] = {
    21: "FTP sin cifrado",
    23: "Telnet sin cifrado",
    513: "rlogin sin cifrado",
    514: "rsh sin cifrado",
}

SENSITIVE_WILDCARD_PORTS: dict[int, str] = {
    2375: "Docker daemon TCP sin TLS",
    3306: "MySQL/MariaDB expuesto en todas las interfaces",
    5432: "PostgreSQL expuesto en todas las interfaces",
    6379: "Redis/KeyDB expuesto en todas las interfaces",
    9200: "Elasticsearch expuesto en todas las interfaces",
    27017: "MongoDB expuesto en todas las interfaces",
}

INSECURE_SYSCTL_CHECKS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "net.ipv4.ip_forward",
        "1",
        "medium",
        "IPv4 packet forwarding habilitado",
        "Deshabilitar net.ipv4.ip_forward=0 si el host no actúa como router o nodo contenedor.",
    ),
    (
        "kernel.kptr_restrict",
        "0",
        "medium",
        "Punteros del kernel expuestos (kernel.kptr_restrict=0)",
        "Configurar kernel.kptr_restrict=2 en /etc/sysctl.d/99-hardening.conf.",
    ),
    (
        "kernel.randomize_va_space",
        "0",
        "high",
        "ASLR deshabilitado en kernel (kernel.randomize_va_space=0)",
        "Habilitar ASLR completo configurando kernel.randomize_va_space=2.",
    ),
)


def is_wildcard_address(addr: str) -> bool:
    """Return True if bind address listens on all interfaces."""
    return addr.strip().lower() in WILDCARD_ADDRS


def is_loopback_address(addr: str) -> bool:
    """Return True if bind address is restricted to local loopback."""
    return addr.strip().lower() in LOOPBACK_ADDRS


def _analyze_single_socket(sock: ListeningSocket) -> NormalizedFinding | None:
    target = f"{sock.local_addr}:{sock.port}"
    wildcard = is_wildcard_address(sock.local_addr)
    loopback = is_loopback_address(sock.local_addr)

    if sock.port in UNENCRYPTED_PORTS:
        label = UNENCRYPTED_PORTS[sock.port]
        return NormalizedFinding(
            fingerprint=compute_fingerprint("native_net", "network", "UNENCRYPTED_BIND", target),
            rule_id="UNENCRYPTED_BIND",
            source_tool="native_net",
            category="network",
            base_severity="high",
            confidence="high",
            title=f"Puerto sin cifrado escuchando: {label} ({target})",
            description=f"El proceso '{sock.process or 'desconocido'}' escucha en {target}.",
            evidence=sock.model_dump(),
            remediation=f"Deshabilitar {label} y migrar a alternativa cifrada (SSH/TLS).",
            reference_ids=["CWE-319"],
            exposed_wildcard=wildcard,
            loopback_only=loopback,
            exposed_ports=[target] if wildcard else [],
        )

    if wildcard and sock.port in SENSITIVE_WILDCARD_PORTS:
        label = SENSITIVE_WILDCARD_PORTS[sock.port]
        return NormalizedFinding(
            fingerprint=compute_fingerprint("native_net", "network", "SENSITIVE_WILDCARD", target),
            rule_id="SENSITIVE_WILDCARD",
            source_tool="native_net",
            category="network",
            base_severity="high",
            confidence="high",
            title=f"Servicio sensible expuesto en wildcard: {label} ({target})",
            description=f"Servicio '{sock.process or 'desconocido'}' enlazado a {target}.",
            evidence=sock.model_dump(),
            remediation="Restringir el enlace a 127.0.0.1 o red privada dedicada con firewall.",
            reference_ids=["CWE-284"],
            exposed_wildcard=True,
            exposed_ports=[target],
        )
    return None


def analyze_network(network: NetworkPayload) -> list[NormalizedFinding]:
    """Analyze listening sockets collected by native network probe."""
    findings: list[NormalizedFinding] = []
    for sock in network.listening_sockets:
        item = _analyze_single_socket(sock)
        if item is not None:
            findings.append(item)
    return findings


def analyze_sysctl(sysctl: dict[str, str]) -> list[NormalizedFinding]:
    """Analyze collected kernel sysctl posture parameters."""
    findings: list[NormalizedFinding] = []
    for key, bad_val, severity, title, remediation in INSECURE_SYSCTL_CHECKS:
        current = sysctl.get(key)
        if current is None or current.strip() != bad_val:
            continue
        rule_id = f"SYSCTL_{key.upper().replace('.', '_')}"
        findings.append(
            NormalizedFinding(
                fingerprint=compute_fingerprint("native_systemd", "hardening", rule_id, key),
                rule_id=rule_id,
                source_tool="native_systemd",
                category="hardening",
                base_severity=severity,
                confidence="high",
                title=title,
                description=f"Parámetro sysctl {key}={current.strip()} reduce el endurecimiento.",
                evidence={"parameter": key, "value": current.strip()},
                remediation=remediation,
                reference_ids=[f"SYSCTL:{key}"],
            )
        )
    return findings
