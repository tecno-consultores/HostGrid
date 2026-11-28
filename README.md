# HostGrid

**Plano de control centralizado para auditoría de postura de seguridad, análisis offline de CVEs consciente de distribución, detección de deriva (*drift*) y parcheo gobernado para flotas de servidores Linux.**

Diseñado específicamente para operar en entornos de producción reales: servidores sin acceso a Internet, redes *air-gapped* y sistemas Linux *legacy* o en fin de vida (EOL).

---

## Principios Arquitectónicos

1. **Offline-First**: Ningún servidor monitoreado necesita acceso a Internet jamás; el Servidor Central concentra la actualización de bases de CVEs, tablas EOL y artefactos portables firmados.
2. **Cero dependencias en el Agente**: `hostgrid-agent` se compila como binario único estático en Go (`CGO_ENABLED=0`) para `linux/amd64`, `linux/arm64` y `linux/386`, sin Python, Node ni `glibc` moderna.
3. **Modelo Pull Seguro**: El agente solo abre conexiones salientes TLS 1.3 (HTTPS/mTLS) hacia el Control Plane o nodo Relay; nunca expone puertos entrantes.
4. **Herramientas Aisladas y Versionadas**: Prohibido instalar paquetes en el host (`apt`/`yum`); herramientas como Lynis portable se descargan firmadas (Ed25519 + SHA-256) y viven aisladas en `/opt/hostgrid/tools/`.
5. **Análisis de CVEs Distro-Aware**: El agente extrae el inventario SBOM (`/var/lib/dpkg/status`, base RPM o `apk`) y el servidor lo cruza contra feeds conscientes de *backports* (OSV/OVAL/Trivy offline) y tablas EOL.
6. **Degradación Controlada (*Capability Probe*)**: Detecta kernel, distro, sistema `init` y binarios presentes; si una comprobación no aplica (ej. `systemd` en `SysVinit`), registra `not_supported_on_os` y usa el recolector clásico equivalente.
7. **Gobernanza desde el Diseño**: Pre-verificación de repositorios, `Dry-Run` obligatorio, aprobación `Maker-Checker`, despliegue canario, `Safe Mode` con *rollback* y bitácora de auditoría inmutable tipo WORM (encadenada por SHA-256).

---

## Estructura del Monorepo

```text
HostGrid/
├── README.md                  # Guía principal del proyecto
├── ARCHITECTURE.md            # Arquitectura, diagramas Mermaid y modelo de amenazas STRIDE
├── SPEC.md                    # Contratos REST v1, esquema de BD, protocolo agente y formato .bundle
├── Makefile                   # Compilación cruzada Go, lint/tests en Docker y gestión de despliegue
├── agent/                     # Agente estático Go (CGO_ENABLED=0) + ejecutor Safe Mode (Fase 3)
├── relay/                     # Nodo Relay DMZ estático Go (proxy allow-list + caché de bundles firmados)
├── agentless/                 # Recolector POSIX /bin/sh para hosts legacy extremos
├── server/                    # Control Plane Python 3.12+ (FastAPI, SQLAlchemy 2.0, Alembic)
├── web/                       # Consola de operaciones (React + TypeScript + Vite + Tailwind)
├── tools-packaging/           # Empaquetado y firma Ed25519 de herramientas portables (Lynis)
└── deploy/                    # Docker Compose endurecido (incluyendo perfil relay) y plantilla .env.example
```

Documentación de referencia:
- [ARCHITECTURE.md](./ARCHITECTURE.md) — Topologías LAN / Relay / Air-Gapped, pipeline de ingesta, STRIDE y gobernanza.
- [SPEC.md](./SPEC.md) — Esquema de base de datos, esquema SARIF unificado, protocolo agente-servidor, formato `.bundle` y contratos OpenAPI.

---

## Inicio Rápido

### Prerrequisitos

- Docker Engine y Docker Compose v2 (`docker compose`).
- GNU `make` y `openssl`.

### 1. Configurar variables de entorno (despliegue)

Copia la plantilla y genera secretos criptográficos únicos (nunca hagas commit de `deploy/.env`):

```bash
cp deploy/.env.example deploy/.env
# Generar contraseñas/claves aleatorias de 32 bytes:
openssl rand -hex 32   # Usar para POSTGRES_PASSWORD
openssl rand -hex 32   # Usar para HOSTGRID_JWT_SECRET
```

### 2. Comandos disponibles (`Makefile`)

Todas las tareas de compilación, linting y pruebas se ejecutan en contenedores Docker efímeros sin requerir toolchains locales:

```bash
make help               # Lista todos los targets disponibles
make validate-compose   # Valida sintaxis de deploy/docker-compose.yml sin exponer secretos reales
make build-agent        # Compila hostgrid-agent estático (CGO_ENABLED=0) para amd64, arm64 y 386 en dist/agent/
make build-relay        # Compila hostgrid-relay estático (CGO_ENABLED=0) para amd64 y arm64 en dist/relay/
make lint-agent         # Ejecuta gofmt check y go vet sobre agent/
make lint-relay         # Ejecuta gofmt check y go vet sobre relay/
make lint-server        # Ejecuta ruff y mypy --strict sobre server/
make lint-web           # Ejecuta typecheck y eslint sobre web/
make lint-shell         # Valida scripts POSIX con shellcheck -s sh
make test               # Ejecuta todas las suites de pruebas (server, agent, relay y web)
make up                 # Levanta PostgreSQL + Control Plane + Frontend Web
make down               # Detiene el stack
```

---

## Uso del Agente y Herramientas (Fase 1)

### 1. Agente estático Go (`hostgrid-agent`)

Tras ejecutar `make build-agent`, los binarios estáticos (`amd64`, `arm64`, `386`) y sus sumas `SHA256SUMS` quedan disponibles en `dist/agent/`.

#### Enrolamiento (`enroll`) — Modo LAN, Relay/Proxy o mTLS

```bash
# Modo LAN directo con CA personalizada
./hostgrid-agent enroll \
  --server https://controlplane.internal:8443 \
  --token hg_enroll_xxxxxxxx \
  --mode lan \
  --env prod \
  --ca-cert /etc/hostgrid/ca.pem

# Modo subred cerrada vía Proxy/Relay HTTPS y certificado cliente mTLS
# (Si se omite --proxy, el cliente respeta HTTPS_PROXY / HTTP_PROXY / NO_PROXY)
./hostgrid-agent enroll \
  --server https://controlplane.internal:8443 \
  --token hg_enroll_xxxxxxxx \
  --mode relay \
  --env dmz \
  --proxy https://relay.dmz:8443 \
  --ca-cert /etc/hostgrid/ca.pem \
  --client-cert /etc/hostgrid/client.crt \
  --client-key /etc/hostgrid/client.key
```

El enrolamiento guarda la identidad del host en `/etc/hostgrid/agent.json` con permisos estrictos `0600` (configurable con `--config`).

#### Escaneo único (`scan`) y exportación *Air-Gapped* (`--offline-export`)

```bash
# Escaneo único con envío directo al Control Plane (o vía proxy_url/HTTPS_PROXY)
./hostgrid-agent scan --config /etc/hostgrid/agent.json

# Exportación air-gapped (.bundle tar.gz con manifest.json y manifest.sig) sin red
./hostgrid-agent scan \
  --offline-export /tmp/hostgrid-srv01.bundle \
  --env prod \
  --lynis-dir /opt/hostgrid/tools/lynis/3.1.4

# Escaneo sin ejecutar Lynis portable
./hostgrid-agent scan --config /etc/hostgrid/agent.json --skip-lynis
```

#### Modo daemon (`run`) con sondeo pull de `patch-jobs`

```bash
# Modo por defecto (SOLO LECTURA / dry-run): ejecuta escaneo inicial, heartbeats,
# escaneos programados y sondeo periódico de patch-jobs cada 60s sin mutar paquetes
./hostgrid-agent run --config /etc/hostgrid/agent.json

# Habilitar aplicación real de oleadas aprobadas (Maker-Checker + Safe Mode)
# e intervalo de sondeo de parches personalizado:
./hostgrid-agent run \
  --config /etc/hostgrid/agent.json \
  --allow-mutation=true \
  --patch-interval 2m

# Deshabilitar por completo el sondeo pull de patch-jobs en el daemon:
./hostgrid-agent run --config /etc/hostgrid/agent.json --patch-interval 0
```

#### Parcheo gobernado bajo demanda (`patch` — Fase 3)

```bash
# Modo por defecto (solo lectura): valida repositorios firmados (GPG) y reporta Dry-Run
./hostgrid-agent patch --config /etc/hostgrid/agent.json

# Aplicar oleadas aprobadas explícitamente con guardia Safe Mode y rollback selectivo
./hostgrid-agent patch --config /etc/hostgrid/agent.json --allow-mutation
```

### 2. Nodo Relay DMZ (`hostgrid-relay` — Fase 3)

Tras ejecutar `make build-relay`, los binarios estáticos (`amd64`, `arm64`) y `SHA256SUMS` quedan en `dist/relay/`. El Relay solo reenvía rutas allow-list del protocolo de agentes y cachea bundles firmados (con verificación SHA-256 y desambiguación por `?arch=`) sin poseer nunca claves privadas Ed25519:

```bash
# Arranque endurecido con TLS 1.3 entrante + mTLS para agentes + mTLS saliente hacia Control Plane
./hostgrid-relay \
  --listen :8443 \
  --upstream https://controlplane.internal:8443 \
  --cache-dir /var/cache/hostgrid-relay \
  --tls-cert /etc/hostgrid/certs/relay.crt \
  --tls-key /etc/hostgrid/certs/relay.key \
  --client-ca /etc/hostgrid/certs/agents-ca.pem \
  --upstream-ca /etc/hostgrid/certs/server-ca.pem \
  --upstream-client-cert /etc/hostgrid/certs/relay-client.crt \
  --upstream-client-key /etc/hostgrid/certs/relay-client.key

# Sonda de salud TLS 1.3 / mTLS (usada por Docker HEALTHCHECK)
./hostgrid-relay healthcheck \
  --ca-cert /etc/hostgrid/certs/relay-ca.pem \
  --client-cert /etc/hostgrid/certs/health-client.crt \
  --client-key /etc/hostgrid/certs/health-client.key
```

Para levantarlo junto al Control Plane mediante Docker Compose:

1. Si el Control Plane corre detrás de Nginx/reverse proxy TLS (HTTP `:8000` por defecto), configura `HOSTGRID_RELAY_UPSTREAM=https://<proxy-tls>:8443` en `deploy/.env`.
2. Si deseas TLS/mTLS nativo directamente en el contenedor `server`, descomenta los montajes de certificados en `deploy/docker-compose.yml`, configura `HOSTGRID_TLS_CERTFILE`, `HOSTGRID_TLS_KEYFILE` (y opcionalmente `HOSTGRID_TLS_CA_CERTS`), define `HOSTGRID_SERVER_PORT=8443`, `HOSTGRID_API_PORT=8443`, `HOSTGRID_WEB_UPSTREAM_URL=https://server:8443` (con `HOSTGRID_WEB_UPSTREAM_CA` y opcionalmente `HOSTGRID_WEB_UPSTREAM_CLIENT_CERT`/`KEY` para que Nginx proxee sobre HTTPS/mTLS) y `HOSTGRID_RELAY_UPSTREAM=https://server:8443` (junto con `HOSTGRID_RELAY_HEALTH_*` cuando el Relay usa TLS/mTLS entrante).
3. Levanta con el perfil opcional:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml --profile relay up -d --build
```

### 3. Recolector Agentless POSIX (`agentless/collect_posix.sh`)

Para servidores *legacy* extremos o *appliances* donde no se despliegue el binario Go:

```bash
ssh -T root@legacy-host < agentless/collect_posix.sh > host.json
# Ingestar luego vía API: POST /api/v1/snapshots/import-agentless
```

### 4. Empaquetado y firma Ed25519 de Lynis portable (`tools-packaging/build_lynis_bundle.sh`)

Genera el tarball portable minimalista, el manifiesto canónico JSON y la firma Ed25519 en Base64 para distribuir Lynis desde el Control Plane:

```bash
./tools-packaging/build_lynis_bundle.sh \
  --source-dir /ruta/a/lynis-3.1.4 \
  --version 3.1.4 \
  --out-dir tools-packaging/out \
  --generate-key
# O usando una clave privada Ed25519 existente:
#   --privkey /ruta/segura/hostgrid-bundle-ed25519.key
```

Los endpoints `GET /api/v1/bundles/{tool}/{version}/manifest` y `/download` admiten el parámetro opcional `?arch=noarch|amd64|arm64|386` para resolver arquitecturas de forma determinista cuando existen múltiples binarios para una misma versión.

---

## Operación del Control Plane y Consola Web (Fases 2 y 3)

### Sincronización Offline de Feeds CVE (OSV / Trivy / OVAL)

Desde la consola web (`/cves`, desplegable *Sincronización Offline de Feeds CVE — Admin*) o vía API (`admin`):

```bash
# Importar feed offline OSV JSON, Trivy JSON u OVAL XML (anti-XXE) y re-evaluar toda la flota
curl -fsS -X POST http://127.0.0.1:8000/api/v1/cves/import-feed \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"feed_format":"trivy","ecosystem":"Debian:12","payload":"...","rescan_fleet":true}'

# Re-evaluar manualmente los últimos snapshots de la flota contra el catálogo CVE cargado
curl -fsS -X POST http://127.0.0.1:8000/api/v1/cves/rescan-fleet \
  -H "Authorization: Bearer $ADMIN_JWT"
```

### Exportación de Reportes por Servidor (JSON / SARIF / Markdown / HTML)

Desde la vista de detalle de cada servidor (`/hosts/:hostId`) o directamente vía API (`viewer+`):

```bash
# Formatos soportados: json | sarif | markdown | html (imprimible a PDF con cabecera CSP estricta)
curl -fsS "http://127.0.0.1:8000/api/v1/reports/hosts/$HOST_ID?format=markdown" \
  -H "Authorization: Bearer $USER_JWT" -o reporte-host.md
curl -fsS "http://127.0.0.1:8000/api/v1/reports/hosts/$HOST_ID?format=html" \
  -H "Authorization: Bearer $USER_JWT" -o reporte-host.html
```

### Consola Web: Gobernanza (`/governance`) y Operaciones / Administración RBAC (`/operations`)

- **Gobernanza de Parcheo (`/governance`)**:
  - Creación de `PatchPlan` (`operator`/`admin`) con política configurable de oleadas canario (`canary_percent`, `max_wave_percent`), política Safe Mode (`safe_mode_enabled`, `max_failed_hosts`, `rollback_on_unreachable`) y cabecera `Idempotency-Key` (detectando reutilización con payload distinto vía `409 Conflict`).
  - Flujo completo: Precheck de repositorios firmados (visualizando `blocked_host_ids` en `FAILED_PRECHECK`), simulación `Dry-Run`, aprobación/rechazo `Maker-Checker` (`approver`/`admin` distinto al creador), ejecución progresiva por oleadas canario, rollback Safe Mode y consulta de bitácora WORM SHA-256.
- **Operaciones y Administración RBAC (`/operations`)**:
  - **Tokens de Enrolamiento (`operator`/`admin`)**: emite tokens de un solo uso (`POST /api/v1/enrollments/tokens`) con entorno y TTL configurables, mostrando el token secreto una única vez junto al comando `hostgrid-agent enroll ...` listo para copiar.
  - **Bundles Portables Firmados (`operator`/`admin`)**: registra tarballs `.tar.gz` (`POST /api/v1/bundles/register`) con versión, arquitectura (`noarch|amd64|arm64|386`) y firma Ed25519 opcional.
  - **Usuarios y Roles RBAC (`admin`)**: lista, crea cuentas (`viewer|operator|approver|admin`), modifica roles, activa/desactiva cuentas (con bloqueo anti auto-desactivación/degradación) y desbloquea intentos fallidos (`/api/v1/users`).

---

## Hoja de Ruta

- **Fase 0 (Completada)**: Estructura del monorepo, especificaciones técnicas (`ARCHITECTURE.md`, `SPEC.md`), manifiestos base (`pyproject.toml`, `go.mod`, `package.json`), `Makefile` y despliegue Docker endurecido.
- **Fase 1 (Completada)**: MVP de extremo a extremo en modo lectura:
  - Control Plane FastAPI + SQLAlchemy 2.0 + Alembic + parser `lynis-report.dat` + detector EOL offline + motor CVE distro-aware + motor de *drift* + bitácora WORM encadenada por SHA-256 + contratos base de gobernanza de parcheo (`server/app/services/patching/`).
  - Agente Go estático `amd64`/`arm64`/`386` con *Capability Probe*, colectores SBOM/red/sysctl/servicios/repos (incluyendo DEB822 `.sources`), soporte proxy/relay (`--proxy` y variables de entorno) + mTLS, exportación `.bundle` *air-gapped* y contratos base de actualización segura (`agent/internal/updater/`).
  - Recolector POSIX `agentless/collect_posix.sh`, empaquetador firmado `tools-packaging/build_lynis_bundle.sh`, consola Web MVP y suites completas de pruebas y linting.
- **Fase 2 (Completada)**:
  - Parsers offline de feeds CVE distro-aware para **OSV JSON**, **Trivy JSON** y **OVAL XML** (con bloqueo anti-XXE), endpoint `POST /api/v1/cves/import-feed`, re-evaluación global de flota `POST /api/v1/cves/rescan-fleet` y panel admin de importación offline en la consola web.
  - Exportación ejecutiva de reportes por servidor en **Markdown** (`format=markdown`) y **HTML imprimible a PDF** (`format=html`) con escape estricto anti-XSS, además de JSON y SARIF 2.1.0.
- **Fase 3 (Completada)**:
  - **Parcheo Gobernado de extremo a extremo**: API REST `/api/v1/patching/plans` (precheck de repositorios, simulación `Dry-Run`, aprobación `Maker-Checker` con `approver != creator`, oleadas canario progresivas y rollback `Safe Mode`), administración de usuarios RBAC `/api/v1/users`, endpoints *pull* del agente (`/api/v1/agents/{host_id}/patch-jobs`), consola web de Gobernanza (`/governance`) y bitácora WORM encadenada por SHA-256.
  - **Agente Go (`hostgrid-agent patch`)**: verificador nativo de repositorios/GPG, simulador `Dry-Run` (`apt`/`dnf`/`yum`/`apk`), aplicador no interactivo (`--allow-mutation` explícito, solo lectura por defecto) y guardia `Safe Mode` con rollback de versiones.
  - **Nodo Relay DMZ (`relay/`)**: binario estático Go (`CGO_ENABLED=0`) sin claves privadas Ed25519, enrutado allow-list exclusivo para protocolo de agentes, caché local verificada por SHA-256 de bundles firmados y perfil endurecido `relay` en `deploy/docker-compose.yml`.

---

## Licencia

Distribuido bajo licencia **GNU General Public License v3.0 (GPL-3.0)**. Consulta el archivo [LICENSE](./LICENSE).
