#!/bin/sh
# HostGrid Plan B Agentless Collector (Pure POSIX /bin/sh — zero external runtime deps).
# Usage: ssh -T root@legacy-host < agentless/collect_posix.sh > host.json
# Ingest via: POST /api/v1/snapshots/import-agentless

set -eu

json_escape() {
    printf '%s' "$1" \
        | tr -d '\000-\010\013\014\015\016-\037\177' \
        | sed \
            -e 's/\\/\\\\/g' \
            -e 's/"/\\"/g' \
            -e 's/	/\\t/g' \
        | awk 'NR>1{printf "\\n"}{printf "%s",$0}'
}

compute_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}'
    else
        # Fallback deterministic 64-hex pad if neither sha256sum nor openssl exists.
        printf '%s' "$1" | od -An -tx1 | tr -d ' \n' | cut -c1-64 | awk '{printf "%-64s", $0}' | tr ' ' '0'
    fi
}

detect_hostname() {
    if command -v hostname >/dev/null 2>&1; then
        hostname 2>/dev/null || printf 'unknown-host'
    elif [ -r /proc/sys/kernel/hostname ]; then
        cat /proc/sys/kernel/hostname
    else
        printf 'unknown-host'
    fi
}

detect_arch() {
    raw_arch=$(uname -m 2>/dev/null || printf 'x86_64')
    case "$raw_arch" in
        x86_64|amd64) printf 'amd64' ;;
        aarch64|arm64) printf 'arm64' ;;
        i386|i486|i586|i686) printf '386' ;;
        *) printf 'amd64' ;;
    esac
}

detect_os() {
    OS_FAMILY="other"
    OS_NAME="Unknown Linux"
    OS_VERSION="unknown"
    if [ -r /etc/os-release ]; then
        raw_id=$(awk -F= '/^ID=/{gsub(/["\047]/,"",$2); print tolower($2); exit}' /etc/os-release)
        raw_name=$(awk -F= '/^NAME=/{gsub(/["\047]/,"",$2); print $2; exit}' /etc/os-release)
        raw_ver=$(awk -F= '/^VERSION_ID=/{gsub(/["\047]/,"",$2); print $2; exit}' /etc/os-release)
        case "$raw_id" in
            debian|ubuntu|centos|rhel|alpine) OS_FAMILY="$raw_id" ;;
            sles|opensuse*) OS_FAMILY="suse" ;;
            rocky|almalinux|ol|fedora) OS_FAMILY="rhel" ;;
            *) OS_FAMILY="other" ;;
        esac
        [ -n "$raw_name" ] && OS_NAME="$raw_name"
        [ -n "$raw_ver" ] && OS_VERSION="$raw_ver"
    elif [ -r /etc/debian_version ]; then
        OS_FAMILY="debian"
        OS_NAME="Debian GNU/Linux"
        OS_VERSION=$(cut -d. -f1 /etc/debian_version | tr -d ' \r\n')
    elif [ -r /etc/redhat-release ]; then
        OS_NAME=$(tr -d '\r\n' < /etc/redhat-release)
        case "$(printf '%s' "$OS_NAME" | tr '[:upper:]' '[:lower:]')" in
            *centos*) OS_FAMILY="centos" ;;
            *) OS_FAMILY="rhel" ;;
        esac
        OS_VERSION=$(printf '%s' "$OS_NAME" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]/){print $i; exit}}')
        [ -z "$OS_VERSION" ] && OS_VERSION="unknown"
    elif [ -r /etc/alpine-release ]; then
        OS_FAMILY="alpine"
        OS_NAME="Alpine Linux"
        OS_VERSION=$(tr -d ' \r\n' < /etc/alpine-release)
    fi
}

detect_init() {
    if [ -d /run/systemd/system ]; then
        printf 'systemd'
    elif [ -d /run/openrc ]; then
        printf 'openrc'
    elif [ -x /sbin/initctl ]; then
        printf 'upstart'
    elif [ -d /etc/init.d ]; then
        printf 'sysvinit'
    else
        printf 'unknown'
    fi
}

emit_packages() {
    printf '['
    if [ -r /var/lib/dpkg/status ]; then
        awk '
            BEGIN { pkg=""; ver=""; src=""; arch="unknown"; inst=0 }
            /^Package:/ { pkg=$2 }
            /^Status:/ { inst=($0 ~ /install ok installed/) ? 1 : 0 }
            /^Source:/ { src=$2 }
            /^Version:/ { ver=$2 }
            /^Architecture:/ { arch=$2 }
            /^$/ {
                if (inst && pkg != "" && ver != "") {
                    if (src == "") src=pkg
                    printf "%s\t%s\t%s\t%s\n", pkg, src, ver, arch
                }
                pkg=""; ver=""; src=""; arch="unknown"; inst=0
            }
            END {
                if (inst && pkg != "" && ver != "") {
                    if (src == "") src=pkg
                    printf "%s\t%s\t%s\t%s\n", pkg, src, ver, arch
                }
            }
        ' /var/lib/dpkg/status | {
            first_dpkg=1
            while IFS='	' read -r p_name p_src p_ver p_arch; do
                [ "$first_dpkg" -eq 0 ] && printf ','
                first_dpkg=0
                printf '{"package_manager":"dpkg","name":"%s","source_package":"%s","epoch":"","version":"%s","release":"","arch":"%s"}' \
                    "$(json_escape "$p_name")" "$(json_escape "$p_src")" "$(json_escape "$p_ver")" "$(json_escape "$p_arch")"
            done
        }
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qa --qf '%{NAME}\t%{SOURCERPM}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' 2>/dev/null | {
            first_rpm=1
            while IFS='	' read -r p_name p_srpm p_epoch p_ver p_rel p_arch; do
                [ "$p_name" = "gpg-pubkey" ] && continue
                [ -z "$p_name" ] && continue
                [ "$p_epoch" = "(none)" ] && p_epoch=""
                [ "$p_arch" = "(none)" ] && p_arch="unknown"
                if [ -z "$p_srpm" ] || [ "$p_srpm" = "(none)" ]; then
                    p_src="$p_name"
                else
                    p_src=$(printf '%s' "$p_srpm" | sed 's/\.src\.rpm$//' | awk -F- '{if(NF>=3){for(i=1;i<=NF-2;i++){printf "%s%s",(i>1?"-":""),$i}}else{print $0}}')
                fi
                [ "$first_rpm" -eq 0 ] && printf ','
                first_rpm=0
                printf '{"package_manager":"rpm","name":"%s","source_package":"%s","epoch":"%s","version":"%s","release":"%s","arch":"%s"}' \
                    "$(json_escape "$p_name")" "$(json_escape "$p_src")" "$(json_escape "$p_epoch")" "$(json_escape "$p_ver")" "$(json_escape "$p_rel")" "$(json_escape "$p_arch")"
            done
        }
    elif [ -r /lib/apk/db/installed ]; then
        awk '
            BEGIN { pkg=""; ver=""; src=""; arch="unknown" }
            /^P:/ { pkg=substr($0,3) }
            /^V:/ { ver=substr($0,3) }
            /^A:/ { arch=substr($0,3) }
            /^o:/ { src=substr($0,3) }
            /^$/ {
                if (pkg != "" && ver != "") {
                    if (src == "") src=pkg
                    printf "%s\t%s\t%s\t%s\n", pkg, src, ver, arch
                }
                pkg=""; ver=""; src=""; arch="unknown"
            }
            END {
                if (pkg != "" && ver != "") {
                    if (src == "") src=pkg
                    printf "%s\t%s\t%s\t%s\n", pkg, src, ver, arch
                }
            }
        ' /lib/apk/db/installed | {
            first_apk=1
            while IFS='	' read -r p_name p_src p_ver p_arch; do
                [ "$first_apk" -eq 0 ] && printf ','
                first_apk=0
                printf '{"package_manager":"apk","name":"%s","source_package":"%s","epoch":"","version":"%s","release":"","arch":"%s"}' \
                    "$(json_escape "$p_name")" "$(json_escape "$p_src")" "$(json_escape "$p_ver")" "$(json_escape "$p_arch")"
            done
        }
    fi
    printf ']'
}

emit_sockets() {
    printf '['
    if command -v ss >/dev/null 2>&1; then
        # Omit -H for legacy iproute2 compatibility; filter valid proto lines directly.
        ss -tulnp 2>/dev/null | awk '
            $1 ~ /^(tcp|tcp6|udp|udp6)$/ {
                proc=""
                if (match($0, /\(\("[^"]+"/)) {
                    proc=substr($0, RSTART+3, RLENGTH-4)
                }
                print $1 "\t" $5 "\t" proc
            }
        ' | {
            first_ss=1
            while IFS='	' read -r s_proto s_local s_proc; do
                s_port=$(printf '%s' "$s_local" | awk -F: '{print $NF}')
                s_addr=$(printf '%s' "$s_local" | sed 's/:[^:]*$//' | tr -d '[]' | sed 's/%.*$//')
                [ "$s_addr" = "*" ] && s_addr="0.0.0.0"
                [ -z "$s_addr" ] && s_addr="0.0.0.0"
                case "$s_port" in
                    *[!0-9]*|"") continue ;;
                esac
                [ "$first_ss" -eq 0 ] && printf ','
                first_ss=0
                printf '{"proto":"%s","local_addr":"%s","port":%s,"process":"%s"}' \
                    "$s_proto" "$(json_escape "$s_addr")" "$s_port" "$(json_escape "$s_proc")"
            done
        }
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulnp 2>/dev/null | awk '
            /^(tcp|tcp6|udp|udp6)[[:space:]]/ {
                proc=""
                for (i=6; i<=NF; i++) {
                    if ($i ~ /^[0-9]+\//) {
                        proc=$i
                        sub(/^[0-9]+\//, "", proc)
                        sub(/:$/, "", proc)
                        break
                    }
                }
                print $1 "\t" $4 "\t" proc
            }
        ' | {
            first_ns=1
            while IFS='	' read -r s_proto s_local s_proc; do
                s_port=$(printf '%s' "$s_local" | awk -F: '{print $NF}')
                s_addr=$(printf '%s' "$s_local" | sed 's/:[^:]*$//' | tr -d '[]' | sed 's/%.*$//')
                [ "$s_addr" = "*" ] && s_addr="0.0.0.0"
                [ -z "$s_addr" ] && s_addr="0.0.0.0"
                case "$s_port" in
                    *[!0-9]*|"") continue ;;
                esac
                [ "$first_ns" -eq 0 ] && printf ','
                first_ns=0
                printf '{"proto":"%s","local_addr":"%s","port":%s,"process":"%s"}' \
                    "$s_proto" "$(json_escape "$s_addr")" "$s_port" "$(json_escape "$s_proc")"
            done
        }
    elif [ -r /proc/net/tcp ]; then
        awk '
            function hex2dec(h,    i, c, v, n) {
                h = toupper(h)
                n = 0
                for (i = 1; i <= length(h); i++) {
                    c = substr(h, i, 1)
                    v = index("0123456789ABCDEF", c) - 1
                    if (v < 0) return -1
                    n = n * 16 + v
                }
                return n
            }
            NR > 1 && $4 == "0A" {
                split($2, parts, ":")
                if (length(parts[1]) == 8) {
                    o1 = hex2dec(substr(parts[1], 7, 2))
                    o2 = hex2dec(substr(parts[1], 5, 2))
                    o3 = hex2dec(substr(parts[1], 3, 2))
                    o4 = hex2dec(substr(parts[1], 1, 2))
                    port = hex2dec(parts[2])
                    if (o1 >= 0 && port >= 0) {
                        if (emitted > 0) printf ","
                        emitted++
                        printf "{\"proto\":\"tcp\",\"local_addr\":\"%d.%d.%d.%d\",\"port\":%d,\"process\":\"\"}", o1, o2, o3, o4, port
                    }
                }
            }
        ' /proc/net/tcp
    fi
    printf ']'
}

emit_services() {
    init_sys="$1"
    printf '['
    if [ "$init_sys" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1 "\t" $4}' | {
            first_sc=1
            while IFS='	' read -r svc_unit svc_state; do
                svc_name=$(printf '%s' "$svc_unit" | sed 's/\.service$//')
                [ -z "$svc_name" ] && continue
                [ "$first_sc" -eq 0 ] && printf ','
                first_sc=0
                printf '{"name":"%s","state":"%s","init_system":"systemd"}' \
                    "$(json_escape "$svc_name")" "$(json_escape "$svc_state")"
            done
        }
    elif [ -d /etc/init.d ]; then
        first_init=1
        for entry in /etc/init.d/*; do
            [ -f "$entry" ] || continue
            svc_name=$(basename "$entry")
            [ "$svc_name" = "README" ] && continue
            [ "$first_init" -eq 0 ] && printf ','
            first_init=0
            printf '{"name":"%s","state":"configured","init_system":"%s"}' \
                "$(json_escape "$svc_name")" "$(json_escape "$init_sys")"
        done
    fi
    printf ']'
}

emit_sysctl() {
    first=1
    printf '{'
    for key in net.ipv4.ip_forward kernel.kptr_restrict kernel.randomize_va_space; do
        rel=$(printf '%s' "$key" | tr '.' '/')
        if [ -r "/proc/sys/$rel" ]; then
            val=$(tr -d ' \r\n' < "/proc/sys/$rel")
            [ "$first" -eq 0 ] && printf ','
            first=0
            printf '"%s":"%s"' "$key" "$(json_escape "$val")"
        fi
    done
    if [ -r /etc/ssh/sshd_config ]; then
        root_login=$(awk '/^[[:space:]]*PermitRootLogin[[:space:]]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
        if [ -n "$root_login" ]; then
            [ "$first" -eq 0 ] && printf ','
            first=0
            printf '"ssh.PermitRootLogin":"%s"' "$(json_escape "$root_login")"
        fi
        pass_auth=$(awk '/^[[:space:]]*PasswordAuthentication[[:space:]]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
        if [ -n "$pass_auth" ]; then
            [ "$first" -eq 0 ] && printf ','
            first=0
            printf '"ssh.PasswordAuthentication":"%s"' "$(json_escape "$pass_auth")"
        fi
    fi
    printf '}'
}

HOSTNAME_VAL=$(detect_hostname)
ARCH_VAL=$(detect_arch)
KERNEL_VAL=$(uname -r 2>/dev/null || printf 'unknown')
INIT_VAL=$(detect_init)
detect_os

if [ -r /etc/machine-id ]; then
    RAW_MID=$(tr -d ' \r\n' < /etc/machine-id)
elif [ -r /var/lib/dbus/machine-id ]; then
    RAW_MID=$(tr -d ' \r\n' < /var/lib/dbus/machine-id)
else
    RAW_MID="hostgrid-agentless:$HOSTNAME_VAL"
fi
MACHINE_HASH=$(compute_sha256 "$RAW_MID")
COLLECTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z" 2>/dev/null || printf '1970-01-01T00:00:00.000Z')

NET_CAP_BIN="none"
NET_CAP_STATUS="not_supported_on_os"
NET_CAP_FALLBACK="false"
if command -v ss >/dev/null 2>&1; then
    NET_CAP_BIN="ss"
    NET_CAP_STATUS="supported"
elif command -v netstat >/dev/null 2>&1; then
    NET_CAP_BIN="netstat"
    NET_CAP_STATUS="supported"
    NET_CAP_FALLBACK="true"
elif [ -r /proc/net/tcp ]; then
    NET_CAP_BIN="/proc/net/tcp"
    NET_CAP_STATUS="supported"
    NET_CAP_FALLBACK="true"
fi

printf '{"hostname":"%s","machine_id_hash":"%s","environment":"prod","collected_at":"%s","agent_version":"agentless-posix-1.0","connectivity_mode":"agentless","probe":{"os_family":"%s","os_name":"%s","os_version":"%s","kernel_version":"%s","arch":"%s","init_system":"%s","capabilities":{"network_inspector":{"status":"%s","binary":"%s","fallback_used":%s}}},"packages":' \
    "$(json_escape "$HOSTNAME_VAL")" \
    "$MACHINE_HASH" \
    "$COLLECTED_AT" \
    "$(json_escape "$OS_FAMILY")" \
    "$(json_escape "$OS_NAME")" \
    "$(json_escape "$OS_VERSION")" \
    "$(json_escape "$KERNEL_VAL")" \
    "$ARCH_VAL" \
    "$INIT_VAL" \
    "$NET_CAP_STATUS" \
    "$NET_CAP_BIN" \
    "$NET_CAP_FALLBACK"

emit_packages
printf ',"network":{"listening_sockets":'
emit_sockets
printf '},"services":'
emit_services "$INIT_VAL"
printf ',"sysctl":'
emit_sysctl
printf ',"repos":{"access_ok":null,"configured_sources":[],"check_detail":"agentless_readonly"},"lynis":{"executed":false,"report_dat":""}}\n'
