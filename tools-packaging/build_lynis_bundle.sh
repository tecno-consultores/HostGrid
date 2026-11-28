#!/bin/sh
# HostGrid Portable Lynis Packager & Ed25519 Signer (SPEC.md section 5.2).
# Packages only the minimal portable Lynis tree (lynis, include/, db/, plugins/, default.prf)
# with normalized root:root ownership, zero external symlinks, deterministic canonical manifest,
# and Ed25519 Base64 signature.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out}"
KEY_DIR="${KEY_DIR:-$SCRIPT_DIR/keys}"
SOURCE_DIR=""
VERSION=""
PRIVKEY_PEM=""
GENERATE_KEY=0

usage() {
    cat <<'EOF'
Usage: build_lynis_bundle.sh --source-dir <path> --version <semver> [options]

Options:
  --source-dir <dir>   Local directory containing extracted Lynis source tree
  --version <ver>      Lynis version (e.g. 3.1.4)
  --out-dir <dir>      Output directory for tarball, manifest.json, and manifest.sig
  --privkey <pem>      Ed25519 private key in PEM format for signing
  --generate-key       Generate an ephemeral Ed25519 keypair under tools-packaging/keys/
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-dir) shift; SOURCE_DIR="${1:-}" ;;
        --version) shift; VERSION="${1:-}" ;;
        --out-dir) shift; OUT_DIR="${1:-}" ;;
        --privkey) shift; PRIVKEY_PEM="${1:-}" ;;
        --generate-key) GENERATE_KEY=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$SOURCE_DIR" ] || [ -z "$VERSION" ]; then
    printf 'Error: --source-dir and --version are required.\n' >&2
    usage >&2
    exit 2
fi

case "$VERSION" in
    *[!a-zA-Z0-9._-]*|*..*)
        printf 'Error: invalid version string "%s"\n' "$VERSION" >&2
        exit 2
        ;;
esac

if [ ! -f "$SOURCE_DIR/lynis" ]; then
    printf 'Error: %s/lynis executable not found.\n' "$SOURCE_DIR" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

if [ "$GENERATE_KEY" -eq 1 ]; then
    mkdir -p "$KEY_DIR"
    chmod 700 "$KEY_DIR"
    PRIVKEY_PEM="$KEY_DIR/hostgrid-bundle-ed25519.key"
    PUBKEY_PEM="$KEY_DIR/hostgrid-bundle-ed25519.pub"
    if [ ! -f "$PRIVKEY_PEM" ]; then
        openssl genpkey -algorithm ED25519 -out "$PRIVKEY_PEM"
        chmod 600 "$PRIVKEY_PEM"
        openssl pkey -in "$PRIVKEY_PEM" -pubout -out "$PUBKEY_PEM"
    fi
fi

if [ -z "$PRIVKEY_PEM" ] || [ ! -r "$PRIVKEY_PEM" ]; then
    printf 'Error: readable Ed25519 --privkey <pem> or --generate-key is required.\n' >&2
    exit 1
fi

STAGE_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$STAGE_DIR"
}
trap cleanup EXIT INT TERM

for item in lynis include db plugins default.prf; do
    if [ -e "$SOURCE_DIR/$item" ] || [ -L "$SOURCE_DIR/$item" ]; then
        if [ -L "$SOURCE_DIR/$item" ]; then
            printf 'Error: refusing symlink in portable Lynis tree: %s\n' "$item" >&2
            exit 1
        fi
        if find "$SOURCE_DIR/$item" -type l | grep -q .; then
            printf 'Error: nested symlinks detected in Lynis source tree (%s).\n' "$item" >&2
            exit 1
        fi
        cp -RP "$SOURCE_DIR/$item" "$STAGE_DIR/$item"
    fi
done

chmod 0755 "$STAGE_DIR/lynis"
find "$STAGE_DIR" -type d -exec chmod 0755 {} +
find "$STAGE_DIR" -type f ! -name lynis -exec chmod 0644 {} +

FILENAME="lynis-${VERSION}-portable.tar.gz"
TARBALL_PATH="$OUT_DIR/$FILENAME"
MANIFEST_PATH="$OUT_DIR/lynis-${VERSION}-portable.manifest.json"
SIG_PATH="$OUT_DIR/lynis-${VERSION}-portable.manifest.sig"

if tar --version 2>/dev/null | grep -qi gnu; then
    tar --numeric-owner --owner=0 --group=0 -C "$STAGE_DIR" -czf "$TARBALL_PATH" .
else
    tar --numeric-owner -C "$STAGE_DIR" -czf "$TARBALL_PATH" .
fi

TAR_SHA256=$(sha256sum "$TARBALL_PATH" | awk '{print $1}')
TAR_SIZE=$(wc -c < "$TARBALL_PATH" | tr -d ' ')

# Exact sorted-key canonical JSON matching server/app/services/artifacts/tool_bundles.py
CANONICAL_JSON=$(printf '{"arch":"noarch","filename":"%s","sha256":"%s","size_bytes":%s,"tool_name":"lynis","version":"%s"}' \
    "$FILENAME" "$TAR_SHA256" "$TAR_SIZE" "$VERSION")

printf '%s' "$CANONICAL_JSON" > "$MANIFEST_PATH"

# Ed25519 raw signature encoded in Base64 (OpenSSL 3 pkeyutl -rawin).
openssl pkeyutl -sign -inkey "$PRIVKEY_PEM" -rawin -in "$MANIFEST_PATH" | base64 | tr -d '\n' > "$SIG_PATH"
printf '\n' >> "$SIG_PATH"

# Extract raw 32-byte public key Base64 for HOSTGRID_BUNDLE_SIGNING_PUBKEY_B64.
RAW_PUB_B64=$(openssl pkey -in "$PRIVKEY_PEM" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')

printf 'Built portable Lynis bundle:\n'
printf '  Tarball:   %s\n' "$TARBALL_PATH"
printf '  SHA-256:   %s\n' "$TAR_SHA256"
printf '  Size:      %s bytes\n' "$TAR_SIZE"
printf '  Manifest:  %s\n' "$MANIFEST_PATH"
printf '  Signature: %s\n' "$SIG_PATH"
printf '  PubKeyB64: %s\n' "$RAW_PUB_B64"
