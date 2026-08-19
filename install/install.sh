#!/bin/sh
# Postal (p5) installer.
#
#   curl -fsSL https://postal.bot/install.sh | sh
#
# Lands `p5` on PATH at /usr/local/bin or ~/.local/bin. Idempotent.
#
# Remote (default, when release assets exist):
#   1. Fetch tarball + SHA256SUMS + https://postal.bot/keys/minisign.pub
#      (same key is also on the GitHub release until DNS is live)
#   2. Check SHA256SUMS; minisign -Vm the tarball
#   3. Install p5 into $prefix/bin
#
# Local cargo (until postal.bot DNS / release assets exist):
#   P5_LOCAL=1 ./install/install.sh
#   ./install/install.sh --from-cargo
#   → cargo install --path crates/p5 --root "$prefix"
#
# Do not invent a minisign key here. The published pubkey path is the
# ceremony; this script only fetches it.
#
# POSIX sh. No bash-isms.
set -eu
( set -o pipefail ) 2>/dev/null && set -o pipefail || true

PRODUCT="Postal"
COMMAND="p5"
SITE="postal.bot"
REPO_SLUG="Alakazam-211/postal-bot"
KEY_URL="https://postal.bot/keys/minisign.pub"
DIST_BASE="https://postal.bot/releases/latest"
GH_DIST_BASE="https://github.com/${REPO_SLUG}/releases/latest/download"

FROM_CARGO="${P5_LOCAL:-0}"
PREFIX="${P5_PREFIX:-}"

usage() {
    cat <<EOF
Usage: install.sh [--from-cargo] [--prefix DIR]

Install the ${PRODUCT} (${COMMAND}) binary.

  --from-cargo    cargo install --path crates/p5 --root \$prefix
  --prefix DIR    install prefix (bin lands in DIR/bin)
  -h, --help      show this help

Env:
  P5_LOCAL=1      same as --from-cargo
  P5_PREFIX       same as --prefix
  P5_REPO         checkout root (default: detect from this script or cwd)

Default prefix: /usr/local if writable, else ~/.local.

Remote installs minisign-verify against ${KEY_URL}
and check SHA256SUMS next to the asset. If those files are missing,
this script errors — postal.bot DNS is not live yet. Use --from-cargo.
EOF
}

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --from-cargo) FROM_CARGO=1; shift ;;
        --prefix)
            [ -n "${2:-}" ] || die "--prefix needs a directory"
            PREFIX="$2"
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

# Prefer /usr/local when we can write it; otherwise user-local.
choose_prefix() {
    if [ -n "$PREFIX" ]; then
        printf '%s\n' "$PREFIX"
        return
    fi
    if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        printf '%s\n' /usr/local
        return
    fi
    if [ ! -e /usr/local/bin ] && [ -d /usr/local ] && [ -w /usr/local ]; then
        printf '%s\n' /usr/local
        return
    fi
    printf '%s\n' "${HOME}/.local"
}

# curl|sh has no script path; --from-cargo then needs cwd or P5_REPO.
repo_root() {
    if [ -n "${P5_REPO:-}" ]; then
        printf '%s\n' "$P5_REPO"
        return
    fi
    _arg0="$0"
    case "$_arg0" in
        /*) _path="$_arg0" ;;
        *)  _path="$(pwd)/$_arg0" ;;
    esac
    if [ -f "$_path" ]; then
        _dir=$(CDPATH= cd -- "$(dirname "$_path")" && pwd) || true
        if [ -n "$_dir" ]; then
            _root=$(CDPATH= cd -- "$_dir/.." && pwd) || true
            if [ -n "$_root" ] && [ -f "$_root/crates/p5/Cargo.toml" ]; then
                printf '%s\n' "$_root"
                return
            fi
        fi
    fi
    if [ -f "$(pwd)/crates/p5/Cargo.toml" ]; then
        pwd
        return
    fi
    return 1
}

detect_target() {
    _os=""
    _arch=""
    case "$(uname -s)" in
        Darwin) _os="macos" ;;
        Linux)  _os="linux" ;;
        *) die "unsupported OS: $(uname -s) (expected Darwin or Linux)" ;;
    esac
    case "$(uname -m)" in
        arm64|aarch64) _arch="aarch64" ;;
        x86_64|amd64)  _arch="x86_64" ;;
        *) die "unsupported CPU: $(uname -m) (expected aarch64 or x86_64)" ;;
    esac
    printf '%s-%s\n' "$_os" "$_arch"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "need sha256sum or shasum to check SHA256SUMS"
    fi
}

fetch() {
    # fetch <url> <dest> — stderr swallowed; caller prints a single assets-missing error.
    command -v curl >/dev/null 2>&1 || die "curl is required"
    curl -fsSL --connect-timeout 8 --max-time 60 "$1" -o "$2" 2>/dev/null
}

assets_missing() {
    die "$*

${PRODUCT} release assets are not published yet (postal.bot DNS is not live).
The remote pipe needs:
  ${KEY_URL}
  ${DIST_BASE}/SHA256SUMS
  ${DIST_BASE}/p5-<os>-<arch>.tar.gz
  (same files on GitHub ${REPO_SLUG} releases as a fallback)

Until those exist, install from a local checkout:

  P5_LOCAL=1 ./install/install.sh
  ./install/install.sh --from-cargo

Or: cargo install --path crates/p5"
}

need_on_path() {
    _bindir="$1"
    case ":${PATH}:" in
        *":${_bindir}:"*) return 0 ;;
        *) return 1 ;;
    esac
}

PREFIX=$(choose_prefix)
BINDIR="${PREFIX}/bin"

if [ "$FROM_CARGO" = "1" ]; then
    command -v cargo >/dev/null 2>&1 || die "cargo not found (needed for --from-cargo / P5_LOCAL=1)"
    ROOT=$(repo_root) || die "cannot find crates/p5 (set P5_REPO or run from the postal-bot checkout)"
    echo "Installing ${COMMAND} from cargo (${ROOT}/crates/p5) → ${BINDIR}"
    # --force so a second run is a no-op replace (idempotent).
    cargo install --path "${ROOT}/crates/p5" --root "$PREFIX" --force --locked
else
    command -v curl >/dev/null 2>&1 || die "curl is required"
    TARGET=$(detect_target)
    TARBALL="p5-${TARGET}.tar.gz"
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT

    TAR_PATH="${TMP}/${TARBALL}"
    SUMS_PATH="${TMP}/SHA256SUMS"
    KEY_PATH="${TMP}/minisign.pub"
    SIG_PATH="${TMP}/${TARBALL}.minisig"

    echo "Fetching ${COMMAND} (${TARGET})…"
    if fetch "${DIST_BASE}/${TARBALL}" "$TAR_PATH"; then
        :
    elif fetch "${GH_DIST_BASE}/${TARBALL}" "$TAR_PATH"; then
        :
    else
        assets_missing "no tarball at ${DIST_BASE}/${TARBALL} or ${GH_DIST_BASE}/${TARBALL}"
    fi

    if fetch "${DIST_BASE}/SHA256SUMS" "$SUMS_PATH"; then
        :
    elif fetch "${GH_DIST_BASE}/SHA256SUMS" "$SUMS_PATH"; then
        :
    else
        assets_missing "SHA256SUMS missing next to the asset"
    fi

    if fetch "$KEY_URL" "$KEY_PATH"; then
        :
    elif fetch "${GH_DIST_BASE}/minisign.pub" "$KEY_PATH"; then
        :
    else
        assets_missing "minisign pubkey missing at ${KEY_URL}"
    fi

    GOT=$(sha256_of "$TAR_PATH")
    EXPECT=$(awk -v f="$TARBALL" '$2 == f || $2 == "*"f { print $1; exit }' "$SUMS_PATH")
    [ -n "$EXPECT" ] || die "SHA256SUMS has no entry for ${TARBALL}"
    [ "$GOT" = "$EXPECT" ] || die "SHA256 mismatch for ${TARBALL} (got ${GOT}, want ${EXPECT})"

    command -v minisign >/dev/null 2>&1 || die "minisign is required to verify the tarball
  macOS:  brew install minisign
  Debian: sudo apt-get install minisign
  Other:  https://jedisct1.github.io/minisign/"

    if fetch "${DIST_BASE}/${TARBALL}.minisig" "$SIG_PATH"; then
        :
    elif fetch "${GH_DIST_BASE}/${TARBALL}.minisig" "$SIG_PATH"; then
        :
    else
        assets_missing "${TARBALL}.minisig missing (cannot minisign-verify)"
    fi

    echo "Verifying minisign (${KEY_URL})…"
    minisign -Vm "$TAR_PATH" -p "$KEY_PATH" -x "$SIG_PATH" >/dev/null \
        || die "minisign verify failed"

    EXTRACT="${TMP}/out"
    mkdir -p "$EXTRACT"
    tar -xzf "$TAR_PATH" -C "$EXTRACT"
    if [ -f "${EXTRACT}/p5" ]; then
        SRC="${EXTRACT}/p5"
    elif [ -f "${EXTRACT}/bin/p5" ]; then
        SRC="${EXTRACT}/bin/p5"
    else
        die "tarball ${TARBALL} did not contain p5"
    fi
    chmod 755 "$SRC"
    mkdir -p "$BINDIR"
    # Replace in place so a second run is a no-op overwrite.
    cp "$SRC" "${BINDIR}/p5"
    chmod 755 "${BINDIR}/p5"
fi

echo "Installed ${BINDIR}/p5"
if ! need_on_path "$BINDIR"; then
    echo "Note: ${BINDIR} is not on PATH. Add it, e.g.:"
    echo "  export PATH=\"${BINDIR}:\$PATH\""
fi

if [ -x "${BINDIR}/p5" ]; then
    "${BINDIR}/p5" whoami || true
fi
