#!/bin/sh
# Postal (p5) installer.
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://postal.bot/install.sh | sh
#
# Lands `p5` on PATH at /usr/local/bin or ~/.local/bin. Idempotent.
#
# Remote (default, when release assets exist):
#   1. Fetch one origin's full set: tarball + SHA256SUMS + minisign.pub + .minisig
#      (postal.bot first; GitHub release as a whole-set fallback)
#   2. Check SHA256SUMS; minisign -Vm the tarball
#   3. Atomic-install p5 into $prefix/bin
#
# Local cargo (until postal.bot DNS / release assets exist):
#   P5_LOCAL=1 ./install/install.sh
#   ./install/install.sh --from-cargo
#   → cargo build --release, then copy target/release/p5 into $prefix/bin
#   (not `cargo install --root` — that writes .crates.toml next to bin)
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

  --from-cargo    cargo build crates/p5 and install p5 into \$prefix/bin
  --prefix DIR    install prefix (bin lands in DIR/bin)
  -h, --help      show this help

Env:
  P5_LOCAL=1      same as --from-cargo
  P5_PREFIX       same as --prefix
  P5_REPO         checkout root (default: detect from this script or cwd)

Default prefix: /usr/local if writable, else ~/.local.

Remote installs minisign-verify against ${KEY_URL}
and check SHA256SUMS next to the asset (one origin per attempt).
If those files are missing, this script errors — postal.bot DNS
is not live yet. Use --from-cargo.
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

is_gzip() {
    _hex=$(od -An -tx1 -N2 "$1" 2>/dev/null | tr -d ' \n\t' | tr 'A-F' 'a-f')
    [ "$_hex" = "1f8b" ]
}

fetch() {
    # fetch <url> <dest> — stderr swallowed; caller prints a single assets-missing error.
    # Empty/short/HTML 200s fail so parking pages do not look like assets.
    _url="$1"
    _dest="$2"
    command -v curl >/dev/null 2>&1 || die "curl is required"
    rm -f "$_dest"
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 8 --max-time 60 \
        "$_url" -o "$_dest" 2>/dev/null || return 1
    [ -s "$_dest" ] || return 1
    _sz=$(wc -c < "$_dest" | tr -d ' ')
    [ "$_sz" -ge 16 ] || return 1
    if dd if="$_dest" bs=64 count=1 2>/dev/null | grep -qi '<html\|<!doctype'; then
        return 1
    fi
    return 0
}

assets_missing() {
    die "$*

${PRODUCT} release assets are not published yet (postal.bot DNS is not live).
The remote pipe needs one complete origin set:
  ${KEY_URL}
  ${DIST_BASE}/SHA256SUMS
  ${DIST_BASE}/p5-<os>-<arch>.tar.gz
  ${DIST_BASE}/p5-<os>-<arch>.tar.gz.minisig
  (same files on GitHub ${REPO_SLUG} releases as a whole-set fallback)

Until those exist, install from a local checkout:

  P5_LOCAL=1 ./install/install.sh
  ./install/install.sh --from-cargo

Or: cargo build --release -p p5"
}

need_on_path() {
    _bindir="$1"
    case ":${PATH}:" in
        *":${_bindir}:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Atomic replace so a running p5 is not ETXTBSY (Linux) and a crash
# cannot leave a truncated destination.
install_bin() {
    _src="$1"
    [ -f "$_src" ] || die "install source is not a regular file: $_src"
    [ ! -h "$_src" ] || die "refusing to install a symlink ($_src)"
    mkdir -p "$BINDIR"
    cp "$_src" "${BINDIR}/p5.new"
    chmod 755 "${BINDIR}/p5.new"
    mv -f "${BINDIR}/p5.new" "${BINDIR}/p5"
}

# One origin, one set. Do not mix tarball from A with sums/key/sig from B.
try_origin() {
    _base="$1"
    _key="$2"
    rm -f "$TAR_PATH" "$SUMS_PATH" "$KEY_PATH" "$SIG_PATH"
    fetch "${_base}/${TARBALL}" "$TAR_PATH" || return 1
    is_gzip "$TAR_PATH" || return 1
    fetch "${_base}/SHA256SUMS" "$SUMS_PATH" || return 1
    fetch "$_key" "$KEY_PATH" || return 1
    fetch "${_base}/${TARBALL}.minisig" "$SIG_PATH" || return 1
    return 0
}

PREFIX=$(choose_prefix)
BINDIR="${PREFIX}/bin"

if [ "$FROM_CARGO" = "1" ]; then
    command -v cargo >/dev/null 2>&1 || die "cargo not found (needed for --from-cargo / P5_LOCAL=1)"
    ROOT=$(repo_root) || die "cannot find crates/p5 (set P5_REPO or run from the postal-bot checkout)"
    echo "Building ${COMMAND} from cargo (${ROOT}/crates/p5) → ${BINDIR}"
    cargo build --release --locked --manifest-path "${ROOT}/crates/p5/Cargo.toml"
    if [ -n "${CARGO_TARGET_DIR:-}" ]; then
        SRC="${CARGO_TARGET_DIR}/release/p5"
    else
        SRC="${ROOT}/target/release/p5"
    fi
    install_bin "$SRC"
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
    USED_KEY="$KEY_URL"

    echo "Fetching ${COMMAND} (${TARGET})…"
    if try_origin "$DIST_BASE" "$KEY_URL"; then
        USED_KEY="$KEY_URL"
    elif try_origin "$GH_DIST_BASE" "${GH_DIST_BASE}/minisign.pub"; then
        USED_KEY="${GH_DIST_BASE}/minisign.pub"
    else
        assets_missing "no complete asset set at ${DIST_BASE} or ${GH_DIST_BASE}"
    fi

    GOT=$(sha256_of "$TAR_PATH")
    EXPECT=$(awk -v f="$TARBALL" '$2 == f || $2 == "*"f { print $1; exit }' "$SUMS_PATH")
    [ -n "$EXPECT" ] || die "SHA256SUMS has no entry for ${TARBALL}"
    [ "$GOT" = "$EXPECT" ] || die "SHA256 mismatch for ${TARBALL} (got ${GOT}, want ${EXPECT})"

    command -v minisign >/dev/null 2>&1 || die "minisign is required to verify the tarball
  macOS:  brew install minisign
  Debian: sudo apt-get install minisign
  Other:  https://jedisct1.github.io/minisign/"

    echo "Verifying minisign (${USED_KEY})…"
    minisign -Vm "$TAR_PATH" -p "$KEY_PATH" -x "$SIG_PATH" >/dev/null \
        || die "minisign verify failed"

    EXTRACT="${TMP}/out"
    mkdir -p "$EXTRACT"
    tar -xzf "$TAR_PATH" -C "$EXTRACT"
    if [ -e "${EXTRACT}/p5" ]; then
        SRC="${EXTRACT}/p5"
    elif [ -e "${EXTRACT}/bin/p5" ]; then
        SRC="${EXTRACT}/bin/p5"
    else
        die "tarball ${TARBALL} did not contain p5"
    fi
    install_bin "$SRC"
fi

echo "Installed ${BINDIR}/p5"
if ! need_on_path "$BINDIR"; then
    echo "Note: ${BINDIR} is not on PATH. Add it, e.g.:"
    echo "  export PATH=\"${BINDIR}:\$PATH\""
fi

if [ -x "${BINDIR}/p5" ]; then
    "${BINDIR}/p5" whoami || true
fi
