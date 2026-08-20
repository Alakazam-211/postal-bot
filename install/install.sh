#!/bin/sh
# Postal (p5) installer.
#
#   curl -fsSL https://www.postal.bot/install.sh | sh
#
# Lands `p5` on PATH at /usr/local/bin or ~/.local/bin. Idempotent.
# No GitHub login. Prefers a platform tarball; otherwise a source
# tree + cargo (Cortana has rust, not a private clone).
#
# Local cargo (from a checkout):
#   P5_LOCAL=1 ./install/install.sh
#   ./install/install.sh --from-cargo
#
# POSIX sh. No bash-isms.
set -eu
( set -o pipefail ) 2>/dev/null && set -o pipefail || true

PRODUCT="Postal"
COMMAND="p5"
SITE="postal.bot"
WWW_DIST="https://www.postal.bot/releases/latest"
APEX_DIST="https://postal.bot/releases/latest"
KEY_URL="https://www.postal.bot/keys/minisign.pub"

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

Remote pipe (no GitHub):
  1. ${WWW_DIST}/p5-<os>-<arch>.tar.gz + SHA256SUMS
  2. else ${WWW_DIST}/p5-src.tar.gz and cargo build --release --locked
  Apex ${APEX_DIST} is a fallback if www is unreachable.
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
    # fetch <url> <dest>
    _url="$1"
    _dest="$2"
    command -v curl >/dev/null 2>&1 || die "curl is required"
    rm -f "$_dest"
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 8 --max-time 120 \
        "$_url" -o "$_dest" 2>/dev/null || return 1
    [ -s "$_dest" ] || return 1
    _sz=$(wc -c < "$_dest" | tr -d ' ')
    [ "$_sz" -ge 16 ] || return 1
    if dd if="$_dest" bs=64 count=1 2>/dev/null | grep -qi '<html\|<!doctype'; then
        return 1
    fi
    return 0
}

sum_for() {
    awk -v f="$1" '$2 == f || $2 == "*"f { print $1; exit }' "$SUMS_PATH"
}

check_sha() {
    _file="$1"
    _name="$2"
    GOT=$(sha256_of "$_file")
    EXPECT=$(sum_for "$_name")
    [ -n "$EXPECT" ] || die "SHA256SUMS has no entry for ${_name}"
    [ "$GOT" = "$EXPECT" ] || die "SHA256 mismatch for ${_name} (got ${GOT}, want ${EXPECT})"
}

maybe_minisign() {
    _tar="$1"
    _sig="$2"
    _key="$3"
    [ -s "$_sig" ] && [ -s "$_key" ] || return 0
    if ! command -v minisign >/dev/null 2>&1; then
        echo "install.sh: minisign not on PATH; skipping signature (SHA256 still checked)" >&2
        return 0
    fi
    echo "Verifying minisign…"
    minisign -Vm "$_tar" -p "$_key" -x "$_sig" >/dev/null \
        || die "minisign verify failed"
}

find_p5_bin() {
    _dir="$1"
    if [ -e "${_dir}/p5" ]; then
        printf '%s\n' "${_dir}/p5"
    elif [ -e "${_dir}/bin/p5" ]; then
        printf '%s\n' "${_dir}/bin/p5"
    else
        return 1
    fi
}

find_src_root() {
    _dir="$1"
    # tarball is postal-bot/crates/p5/Cargo.toml — that's depth 4 from the extract root.
    for _cand in \
        "${_dir}/crates/p5/Cargo.toml" \
        "${_dir}/postal-bot/crates/p5/Cargo.toml"
    do
        if [ -f "$_cand" ]; then
            CDPATH= cd -- "$(dirname "$_cand")/../.." && pwd
            return 0
        fi
    done
    # Do not put a case-arm `)` inside `$(...)` — /bin/sh ends the substitution there.
    _hit=$(find "$_dir" -maxdepth 6 -path '*/crates/p5/Cargo.toml' -print 2>/dev/null | head -n 1)
    if [ -n "$_hit" ]; then
        CDPATH= cd -- "$(dirname "$_hit")/../.." && pwd
        return 0
    fi
    return 1
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
    _name="$2"
    [ -n "$_name" ] || _name="p5"
    [ -f "$_src" ] || die "install source is not a regular file: $_src"
    [ ! -h "$_src" ] || die "refusing to install a symlink ($_src)"
    mkdir -p "$BINDIR"
    cp "$_src" "${BINDIR}/${_name}.new"
    chmod 755 "${BINDIR}/${_name}.new"
    mv -f "${BINDIR}/${_name}.new" "${BINDIR}/${_name}"
}

install_frpc() {
    _tgt="${1:-}"
    [ -n "$_tgt" ] || return 0
    command -v curl >/dev/null 2>&1 || return 0
    _tar="frpc-${_tgt}.tar.gz"
    _tmp=$(mktemp -d)
    _path="${_tmp}/${_tar}"
    _sums="${_tmp}/SHA256SUMS"
    if fetch "${WWW_DIST}/${_tar}" "$_path" || fetch "${APEX_DIST}/${_tar}" "$_path"; then
        :
    else
        rm -rf "$_tmp"
        echo "install.sh: no ${_tar} at ${WWW_DIST} — tunnel will stay down until frpc is next to p5" >&2
        return 0
    fi
    if fetch "${WWW_DIST}/SHA256SUMS" "$_sums" || fetch "${APEX_DIST}/SHA256SUMS" "$_sums"; then
        _got=$(sha256_of "$_path")
        _want=$(awk -v f="$_tar" '$2 == f || $2 == "*"f { print $1; exit }' "$_sums")
        if [ -n "$_want" ] && [ "$_got" != "$_want" ]; then
            rm -rf "$_tmp"
            echo "install.sh: SHA256 mismatch for ${_tar}; skipping frpc" >&2
            return 0
        fi
    fi
    _out="${_tmp}/out"
    mkdir -p "$_out"
    tar -xzf "$_path" -C "$_out"
    _bin=""
    if [ -f "${_out}/frpc" ]; then
        _bin="${_out}/frpc"
    elif [ -f "${_out}/bin/frpc" ]; then
        _bin="${_out}/bin/frpc"
    fi
    if [ -z "$_bin" ]; then
        rm -rf "$_tmp"
        echo "install.sh: ${_tar} had no frpc binary" >&2
        return 0
    fi
    install_bin "$_bin" frpc
    echo "Installed ${BINDIR}/frpc (with p5)"
    rm -rf "$_tmp"
}

try_prebuilt() {
    _base="$1"
    rm -f "$TAR_PATH" "$SUMS_PATH" "$KEY_PATH" "$SIG_PATH"
    fetch "${_base}/${TARBALL}" "$TAR_PATH" || return 1
    is_gzip "$TAR_PATH" || return 1
    fetch "${_base}/SHA256SUMS" "$SUMS_PATH" || return 1
    check_sha "$TAR_PATH" "$TARBALL"
    fetch "${_base}/${TARBALL}.minisig" "$SIG_PATH" || true
    fetch "$KEY_URL" "$KEY_PATH" || fetch "${_base}/minisign.pub" "$KEY_PATH" || true
    maybe_minisign "$TAR_PATH" "$SIG_PATH" "$KEY_PATH"
    EXTRACT="${TMP}/out"
    rm -rf "$EXTRACT"
    mkdir -p "$EXTRACT"
    tar -xzf "$TAR_PATH" -C "$EXTRACT"
    SRC=$(find_p5_bin "$EXTRACT") || die "tarball ${TARBALL} did not contain p5"
    install_bin "$SRC" p5
    echo "Installed ${BINDIR}/p5 (prebuilt ${TARGET} from ${_base})"
    if [ -f "${EXTRACT}/frpc" ]; then
        install_bin "${EXTRACT}/frpc" frpc
        echo "Installed ${BINDIR}/frpc (from ${TARBALL})"
    fi
}

try_source() {
    _base="$1"
    command -v cargo >/dev/null 2>&1 || return 1
    SRC_TAR="p5-src.tar.gz"
    SRC_PATH="${TMP}/${SRC_TAR}"
    rm -f "$SRC_PATH" "$SUMS_PATH"
    fetch "${_base}/${SRC_TAR}" "$SRC_PATH" || return 1
    is_gzip "$SRC_PATH" || return 1
    fetch "${_base}/SHA256SUMS" "$SUMS_PATH" || return 1
    check_sha "$SRC_PATH" "$SRC_TAR"
    SRC_DIR="${TMP}/src"
    rm -rf "$SRC_DIR"
    mkdir -p "$SRC_DIR"
    tar -xzf "$SRC_PATH" -C "$SRC_DIR"
    ROOT=$(find_src_root "$SRC_DIR") || die "source tarball has no crates/p5"
    echo "Building ${COMMAND} from source (${ROOT}) → ${BINDIR}"
    cargo build --release --locked --manifest-path "${ROOT}/crates/p5/Cargo.toml"
    if [ -n "${CARGO_TARGET_DIR:-}" ]; then
        SRC="${CARGO_TARGET_DIR}/release/p5"
    else
        SRC="${ROOT}/target/release/p5"
    fi
    install_bin "$SRC" p5
    echo "Installed ${BINDIR}/p5 (built from ${_base}/${SRC_TAR})"
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
    install_bin "$SRC" p5
    TARGET=$(detect_target)
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
    if try_prebuilt "$WWW_DIST"; then
        :
    elif try_prebuilt "$APEX_DIST"; then
        :
    elif try_source "$WWW_DIST"; then
        :
    elif try_source "$APEX_DIST"; then
        :
    else
        die "no ${TARBALL} or p5-src.tar.gz at ${WWW_DIST} (or ${APEX_DIST}).
Need curl + (a matching tarball, or cargo to build p5-src.tar.gz).
No GitHub clone is required."
    fi
fi

install_frpc "$TARGET"
echo "Installed ${BINDIR}/p5"
if ! need_on_path "$BINDIR"; then
    echo "Note: ${BINDIR} is not on PATH. Add it, e.g.:"
    echo "  export PATH=\"${BINDIR}:\$PATH\""
fi

if [ -x "${BINDIR}/p5" ]; then
    "${BINDIR}/p5" whoami || true
fi
