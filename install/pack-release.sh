#!/bin/sh
# Build source + native prebuilt tarballs into site/public/releases/latest for Vercel.
#
# Run on each pack host:
#   macOS aarch64 → p5-macos-aarch64.tar.gz
#   Linux x86_64  → p5-linux-x86_64.tar.gz   (GitHub Actions ubuntu-latest)
#   Linux aarch64 → p5-linux-aarch64.tar.gz  (GitHub Actions ubuntu-24.04-arm)
#
# DIST is not wiped. Copy a CI linux tarball in before a macOS pack so
# SHA256SUMS lists every platform. Never `vercel --prod` from repo root
# (that can steal www). Deploy `site/` (the postal-bot project) only.
#
# Packs HEAD via git archive (uncommitted files stay out). Checkout a
# clean tree first. Native tarballs carry p5, frpc, LICENSE, NOTICE,
# THIRD-PARTY, and frpc.LICENSE.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SITE="${ROOT}/site/public"
DIST="${SITE}/releases/latest"
VER=$(awk -F '"' '/^version = / { print $2; exit }' "${ROOT}/crates/p5/Cargo.toml")
[ -n "$VER" ] || { echo "pack-release: no version in crates/p5/Cargo.toml" >&2; exit 1; }
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
COPYFILE_DISABLE=1
export COPYFILE_DISABLE

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "pack-release: need a git checkout" >&2
    exit 1
}
PACK_PATHS="Cargo.toml Cargo.lock crates harness install scripts README.md LICENSE THIRD-PARTY.md"
if ! git -C "$ROOT" diff --quiet HEAD -- $PACK_PATHS \
    || ! git -C "$ROOT" diff --cached --quiet -- $PACK_PATHS; then
    echo "pack-release: dirty tree; checkout a clean commit (src tarball is git archive of HEAD)" >&2
    exit 1
fi

mkdir -p "$DIST"
# Source tree from HEAD only — uncommitted files stay out.
git -C "$ROOT" archive --format=tar --prefix=postal-bot/ HEAD \
    Cargo.toml Cargo.lock crates harness install scripts README.md LICENSE THIRD-PARTY.md \
    > "${STAGE}/src.tar"
mkdir -p "${STAGE}/srcwrap"
tar -xf "${STAGE}/src.tar" -C "${STAGE}/srcwrap"
rm -f "${STAGE}/srcwrap/postal-bot/install/pack-release.sh"
( CDPATH= cd -- "${STAGE}/srcwrap" && tar -czf "${DIST}/p5-src.tar.gz" postal-bot )

# Native prebuilt for this machine.
echo "pack-release: cargo build --release -p p5" >&2
cargo build --release --locked --manifest-path "${ROOT}/crates/p5/Cargo.toml"
OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in Darwin) OS=macos ;; Linux) OS=linux ;; esac
case "$ARCH" in arm64|aarch64) ARCH=aarch64 ;; x86_64|amd64) ARCH=x86_64 ;; esac
NATIVE="p5-${OS}-${ARCH}.tar.gz"
BIN="${ROOT}/target/release/p5"
[ -f "$BIN" ] || { echo "pack-release: missing ${BIN}" >&2; exit 1; }
mkdir -p "${STAGE}/bin"
cp "$BIN" "${STAGE}/bin/p5"
chmod 755 "${STAGE}/bin/p5"

# Licence texts Steward asked for in every native tarball.
[ -f "${ROOT}/LICENSE" ] || { echo "pack-release: missing LICENSE" >&2; exit 1; }
[ -f "${ROOT}/crates/postal-sdk/NOTICE" ] || { echo "pack-release: missing postal-sdk NOTICE" >&2; exit 1; }
[ -f "${ROOT}/THIRD-PARTY.md" ] || { echo "pack-release: missing THIRD-PARTY.md (cargo about generate)" >&2; exit 1; }
[ -f "${ROOT}/install/licenses/frpc.Apache-2.0" ] || { echo "pack-release: missing frpc Apache-2.0 text" >&2; exit 1; }
cp "${ROOT}/LICENSE" "${STAGE}/bin/LICENSE"
cp "${ROOT}/crates/postal-sdk/NOTICE" "${STAGE}/bin/NOTICE"
cp "${ROOT}/THIRD-PARTY.md" "${STAGE}/bin/THIRD-PARTY"
cp "${ROOT}/install/licenses/frpc.Apache-2.0" "${STAGE}/bin/frpc.LICENSE"

# Bundle frpc (same origin as p5). Pin matches k2 / frpc.toml v0.61.
# Checksums from https://github.com/fatedier/frp/releases/download/v0.61.1/frp_sha256_checksums.txt
FRP_VER=0.61.1
frp_sha256() {
    case "$1" in
        darwin_arm64)  printf '%s\n' 3e65f13a17a284bd6013e6bb6856bc2720074cea6094cc446c1f4c3932154c2d ;;
        darwin_amd64)  printf '%s\n' 403a0ee5e92f083a863d984b7af1e9d70ba2aaa28e87f42f1fe085adf76b8491 ;;
        linux_amd64)   printf '%s\n' bff260b68ca7b1461182a46c4f34e9709ba32764eed30a15dd94ac97f50a2c40 ;;
        linux_arm64)   printf '%s\n' af6366f2b43920ebfe6235dba6060770399ed1fb18601e5818552bd46a7621f8 ;;
        *) echo "pack-release: no pinned sha256 for frp ${FRP_VER}_$1" >&2; return 1 ;;
    esac
}
fetch_frpc() {
    _os="$1"
    _arch="$2"
    _goos="$3"
    _goarch="$4"
    _want=$(frp_sha256 "${_goos}_${_goarch}") || exit 1
    _url="https://github.com/fatedier/frp/releases/download/v${FRP_VER}/frp_${FRP_VER}_${_goos}_${_goarch}.tar.gz"
    _zip="${STAGE}/frp-${_os}-${_arch}.tar.gz"
    echo "pack-release: fetch frpc ${_os}-${_arch}" >&2
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 60 \
        "$_url" -o "$_zip" || {
        echo "pack-release: frpc ${_os}-${_arch} download failed" >&2
        exit 1
    }
    _got=$(sha256_of "$_zip")
    if [ "$_got" != "$_want" ]; then
        echo "pack-release: frpc ${_os}-${_arch} sha256 mismatch (got ${_got}, want ${_want})" >&2
        exit 1
    fi
    _dir="${STAGE}/frp-${_os}-${_arch}"
    mkdir -p "$_dir"
    tar -xzf "$_zip" -C "$_dir"
    _bin=$(find "$_dir" -name frpc -type f | head -n 1)
    if [ -z "$_bin" ] || [ ! -f "$_bin" ]; then
        echo "pack-release: no frpc in ${_url}" >&2
        exit 1
    fi
    _out="${STAGE}/frpcout-${_os}-${_arch}"
    mkdir -p "$_out"
    cp "$_bin" "${_out}/frpc"
    chmod 755 "${_out}/frpc"
    ( CDPATH= cd -- "$_out" && tar -czf "${DIST}/frpc-${_os}-${_arch}.tar.gz" frpc )
    # Native p5 tarball also carries frpc so one extract is enough.
    if [ "p5-${_os}-${_arch}.tar.gz" = "$NATIVE" ]; then
        cp "${_out}/frpc" "${STAGE}/bin/frpc"
    fi
}
fetch_frpc macos aarch64 darwin arm64
fetch_frpc macos x86_64 darwin amd64
fetch_frpc linux x86_64 linux amd64
fetch_frpc linux aarch64 linux arm64

[ -f "${STAGE}/bin/frpc" ] || { echo "pack-release: native tarball missing frpc" >&2; exit 1; }
( CDPATH= cd -- "${STAGE}/bin" && tar -czf "${DIST}/${NATIVE}" p5 frpc LICENSE NOTICE THIRD-PARTY frpc.LICENSE )

cp "${ROOT}/install/install.sh" "${SITE}/install.sh"
chmod 644 "${SITE}/install.sh"
# macOS /bin/sh parses the whole file; catch case-arm `)` inside `$(...)`.
/bin/sh -n "${SITE}/install.sh" || {
    echo "pack-release: site/public/install.sh failed sh -n" >&2
    exit 1
}
cp "${ROOT}/scripts/grokbot-setup.sh" "${SITE}/grokbot-setup.sh"
chmod 644 "${SITE}/grokbot-setup.sh"

{
    ( CDPATH= cd -- "$DIST" && ls p5-src.tar.gz p5-*.tar.gz frpc-*.tar.gz 2>/dev/null | sort -u | while read -r f; do
        sha256sum "$f" 2>/dev/null || shasum -a 256 "$f"
    done )
} > "${DIST}/SHA256SUMS"

# Next (postal-bot Vercel) serves site/public/releases/*. Pin a versioned
# tree too so P5_VERSION=X.Y.Z does not depend on latest.
sync_release_tree() {
    _dest="$1"
    mkdir -p "$_dest"
    ( CDPATH= cd -- "$DIST" && ls p5-src.tar.gz p5-*.tar.gz frpc-*.tar.gz SHA256SUMS 2>/dev/null | while read -r f; do
        cp "$f" "${_dest}/${f}"
    done )
}
sync_release_tree "${SITE}/releases/${VER}"

echo "pack-release: wrote ${DIST} (p5 ${VER})" >&2
cat "${DIST}/SHA256SUMS" >&2
