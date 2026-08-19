#!/bin/sh
# Build source + native prebuilt tarballs into web/releases/latest for Vercel.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DIST="${ROOT}/web/releases/latest"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
COPYFILE_DISABLE=1
export COPYFILE_DISABLE

mkdir -p "$DIST"
# Source tree Cortana can cargo-build (no git).
SRC="${STAGE}/postal-bot"
mkdir -p "$SRC"
# Working tree — includes uncommitted last-mile / plugin files.
for p in Cargo.toml Cargo.lock crates harness install scripts README.md LICENSE; do
    if [ -e "${ROOT}/${p}" ]; then
        cp -R "${ROOT}/${p}" "${SRC}/${p}"
    fi
done
rm -rf "${SRC}/crates/"*/target "${SRC}/target" "${SRC}/install/pack-release.sh"
# drop any accidental .k2
rm -rf "${SRC}/.k2" "${SRC}/crates/"*/.k2
mkdir -p "${STAGE}/srcwrap"
# tar from STAGE so the archive contains postal-bot/...
( CDPATH= cd -- "$STAGE" && tar -czf "${DIST}/p5-src.tar.gz" postal-bot )

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
( CDPATH= cd -- "${STAGE}/bin" && tar -czf "${DIST}/${NATIVE}" p5 )

# Bundle frpc (same origin as p5). Pin matches k2 / frpc.toml v0.61.
FRP_VER=0.61.1
fetch_frpc() {
    _os="$1"
    _arch="$2"
    _goos="$3"
    _goarch="$4"
    _url="https://github.com/fatedier/frp/releases/download/v${FRP_VER}/frp_${FRP_VER}_${_goos}_${_goarch}.tar.gz"
    _zip="${STAGE}/frp-${_os}-${_arch}.tar.gz"
    echo "pack-release: fetch frpc ${_os}-${_arch}" >&2
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 60 \
        "$_url" -o "$_zip" || {
        echo "pack-release: skip frpc ${_os}-${_arch} (download failed)" >&2
        return 0
    }
    _dir="${STAGE}/frp-${_os}-${_arch}"
    mkdir -p "$_dir"
    tar -xzf "$_zip" -C "$_dir"
    _bin=$(find "$_dir" -name frpc -type f | head -n 1)
    if [ -z "$_bin" ] || [ ! -f "$_bin" ]; then
        echo "pack-release: no frpc in ${_url}" >&2
        return 0
    fi
    _out="${STAGE}/frpcout-${_os}-${_arch}"
    mkdir -p "$_out"
    cp "$_bin" "${_out}/frpc"
    chmod 755 "${_out}/frpc"
    ( CDPATH= cd -- "$_out" && tar -czf "${DIST}/frpc-${_os}-${_arch}.tar.gz" frpc )
    # Native p5 tarball also carries frpc so one extract is enough.
    if [ "p5-${_os}-${_arch}.tar.gz" = "$NATIVE" ]; then
        cp "${_out}/frpc" "${STAGE}/bin/frpc"
        ( CDPATH= cd -- "${STAGE}/bin" && tar -czf "${DIST}/${NATIVE}" p5 frpc )
    fi
}
fetch_frpc macos aarch64 darwin arm64
fetch_frpc macos x86_64 darwin amd64
fetch_frpc linux x86_64 linux amd64
fetch_frpc linux aarch64 linux arm64

cp "${ROOT}/install/install.sh" "${ROOT}/web/install.sh"
chmod 644 "${ROOT}/web/install.sh"
cp "${ROOT}/scripts/grokbot-setup.sh" "${ROOT}/web/grokbot-setup.sh"
chmod 644 "${ROOT}/web/grokbot-setup.sh"

{
    ( CDPATH= cd -- "$DIST" && ls p5-src.tar.gz p5-*.tar.gz frpc-*.tar.gz 2>/dev/null | sort -u | while read -r f; do
        sha256sum "$f" 2>/dev/null || shasum -a 256 "$f"
    done )
} > "${DIST}/SHA256SUMS"

echo "pack-release: wrote ${DIST}" >&2
cat "${DIST}/SHA256SUMS" >&2
