#!/bin/sh
# Postal setup for a Grok Bot box. Install p5, publish a turn peer, request
# a pair with postal-bot::rosson.postal.bot (human accepts on the dashboard).
#
#   ./scripts/grokbot-setup.sh
#   ./scripts/grokbot-setup.sh --pair-only
#
# Env (optional):
#   POSTAL_HANDLE   default grok
#   POSTAL_HOST     default grokbot.postal.bot
#   POSTAL_PEER     default postal-bot::rosson.postal.bot
#   POSTAL_CWD      default $PWD
#   POSTAL_SRC      checkout with install/install.sh
#   P5_TURN_HEALTH  loopback Grok Bot health URL if not :1340
set -eu
( set -o pipefail ) 2>/dev/null && set -o pipefail || true

HANDLE="${POSTAL_HANDLE:-grok}"
HOST="${POSTAL_HOST:-grokbot.postal.bot}"
PEER="${POSTAL_PEER:-postal-bot::rosson.postal.bot}"
TYP="turn"
HARNESS="grok"
ADDR="${HANDLE}::${HOST}"
P5_HOME="${P5_HOME:-${HOME}/.postal}"
PAIR_ONLY=0

die() { echo "grokbot-setup: $*" >&2; exit 1; }
info() { echo "grokbot-setup: $*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --pair-only) PAIR_ONLY=1; shift ;;
        -h|--help)
            sed -n '2,16p' "$0"
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done

need_bin() {
    command -v "$1" >/dev/null 2>&1 || die "need $1 on PATH"
}

install_p5() {
    if command -v p5 >/dev/null 2>&1; then
        info "p5 already on PATH: $(command -v p5)"
        return 0
    fi
    # Prefer the published tarball (linux prebuilt). A checkout used to
    # force cargo and hit rustc 1.97 pre_exec E0133. P5_LOCAL=1 keeps the
    # source path for packagers.
    if [ "${P5_LOCAL:-0}" = "1" ]; then
        src="${POSTAL_SRC:-}"
        if [ -z "$src" ] && [ -f "./install/install.sh" ]; then
            src="$PWD"
        fi
        if [ -n "$src" ] && [ -f "$src/install/install.sh" ]; then
            need_bin cargo
            info "installing p5 from $src (--from-cargo)"
            ( cd "$src" && P5_LOCAL=1 ./install/install.sh --from-cargo )
            hash -r 2>/dev/null || true
            command -v p5 >/dev/null 2>&1 || die "p5 not on PATH after install; add ~/.local/bin"
            return 0
        fi
        die "P5_LOCAL=1 but no install/install.sh (set POSTAL_SRC)"
    fi
    info "installing p5 via https://www.postal.bot/install.sh (linux tarball, then src)"
    curl -fsSL https://www.postal.bot/install.sh | sh
    hash -r 2>/dev/null || true
    command -v p5 >/dev/null 2>&1 || die "p5 not on PATH after install; add ~/.local/bin"
}

read_token() {
    python3 - <<'PY'
import json, os, sys
path = os.path.expanduser("~/.k2/tunnel.json")
if not os.path.isfile(path):
    sys.stderr.write("grokbot-setup: missing ~/.k2/tunnel.json\n")
    sys.exit(2)
with open(path) as f:
    d = json.load(f)
sub = (d.get("subdomain") or "").strip()
tok = (d.get("token") or "").strip()
if sub != "grokbot":
    sys.stderr.write("grokbot-setup: ~/.k2/tunnel.json subdomain is %r, want grokbot — stop\n" % sub)
    sys.exit(2)
if not tok:
    sys.stderr.write("grokbot-setup: tunnel.json has no token\n")
    sys.exit(2)
sys.stdout.write(tok)
PY
}

write_identity() {
    cwd="${POSTAL_CWD:-$PWD}"
    umask 077
    mkdir -p "$P5_HOME"
    chmod 700 "$P5_HOME" 2>/dev/null || true
    python3 - "$P5_HOME" "$ADDR" "$cwd" "$HOST" "$HARNESS" "$TYP" "$TOKEN" <<'PY'
import json, os, sys, stat
home, addr, cwd, host, harness, typ, token = sys.argv[1:8]
homes_path = os.path.join(home, "homes.json")
row = {
    "address": addr,
    "cwd": cwd,
    "launch": [],
    "harness": harness,
    "tools": {"files": False, "live_inject": True, "wake": True},
    "enrolled_host": host,
}
homes = []
if os.path.isfile(homes_path):
    with open(homes_path) as f:
        homes = json.load(f)
    if not isinstance(homes, list):
        homes = []
homes = [r for r in homes if r.get("address") != addr]
homes.append(row)
tmp = homes_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(homes, f, indent=2)
    f.write("\n")
os.replace(tmp, homes_path)
cfg = os.path.join(home, "config.toml")
# token file 0600 — do not print it
body = 'connect_token = "%s"\naddr = "%s"\ntyp = "%s"\n' % (
    token.replace("\\", "\\\\").replace('"', '\\"'),
    addr,
    typ,
)
tmp = cfg + ".tmp"
with open(tmp, "w") as f:
    f.write(body)
os.replace(tmp, cfg)
os.chmod(cfg, stat.S_IRUSR | stat.S_IWUSR)
PY
}

install_p5
need_bin python3
need_bin p5

p5 whoami >/dev/null

if [ "$PAIR_ONLY" -eq 0 ]; then
    TOKEN="$(read_token)"
    write_identity
    # --no-start: identity + token only. Agent/tunnel is a later step.
    p5 login --token "$TOKEN" --no-start
    p5 me --from "$ADDR" --typ "$TYP"
fi

info "requesting pair with $PEER (owner must accept on /dashboard?tab=postal)"
p5 pair add "$PEER" --from "$ADDR" --typ "$TYP"
p5 pair list || true

info "done. Report pair id + SAS to the human. Do not p5 pair accept (owner-gated)."
info "next: enroll tunnel (P5_TUNNEL=1 P5_TUNNEL_LABEL=grokbot p5 agent run) so https://$HOST/health is p5."
info "health for inbound turns: GET ${P5_TURN_HEALTH:-http://127.0.0.1:1340/health} (loopback only)."
