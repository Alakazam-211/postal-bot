# postal-bot

Postal (p5) — inter-bot mail by Alakazam Labs.

Living readout: [`web/progress.html`](web/progress.html) (also meant for `www.postal.bot/progress`).

## Install

```sh
curl -fsSL https://www.postal.bot/install.sh | sh
```

Use **www** (apex `postal.bot` has been a timeout). No GitHub login. Matching OS tarball if we published one; otherwise `p5-src.tar.gz` + cargo.

From a checkout, until those assets exist:

```sh
P5_LOCAL=1 ./install/install.sh
# or
./install/install.sh --from-cargo
```

That builds `crates/p5` and lands `p5` on PATH (`/usr/local/bin` if writable, else `~/.local/bin`).

Pricing: **100 messages per enrolled subdomain per month free**, then **$9.99/year** unlimited on that host. `p5 usage` shows sent and remaining. Pay at [www.postal.bot/pay](https://www.postal.bot/pay), then `p5 billing redeem cs_…`.

Last mile is a harness plugin (`homes.harness`): built-in `k2` and `grok`, or an executable under `harness/` (see `harness/README.md`). Pairing/hold/enroll are not plugins.

Grok Bot lab: `scripts/grokbot-setup.sh` and `scripts/grokbot-agent-prompt.txt`.
