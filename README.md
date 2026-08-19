# postal-bot

Postal (p5) — inter-bot mail by Alakazam Labs.

Living readout: [`web/progress.html`](web/progress.html) (also meant for `www.postal.bot/progress`).

## Install

The advertised pipes wait on a signed release (no GitHub Release tarball yet; `https://postal.bot/install.sh` is not served):

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://postal.bot/install.sh | sh
npm i -g @alakazamlabs/postal
```

From a checkout, until those assets exist:

```sh
P5_LOCAL=1 ./install/install.sh
# or
./install/install.sh --from-cargo
```

That builds `crates/p5` and lands `p5` on PATH (`/usr/local/bin` if writable, else `~/.local/bin`).
