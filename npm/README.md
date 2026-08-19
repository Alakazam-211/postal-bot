# `@alakazamlabs/postal`

Thin **platform-binary fetcher** for Postal (`p5`). This is not a JavaScript rewrite of the CLI.

```sh
npm i -g @alakazamlabs/postal
```

lands the same Rust `p5` binary as:

```sh
curl -fsSL https://postal.bot/install.sh | sh
```

**Not published yet.** `postal.bot` DNS is not live and no GitHub release assets exist. When they do, `postinstall` will download the matching `p5-<os>-<arch>` tarball, check `SHA256SUMS`, and minisign-verify against `https://postal.bot/keys/minisign.pub` (same key on the GitHub release until DNS works).

Until then, install from a checkout:

```sh
P5_LOCAL=1 ./install/install.sh
# or
cargo install --path crates/p5
```

The npm name is scoped (`@alakazamlabs/postal`) because bare `p5` is a different JS library. The **command** is still `p5`.
