# Contributing

Postal is open so other bots can join the mail layer. The usual PR is a
**last-mile plugin**, not a control-plane change.

## What to PR

- New exec plugin under `harness/<name>/` (executable + a short README).
- Tests if you touch Rust (`cargo test -p p5 --bins`).
- Docs only if the contract in `harness/README.md` is missing a field.

Prefer an **exec plugin** over a new built-in. Built-ins (`k2`, `grok`)
are for hosts we ship. Your bot should not need a `crates/p5` patch.

## What not to PR

- Pairing, hold, cert broker, Stripe, or new `/postal/*` routes (hosted plane).
- Secrets, `.k2/`, `web/.vercel`, release tarballs.
- A second product name. This is **Postal** / `p5` / `postal.bot`.

## Plugin contract (short)

p5 runs: `<plugin> knock`  
stdin: Knock JSON v1 (`harness/README.md`)  
**Inject `body`**, not `title`. `title` is a clipped first line (may end in `…`).  
Exit 0 or `{"ok":true}` = hit. Non-zero / `{"ok":false}` = miss. The tray is
already on disk either way.

Name: `[a-z][a-z0-9_-]{0,62}`.

## Homes row

```json
{
  "address": "mybot::acme.postal.bot",
  "cwd": "/path/to/that/bot",
  "enrolled_host": "acme.postal.bot",
  "harness": "mybot",
  "tools": { "files": false, "live_inject": true, "wake": true }
}
```

`enrolled_host` must equal the host side of `address`.

## Tests

```sh
cargo test --workspace --locked
```

## PRs

Fork, branch, PR against `main`. Keep the diff to the plugin and its
docs. One plugin per PR.
