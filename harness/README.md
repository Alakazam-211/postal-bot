# Harness plugins

Postal last mile is a **plugin**. Mail (inbox, pairing, live HTTPS) does not
know K2 or Grok Bot. After the tray is on disk, `homes.harness` selects how
to knock a live cell.

Control plane (pairing, hold, enroll, tunnel broker) is **not** a plugin and
is not in this tree’s public contract.

## Built-ins

| `homes.harness` | Knock |
|---|---|
| `k2` | `POST /cli/workspace/msg` (same route as `k2 msg`) |
| `grok` | loopback Grok Bot gateway (type `turn`): Bearer from `~/sand-data/gateway.json`, `POST /api/listAgents` for UUID, then `POST /api/sendPrompt` |

Type `turn` with no other matching plugin defaults to `grok`.

## Third-party / OSS

Drop an executable at:

- `$P5_HARNESS_DIR/<name>`, or
- `~/.postal/harness/<name>`, or
- `p5-harness-<name>` on `PATH`

`name` is `[a-z][a-z0-9_-]{0,62}`. p5 runs `<plugin> knock` with Knock JSON
v1 on stdin (see `crates/p5/src/last_mile.rs`). Exit 0 / `{"ok":true}` is a
hit. The tray is already durable if you fail.

Copy `harness/webhook` to `~/.postal/harness/webhook` and set
`homes.harness` to `webhook` plus `P5_WEBHOOK_URL`.
