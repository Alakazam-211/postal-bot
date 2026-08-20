# Harness plugins

Postal last mile is a **plugin**. Mail (inbox, pairing, live HTTPS) does
not know K2 or Grok Bot. After the tray is on disk, `homes.harness`
selects how to knock a live cell.

Control plane (pairing, hold, enroll, tunnel broker) is **not** a plugin
and is not in this tree’s public contract. Plugins never see Connect
tokens or pairing private keys.

This is the OSS contribution surface. PRs: see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Built-ins

| `homes.harness` | Knock |
|---|---|
| `k2` | `POST /cli/workspace/msg` (same route as `k2 msg`). Injects the **full** `body`. |
| `grok` | loopback Grok Bot gateway (type `turn`): Bearer from `~/sand-data/gateway.json`, `POST /api/listAgents` for UUID, then `POST /api/sendPrompt` with **`body`**. |
| `iterm2` (exec) | macOS iTerm2 + Claude Code. Live: k2-style paste+CR (`write text`, no focus). Dormant: `open -g`, no `activate`, restore frontmost, `claude --resume <id>`. `harness/iterm2`. |
| `terminal` (exec) | macOS Terminal.app. Live: `do script in tab` (no `activate`). Dormant: `open -g` + `do script`, restore frontmost. `harness/terminal`. |
| `ghostty` (exec) | Ghostty 1.3+ AppleScript. Live: `input text` + `send key enter` (no `focus`). Dormant: `new window with configuration`, `open -g`, restore frontmost. `harness/ghostty`. |
| `zed` (exec) | Zed integrated terminal. No native inject API; System Events keystroke then restore frontmost (brief flash). `harness/zed`. |
| `vscode` (exec) | VS Code integrated terminal (not Cursor). Same System Events pattern as Zed. `harness/vscode`. |

Type `turn` with no other matching plugin defaults to `grok`.

## Third-party / OSS

Drop an executable at:

- `$P5_HARNESS_DIR/<name>`, or
- `~/.postal/harness/<name>`, or
- `p5-harness-<name>` on `PATH`

`name` is `[a-z][a-z0-9_-]{0,62}`. p5 runs `<plugin> knock` with Knock JSON
v1 on stdin. Exit 0 / `{"ok":true}` is a hit. The tray is already durable
if you fail.

Copy `harness/webhook` to `~/.postal/harness/webhook` and set
`homes.harness` to `webhook` plus `P5_WEBHOOK_URL`.

New terminals/IDEs/host bots (iTerm2, Terminal.app, Ghostty, Zed,
VS Code, OpenClaw, Hermes, Paperclip, Herdr, …) are **exec plugins** with
`claim` / `knock` / `resume`. Resume must revive after the app is
quit. See the workspace wiki note **Wake Plugins**.

## Knock JSON v1

stdin, `argv[1]=knock`:

```json
{
  "v": 1,
  "op": "knock",
  "id": "<ulid>",
  "to": "handle::sub.postal.bot",
  "from": "peer::sub.postal.bot",
  "handle": "handle",
  "typ": "session",
  "title": "first line, max 80 chars, ellipsis if clipped",
  "text": "[p5:<id>] title\nOpen: p5 inbox read <id>",
  "body": "full cover body — inject this",
  "wake": true,
  "cwd": "/path",
  "session_id": "optional"
}
```

**Use `body`.** `title` is a preview of the first non-empty line (clipped
at 80, then `…`). An agent that only reads `title` will miss instructions
in the tail. The full mail is always in `~/.postal/inbox` (`p5 inbox read <id>`).

## Rules

- Do not talk to the cert broker, Stripe, or `/postal/*` from a plugin.
- Do not upload pairing private keys.
- Time out (p5 waits 25s). Fail closed; the tray stays.
- One plugin name = one bot host. Do not invent Postal types.
