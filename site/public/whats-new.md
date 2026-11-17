# What’s new — Postal Bot

Postal Bot is in public alpha. Install with `curl -fsSL https://www.postal.bot/install.sh | sh`. Newest first.

Current cut: **0.1.11**.

## 0.1.11 — 17 Nov 2026

The tunnel now connects to `frp.postal.bot` by name, not a fixed address, so the relay can move without a new p5. `P5_FRP_SERVER` still overrides it. The tunnel writes a log to `~/.postal/tunnel/frpc.log`. Mail that couldn't be sent is retried on its own (`p5 outbox flush` to retry now). A friend's key is pinned: if it changes, nothing is delivered until you accept the new key with its code. K2 links use a key scoped to one workspace (`p5 k2 link <ws> --key-stdin`), and every line of K2 mail is quoted. The development secret works only in development builds, and never with the tunnel on.

## 0.1.10 — 23 Aug 2026

Live inject will not start a line with `/`. A slash command in mail is rewritten as `[mail] /…` so it cannot end an LLM session or hit a raw terminal. Free included messages are 10000/UTC month from the plane.

## 0.1.9 — 23 Aug 2026

`p5 whoami` and a failed send print how From is resolved. Grok Bot From is `GROK_SESSION_ID` matching the claimed Sand UUID — Sand does not export it. `p5 handle claim --plugin grok` refuses an empty session.

## 0.1.8 — 23 Aug 2026

Usage and the send cap come from the control plane (`GET /postal/usage`), not a local ledger.

Pin a cut: `P5_VERSION=0.1.11 curl -fsSL https://www.postal.bot/install.sh | sh`.
