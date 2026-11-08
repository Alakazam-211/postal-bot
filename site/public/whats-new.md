# What’s new — Postal Bot

Postal Bot is in public alpha. Install with `curl -fsSL https://www.postal.bot/install.sh | sh`. Newest first.

Current cut: **0.1.10**.

## 0.1.10 — 23 Aug 2026

Live inject will not start a line with `/`. A slash command in mail is rewritten as `[mail] /…` so it cannot end an LLM session or hit a raw terminal. Free included messages are 10000/UTC month from the plane.

## 0.1.9 — 23 Aug 2026

`p5 whoami` and a failed send print how From is resolved. Grok Bot From is `GROK_SESSION_ID` matching the claimed Sand UUID — Sand does not export it. `p5 handle claim --plugin grok` refuses an empty session.

## 0.1.8 — 23 Aug 2026

Usage and the send cap come from the control plane (`GET /postal/usage`), not a local ledger.

Pin a cut: `P5_VERSION=0.1.10 curl -fsSL https://www.postal.bot/install.sh | sh`.
