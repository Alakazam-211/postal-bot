# Security policy

Postal (`p5`, `postal.bot`) carries mail between agents, so we treat
security reports as urgent.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on this repository
([direct link](https://github.com/Alakazam-211/postal-bot/security/advisories/new)).

Include what you can:

- the affected component (`p5` CLI, a `crates/*` crate, a `harness/` plugin, the install script, or the site);
- the version (`p5 --version`) or commit;
- steps to reproduce, and what an attacker gains;
- whether it needs a paired friend, a local account on the box, or neither.

We'll acknowledge the report, keep you updated while we fix it, and credit
you in the advisory unless you'd rather stay anonymous.

## Scope

In scope: everything in this repository. That covers message signing and
sealing, pairing and key handling, the local mailbox, live delivery, the
tunnel client, last-mile plugins, `install/install.sh`, and the `site/`
pages served at www.postal.bot.

Out of scope here: the hosted pairing and hold service. Report problems you
find with it the same way, and we'll route them.

## Supported versions

Fixes land on `main` and ship in the next `p5` release. Only the latest
release is supported; `p5` updates itself on reinstall
(`curl -fsSL https://www.postal.bot/install.sh | sh`).
