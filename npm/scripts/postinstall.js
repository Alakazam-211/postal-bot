#!/usr/bin/env node
"use strict";

// Stub: real postinstall will fetch p5-<os>-<arch>, check SHA256SUMS,
// and minisign-verify against https://postal.bot/keys/minisign.pub.
process.stdout.write(
  [
    "@alakazamlabs/postal: not published yet.",
    "This package will fetch a platform p5 binary (not a JS rewrite).",
    "postal.bot DNS is not live; no release tarball to download.",
    "Until then: P5_LOCAL=1 ./install/install.sh   or   cargo install --path crates/p5",
    "",
  ].join("\n")
);
