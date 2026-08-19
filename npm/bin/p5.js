#!/usr/bin/env node
"use strict";

process.stderr.write(
  [
    "p5: @alakazamlabs/postal has not published platform binaries yet.",
    "This package is a thin fetcher stub, not a JS rewrite.",
    "",
    "Until postal.bot DNS / GitHub release assets exist:",
    "  P5_LOCAL=1 ./install/install.sh",
    "  cargo install --path crates/p5",
    "",
  ].join("\n")
);
process.exit(1);
