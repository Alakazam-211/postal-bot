import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // postal-bot owns www.postal.bot and proxies the account pages from k2.dev
  // (K2 Web plane). Our own scripts load from postal-bot.vercel.app so that
  // www.postal.bot/_next/* is free to carry k2.dev's chunks for those pages.
  assetPrefix:
    process.env.VERCEL_ENV === "production"
      ? "https://postal-bot.vercel.app"
      : undefined,
  async redirects() {
    return [
      { source: "/progress", destination: "/whats-new", permanent: true },
      { source: "/progress.html", destination: "/whats-new", permanent: true },
      // Apex is often aliased to this project. Send humans to www (k2-dev-web).
      {
        source: "/",
        has: [{ type: "host", value: "postal.bot" }],
        destination: "https://www.postal.bot/",
        permanent: true,
      },
      {
        source: "/:path*",
        has: [{ type: "host", value: "postal.bot" }],
        destination: "https://www.postal.bot/:path*",
        permanent: true,
      },
    ];
  },
  async rewrites() {
    // A rewrite to k2.dev arrives with Host k2.dev, so its postal-host
    // middleware never runs: point straight at the /p/* pages (K2 Web, PR #41).
    const PLANE = "https://k2.dev";
    const pages: Array<[string, string]> = [
      ["/login", "/p/login"],
      ["/signup", "/p/signup"],
      ["/account", "/p/account"],
      ["/dashboard", "/p/account"],
      ["/forgot-password", "/p/forgot-password"],
      ["/cli", "/p/cli/approve"],
      ["/cli/approve", "/p/cli/approve"],
    ];
    return {
      beforeFiles: [
        ...pages.map(([source, path]) => ({ source, destination: `${PLANE}${path}` })),
        { source: "/cli/:path*", destination: `${PLANE}/p/cli/:path*` },
        { source: "/p/:path*", destination: `${PLANE}/p/:path*` },
        { source: "/postal/:path*", destination: `${PLANE}/postal/:path*` },
        { source: "/api/:path*", destination: `${PLANE}/api/:path*` },
        { source: "/auth/:path*", destination: `${PLANE}/auth/:path*` },
        { source: "/reset-password", destination: `${PLANE}/reset-password` },
        // The proxied pages ask for /_next/* on our host. Only on www, where
        // our own assets come from assetPrefix instead.
        {
          source: "/_next/:path*",
          has: [{ type: "host", value: "www.postal.bot" }],
          destination: `${PLANE}/_next/:path*`,
        },
      ],
    };
  },
  async headers() {
    const agentCors = [
      { key: "Access-Control-Allow-Origin", value: "*" },
      { key: "Access-Control-Allow-Methods", value: "GET, OPTIONS" },
      { key: "Cache-Control", value: "public, max-age=3600" },
    ];
    const describedBy = {
      key: "Link",
      value: '</llms.txt>; rel="describedby"',
    };
    return [
      {
        source: "/install.sh",
        headers: [
          { key: "Content-Type", value: "text/plain; charset=utf-8" },
          { key: "Cache-Control", value: "no-cache" },
        ],
      },
      {
        source: "/grokbot-setup.sh",
        headers: [
          { key: "Content-Type", value: "text/plain; charset=utf-8" },
          { key: "Cache-Control", value: "no-cache" },
        ],
      },
      {
        source: "/releases/:path*",
        headers: [{ key: "Cache-Control", value: "public, max-age=60" }],
      },
      {
        source: "/robots.txt",
        headers: [
          { key: "Content-Type", value: "text/plain; charset=utf-8" },
          ...agentCors,
        ],
      },
      {
        source: "/llms.txt",
        headers: [
          { key: "Content-Type", value: "text/markdown; charset=utf-8" },
          ...agentCors,
        ],
      },
      {
        source: "/llms-full.txt",
        headers: [
          { key: "Content-Type", value: "text/markdown; charset=utf-8" },
          ...agentCors,
        ],
      },
      {
        source: "/agents.txt",
        headers: [
          { key: "Content-Type", value: "text/plain; charset=utf-8" },
          ...agentCors,
        ],
      },
      {
        source: "/agents.json",
        headers: [
          { key: "Content-Type", value: "application/json; charset=utf-8" },
          ...agentCors,
        ],
      },
      {
        source: "/.well-known/agents.txt",
        headers: [
          { key: "Content-Type", value: "text/plain; charset=utf-8" },
          ...agentCors,
        ],
      },
      {
        source: "/.well-known/agents.json",
        headers: [
          { key: "Content-Type", value: "application/json; charset=utf-8" },
          ...agentCors,
        ],
      },
      {
        source: "/index.md",
        headers: [
          { key: "Content-Type", value: "text/markdown; charset=utf-8" },
          describedBy,
          ...agentCors,
        ],
      },
      {
        source: "/docs.md",
        headers: [
          { key: "Content-Type", value: "text/markdown; charset=utf-8" },
          describedBy,
          ...agentCors,
        ],
      },
      {
        source: "/whats-new.md",
        headers: [
          { key: "Content-Type", value: "text/markdown; charset=utf-8" },
          describedBy,
          ...agentCors,
        ],
      },
      {
        source: "/privacy.md",
        headers: [
          { key: "Content-Type", value: "text/markdown; charset=utf-8" },
          describedBy,
          ...agentCors,
        ],
      },
      {
        source: "/skills/:path*",
        headers: [
          { key: "Content-Type", value: "text/markdown; charset=utf-8" },
          ...agentCors,
        ],
      },
      {
        source: "/:path*",
        headers: [describedBy],
      },
    ];
  },
};

export default nextConfig;
