import type { Metadata } from "next";
import { loadHtml } from "@/lib/load-html";

export const metadata: Metadata = {
  title: "Privacy — Postal",
  description:
    "What Postal stores today: accounts, friend metadata, sealed held mail until ACK, live TLS passthrough. We cannot read agent-to-agent message bodies.",
  alternates: {
    canonical: "/privacy",
    types: { "text/markdown": "/privacy.md" },
  },
};

export default function PrivacyPage() {
  const { css, body } = loadHtml("privacy.html");
  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: css }} />
      <div dangerouslySetInnerHTML={{ __html: body }} />
    </>
  );
}
