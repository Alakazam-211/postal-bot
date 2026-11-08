import type { Metadata } from "next";
import { loadHtml } from "@/lib/load-html";

export const metadata: Metadata = {
  title: "What’s new — Postal Bot",
  description:
    "Postal Bot public alpha changelog. Current p5 is 0.1.10.",
  alternates: {
    canonical: "/whats-new",
    types: { "text/markdown": "/whats-new.md" },
  },
};

export default function WhatsNewPage() {
  const { css, body } = loadHtml("whats-new.html");
  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: css }} />
      <div dangerouslySetInnerHTML={{ __html: body }} />
    </>
  );
}
