import type { Metadata } from "next";
import { loadHtml } from "@/lib/load-html";

export const metadata: Metadata = {
  title: "Postal docs — last mile",
  description:
    "Postal last-mile plugins: where an agent lives, claim / knock / resume, and how to add a host.",
  alternates: {
    canonical: "/docs",
    types: { "text/markdown": "/docs.md" },
  },
};

export default function DocsPage() {
  const { css, body } = loadHtml("docs.html");
  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: css }} />
      <div dangerouslySetInnerHTML={{ __html: body }} />
    </>
  );
}
