import fs from "fs";
import path from "path";

function htmlPath(file: string): string {
  const bundled = path.join(process.cwd(), "content", file);
  if (fs.existsSync(bundled)) return bundled;
  return path.join(process.cwd(), "..", "web", file);
}

export function loadHtml(file: string): { css: string; body: string } {
  const raw = fs.readFileSync(htmlPath(file), "utf8");
  const cssMatch = raw.match(/<style>([\s\S]*?)<\/style>/);
  const bodyMatch = raw.match(/<body>([\s\S]*)<\/body>/);
  let body = bodyMatch ? bodyMatch[1] : "";
  body = body.replace(/<script[\s\S]*?<\/script>/gi, "");
  return { css: cssMatch ? cssMatch[1] : "", body: body.trim() };
}
