import { loadHtml } from "@/lib/load-html";
import HomeScripts from "@/app/HomeScripts";

export default function HomePage() {
  const { css, body } = loadHtml("index.html");
  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: css }} />
      <div dangerouslySetInnerHTML={{ __html: body }} />
      <HomeScripts />
    </>
  );
}
