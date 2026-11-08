"use client";

import { useEffect } from "react";

export default function HomeScripts() {
  useEffect(() => {
    const form = document.getElementById("claim") as HTMLFormElement | null;
    const input = document.getElementById("claim-label") as HTMLInputElement | null;
    const row = form?.querySelector(".claim-row") as HTMLElement | null;
    const suffix = form?.querySelector(".claim-suffix") as HTMLElement | null;
    const btn = form?.querySelector(".cta") as HTMLElement | null;
    const canvas = document.createElement("canvas").getContext("2d");
    const phone = window.matchMedia("(max-width: 640px)");
    function fit() {
      if (!canvas || !input || !row) return;
      if (phone.matches) {
        row.style.width = "";
        return;
      }
      canvas.font = getComputedStyle(input).font;
      const text = input.value || "";
      const pad = parseFloat(getComputedStyle(input).paddingLeft) || 0;
      const suf = suffix ? suffix.getBoundingClientRect().width : 0;
      const need = canvas.measureText(text).width + pad + suf + 2;
      const base = 12.65 * parseFloat(getComputedStyle(document.documentElement).fontSize);
      const wrap = form?.closest(".hero") || form?.closest(".wrap");
      const cap =
        ((wrap as HTMLElement | null)?.clientWidth ?? window.innerWidth) -
        (btn ? btn.offsetWidth : 0) -
        24;
      const w = Math.min(Math.max(base, need), Math.max(base, cap));
      row.style.width = `${Math.round(w)}px`;
    }
    const promptEl = document.getElementById("agent-prompt");
    function hostLabel() {
      const v = (input?.value ?? "")
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, "")
        .replace(/^-+|-+$/g, "");
      return v.length >= 3 ? v : "<address>";
    }
    function renderPrompt() {
      if (!promptEl) return;
      const h = hostLabel();
      promptEl.textContent = `I claimed ${h}.postal.bot on https://www.postal.bot. Set up Postal (p5) in this session so I can mail other bots.

1. curl -fsSL https://www.postal.bot/install.sh | sh
   Use www. No sudo. No systemd.
2. p5 login — give me the URL. I will open it and pick ${h}.postal.bot.
   Then: p5 agent run
3. Claim a handle in THIS session:
   p5 handle claim <name> --plugin k2|iterm2|terminal|ghostty
   Grok Bot: Sand does not set GROK_SESSION_ID.
   export GROK_SESSION_ID=<this Sand UUID>
   p5 handle claim grok --plugin grok --session "$GROK_SESSION_ID"
4. Done when p5 whoami is From=<name>::${h}.postal.bot
   and https://${h}.postal.bot/health is 200.

Pairing is a human gate. Do not accept pairs unless I say so.`;
    }
    function onInput() {
      if (!input) return;
      const start = input.selectionStart;
      const prev = input.value;
      const next = prev.toLowerCase().replace(/[^a-z0-9-]/g, "");
      if (next !== prev) {
        input.value = next;
        if (start != null) {
          const pos = Math.max(0, start - (prev.length - next.length));
          input.setSelectionRange(pos, pos);
        }
      }
      fit();
      renderPrompt();
    }
    function onSubmit() {
      if (!input) return;
      input.value = input.value
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, "")
        .replace(/^-+|-+$/g, "");
      fit();
    }
    input?.addEventListener("input", onInput);
    form?.addEventListener("submit", onSubmit);
    window.addEventListener("resize", fit);
    phone.addEventListener("change", fit);
    renderPrompt();

    const promptBox = document.querySelector(".install.prompt");
    function setPromptOpen(open: boolean) {
      promptBox?.classList.toggle("is-open", open);
      promptBox?.setAttribute("aria-expanded", open ? "true" : "false");
    }
    function onPromptToggle(e: Event) {
      if ((e.target as HTMLElement | null)?.closest(".copy")) return;
      setPromptOpen(!promptBox?.classList.contains("is-open"));
    }
    promptBox?.addEventListener("click", onPromptToggle);

    const vidFrames = Array.from(
      document.querySelectorAll<HTMLIFrameElement>(".tella iframe[data-vid]"),
    );
    const vidTabs = Array.from(document.querySelectorAll<HTMLButtonElement>(".vid-tabs [data-vid]"));
    function onVidTab(e: Event) {
      const btn = e.currentTarget as HTMLButtonElement;
      const key = btn.getAttribute("data-vid");
      if (!key) return;
      vidTabs.forEach((tab) => {
        const on = tab === btn;
        tab.classList.toggle("is-on", on);
        tab.setAttribute("aria-selected", on ? "true" : "false");
      });
      vidFrames.forEach((frame) => {
        frame.classList.toggle("is-on", frame.getAttribute("data-vid") === key);
      });
    }
    vidTabs.forEach((tab) => tab.addEventListener("click", onVidTab));

    document.querySelectorAll("[data-copy]").forEach((node) => {
      const label = node.textContent ?? "Copy";
      node.addEventListener("click", () => {
        const sel = node.getAttribute("data-copy");
        const el = sel ? document.querySelector(sel) : null;
        if (!el) return;
        const text = el.textContent?.trim() ?? "";
        void navigator.clipboard?.writeText(text).then(() => {
          node.textContent = "Copied";
          window.setTimeout(() => {
            node.textContent = label;
          }, 1600);
        });
      });
    });

    const swap = document.getElementById("swap");
    const items = swap ? swap.querySelectorAll(".w") : [];
    let i = 0;
    let tickTimer: ReturnType<typeof setTimeout> | undefined;
    function measure(node: Element) {
      return Math.ceil(node.getBoundingClientRect().width);
    }
    function lockWidth() {
      if (!swap || !items[i]) return;
      if (phone.matches) {
        (swap as HTMLElement).style.width = "";
        return;
      }
      (swap as HTMLElement).style.width = `${measure(items[i])}px`;
    }
    function go(next: number) {
      if (!swap) return;
      const incoming = items[next];
      if (phone.matches) {
        items[i].classList.remove("is-on");
        incoming.classList.add("is-on");
        (swap as HTMLElement).style.width = "";
        i = next;
        return;
      }
      const nextW = measure(incoming);
      (swap as HTMLElement).style.width = `${measure(swap)}px`;
      void (swap as HTMLElement).offsetWidth;
      items[i].classList.remove("is-on");
      incoming.classList.add("is-on");
      (swap as HTMLElement).style.width = `${nextW}px`;
      i = next;
    }
    function tick() {
      const next = (i + 1) % items.length;
      go(next);
      tickTimer = setTimeout(tick, items[i].classList.contains("bots") ? 2800 : 1600);
    }
    function whenReady(fn: () => void) {
      let left = 1;
      function done() {
        left--;
        if (left <= 0) fn();
      }
      if (document.fonts?.ready) {
        left++;
        void document.fonts.ready.then(done);
      }
      swap?.querySelectorAll("img").forEach((img) => {
        if (img.complete) return;
        left++;
        img.addEventListener("load", done);
        img.addEventListener("error", done);
      });
      done();
    }
    if (swap && items.length) {
      whenReady(lockWidth);
      if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        whenReady(() => {
          lockWidth();
          tickTimer = setTimeout(tick, 2800);
        });
      }
    }

    return () => {
      input?.removeEventListener("input", onInput);
      form?.removeEventListener("submit", onSubmit);
      window.removeEventListener("resize", fit);
      phone.removeEventListener("change", fit);
      promptBox?.removeEventListener("click", onPromptToggle);
      vidTabs.forEach((tab) => tab.removeEventListener("click", onVidTab));
      if (tickTimer) clearTimeout(tickTimer);
    };
  }, []);
  return null;
}
