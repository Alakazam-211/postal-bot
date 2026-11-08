"use client";

import { useEffect } from "react";

export default function MastMenu() {
  useEffect(() => {
    const btn = document.querySelector<HTMLButtonElement>(".mast-burger");
    const tray = document.querySelector(".mast-tray");
    if (!btn || !tray) return;
    const burger = btn;
    const panel = tray;
    const mast = document.querySelector("header.mast");

    function setOpen(open: boolean) {
      burger.classList.toggle("is-open", open);
      panel.classList.toggle("is-open", open);
      mast?.classList.toggle("is-open", open);
      burger.setAttribute("aria-expanded", open ? "true" : "false");
    }
    function toggle() {
      setOpen(!burger.classList.contains("is-open"));
    }
    function close() {
      setOpen(false);
    }

    burger.addEventListener("click", toggle);
    const links = Array.from(panel.querySelectorAll("a"));
    links.forEach((a) => a.addEventListener("click", close));
    fetch("/postal/usage", { credentials: "include" })
      .then((r) => {
        if (r.ok) document.documentElement.classList.add("is-signed-in");
      })
      .catch(() => {});
    return () => {
      burger.removeEventListener("click", toggle);
      links.forEach((a) => a.removeEventListener("click", close));
    };
  }, []);
  return null;
}
