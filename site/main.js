const root = document.documentElement;
root.classList.add("js");

const saved = () => {
  try {
    return localStorage.getItem("theme");
  } catch {
    return null;
  }
};
if (saved()) root.dataset.theme = saved();

const isDark = () => root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;

addEventListener("DOMContentLoaded", () => {
  const theme = document.getElementById("theme");
  const label = () => {
    theme.textContent = isDark() ? "light" : "dark";
    theme.setAttribute("aria-label", `Switch to ${theme.textContent} mode`);
  };
  theme.hidden = false;
  label();
  theme.addEventListener("click", () => {
    root.dataset.theme = isDark() ? "light" : "dark";
    try {
      localStorage.setItem("theme", root.dataset.theme);
    } catch {}
    label();
  });

  const tabs = [...document.querySelectorAll("[data-tab]")];
  const show = (name) => {
    for (const t of tabs) t.setAttribute("aria-pressed", String(t.dataset.tab === name));
    for (const p of document.querySelectorAll("[data-panel]")) p.classList.toggle("on", p.dataset.panel === name);
  };
  document.querySelector(".tabs").hidden = false;
  for (const t of tabs) t.addEventListener("click", () => show(t.dataset.tab));
  show("claude");

  for (const button of document.querySelectorAll(".copy")) {
    button.hidden = false;
    button.addEventListener("click", async () => {
      await navigator.clipboard.writeText(button.parentElement.querySelector("[data-copy]").textContent);
      button.textContent = "copied";
      setTimeout(() => (button.textContent = "copy"), 1500);
    });
  }
});
