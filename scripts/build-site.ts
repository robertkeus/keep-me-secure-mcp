import { readFileSync, writeFileSync } from "node:fs";
import { INCIDENTS } from "../src/platforms.ts";
import { RUNTIME_ADVISORIES } from "../src/runtimes.ts";

const escape = (s: string) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
const sorted = [...INCIDENTS].sort((a, b) => b.date.localeCompare(a.date));

const entries = sorted
  .map(
    (i) => `<article>
<h2>${escape(i.platform)}</h2>
<p class="dim"><time datetime="${i.date}">${i.date}</time></p>
<p>${escape(i.summary)}</p>
<p class="dim">What to do: ${escape(i.action)}</p>
<p><a href="${escape(i.source)}">Source</a></p>
</article>`,
  )
  .join("\n\n");

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Developer platform security incidents | Keep Me Secure</title>
<meta name="description" content="Recent security incidents at developer and AI platforms, with what to do and a link to each company's statement.">
<link rel="canonical" href="https://keepmesecure.dev/incidents">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/style.css">
<meta name="color-scheme" content="light dark">
<script src="/main.js"></script>
</head>
<body>
<div class="page">

<header class="top">
<a class="brand" href="/">keep-me-secure</a>
<nav aria-label="Main">
<a href="https://github.com/robertkeus/keep-me-secure-mcp">github</a>
<button type="button" id="theme" class="btn" hidden>dark</button>
</nav>
</header>

<main>

<section class="hero">
<h1><span class="dim">$ </span>Platform incidents</h1>
<p class="lead">Security incidents at developer and AI platforms, with what to do. We list what each company has said, and link the source. This list isn't complete, so also check your platform's status page.</p>
<p class="dim">Rotating a secret means revoking it where it was issued. Deleting it from the platform doesn't invalidate it.</p>
</section>

${entries}

</main>

<footer class="bottom">
<span class="dim"><a href="/incidents.json">Data as JSON</a> · <a href="/changelog">Changelog</a> · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a></span>
<a href="/">Keep Me Secure</a>
</footer>

</div>
</body>
</html>
`;

const inline = (s: string) => escape(s).replace(/`([^`]+)`/g, "<code>$1</code>");
const releases = readFileSync("CHANGELOG.md", "utf8")
  .split(/^## /m)
  .slice(1)
  .map((block) => {
    const [title, ...lines] = block.trim().split("\n").filter(Boolean);
    const [, version, date] = title!.match(/^(\S+) \((.+)\)$/)!;
    const notes = lines.filter((l) => !l.startsWith("- ")).map((l) => `<p class="dim">${inline(l)}</p>`);
    const items = lines.filter((l) => l.startsWith("- ")).map((l) => `<li>${inline(l.slice(2))}</li>`);
    return `<article>
<h2>${escape(version!)}</h2>
<p class="dim"><time datetime="${escape(date!)}">${escape(date!)}</time></p>
${notes.join("\n")}
<ul class="plain">
${items.join("\n")}
</ul>
</article>`;
  })
  .join("\n\n");

const changelog = page
  .replace("<title>Developer platform security incidents | Keep Me Secure</title>", "<title>Changelog | Keep Me Secure</title>")
  .replace(/<meta name="description"[^>]*>/, '<meta name="description" content="What changed in each release of Keep Me Secure.">')
  .replace("https://keepmesecure.dev/incidents", "https://keepmesecure.dev/changelog")
  .replace(/<section class="hero">[\s\S]*<\/main>/, `<section class="hero">
<h1><span class="dim">$ </span>Changelog</h1>
<p class="lead">What changed in each release. To update the Claude Code plugin, run <code>claude plugin marketplace update keep-me-secure-mcp</code>, then <code>claude plugin update keep-me-secure@keep-me-secure-mcp</code>.</p>
</section>

${releases}

</main>`)
  .replace('<a href="/incidents.json">Data as JSON</a> · ', "");

writeFileSync("site/changelog.html", changelog);
writeFileSync("site/incidents.json", JSON.stringify(sorted, null, 2) + "\n");
writeFileSync("site/incidents.html", page);
writeFileSync("site/runtimes.json", JSON.stringify(RUNTIME_ADVISORIES, null, 2) + "\n");
