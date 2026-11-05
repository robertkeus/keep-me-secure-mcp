#!/usr/bin/env python3
"""Generates the animated README terminal: python3 assets/hero.py

GitHub strips scripts from READMEs, so this is CSS animation inside an SVG.
Every element's normal state is its final state, which is what viewers that
don't animate, and people who prefer reduced motion, see.
"""
from pathlib import Path

LOOP = 12000
THEMES = {
    "light": {"bg": "#ffffff", "fg": "#000000", "dim": "#525252"},
    "dark": {"bg": "#0a0a0a", "fg": "#fafafa", "dim": "#a3a3a3"},
}
QUESTION = "Is my stack secure?"
ROWS = [
    ("php", "api/composer.lock", 39, 2000),
    ("npm", "web/package-lock.json", 51, 2500),
    ("go", "worker/go.mod", 15, 3000),
    ("java", "svc/gradle.lockfile", 6, 3400),
]
FINDINGS = [
    ("NOW", "log4j-core 2.14.1 → 2.25.4", "critical, exploited", 4900),
    ("NOW", "spring-beans 5.3.0 → 5.3.20", "critical, exploited", 5300),
    ("TODAY", "guzzlehttp/guzzle 7.4.0 → 7.15.2", "high", 5700),
]
CHAR = 12
TEXT_X = 44


def pct(ms):
    return f"{ms / LOOP * 100:.2f}"


class Motion:
    """Collects one keyframes rule per distinct timing."""

    def __init__(self):
        self.rules = {}

    def show(self, at, until=None):
        name = f"s{at}" + (f"-{until}" if until else "")
        end = pct(until) if until else "97"
        self.rules[name] = (
            f"@keyframes {name}{{0%,{pct(at)}%{{opacity:0}}"
            f"{float(pct(at)) + 0.01:.2f}%,{end}%{{opacity:1}}"
            f"{float(end) + 0.01:.2f}%,100%{{opacity:0}}}}"
        )
        return f'style="animation:{name} {LOOP}ms linear infinite"'

    def grow(self, at, length=600):
        name = f"g{at}"
        self.rules[name] = (
            f"@keyframes {name}{{0%,{pct(at)}%{{transform:scaleX(0)}}"
            f"{pct(at + length)}%,97%{{transform:scaleX(1)}}"
            f"97.01%,100%{{transform:scaleX(0)}}}}"
        )
        return f'class="bar" style="animation:{name} {LOOP}ms linear infinite"'

    def caret(self):
        travel = len(QUESTION) * CHAR
        self.rules["caret"] = (
            f"@keyframes caret{{0%,{pct(400)}%{{transform:translateX(-{travel}px)}}"
            f"{pct(1600)}%,100%{{transform:translateX(0)}}}}"
        )
        return (
            f'style="animation:caret {LOOP}ms steps({len(QUESTION)},end) infinite"'
        )


def render(theme):
    c = THEMES[theme]
    m = Motion()
    out = []

    def text(x, y, value, fill="fg", extra=""):
        out.append(f'<text x="{x}" y="{y}" fill="{c[fill]}" {extra}>{value}</text>')

    out.append(f'<rect x="1" y="1" width="878" height="458" fill="{c["bg"]}" stroke="{c["fg"]}" stroke-width="2"/>')
    out.append(f'<line x1="0" y1="38" x2="880" y2="38" stroke="{c["fg"]}" stroke-width="2"/>')
    text(16, 25, "keep-me-secure", extra='font-weight="700"')
    text(864, 25, "ready", "dim", f'text-anchor="end" {m.show(0, 1900)}')
    text(864, 25, "checking…", "dim", f'text-anchor="end" {m.show(1900, 4400)}')
    text(864, 25, "111 packages checked", "dim", f'text-anchor="end" {m.show(4400)}')

    text(20, 82, "&gt;", "dim", 'font-size="20"')
    for i, char in enumerate(QUESTION):
        if char != " ":
            at = 400 + i * 1200 // len(QUESTION)
            text(TEXT_X + i * CHAR, 82, char, extra=f'font-size="20" font-weight="700" {m.show(at)}')
    caret_x = TEXT_X + len(QUESTION) * CHAR + 3
    out.append(f'<g {m.caret()}><rect class="blink" x="{caret_x}" y="65" width="11" height="21" fill="{c["fg"]}"/></g>')

    for i, (lang, file, total, at) in enumerate(ROWS):
        y = 118 + i * 22
        out.append(f"<g {m.show(at)}>")
        text(20, y, lang, extra='font-weight="700"')
        text(88, y, file, "dim")
        out.append(f'<rect x="296" y="{y - 10}" width="504" height="10" fill="none" stroke="{c["fg"]}"/>')
        out.append(f'<rect {m.grow(at)} x="296" y="{y - 10}" width="504" height="10" fill="{c["fg"]}"/>')
        out.append("</g>")
        text(860, y, total, extra=f'text-anchor="end" {m.show(at + 600)}')

    out.append(f"<g {m.show(4400)}>")
    out.append(f'<rect x="20" y="209" width="44" height="24" fill="{c["fg"]}"/>')
    text(42, 226, "NO", "bg", 'text-anchor="middle" font-weight="700"')
    text(76, 226, "18 of 111 packages need patching", extra='font-weight="700"')
    out.append("</g>")

    for i, (when, name, note, at) in enumerate(FINDINGS):
        y = 262 + i * 26
        solid = when == "NOW"
        out.append(f"<g {m.show(at)}>")
        out.append(f'<rect x="20.5" y="{y - 15.5}" width="64" height="21" fill="{c["fg"] if solid else "none"}" stroke="{c["fg"]}"/>')
        text(52, y, when, "bg" if solid else "fg", 'text-anchor="middle" font-size="12" font-weight="700"')
        text(96, y, name)
        text(860, y, note, "dim", 'text-anchor="end"')
        out.append("</g>")

    text(20, 432, "Want me to run the upgrades? Nothing changes without your OK.", "dim", m.show(6300))

    style = (
        "svg{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;font-size:14px}"
        ".bar{transform-box:fill-box;transform-origin:left}"
        ".blink{animation:blink 1s steps(2,jump-none) infinite}"
        "@keyframes blink{0%{opacity:1}100%{opacity:0}}"
        + "".join(m.rules.values())
        + "@media (prefers-reduced-motion:reduce){*{animation:none!important}}"
    )
    label = (
        "A terminal. Someone asks: Is my stack secure? It scans 111 packages across PHP, npm, Go and Java, "
        "then answers no: 18 packages need patching, starting with log4j-core and spring-beans."
    )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="880" height="460" viewBox="0 0 880 460" role="img" '
        f'aria-label="{label}"><title>{label}</title><style>{style}</style>' + "".join(out) + "</svg>\n"
    )


for name in THEMES:
    Path(__file__).with_name(f"hero-{name}.svg").write_text(render(name), encoding="utf-8")
