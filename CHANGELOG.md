# Changelog

## 1.6.0 (2026-11-06)

- Shows when your Node.js or PHP version stops getting support, and whether it's an LTS line
- Checks whether npm, pnpm, Yarn and Composer wait before installing new releases, and how to let an urgent fix through
- Flags direct dependencies that are deprecated, abandoned, or have had no release for two years
- Adds this changelog

## 1.5.0 (2026-11-06)

- Checks declared Node.js and PHP versions against known flaws, with exploited status taken live from CISA
- Adds the `check_runtime` tool
- Reports ranges and unreadable versions as unverified, never as clear
- Adds the privacy statement and terms

## 1.4.0 (2026-11-05)

- Warns about security incidents at platforms a project uses, such as Railway and Vercel
- Adds the `check_platform` tool and a public incidents page

## 1.3.2 (2026-11-05)

Security release, after independent audits.

- Malicious releases stay flagged when an ordinary advisory shares their alias
- Text from a repo can no longer reach the agent through the session-start message
- Advisory ids and versions must match strict patterns, and cache keys can't choose a file path
- Anything that can't be read gives unknown, never no
- Replaces the YAML library with a line-based pnpm reader
- Fixes slow parsing, IPv6 rate limit keys and chunked request limits
- Pins workflows to commits and the base image to a digest

## 1.3.1 (2026-11-05)

- Skips lockfiles in test and example folders, and lists them in the result
- Reports a package found in several lockfiles once, and lists the five worst advisories, which makes results much smaller

## 1.3.0 (2026-11-05)

- Adds the Claude Code plugin, with a daily check at session start and no Docker needed

## 1.2.0 (2026-11-05)

- Adds the hosted server at mcp.keepmesecure.dev, and the `check_packages` tool
- Adds self-hosting and the website

## 1.1.1 (2026-11-05)

- Moves to Node.js 26 LTS
- Lists the project on the MCP Registry

## 1.1.0 (2026-11-05)

- Adds Go, Rust, Ruby, Java and .NET
- Broad questions like "Is my stack secure?" now trigger a full check

## 1.0.0 (2026-11-04)

- First stable release, with retries and pinned installs

## 0.1.0 (2026-11-04)

- First release: checks PHP, JavaScript and Python lockfiles against public advisories
