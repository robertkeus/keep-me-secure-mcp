# keep-me-secure-mcp

An MCP server that tells your coding agent whether your installed packages need patching.

Every day when you start coding, it checks your lockfiles against public security advisories. You can also ask your agent directly: "Do I need to patch any of my PHP packages?" The answer is yes, no or unknown, with advice on what to do.

Supports PHP (Composer), JavaScript (npm, pnpm, Yarn) and Python (pip, Poetry, uv).

## Setup

You need Docker. Run this in your project:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" ghcr.io/robertkeus/keep-me-secure-mcp:latest init
```

This adds or updates three files:

| File | Purpose |
|---|---|
| `.mcp.json` | Registers the MCP server |
| `.claude/settings.json` | Claude Code hook that runs the check when a session starts |
| `AGENTS.md` | Tells other agents to run the check at the start of a session |

An MCP server can't start itself, so the hook and the `AGENTS.md` rule are what make the check happen each day. Agents that use their own config file need the `.mcp.json` entry copied there.

## Tools

| Tool | Question it answers | Input |
|---|---|---|
| `check_project` | Do I need to patch anything? | `ecosystem`, `path` and `refresh`, all optional |
| `check_package` | Is this exact version safe? | `ecosystem`, `name`, `version` |

Example result, shortened:

```json
{
  "verdict": "yes",
  "urgency": "today",
  "findings": [{
    "package": "guzzlehttp/guzzle",
    "installed": "7.4.0",
    "fixed_in": "7.15.2",
    "direct": true,
    "severity": "HIGH",
    "exploited": false,
    "advice": "Upgrade guzzlehttp/guzzle to 7.15.2 or later.",
    "command": "composer update guzzlehttp/guzzle --with-dependencies"
  }],
  "coverage": { "scanned": 2, "private": ["acme/internal"], "unchecked": [] }
}
```

### Verdicts

- `yes`: at least one installed version has a known advisory.
- `no`: every package was checked and none has a known advisory.
- `unknown`: the check was incomplete, for example a missing lockfile, an unsupported ecosystem or a failed lookup. `coverage.unchecked` says why. Don't read this as safe.

### Urgency

- `now`: a malicious package, or a vulnerability in the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list of actively exploited issues.
- `today`: critical, high or unrated severity.
- `this_week`: everything else.

For malicious packages, upgrading isn't enough. The advice is to remove the package, rotate secrets and check for changes it may have made.

## Data and privacy

- Names and versions of public packages are sent to [OSV.dev](https://osv.dev). When something is affected, CVE ids go to [FIRST EPSS](https://www.first.org/epss/). The CISA KEV feed is downloaded.
- Packages from private registries, git or local paths are not sent anywhere. They're listed in `coverage.private` and aren't checked.
- Results are cached per day in the `kms-cache` Docker volume. A lockfile change triggers a new check.

## Security

- The container gets your project read-only, runs as a non-root user with a read-only filesystem and no capabilities.
- It never installs or upgrades anything. The agent proposes a command and you approve it.
- Advisory text is shortened, flattened and labelled `summary_untrusted`, because it's third-party text that reaches your agent. Advice and commands are built only from validated package names and versions.

## Limits

- A `no` means no known issue at `checked_at`. OSV can lag behind an incident by a few hours.
- It doesn't check whether your code actually reaches the vulnerable function.
- For a transitive dependency, the fix may have to come from upgrading its parent package.

## Development

```bash
docker compose build
```

```bash
docker compose run --rm test
```

```bash
docker compose run --rm -e LIVE=1 test
```

To try it on a vulnerable project:

```bash
PROJECT_DIR=./test/fixtures/php docker compose run --rm -T mcp check
```

Pushing a `v*` tag publishes the image to GHCR.
