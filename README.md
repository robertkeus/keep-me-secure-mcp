# keep-me-secure-mcp

An MCP server that tells your coding agent whether your installed packages need patching.

Every day when you start coding, it checks every package in your lockfiles against public security advisories. You can also ask your agent directly: "Is my stack secure?" or "Do I need to patch any of my PHP packages?" The answer is yes, no or unknown, with advice on what to do.

| Language | Reads |
|---|---|
| PHP | `composer.lock` |
| JavaScript | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| Python | `requirements*.txt`, `poetry.lock`, `uv.lock` |
| Go | `go.mod` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| Java, Kotlin | `gradle.lockfile` |
| .NET | `packages.lock.json` |

Maven has no lockfile, so `pom.xml` projects return `unknown`. So do Gradle and .NET projects with locking turned off.

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

The config pins the image version, so a new release never reaches your project unannounced. Run the command again to upgrade.

An MCP server can't start itself, so the hook and the `AGENTS.md` rule are what make the check happen each day.

### Other agents

`init` only configures Claude Code directly, but the `AGENTS.md` rule works for other agents too. Keep it: in testing, Codex only called the tool when that rule was present.

Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.keep-me-secure]
command = "sh"
args = ["-c", "exec docker run -i --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges -v \"$PWD:/workspace:ro\" -v kms-cache:/cache ghcr.io/robertkeus/keep-me-secure-mcp:latest"]
```

opencode, in `opencode.json`:

```json
{
  "mcp": {
    "keep-me-secure": {
      "type": "local",
      "command": ["sh", "-c", "exec docker run -i --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges -v \"$PWD:/workspace:ro\" -v kms-cache:/cache ghcr.io/robertkeus/keep-me-secure-mcp:latest"],
      "enabled": true
    }
  }
}
```

Tested with Claude Code, Codex and opencode. Cursor and other MCP clients should work with the same command, but haven't been tested. The agent must start in your project folder, because `$PWD` is what gets scanned.

## Tools

| Tool | Question it answers | Input |
|---|---|---|
| `check_project` | Is my stack secure? Do I need to patch anything? | `ecosystem`, `path` and `refresh`, all optional |
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
  "coverage": { "scanned": 2, "by_ecosystem": { "Packagist": 2 }, "private": ["acme/internal"], "unchecked": [] }
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
- Go, Java and .NET lockfiles don't show which registry a package came from, so private package names in those ecosystems are sent to OSV. Local `replace` paths in `go.mod` are the exception.
- Results are cached per day in the `kms-cache` Docker volume. A lockfile change triggers a new check.

## Security

- The container gets your project read-only, runs as a non-root user with a read-only filesystem and no capabilities.
- It never installs or upgrades anything. The agent proposes a command and you approve it.
- Images are published with provenance and an SBOM.
- Advisory text is shortened, flattened and labelled `summary_untrusted`, because it's third-party text that reaches your agent. Advice and commands are built only from validated package names and versions.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Limits

- It covers third-party packages only, not language runtimes, OS packages, Docker base images or your own code. A `no` doesn't mean your whole stack is secure.
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
