# Torana for Claude Code

Security skills for [Claude Code](https://claude.com/claude-code). Scan your code for
vulnerabilities, work out which findings actually matter, and push the results to your
Torana tenant — all from the terminal you already work in.

```
/plugin marketplace add Torana-Inc/torana-skills
/plugin install torana@torana-skills
```

Then, in any repository:

```
cd ~/code/your-service
claude
> scan this repo for vulnerabilities
```

---

## Requirements

| | Why |
|---|---|
| **Claude Code** v2.1+ | The runtime. `claude --version` |
| **git** | You install from a git repository, and the skills read your repo's remote |
| **Python 3.12+** *or* [`uv`](https://docs.astral.sh/uv/) | The `torana` CLI installs into its own virtualenv at `~/.torana-venv`. If you have `uv`, it fetches a suitable Python itself |
| **Network access** to `pypi.org`, `github.com`, `api.osv.dev`, and your Torana tenant | Dependency install, scanner downloads, the public vulnerability database, and pushing results |
| *(optional)* [`gh`](https://cli.github.com/) | Only for the skills that open pull requests or read repository metadata |

**You do not need to create a virtualenv, install the `torana` CLI, or install any
scanner yourself.** The plugin ships the CLI, and installs it — plus the scanners it
needs — the first time you use a skill that requires them. Everything it installs lives
under your home directory (`~/.torana-venv`, `~/.torana/`) and nothing is installed
system-wide.

## What you get

| Skill | What it does |
|---|---|
| **scan** | SAST, dependency (SCA), IaC, secrets and container scanning. Produces a standard SARIF 2.1.0 document; optionally pushes to Torana |
| **asset-inventory** | Records what a repository *is* — owner, criticality, environment, data sensitivity. The context no scanner can infer |
| **entity-graph** | Reads your deployment manifests (Compose, Kustomize, Helm, Kubernetes) to map what the repo deploys and what is internet-facing |
| **impact** | For one finding: is it reachable and exposed, what does fixing it ripple into, and what does a version bump add or remove |
| **pentest** | Proves whether a finding is actually exploitable in a running deployment, using benign payloads and with your approval before anything is fired |
| **alert-triage** | Works the alerts assigned to you: classify, patch on a branch, open a real pull request |
| **vm** | Vulnerability-management and AppSec advice grounded in your own data — and builds programs, dashboards and alert routes on Torana |
| **build** | Builds and deploys a Torana program from a plain-English description |
| **text-to-sql** | Turns a question about your security data into SQL that will actually return rows |
| **supply-graph** | Answers "why is this dashboard panel empty?" and "what breaks if we disconnect this integration?" |
| **(core)** | CLI bootstrap, authentication, and the reference material the other skills rely on |

You don't invoke these by name. Describe what you want — *"scan this repo"*, *"is this CVE
exploitable?"*, *"what should we fix first?"* — and Claude loads the right one. To call one
explicitly, use `/torana:<name>`, e.g. `/torana:torana-scan`.

## Scanning without a Torana account

The scan skill has two modes and **defaults to the local one**: it walks your code, prints
a findings table, and writes `scan.sarif` in the repository. Nothing leaves your machine
except dependency lookups against the public [OSV.dev](https://osv.dev) database. No
account, no login, no network path to us.

Pushing findings to Torana is a separate, explicit step you are asked about at the end.

## Connecting to your Torana tenant

Only needed for the parts that read from or write to the platform. Just ask, in a session:

```
> connect me to Torana at https://<your-tenant>.toranasecurity.ai
```

Claude installs the `torana` CLI (first time only), points it at your tenant, and starts
the login — which opens your browser. Credentials are stored under `~/.torana/`, and you
stay logged in across sessions.

Once the CLI is installed you can also drive it yourself at
`~/.torana-venv/bin/torana`. On a machine with **no browser** — a container, a remote box
over SSH, a CI runner — use the two-step login instead:

```bash
torana auth login --web --no-browser --print-url   # prints a URL; open it anywhere
torana auth login --web --no-browser --code <the-code-the-page-shows>
```

## Updating

```
/plugin marketplace update torana-skills
/plugin update torana@torana-skills
```

Skills, the bundled CLI and the scanner manifests all update together. Restart Claude Code
(or run `/reload-plugins`) to pick the new version up.

## Removing it

```
/plugin uninstall torana@torana-skills
```

That removes the plugin. To remove what it installed on your machine as well:
`rm -rf ~/.torana-venv ~/.torana`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Claude doesn't use the skill | Say it explicitly: *"use the torana-scan skill to scan this repo"* |
| Plugin installed but skills missing | Run `/reload-plugins`, or start a new session |
| `cannot bootstrap the torana CLI` | No Python 3.12+ and no `uv` on PATH. Install either, then retry |
| Bootstrap fails downloading dependencies | Your network blocks `pypi.org`. Tell us — we can ship a fully offline bundle |
| Scanners "not installed" | Let the skill install them when it offers, or run its `install_engines.sh` directly. They're pinned and checksum-verified against the upstream release |
| Push returns 401 | Re-run `torana auth login --web` |
| Findings land with no owner or criticality | Run the asset-inventory skill for that repo first |

## Support

- Issues with the skills: open an issue on this repository
- Anything about your Torana tenant: your usual support channel
- Security disclosures: security@toranasecurity.ai

---

© Torana Inc. Licensed for use by Torana customers — see [LICENSE](LICENSE).
# torana-skills
