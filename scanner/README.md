# Torana scanner — scheduled scanning on your own Linux host

Scans repositories checked out on **your** machine and reports findings to your Torana
tenant. No GitHub App, no GitHub Actions, no inbound network, nothing listening.

Use this when your code is not on GitHub, when you cannot add workflows to your
repositories, or when you would rather one host scan many checkouts.

---

## ⛔ What this does NOT do

It performs **full scans only**, so it feeds the inventory, retirement and the staleness
board. **It does not gate pull requests.**

Gating needs [`actions/scan`](../actions/scan), because a gate has to judge *what a
change introduces* — which requires knowing the base commit and being able to post a
check run against a specific head. A scheduled host knows neither.

⚠️ And one security property does not carry over. The GitHub path proves repository
identity cryptographically: GitHub signs *"this job is running in repo X"* and Torana
issues a token bound to X, so a document naming a different repository is refused. A
host has no such issuer, so it authenticates as a **tenant** user. That host can
therefore file findings about **any repository in your tenant**, not only the ones it
scanned. Treat a scanning host as trusted infrastructure accordingly.

---

## Requirements

| | |
|---|---|
| OS | Linux with systemd (Ubuntu 22.04+, Debian 12+, RHEL 9+) |
| Python | 3.12+ **with the venv module** — on Debian/Ubuntu that is the separate `python3-venv` package, which a minimal image does not have even though `python3` is present |
| git | the scanner reads each repository's remote to identify it |
| Network **out** to | your Torana tenant, `github.com` (engine downloads, once), `api.osv.dev` (dependency data) |
| Disk | ~500 MB for the engines |

Nothing listens on a port. Nothing needs inbound access.

---

## Install

```bash
sudo apt-get install -y git python3-venv        # Debian/Ubuntu; RHEL: dnf install git python3
git clone https://github.com/Torana-Inc/torana-skills.git
cd torana-skills
sudo useradd --system --create-home --shell /usr/sbin/nologin torana
sudo bash scanner/install.sh
```

That installs the scan scripts and the `torana` CLI into `/opt/torana`, then downloads
the pinned engines — each **verified against the upstream project's published
checksums**. An engine that cannot be installed is skipped *with a message*; it is never
silently absent, because a missing engine must not look like a clean repository.

⭐ The CLI wheels are committed in this repository, so the install needs no package
index.

## Configure

```bash
sudo $EDITOR /opt/torana/torana-scan.conf
```

Set `TORANA_BASE_URL` and point `TORANA_ROOT` at the directory holding your checkouts.

⛔ **Ask Torana for your tenant address.** It is specific to you and to your environment,
so there is no default to fall back on. The shipped value is a deliberate placeholder
(`CHANGE-ME.example.invalid`) rather than a plausible-looking URL, because a wrong
address does not fail where you would notice: the whole scan runs, and only the final
push fails.

## Authenticate — once

```bash
# 1. Point the CLI at the same tenant address you put in torana-scan.conf.
sudo -u torana /opt/torana/venv/bin/torana config set base-url https://<your-torana-address>

# 2. Then log in.
sudo -u torana /opt/torana/venv/bin/torana auth login --email <user> --password <pw>
```

⛔ **Step 1 is not optional, and skipping it fails confusingly.** `torana-scan.conf` is
read by the scheduled scan, *not* by `auth login` — so with step 1 skipped, the login
targets the CLI's built-in default and reports:

```
ERROR: Cannot reach http://localhost/api/v1/auth/login: [Errno 111] Connection refused
```

which reads like a broken install rather than an unset address. Confirm the target
before logging in:

```bash
sudo -u torana /opt/torana/venv/bin/torana config show   # check base_url
```

⭐ Only once. The CLI holds a **7-day refresh token** and renews it on every run, so a
daily scan never lapses. If the host is off for longer, it re-authenticates from its
saved credentials automatically.

⛔ **Use a dedicated account with `integrations:write` and nothing else.** The CLI stores
credentials under `~torana/.torana` (mode 0600), and a scanning host should not hold an
account that can do more than file findings.

## Schedule

```bash
sudo cp scanner/systemd/* /etc/systemd/system/
sudo systemctl enable --now torana-scan.timer
systemctl list-timers torana-scan.timer
```

Daily at 06:17 plus a random spread of up to 30 minutes — a non-round minute **and** a
jitter, so a fleet of hosts does not all start at once. `Persistent=true` catches up
after downtime, because a skipped scan looks exactly like a clean repository.

## Run it by hand first

```bash
sudo -u torana /opt/torana/torana-scan.sh
journalctl -u torana-scan -n 50
```

---

## Checking it is working

```bash
torana repositories scan-freshness          # healthy | stale | never_scanned
torana vulnerabilities list --repo repo:<host>/<org>/<name>
```

⚠️ **`stale` is the state to watch.** It means a repository reported once and then
stopped — which from the platform's side is indistinguishable from "deleted" or
"nobody opted in", and from a dashboard is indistinguishable from "clean". A stale zero
and a true zero look identical; this is the only thing that tells them apart.

## Narrowing `TORANA_SCAN_TYPES` has a hidden cost

Retirement is scoped per scanner. A domain you stop scanning keeps its existing findings
**forever** — they are never re-reported, so they are never retired — while the
repository still reads `healthy`, because a scan did run. Half your coverage can be off
with every surface looking green.
