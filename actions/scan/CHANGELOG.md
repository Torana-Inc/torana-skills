# Torana Security Scan Action — changelog

## 2026-11-06 — plugin 0.10.0: results Torana can pull, and runs in order

**New:** the Action saves the SARIF and a small scan-meta file (`torana-scan-meta.json`: which commit, which run,
full or changed) as the workflow artifact **`torana-scan-sarif`** (3 days). With Actions: read granted to Torana's
GitHub App, Torana pulls it after each run, so a scan still lands when the push to Torana failed (an unreachable
platform, an expired token). See what was pulled: `torana integrations github-app ci-scan-pulls`.

- `upload-sarif-artifact` (default `auto`): on for a **private** repository, off for a public one. On a public
  repository anyone signed in to GitHub can download a run's artifacts, which would publish the findings list
  (rules, files, lines, severities; secret values are redacted) until it is fixed, so `auto` skips it there. `true`
  forces it on, `false` turns it off. When the event does not say whether the repository is private, `auto` treats
  it as public.
- `sarif-artifact-retention-days` (default `3`, 1-90).
- ⚠️ If your workflow already uploads an artifact named `torana-scan-sarif` itself, set `upload-sarif-artifact:
  "false"`: two uploads of one name in one run fail the second.

**Changed:** the push sends the run (`--run-id`, `--run-attempt`), so an older run never overwrites a newer run's
results on the default branch. This needs the `torana` CLI 0.1.3, which this release vendors in place of 0.1.2.

## 2026-11-03 — works in container jobs

**Fixed:** the Action failed in any job that runs in a container (`container:` in the workflow), before
scanning anything. Its "Engine cache key" step stopped with

```
cat: /…/_work/_actions/Torana-Inc/torana-skills/<sha>/actions/scan/../../plugins/torana/skills/torana-scan/references/scan_pack.json: No such file or directory
```

It located its own files with the expression `${{ github.action_path }}`, which in a container job is the
runner HOST's path, absent inside the container. It now uses `$GITHUB_ACTION_PATH`, which the runner
translates to the container's path. Jobs without `container:` behave exactly as before.

If you pinned an earlier SHA and run in a container, move the pin to this release or later.
