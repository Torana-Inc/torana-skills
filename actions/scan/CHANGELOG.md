# Torana Security Scan Action — changelog

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
