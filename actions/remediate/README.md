# Torana Remediate

Proposes dependency fixes to Torana for a person to approve. When `open-pr` is on, Torana's GitHub App opens the
approved fixes as pull requests. A fix PR always opens as a **draft**. Torana marks it ready for review when your own
CI passes on it and the fix's review approved it.

Your workflow never holds a GitHub write token. It proves which repository it is with GitHub's OIDC, and Torana
binds its short-lived token to that repository.

## Use the reviewed workflow (recommended)

The reusable workflow runs three jobs, so each credential stays where it belongs:

| Job | Holds | Runs on | Does |
|---|---|---|---|
| resolve | a 15-minute Torana token | your choice | proposes fixes; prepares a review case for each approved one |
| review | **your** model credential | `untrusted-runner` | an AI review of each fix (only with `review: true`) |
| open-pr | a 15-minute Torana token | your choice | checks each case against today's code, records its review, has Torana open the PR |

- The job holding your model credential has no Torana token, no OIDC and no GitHub write token. It runs no code from
  your repository. It refuses to start anywhere but the host you chose in `untrusted-runner` (it checks the host
  itself; a runner label is never trusted).
- **No job runs your project's install or tests.** Every job's Actions token is scoped to your default branch, so the
  upgraded package's code could use it to write cache entries your main-branch workflows later restore. The PR opens
  as a draft instead, and **your own CI** runs the build and tests on it with a pull-request-scoped token. The PR
  becomes ready for review only when that CI passed.
- Only the cases and the reviews pass between jobs. They are artifacts kept for **one day**.
- A review's free-text reason is recorded in Torana only. The PR shows the verdict and the files it cites. In a
  **public** repository the reason is withheld from the artifact as well.

```yaml
# .github/workflows/torana-remediate.yml
on:
  schedule: [{ cron: '41 5 * * 1-5' }]     # a non-round minute
  workflow_dispatch:
permissions: {}
jobs:
  remediate:
    permissions: { id-token: write, contents: read }
    uses: Torana-Inc/torana-skills/.github/workflows/remediate.yml@v1
    with:
      torana-url: https://app.toranasecurity.ai
      open-pr: true
      review: true                         # about $0.10–0.50 per fix, at most review-max-plans (5) a run
      untrusted-runner: github-hosted      # where the review runs: see below
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Without `review: true`, fixes open as drafts that say no review was recorded. The case checks still run.

### The model credential

Pass exactly **one** secret: `ANTHROPIC_API_KEY` (billed per use), or `CLAUDE_CODE_OAUTH_TOKEN`, a Claude subscription
token made with `claude setup-token` (counts against that account's plan limits). Either reaches only the review
step. A leaked subscription token acts as that Claude account in Claude Code until you revoke it (about a year if you
do not); it reaches nothing else.

### Where the review runs: `untrusted-runner` (required)

| | `github-hosted` | `isolated` |
|---|---|---|
| Host | a fresh GitHub VM per job | Torana's isolated runner: one throwaway container per job, on a host we run |
| Setup | none | a runner pool in your organization (`untrusted-runner-labels`); today Torana's own repositories only |
| Root in the job | passwordless sudo | none (a non-root user, no new privileges, every capability dropped) |
| Network | the open internet | GitHub and the model API only, through a proxy; no local network |

It is required because it is a trust decision, not a default. Both modes refuse to start as root, with an OIDC token,
or on a host other than the one named. On `isolated`, the job also proves its runner is single-use and that its own
credential is in the review's secret filter.

On a **self-hosted runner** (`torana-runs-on`), resolve and open-pr need python3 (with pip and venv) and node ≥ 18 with
npm. If the runner lacks them, pass `torana-container:` an image that has them. Those two jobs then run in it.

## The single-job Action

`uses: Torana-Inc/torana-skills/actions/remediate@v1` with no `mode` still works. It resolves in the same job that
holds the Torana token and never runs a review. Since EM D-23 S3 d2 it no longer runs your install and tests either:
your own CI does, on the draft PR. Prefer the workflow above.

Never run either on `pull_request` or `pull_request_target`: both refuse.
