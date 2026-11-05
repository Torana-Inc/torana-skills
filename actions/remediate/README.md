# Torana Remediate

Proposes dependency fixes to Torana for a person to approve. When `open-pr` is on, Torana's GitHub App opens the
approved fixes as pull requests. A fix PR always opens as a **draft**. Torana marks it ready for review when your own
CI passes on it and the fix's review approved it.

Your workflow never holds a GitHub write token. It proves which repository it is with GitHub's OIDC, and Torana
binds its short-lived token to that repository.

## Use the reviewed workflow (recommended)

The reusable workflow runs four jobs, so each credential stays where it belongs:

| Job | Holds | Runs on | Does |
|---|---|---|---|
| resolve | a 15-minute Torana token | your choice | proposes fixes; prepares a review case for each approved one |
| gates | nothing | GitHub-hosted | your project's own install and tests, on each fix |
| review | **your** model key | GitHub-hosted | an AI review of each fix (only with `review: true`) |
| open-pr | a 15-minute Torana token | your choice | checks each case against today's code, records its review, has Torana open the PR |

- The job holding your model key has no Torana token, no OIDC and no GitHub write token. It runs no code from your
  repository, and it refuses to start anywhere but a fresh GitHub-hosted runner.
- The jobs holding the Torana token never run your project's install or tests.
- Only the cases, the test results and the reviews pass between jobs. They are artifacts kept for **one day**.
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
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Without `review: true`, fixes open as drafts that say no review was recorded. Gates and the case checks still run.

## The single-job Action

`uses: Torana-Inc/torana-skills/actions/remediate@v1` with no `mode` still works as before. ⚠️ It runs your
project's install and tests (the upgraded package's code) in the same job that holds the Torana token, and that
token may record a review for your repository's approved fixes. Prefer the workflow above.

Never run either on `pull_request` or `pull_request_target`: both refuse.
