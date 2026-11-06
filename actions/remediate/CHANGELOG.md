# Torana Remediate — changelog

## vNEXT (plugin 0.9.2): no install or tests in the Action; where the review runs; a subscription token

**⚠️ Behaviour change for every caller, including the single-job Action:** this Action no longer runs your project's
install and tests on a fix (gates 4/5). They ran with an Actions token scoped to your default branch, which the
upgraded package's code could use to write cache entries your main-branch workflows later restore. The fix PR opens as
a draft, your own CI runs the build and tests on it, and Torana marks it ready only when that CI passed. The PR's
gates section says "not run here: the repository's own CI runs the build and tests on the draft PR".

**Isolated runner guard:** a runner counts as single-use only when its `.runner` says `Ephemeral` is JSON `true` or
the string `"true"` (any case). Before, any truthy value counted, so the string `"false"` read as single-use.

**Reusable workflow:** three jobs (the `gates` job and its artifact are gone).
- New **required** input `untrusted-runner`: `github-hosted` | `isolated` (with `untrusted-runner-labels`). Callers
  must add it. The review job checks the host itself and refuses to start anywhere else, as root, or with OIDC.
- New optional secret `CLAUDE_CODE_OAUTH_TOKEN` (a Claude subscription token), instead of `ANTHROPIC_API_KEY`:
  exactly one of the two.
- The review's own secret filter now reads only the runner's `.credentials*` files, and never a path, URL or sentence.
  Before, a review quoting the runner's work folder or the repository URL was withheld by mistake.
- The reviewer sends no non-essential traffic (`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`).

## vNEXT (plugin 0.9.0) — a reviewed lane, with your own model key

**New:** the reusable workflow `.github/workflows/remediate.yml` (see README.md). With `review: true` and an
`ANTHROPIC_API_KEY` secret, each approved fix is reviewed by an AI before Torana opens its PR. The review runs in a job
that holds no Torana or GitHub credential. Each review costs up to $0.50, for at most `review-max-plans` (default 5)
fixes a run. Install and tests now run in their own job, with no credential at all.

**Also changes, with or without `review`:** the scripts this Action runs are rebuilt from the current scan pack
(previously pantheon-cli `cb9e63a`). Fix PRs now always open as **drafts**, and Torana marks them ready when your CI
passes and the review approved them. PR bodies carry a Review block. The follow-up-commit verbs are included.
Single-job workflows keep working unchanged, without a review.
