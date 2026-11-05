# Torana Remediate — changelog

## vNEXT (plugin 0.9.0) — a reviewed lane, with your own model key

**New:** the reusable workflow `.github/workflows/remediate.yml` (see README.md). With `review: true` and an
`ANTHROPIC_API_KEY` secret, each approved fix is reviewed by an AI before Torana opens its PR. The review runs in a job
that holds no Torana or GitHub credential. Each review costs up to $0.50, for at most `review-max-plans` (default 5)
fixes a run. Install and tests now run in their own job, with no credential at all.

**Also changes, with or without `review`:** the scripts this Action runs are rebuilt from the current scan pack
(previously pantheon-cli `cb9e63a`). Fix PRs now always open as **drafts**, and Torana marks them ready when your CI
passes and the review approved them. PR bodies carry a Review block. The follow-up-commit verbs are included.
Single-job workflows keep working unchanged, without a review.
