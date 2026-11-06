# Torana Remediate — changelog

`@v1` is a moving tag: it follows every compatible v1.x.y release. For a fixed version, pin `@v1.0.0` (or a commit
sha).

## v1.1.1: two failed checks with the same name are judged separately

**Fix:** a check was named by its job name alone (`check_run:<name>`). When two workflows each had a failing job of
the same name (`test`, `build`), one judgement covered both, and the second was never judged. Each judgement now
selects its check by the GitHub check-run id: the `judge` job writes it, and `post` sends it with
`ci judge --check-id`. Torana keeps the judgement by the check's workflow run (`workflow_run_id`), so it still
covers a re-run of that job on the same commit. A judgement made by v1.1.0 (no id) is still recorded by its name.

Needs a Torana platform with this fix (EM D-23 S2 e1, DF migration 120). The plugin's CLI sends the id.

## v1.1.0 (plugin 0.9.4): judge a failed check Torana could not attribute

**New, opt-in:** the reusable workflow `.github/workflows/judge.yml` (README.md, "Judge a failed check"). Three jobs
(`mode: judge-collect | judge | judge-post`) find this repository's fix PRs whose failed check Torana marked unclear,
have an AI judge each one from its failed steps' log (your model credential, at most $0.25 a check, `judge-max-checks`
a run), and record the answer in Torana labelled "this repository's CI". A judgement never marks a PR ready.

No existing caller changes: `remediate.yml` and the single-job Action behave as in v1.0.1. The plugin's scan pack
gains `judge_case.py` and `ci_log_excerpt.py`, and its CLI gains `torana remediation <id> ci judge`.

Needs a Torana platform with CI judgements (EM D-23 S2). ⚠️ Do not add it before: on an older platform `post` cannot record (404), so `collect` picks the same checks again and each run pays for them again.

## v1.0.1 (2026-11-06, plugin 0.9.3): the reviewed lane opens its PR from CI

**Fix:** with `open-pr: true`, the reusable workflow's `open-pr` job stopped before opening anything: `not_ready: The
GitHub CLI (gh) is not installed on this machine`. Its GitHub readiness pre-flight also asked whether the runner's
own `gh` could push. In this lane Torana's GitHub App pushes, so only the platform's checks (App installed, granted,
covering the repository) are asked now. No input or behaviour changes for callers. The single-job Action's
`open-pr` lane gets the same fix.

Needs a Torana platform from 2026-11-06 or later, which admits the remediate Action's CI token on the readiness and
lease-renew routes. On an older platform the job stops with a 403 on the readiness pre-flight.

## v1.0.0 (2026-11-06, plugin 0.9.2): no install or tests in the Action; where the review runs; a subscription token

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

## Also in v1.0.0 (plugin 0.9.0): a reviewed lane, with your own model key

**New:** the reusable workflow `.github/workflows/remediate.yml` (see README.md). With `review: true` and an
`ANTHROPIC_API_KEY` secret, each approved fix is reviewed by an AI before Torana opens its PR. The review runs in a job
that holds no Torana or GitHub credential. Each review costs up to $0.50, for at most `review-max-plans` (default 5)
fixes a run. Install and tests now run in their own job, with no credential at all.

**Also changes, with or without `review`:** the scripts this Action runs are rebuilt from the current scan pack
(previously pantheon-cli `cb9e63a`). Fix PRs now always open as **drafts**, and Torana marks them ready when your CI
passes and the review approved them. PR bodies carry a Review block. The follow-up-commit verbs are included.
Single-job workflows keep working unchanged, without a review.
