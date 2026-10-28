"""actions/remediate: unit tests and the end-to-end dry run against stubs (no network, no GitHub, no Torana).

    python3 -m unittest discover -s actions/remediate/tests -v
    REMEDIATE_SHOW_SEQUENCE=1 … prints the call sequence of the dry run.

The platform is stubbed at two layers: a local HTTP server answers the GitHub OIDC endpoint and Torana's
`/api/v1/ci/github/token` exchange (the action's own HTTP), and a recorded-response `torana` CLI answers every CLI
call (the CLI's HTTP is the CLI's tests' business). The scan-pack scripts are argv-contract stubs; git is real,
against local bare repositories standing in for github.com.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ACTION = os.path.dirname(HERE)
STUBS = os.path.join(HERE, "stubs")
sys.path.insert(0, ACTION)
import remediate  # noqa: E402

SUBJECT = "repo:github.com/acme/api"
DEPLOY = "repo:github.com/acme/deploy"
SHARED = "repo:github.com/acme/shared"
STALE = "00000000-0000-4000-8000-00000000057a"
FRESH = "00000000-0000-4000-8000-000000000f5e"
OK = "00000000-0000-4000-8000-0000000000aa"
OPEN = "00000000-0000-4000-8000-0000000000bb"


class _Stub(http.server.BaseHTTPRequestHandler):
    log_path = ""
    n = 0
    fail_after = None            # refuse every token exchange after this many
    fail_after_clone = False     # refuse every token exchange once a clone has run

    def _log(self, line):
        with open(self.log_path, "a") as fh:
            fh.write(line + "\n")

    def do_GET(self):  # the runner's OIDC endpoint
        assert self.headers["Authorization"] == "Bearer runner-request-token"
        assert "audience=torana" in self.path
        self._reply({"value": "oidc-assertion"})

    def do_POST(self):  # Torana's token exchange
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        assert self.path == "/api/v1/ci/github/token", self.path
        assert body == {"oidc_token": "oidc-assertion", "audience": "torana"}, body
        if (self.fail_after is not None and self.n >= self.fail_after) or \
                (self.fail_after_clone and "git clone" in _read(self.log_path)):
            self._log("HTTP POST /api/v1/ci/github/token -> 503")
            self.send_response(503)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        type(self).n += 1
        self._log(f"HTTP POST /api/v1/ci/github/token -> ci-token-{self.n}")
        self._reply({"access_token": f"ci-token-{self.n}"})

    def _reply(self, data):
        raw = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _bare_repo(root: str, owner: str, name: str, files: dict) -> None:
    src = os.path.join(root, "seed", name)
    os.makedirs(src)
    for path, text in files.items():
        os.makedirs(os.path.dirname(os.path.join(src, path)) or src, exist_ok=True)
        _write(os.path.join(src, path), text)
    g = ["git", "-C", src, "-c", "user.name=t", "-c", "user.email=t@t"]
    # ⛔ NOT `git init -b main`: `-b` arrived in git 2.28, and macOS's bundled Command Line Tools still ship 2.24.3
    # (Apple Git-128, 2019), where it exits 129 `unknown switch` — which errored 24 of this suite's 33 tests at
    # setup, so the Action's own tests had never run on a laptop. Setting HEAD by hand is equivalent before the
    # first commit and works on every git that has `symbolic-ref`. Found 2026-10-28 alongside § 3.6.11's W3-13.
    subprocess.run(["git", "init", "-q", src], check=True)
    subprocess.run(["git", "-C", src, "symbolic-ref", "HEAD", "refs/heads/main"], check=True)
    subprocess.run(g + ["add", "."], check=True)
    subprocess.run(g + ["commit", "-qm", "seed"], check=True)
    subprocess.run(["git", "clone", "-q", "--bare", src, os.path.join(root, "github", owner, f"{name}.git")],
                   check=True)


class DryRun(unittest.TestCase):
    """The whole lane, end to end, on stubs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="remediate-")
        self.log = os.path.join(self.tmp, "calls.log")
        open(self.log, "w").close()
        _Stub.log_path, _Stub.n, _Stub.fail_after, _Stub.fail_after_clone = self.log, 0, None, False
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        _bare_repo(self.tmp, "acme", "deploy", {"base-image/requirements.lock": "pyjwt==2.14.0\n"})
        _bare_repo(self.tmp, "acme", "shared", {"pyproject.toml": "[project]\n"})
        subject = os.path.join(self.tmp, "ws", ".torana-remediate", "src", "api")
        os.makedirs(subject)
        subprocess.run(["git", "init", "-q", subject], check=True)
        bin_dir = os.path.join(self.tmp, "bin")
        os.makedirs(bin_dir)
        for name in ("torana", "git"):
            shutil.copy(os.path.join(STUBS, name), os.path.join(bin_dir, name))
            os.chmod(os.path.join(bin_dir, name), 0o755)
        self.scenario = {
            "queue": [{"ecosystem": "pypi", "package": "pyjwt", "installed": "2.14.0", "fixed": "2.15.0",
                       "alert_id": "a1"}],
            "not_related": [SHARED],
            "plans": [
                {"id": STALE, "state": "proposed", "probe_stale": True, "target_repository": DEPLOY,
                 "pr_state": "none"},
                {"id": FRESH, "state": "proposed", "probe_stale": False, "target_repository": DEPLOY,
                 "pr_state": "none"},
                {"id": OK, "state": "approved", "probe_stale": False, "target_repository": DEPLOY,
                 "pr_state": "none"},
                {"id": OPEN, "state": "approved", "probe_stale": False, "target_repository": DEPLOY,
                 "pr_state": "open"},
            ]}
        self.env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": self.tmp,
            "REAL_GIT": shutil.which("git"), "STUB_LOG": self.log,
            "STUB_SCENARIO": os.path.join(self.tmp, "scenario.json"),
            "ACTIONS_ID_TOKEN_REQUEST_URL": f"{base}/oidc?api-version=2.0",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-request-token",
            "TORANA_BASE_URL": base, "TORANA_OIDC_AUDIENCE": "torana",
            "TORANA_SCAN_REF": os.path.join(STUBS, "references"),
            "GITHUB_SERVER_URL": f"file://{self.tmp}/github", "GITHUB_REPOSITORY": "Acme/API",
            "GITHUB_EVENT_NAME": "schedule", "GITHUB_REF": "refs/heads/main", "REMEDIATE_DEFAULT_BRANCH": "main", "GITHUB_RUN_ID": "991", "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_OUTPUT": os.path.join(self.tmp, "out.txt"),
            "GITHUB_STEP_SUMMARY": os.path.join(self.tmp, "summary.md"),
            "REMEDIATE_SUBJECT": subject, "REMEDIATE_OUT": os.path.join(self.tmp, "ws", ".torana-remediate"),
            "REMEDIATE_WITH": "acme/deploy:base-image\nacme/shared\n", "REMEDIATE_OPEN_PR": "true",
        }

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        if os.environ.get("DISABLE_CLEANUP") != "true":
            shutil.rmtree(self.tmp, ignore_errors=True)

    def run_action(self):
        _write(self.env["STUB_SCENARIO"], json.dumps(self.scenario))
        p = subprocess.run([sys.executable, os.path.join(ACTION, "remediate.py")], env=self.env,
                           capture_output=True, text=True)
        calls = [ln for ln in _read(self.log).splitlines() if ln]
        if os.environ.get("REMEDIATE_SHOW_SEQUENCE"):
            print("\n".join(f"{i:2d}. {c}" for i, c in enumerate(calls, 1)), file=sys.stderr)
        return p, calls

    def test_the_call_sequence(self):
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        no_http = [c for c in calls if not c.startswith("HTTP")]
        expected = [
            "torana alerts reachability-queue --repository repo:github.com/acme/api --include-measured --as-findings",
            # § 3.4.11: deploy is declared related → propose-run mint, clone, revoke
            "torana remediation-plans target-token --subject repo:github.com/acme/api "
            "--target repo:github.com/acme/deploy --holder-run 991:2",
            "git clone deploy.git (auth-via-env)",
            "torana remediation-plans target-token --subject repo:github.com/acme/api "
            "--target repo:github.com/acme/deploy --holder-run 991:2 --revoke --mint-id mint-p1",
            # shared is not declared → refused, never cloned
            "torana remediation-plans target-token --subject repo:github.com/acme/api "
            "--target repo:github.com/acme/shared --holder-run 991:2",
            # § 3.4.6: the stored set, read with the action's token (the planner holds none)
            "torana alert a1 fix-scope --json",
            "script remediation_plan.py --repo api --with deploy/base-image --findings findings.json "
            "--fix-scope-file fix-scope.json --api-diff off",
            "script remediation_apply.py --plan plan.json",
            "torana remediation-plans propose --plan plan.json --findings findings.json --probe probe.json "
            "--repo-key repo:github.com/acme/api --with-key deploy/base-image=repo:github.com/acme/deploy",
            # re-probe: only the stale plan
            "torana remediation-plans list --subject-repository repo:github.com/acme/api --state proposed "
            "--limit 100 --offset 0",
            f"script remediation_apply.py --plan-id {STALE} --with <deploy>=repo:github.com/acme/deploy --probe",
            "torana remediation-plans propose --plan p.json --findings f.json --probe r.json --refresh-plan-id "
            f"{STALE} --repo-key repo:github.com/acme/api",
            "torana remediation-plans list --subject-repository repo:github.com/acme/api --state approved "
            "--limit 100 --offset 0",
            "torana remediation-plans list --subject-repository repo:github.com/acme/api --state overridden "
            "--limit 100 --offset 0",
            "torana remediation-plans list --subject-repository repo:github.com/acme/api --state removal_chosen "
            "--limit 100 --offset 0",
            # open-pr: approved lists again (its own stage), then OK only (OPEN already has a PR)
            "torana remediation-plans list --subject-repository repo:github.com/acme/api --state approved "
            "--limit 100 --offset 0",
            f"torana remediation-plan {OK} target-token --holder-run 991:2",
            "git clone deploy.git (auth-via-env)",
            f"torana remediation-plan {OK} target-token --holder-run 991:2 --revoke --mint-id mint-2",
            f"script remediation_apply.py --plan-id {OK} --with <deploy>=repo:github.com/acme/deploy --open-pr "
            "--holder-run 991:2 --base-branch main --gates-45",
            f"torana remediation-plans lease acquire --plan-id {OK} --holder-run 991:2",
            f"torana remediation-plan {OK} open-pr --diff changes.diff --root copy --probe probe-report.json "
            "--base-sha HEAD",
            "torana remediation-plans lease release lease-1 --holder-run 991:2",
            "torana remediation-plans list --subject-repository repo:github.com/acme/api --state overridden "
            "--limit 100 --offset 0",
            "torana remediation-plans list --subject-repository repo:github.com/acme/api --state removal_chosen "
            "--limit 100 --offset 0",
        ]
        self.assertEqual([c.split("  [")[0] for c in no_http], expected)
        self.assertIn("not declared related", p.stdout)
        self.assertIn("related-repos add", p.stdout)

    def test_every_cli_call_gets_a_token_never_seen_before(self):
        _, calls = self.run_action()
        tokens = [c.split("[ci=")[1].split("]")[0] for c in calls if c.startswith("torana ")]
        self.assertTrue(tokens and all(t.startswith("ci-token-") for t in tokens))
        self.assertEqual(len(tokens), len(set(tokens)), "a CI token was reused across calls")
        # each torana call is preceded by its own exchange: immediately, or (a revoke) right before the clone
        for i, c in enumerate(calls):
            if c.startswith("torana "):
                tok = c.split("[ci=")[1].split("]")[0]
                back = 2 if "--revoke" in c else 1
                self.assertEqual(calls[i - back], f"HTTP POST /api/v1/ci/github/token -> {tok}", c)
                if back == 2:
                    self.assertTrue(calls[i - 1].startswith("git clone"), calls[i - 1])

    def test_apply_mints_through_token_cmd_before_each_write(self):
        _, calls = self.run_action()
        start = calls.index(next(c for c in calls if f"--plan-id {OK}" in c and c.startswith("script")))
        writes = [c for c in calls[start:] if c.startswith(("torana remediation-plans lease",
                                                             f"torana remediation-plan {OK} open-pr"))]
        self.assertEqual(len(writes), 3)
        for w in writes:
            i = calls.index(w)
            self.assertTrue(calls[i - 1].startswith("HTTP POST /api/v1/ci/github/token"), calls[i - 1])

    def test_read_tokens_are_masked_revoked_by_stdin_and_never_persisted(self):
        p, calls = self.run_action()
        for tok in ("ghs_propose_1", "ghs_plan_2"):
            self.assertIn(f"::add-mask::{tok}", p.stdout)
            self.assertNotIn(tok, p.stdout.replace(f"::add-mask::{tok}", ""))
            self.assertTrue(any(f"[stdin-token={tok}]" in c and "--revoke" in c for c in calls), tok)
        for c in calls:
            if c.startswith("git clone"):
                self.assertIn("auth-via-env", c)
        out = self.env["REMEDIATE_OUT"]
        for root, _, files in os.walk(out):
            if root.endswith(".git") and "config" in files:
                cfg = _read(os.path.join(root, "config"))
                self.assertNotIn("ghs_", cfg)
                self.assertNotIn("extraheader", cfg)

    def test_revoke_runs_even_when_the_clone_fails(self):
        shutil.rmtree(os.path.join(self.tmp, "github", "acme", "deploy.git"))
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 1)
        self.assertTrue(any("--revoke --mint-id mint-p1" in c for c in calls))
        self.assertIn("git clone acme/deploy failed", p.stdout)

    def test_open_pr_false_stops_after_reprobe(self):
        self.env["REMEDIATE_OPEN_PR"] = "false"
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertFalse(any("open-pr" in c or "lease" in c for c in calls))

    def test_empty_queue_proposes_nothing(self):
        self.scenario["queue"] = []
        self.scenario["plans"] = []
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0)
        self.assertFalse(any("remediation-plans propose" in c or "remediation_plan.py" in c for c in calls))
        self.assertIn("nothing to plan", _read(self.env["GITHUB_STEP_SUMMARY"]))

    def test_refused_on_pull_request_before_any_call(self):
        for event in ("pull_request", "pull_request_target"):
            self.env["GITHUB_EVENT_NAME"] = event
            p, calls = self.run_action()
            self.assertEqual(p.returncode, 1)
            self.assertEqual(calls, [])
            self.assertIn("never runs on", p.stdout)

    def test_loud_failure_when_the_scan_pack_predates_the_lane(self):
        self.env["TORANA_SCAN_REF"] = self.tmp
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 1)
        self.assertEqual(calls, [])
        self.assertIn("remediation_plan.py, remediation_apply.py", p.stdout)


    # ── the review's MAJORs ─────────────────────────────────────────────────────────

    def test_lease_held_by_another_run_is_a_quiet_skip(self):
        self.scenario["lease_held"] = True
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn(f"::notice::plan {OK}: skipped, the lease on {DEPLOY} is held by another run", p.stdout)
        self.assertNotIn("::error::", p.stdout)
        self.assertFalse(any(" open-pr --diff" in c for c in calls))
        self.assertIn("lease held by another run", _read(self.env["GITHUB_STEP_SUMMARY"]))

    def test_empty_queue_still_reprobes_a_cross_repo_stale_plan(self):
        self.scenario["queue"] = []
        self.env["REMEDIATE_OPEN_PR"] = "false"
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        seq = [c.split("  [")[0] for c in calls if not c.startswith("HTTP")]
        mint = (f"torana remediation-plans target-token --subject {SUBJECT} --target {DEPLOY} --holder-run 991:2")
        i = seq.index(mint)
        self.assertEqual(seq[i + 1], "git clone deploy.git (auth-via-env)")
        self.assertEqual(seq[i + 2], mint + " --revoke --mint-id mint-p1")
        self.assertIn(f"script remediation_apply.py --plan-id {STALE} --with <deploy>={DEPLOY} --probe", seq[i + 3:])
        self.assertFalse(any("remediation_plan.py" in c for c in seq))

    # ── the review's MINORs ─────────────────────────────────────────────────────────

    def test_revoke_survives_a_failing_token_exchange(self):
        _Stub.fail_after_clone = True     # the exchange is down from the moment the read token is in use
        p, calls = self.run_action()
        revoke = [c for c in calls if "--revoke --mint-id mint-p1" in c]
        self.assertEqual(len(revoke), 1, calls)
        self.assertIn("[ci=ci-token-3]", revoke[0])
        self.assertIn("[stdin-token=ghs_propose_1]", revoke[0])
        self.assertEqual(p.returncode, 1)

    def test_no_mint_id_means_no_revoke_with_none(self):
        self.scenario["no_mint_id"] = True
        self.env["REMEDIATE_OPEN_PR"] = "false"
        p, calls = self.run_action()
        self.assertFalse(any("--mint-id None" in c for c in calls))
        self.assertFalse(any("remediation-plans target-token" in c and "--revoke" in c for c in calls))
        self.assertIn("without a mint_id", p.stdout)

    def test_hostile_api_fields_cannot_inject_workflow_commands(self):
        self.scenario["plans"].append({"id": "../../x\n::warning::pwned", "state": "approved",
                                       "target_repository": "repo:github.com/a/b\n::set-env name=X::1",
                                       "pr_state": "none"})
        self.scenario["queue_error"] = "boom\n::warning::pwned\n::set-env name=X::1"
        self.scenario["plans"].append({"id": "00000000-0000-4000-8000-0000000000cc", "state": "approved",
                                       "target_repository": "repo:github.com/acme/..", "pr_state": "none"})
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 1)
        for line in p.stdout.splitlines() + p.stderr.splitlines():
            self.assertFalse(line.startswith(("::warning::pwned", "::set-env")), line)
        self.assertIn("boom%0A::warning::pwned", p.stdout)
        self.assertIn("invalid id", p.stdout)
        self.assertIn("invalid target_repository", p.stdout)
        self.assertFalse(any("x\\n" in c or "/.." in c for c in calls if "target-token" in c))
        self.assertTrue(os.path.isdir(self.tmp))

    def test_open_pr_refused_off_the_default_branch(self):
        self.env["GITHUB_REF"] = "refs/heads/feature-x"
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 1)
        self.assertEqual(calls, [])
        self.assertIn("open-pr runs only on the default branch (main)", p.stdout)
        self.env["REMEDIATE_OPEN_PR"] = "false"
        p, _ = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_scan_pack_scripts_never_see_a_ci_token(self):
        # the stubs assert it (TEST FAILURE → a non-zero exit); a green full run is the proof
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(any(c.startswith("script remediation_plan.py") for c in calls))
        self.assertTrue(any(f"--plan-id {OK}" in c for c in calls))


class Units(unittest.TestCase):
    def test_inside(self):
        self.assertTrue(remediate.inside("/w/out", "/w/out/pr/x/deploy"))
        for bad in ("/w/out", "/w/out/../etc", "/w/outside", "/etc"):
            self.assertFalse(remediate.inside("/w/out", bad), bad)

    def test_safe_escapes_newlines(self):
        self.assertEqual(remediate.safe("a\n::x::\r%"), "a%0A::x::%0D%25")

    def test_parse_with(self):
        t = remediate.parse_with("Acme/Deploy:base-image/\n\n# c\nacme/shared")
        self.assertEqual([(x.owner, x.repo, x.subdir, x.key) for x in t],
                         [("Acme", "Deploy", "base-image", DEPLOY), ("acme", "shared", "", SHARED)])
        for bad in ("acme", "acme/deploy:../x", "https://github.com/acme/deploy", "acme/deploy:a//b", "acme/..",
                    "../deploy"):
            with self.assertRaises(ValueError, msg=bad):
                remediate.parse_with(bad)

    def test_labels_match_the_planners(self):
        run = remediate.Run(env={}, subject_dir="/w/src/api", subject_key=SUBJECT, out="/w", holder_run="1:1",
                            trees=remediate.parse_with("acme/deploy:base-image\nacme/api:sub"), open_pr=False,
                            ref="")
        run.roots = {SUBJECT: "/w/src/api", DEPLOY: "/w/src/deploy"}
        self.assertEqual(remediate.scope_args(run, "plan"),
                         ["--with", "/w/src/deploy/base-image", "--with", "/w/src/api/sub"])
        self.assertEqual(remediate.with_keys(run), ["--with-key", f"deploy/base-image={DEPLOY}",
                                                    "--with-key", f"api/sub={SUBJECT}"])
        # apply gets repository roots (rows carry repo-relative paths), once per key, never the subject
        self.assertEqual(remediate.scope_args(run, "apply"), ["--with", f"/w/src/deploy={DEPLOY}"])

    def test_paging_reads_to_the_end(self):
        pages = {0: list(range(100)), 100: list(range(100, 130))}
        seen = []

        def fake(run, args, **kw):
            off = int(args[args.index("--offset") + 1])
            seen.append(off)
            return 0, {"items": [{"id": i} for i in pages[off]], "total": 130}, ""

        orig = remediate.torana
        remediate.torana = fake
        try:
            run = remediate.Run(env={}, subject_dir="/s", subject_key=SUBJECT, out="/o", holder_run="1:1",
                                trees=[], open_pr=False, ref="")
            self.assertEqual(len(remediate.list_plans(run, "proposed")), 130)
            self.assertEqual(seen, [0, 100])
        finally:
            remediate.torana = orig


if __name__ == "__main__":
    unittest.main()
