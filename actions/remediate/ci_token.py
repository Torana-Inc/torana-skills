#!/usr/bin/env python3
"""Print a FRESH Torana CI token on stdout, and nothing else.

    GitHub OIDC assertion (`permissions: id-token: write`) → POST {TORANA_BASE_URL}/api/v1/ci/github/token

The same exchange as `actions/scan` ("Authenticate to Torana"), as a program, because two callers need it:

- `remediate.py` mints one before every CLI call that writes after a resolve (FIX_PR_SPEC.md § 3.4.9: the CI
  token lives 900 s, `internal_tokens.py:96`, and a resolve can take longer than that).
- `remediation_apply.py` runs it as `TORANA_TOKEN_CMD` before EACH of its own writes (lease, open-pr, the
  refresh propose), which happen after its resolve, where the action cannot reach.

⛔ STDOUT IS THE TOKEN. Every diagnostic goes to stderr, so a caller can take stdout whole.

Environment: ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN (set by the runner when the job has
`id-token: write`), TORANA_BASE_URL, TORANA_OIDC_AUDIENCE (default `torana`). Stdlib only: it runs before and
outside the CLI's venv.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 30


class TokenError(RuntimeError):
    pass


def _get_json(req: urllib.request.Request) -> dict:
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # ⚠️ The platform's refusals are actionable (403 names the missing App installation, 401 the bad
        # assertion), so they are surfaced verbatim, as actions/scan does.
        body = exc.read().decode("utf-8", "replace")[:400]
        raise TokenError(f"HTTP {exc.code} from {req.full_url.split('?')[0]}: {body}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise TokenError(f"{req.full_url.split('?')[0]}: {exc}") from None


def mint(env: "os._Environ[str] | dict" = os.environ) -> str:
    url, bearer = env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise TokenError("no OIDC token available: add 'permissions: { id-token: write }' to this job")
    base = (env.get("TORANA_BASE_URL") or "").rstrip("/")
    if not base:
        raise TokenError("TORANA_BASE_URL is not set")
    audience = env.get("TORANA_OIDC_AUDIENCE") or "torana"
    sep = "&" if "?" in url else "?"
    assertion = _get_json(urllib.request.Request(
        f"{url}{sep}audience={urllib.parse.quote(audience)}", headers={"Authorization": f"Bearer {bearer}"}))
    if not assertion.get("value"):
        raise TokenError("the OIDC endpoint returned no assertion")
    body = json.dumps({"oidc_token": assertion["value"], "audience": audience}).encode("utf-8")
    resp = _get_json(urllib.request.Request(f"{base}/api/v1/ci/github/token", data=body, method="POST",
                                            headers={"content-type": "application/json"}))
    token = resp.get("access_token")
    if not token:
        raise TokenError("Torana's token exchange returned no access_token")
    return token


def main() -> int:
    try:
        sys.stdout.write(mint())
    except TokenError as exc:
        print(f"::error::Torana refused the token exchange: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
