# Recipe — CWE-798 (Hardcoded Credentials)

## When to apply this recipe

The vulnerability says a secret (API key, JWT signing key, password, TLS
private key, OAuth client secret) is committed to source. Common shapes:

- `const jwtSecret = 'sk_live_...';`
- `password: 'admin123',` in a config object
- `Authorization: Bearer ghp_...` in a fixture or example
- `.env` file checked in with real values

## Fix pattern — environment variable + fail-loud + .env.example

Three things land in the PR:

1. **Replace the literal with `process.env.<NAME>`** at the call site.
2. **Fail loudly at boot** if the env var isn't set. Silent fallback to
   an empty string or a default secret is worse than crashing — it hides
   misconfiguration in production.
3. **Add the variable to `.env.example`** (creating the file if needed)
   so the next developer knows it exists.
4. **Add to `.gitignore`** the real `.env` file if not already excluded.
5. **Rotate the leaked secret.** The patch removes the secret from the
   *current* commit, but it remains in `git log`. The skill should
   explicitly remind the dev to rotate.

## Canonical diff (juice-shop-extensions seeded vuln #3)

Before:

```javascript
module.exports = {
  port: process.env.PORT || 3000,

  // CWE-798: Hardcoded credentials. Do not do this in real code.
  jwtSecret: 'sk_live_DEMO_DO_NOT_USE_IN_PROD_a8f3c1e4b2d9',
  // ...
};
```

After:

```diff
 module.exports = {
   port: process.env.PORT || 3000,
-
-  // CWE-798: Hardcoded credentials. Do not do this in real code.
-  jwtSecret: 'sk_live_DEMO_DO_NOT_USE_IN_PROD_a8f3c1e4b2d9',
+  jwtSecret: (() => {
+    if (!process.env.JWT_SECRET) {
+      throw new Error('JWT_SECRET environment variable must be set');
+    }
+    return process.env.JWT_SECRET;
+  })(),
   // ...
 };
```

Plus a new `.env.example` at the repo root:

```
# JWT signing key. Generate with:  openssl rand -hex 32
JWT_SECRET=
```

And confirm `.gitignore` has:

```
.env
.env.local
```

## Verification

- `unset JWT_SECRET && node src/index.js` exits 1 with the error message,
  not 0.
- `JWT_SECRET=$(openssl rand -hex 32) node src/index.js` starts cleanly.
- Project tests still pass (they may need to set `JWT_SECRET` in the test
  setup — flag this to the dev if so).

## Things to watch for

- **Defaults to fall back to.** A pattern like
  `process.env.JWT_SECRET || 'dev-default'` looks safer but is not — the
  dev default ships to production if the env var is missed. Fail-loud is
  the right shape.
- **Multiple instances of the same secret.** A leaked key often appears
  in multiple files (config, tests, deployment scripts). Grep before
  proposing the diff:
  ```bash
  grep -r --include='*.js' --include='*.json' 'sk_live_DEMO' .
  ```
- **Tests that legitimately need a real-but-dummy key.** Use a fixture
  generated at test setup (`crypto.randomBytes(32).toString('hex')`),
  not a checked-in constant.
- **Already-rotated secrets.** If the dev confirms the key was already
  rotated and the leaked value is now invalid, the urgency drops but the
  fix still ships — leaving the leaked value in source is a footgun for
  future developers ("oh, this looks like the JWT secret").

## Stop conditions

- The "secret" is actually a public identifier (Stripe publishable key,
  Google Maps API key with a referrer restriction, OAuth `client_id`).
  These are designed to be public. Mark the alert as `false_positive` and
  do NOT open a PR.
- The secret is in a `terraform.tfvars` or Kubernetes secret manifest.
  The fix belongs in the deployment pipeline (sealed-secrets, KMS,
  Vault), not in this application repo. Surface that to the dev.

## Rotation reminder to print to the user

After the diff is applied (whether or not the PR has been opened), tell
the user verbatim:

> ⚠ **The leaked secret is still in git history.** This patch removes it
> from the current commit, but `git log -p` will still show the value.
> Treat the leaked credential as compromised. **Rotate it now**, before
> merging the PR. For `JWT_SECRET`: generate a new value, redeploy with
> the new value, invalidate any tokens issued under the old key.

## Test generation (T7 — differential regression test)

A hardcoded-secret fix is pinned differently — there's no HTTP sink to exploit,
so the regression test asserts the secret is **gone from the source** and sourced
from config/env instead.

- Author a test/lint assertion that greps the fixed file(s) for the secret pattern
  (the specific key shape, e.g. `AKIA[0-9A-Z]{16}`, `ghp_`, a private-key header)
  and asserts ZERO matches; and that the value is now read from env/secret-store.
- Differential check: on the pre-fix commit the pattern is present (test FAILS);
  post-fix it's absent (test PASSES). If the secret was only rotated but still
  inline, the test correctly stays failing → do not mark `generated`.
- Do NOT put the real secret in the test. Assert on the *pattern/absence*, and
  ensure the committed test never embeds the leaked value.
