# Recipe — CWE-79 (Cross-Site Scripting, XSS)

## When to apply this recipe

The vulnerability says user-controlled input is being written into an HTML
response without escaping. Common shapes:

- Express: `res.send('<html>...' + req.query.x + '...</html>')`
- Express: `res.write(req.body.x)` followed by `res.end()`
- Template literals: `` `<div>${req.params.x}</div>` `` rendered to HTML
- Raw `innerHTML = userInput` on the client side

## Fix pattern — escape at the boundary

The right place to escape is **the moment the value crosses into HTML**,
not where it enters the server (input validation is defense-in-depth, but
output escaping is the actual fix). Pick the smallest, most surgical
escape that works in the surrounding context:

| Context the value lands in | Escape function |
|---|---|
| HTML element body (`<p>HERE</p>`) | `he.encode(value)` — escapes `< > & " '` |
| HTML attribute value (`<a href="HERE">`) | `he.encode(value, { useNamedReferences: false })` — same, but also quote attributes |
| JavaScript string literal embedded in HTML | `JSON.stringify(value)` — produces a safe JS string literal |
| URL component | `encodeURIComponent(value)` — for path/query parts |

**Do not** combine multiple escapes ("HTML-escape then URL-escape") unless
the value really does cross both contexts. Each layer should escape once.

## Canonical diff (juice-shop-extensions seeded vuln #1)

Before:

```javascript
router.get('/echo', (req, res) => {
  const msg = req.query.msg || '';
  res.send(
    '<html><body><h1>Admin Echo</h1><p>You said: ' + msg + '</p></body></html>'
  );
});
```

After:

```diff
+const he = require('he');
+
 router.get('/echo', (req, res) => {
   const msg = req.query.msg || '';
   res.send(
-    '<html><body><h1>Admin Echo</h1><p>You said: ' + msg + '</p></body></html>'
+    '<html><body><h1>Admin Echo</h1><p>You said: ' + he.encode(msg) + '</p></body></html>'
   );
 });
```

Also add `he` to `dependencies` in `package.json` (`npm install --save he`).

## Verification

- The handler returns the literal payload back as `&lt;script&gt;...` instead
  of executing it. Test in browser: `?msg=<script>alert(1)</script>` should
  render the text, not pop a dialog.
- Project tests still pass.

## Things to watch for

- If the handler also serves JSON (`res.json(...)`), the JSON branch does
  NOT need escaping — `res.json` already encodes safely. Only the HTML
  branch needs the fix.
- If the user input is already being rendered by a template engine with
  auto-escape enabled (Handlebars, EJS with `<%= %>`, Pug), the right fix
  is to use the template, not to add manual escaping. Manual escape on top
  of auto-escape produces double-encoded output.
- If multiple handlers in the file have the same bug, propose fixes for
  ALL of them in the same PR — don't ship a partial fix.

## Stop conditions

- The user wants to keep raw HTML rendering for a "preview" feature. Do
  NOT push the patch — escalate back to the user; they may need a
  sanitizer (DOMPurify) rather than an escape. That's a different recipe.
- The XSS is in a third-party template the application includes verbatim.
  The fix belongs upstream; open a PR there, not here.

## Test generation (T7 — differential regression test)

Pin the fix so the XSS can't return (fail pre-fix / pass post-fix, Step 8b).

- **Exploit-as-test (preferred):** use the T9-emitted test if present — it sends a
  unique `<x>${marker}</x>` payload to the reflecting param and asserts the marker
  is NOT reflected raw (i.e. it is escaped/encoded) in the response body.
- **Otherwise author one:** submit a unique marker in the vulnerable param; assert
  the response body contains the *escaped* form (`&lt;x&gt;…`), never the raw
  `<x>…</x>`. For stored XSS, assert on the render path, not just the store.
- Differential check: pre-fix the raw marker reflects; post-fix it's encoded. No
  pre-fix reflection → the test is weak → `uncovered`, do not commit.
