// The npm 4a codemod: rename one exported name of a module (old -> new) at every ES-import site in
// ONE file, and REFUSE every shape a rename cannot be proved to reach.
//
// FIX_PR_PHASE5_CODEMOD_SPEC § 3.5.4. Grown from the measured prototype at
// docs/evidence/fix_pr_phase5_libcst/npm/rename.js with the two changes that section specifies:
// `--ops` (several renames per file in one pass) and the `require()` refusal.
//
// Usage:  node rename.js <file> --ops <ops.json>
//   ops.json = [{"module": "<specifier as the import writes it>", "old": "...", "new": "..."}, ...]
//   stdout = the rewritten source, and NOTHING else (a caller reads it whole)
//   stderr = {"rewritten": [<line>, ...], "refused": [{"line": n, "why": "..."}, ...]}
//   exit 0 on success; exit 3 with {"refused": [{"line": 0, "why": "ts_morph_error: ..."}]} on any throw
//
// ⭐ SEVERAL OPS IN ONE PASS, for the same reason as the Python side (§ 3.5.2 (3)): two renamed symbols
// in one file are ONE run over ONE diff, so Gate B's L1 judges minimality once instead of twice.
//
// ⛔ WHY A LANGUAGE SERVICE AND NOT A TEXT EDIT. `spec.getNameNode().rename()` moves the import binding
// AND every local use of it, resolved by the TypeScript language service — which is also why a
// `require()` of the module is REFUSED below rather than handled: the service's rename does not follow
// CommonJS, so a require-shaped use would be silently left behind while the block claimed complete.
const fs = require("fs");
const { Project, SyntaxKind } = require("ts-morph");

function parseArgs(argv) {
  const file = argv[0];
  const i = argv.indexOf("--ops");
  if (!file || i === -1 || !argv[i + 1]) {
    process.stderr.write(JSON.stringify({
      refused: [{ line: 0, why: "usage: node rename.js <file> --ops <ops.json>" }],
    }) + "\n");
    process.exit(3);
  }
  return { file, ops: JSON.parse(fs.readFileSync(argv[i + 1], "utf8")) };
}

function main() {
  const { file, ops } = parseArgs(process.argv.slice(2));
  const project = new Project({ useInMemoryFileSystem: false, skipAddingFilesFromTsConfig: true });
  const sf = project.addSourceFileAtPath(file);
  const rewritten = new Set();
  const refused = [];
  const line = (n) => n.getStartLineNumber();
  const modules = new Set(ops.map((o) => o.module));

  // ⛔ THE require() SCAN COMES FIRST, and it is a refusal, never a rewrite. The language service's
  // rename only follows ES imports, so `const { fetchAll } = require("oldlib")` keeps the old name
  // after a successful-looking run. Refusing it puts the file:line in front of a person; rewriting
  // the import and leaving this behind is the silent half-fix this design exists to prevent.
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const fn = call.getExpression();
    if (fn.getKind() !== SyntaxKind.Identifier || fn.getText() !== "require") continue;
    const arg = call.getArguments()[0];
    if (!arg || arg.getKind() !== SyntaxKind.StringLiteral) continue;
    if (modules.has(arg.getLiteralValue())) {
      refused.push({ line: line(call), why: "require call" });
    }
  }

  for (const op of ops) {
    // Re-queried per op: a rename rewrites the tree, so declarations fetched before it are stale.
    for (const imp of sf.getImportDeclarations()) {
      if (imp.getModuleSpecifierValue() !== op.module) continue;

      for (const spec of imp.getNamedImports()) {
        if (spec.getName() !== op.old) continue;
        if (spec.getAliasNode()) {
          // `{ old as fa }` -> `{ new as fa }`. Only the imported name changes; every use of `fa`
          // is still correct, so nothing else is touched and nothing is refused.
          spec.setName(op.new);
        } else {
          for (const ref of spec.getNameNode().findReferencesAsNodes()) rewritten.add(line(ref));
          spec.getNameNode().rename(op.new);
        }
        rewritten.add(line(spec));
      }

      const ns = imp.getNamespaceImport();
      if (!ns) continue;
      for (const ref of ns.findReferencesAsNodes()) {
        const parent = ref.getParent();
        if (!parent) continue;
        if (parent.getKind() === SyntaxKind.PropertyAccessExpression
            && parent.getExpression() === ref && parent.getName() === op.old) {
          parent.getNameNode().replaceWithText(op.new);
          rewritten.add(line(parent));
        } else if (parent.getKind() === SyntaxKind.ElementAccessExpression
                   && parent.getExpression() === ref) {
          // ⛔ `o["fetchAll"]` — the property may be computed, so no parse can know whether this site
          // uses the old name. Guessing either way is wrong; the site is listed for a person.
          refused.push({ line: line(parent), why: "computed property access on the module" });
        }
      }
    }
  }

  process.stdout.write(sf.getFullText());
  process.stderr.write(JSON.stringify({
    rewritten: [...rewritten].sort((a, b) => a - b),
    refused,
  }) + "\n");
}

try {
  main();
} catch (err) {
  // ⛔ EXIT 3 AND SAY SO. A thrown ts-morph error must never reach the caller as empty stdout, which
  // would read as "the file became empty" — the applier treats exit 3 as a refusal and writes nothing.
  process.stderr.write(JSON.stringify({
    refused: [{ line: 0, why: "ts_morph_error: " + (err && err.message ? err.message : String(err)) }],
  }) + "\n");
  process.exit(3);
}
