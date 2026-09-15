#!/usr/bin/env python3
"""GENERATE the generator-facing vocabulary contract from the two live registries.

⚠️ The contract is GENERATED, never hand-typed. A hand-typed copy of a registry
drifts the moment a key is added, and drift here is not cosmetic: an author who
trusts a stale row emits a verb the key does not accept, the binder leaves the
hole unbound, and the placeholder survives to EXPLAIN as a syntax error. That
exact failure is already recorded in `question_primitives.py` around
`SQL_EM_058_OBSERVED`, and the nine stale tuples in `reachability.py` are the
same defect in another file.

TWO registries, ONE key set, TWO syntaxes:

  vm_catalog/_vocabulary_snapshot.py   defaults + shapes  (catalog/corpus SQL)
  vm_content/vocabulary_keys.py        legal verbs + prose (app-template SQL)

Both are themselves generated from the canonical registry in
`pantheon-agent-builder/src/services/vm_policy/vocabulary_registry.py`. This
script reads both and asserts they still agree — a divergence is a hard error,
not a warning, because a contract built from two disagreeing sources is worse
than none.

Usage:
    python3 generate_vocabulary_contract.py                  # write the .md
    python3 generate_vocabulary_contract.py --check          # CI: is it stale?
    python3 generate_vocabulary_contract.py --out PATH
"""

import argparse
import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

#: Written by the `policy` decoration in pantheon-shared/.../datalake/decorations.py
#: (kind=DERIVE, mode=FILL) — these columns ARE the SLA policy, already materialised
#: with whatever windows were in force the last time the decoration ran. Reading one
#: applies a STALE policy that the vocabulary key would have overridden at bind time.
#: Verified 2026-08-06 against decorations.py::DECORATIONS["policy"].provides.
DENYLIST: Dict[str, str] = {
    "vulnerability_due_date": (
        "written by the `policy` decoration as "
        "`scan_first_detected_date + (sla_window_days * INTERVAL '1 day')` "
        "(and FILLed by cve_intel from CISA's kev_due_date). Reading it applies "
        "whatever policy was in force when the decoration last ran."
    ),
    "vulnerability_sla_breach_date": (
        "same `policy` decoration, expr "
        "`COALESCE(vulnerability_due_date, scan_first_detected_date + window)`. "
        "Mode=FILL means provenance varies PER ROW — some rows carry an "
        "ETL-written value, others a decoration-written one."
    ),
}

#: The correct replacement for a deny-listed read: compute the deadline from the
#: key + the row's own anchor, so the tenant's CURRENT policy binds.
DENYLIST_REPLACEMENT = (
    "v.scan_first_detected_date\n"
    "        + ({{sla_window_by_severity[v.severity]}})::int * INTERVAL '1 day'"
)

#: Which binder form a SHAPE takes. Derived from binder.py::bind_entry's four
#: substitution passes — NOT invented here.
SHAPE_FORM: Dict[str, str] = {
    "ordered-enum": "{{key.at_or_above}}",
    "key-map": "{{key[t.column]}}",
    "scope-map": "{{key[t.column]}}",
    "routing-map": "{{key[t.column]}}",
    "selector-list": "{{key}}",
    "scalar": "{{key}}",
    "bool": "{{#toggle key}}…{{/toggle}}",
    "module-toggle": "{{#toggle key}}…{{/toggle}}",
    "time-range": "{{key}}",
}

#: Which SQL shapes should reach for a key. Keyed by SHAPE, so a new key inherits
#: guidance automatically instead of needing a hand-written row.
SHAPE_USAGE: Dict[str, str] = {
    "ordered-enum": "severity/criticality filters in WHERE, and CASE ordering",
    "key-map": "per-severity windows/thresholds — arithmetic in WHERE or SELECT",
    "scope-map": "per-scope override; renders its ABSENT branch when unset",
    "routing-map": "routing/notification targets in SELECT — rarely in corpus SQL",
    "selector-list": "set membership: `= ANY(...)` / `<> ALL(...)`",
    "scalar": "a numeric/string comparison in WHERE",
    "bool": "include/exclude a pre-authored block — never a bare literal",
    "module-toggle": "include/exclude a whole module block",
    "time-range": "schedule/quiet-window; almost never in corpus SQL",
}


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"ERROR: cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _torana_root() -> Path:
    root = os.environ.get("TORANA_ROOT")
    if root and Path(root).is_dir():
        return Path(root)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pantheon-data-transformers").is_dir():
            return parent
    raise SystemExit("ERROR: cannot locate TORANA_ROOT")


def load_registries() -> Tuple[Any, Any]:
    """Load both snapshots and PROVE they still describe the same key set."""
    root = _torana_root()
    snap = _load(
        root / "pantheon-data-transformers/pantheon_transformers/vm_catalog"
        / "_vocabulary_snapshot.py", "_vocab_snapshot")
    keys = _load(
        root / "pantheon-program-framework/src/pantheon_program_framework"
        / "vm_content/vocabulary_keys.py", "_vocab_keys")

    a, b = set(snap.VOCABULARY_KEYS), set(keys.LEGAL_VOCAB_KEYS)
    if a != b:
        raise SystemExit(
            "ERROR: the two vocabulary registries have DIVERGED — refusing to "
            "generate a contract from disagreeing sources.\n"
            f"  only in vm_catalog snapshot : {sorted(a - b)}\n"
            f"  only in vm_content keys     : {sorted(b - a)}\n"
            "Regenerate both from the canonical registry before continuing."
        )
    missing = sorted(k for k in a if k not in snap.CONSERVATIVE_DEFAULTS)
    if missing:
        raise SystemExit(
            f"ERROR: keys with no conservative default: {missing}. A key absent "
            "from CONSERVATIVE_DEFAULTS renders as the literal string 'None'."
        )
    return snap, keys


def _fmt_default(value: Any, is_null_default: bool) -> str:
    if value is None:
        return "`null` *(canonically unset)*" if is_null_default else "`null`"
    if isinstance(value, bool):
        return f"`{str(value).upper()}`"
    if isinstance(value, (list, tuple)):
        if not value:
            return "`[]` *(empty — widest scope)*"
        return "`" + ", ".join(str(v) for v in value) + "`"
    if isinstance(value, dict):
        return "`" + ", ".join(f"{k}={v}" for k, v in value.items()) + "`"
    return f"`{value}`"


def _binder_form(key: str, shape: str, verbs: List[str]) -> str:
    """The form to EMIT for this key — the single most load-bearing column."""
    if key in getattr(_binder_form, "_na", ()):
        return "⛔ **never emit**"
    if shape == "ordered-enum" and "at_or_above" in verbs:
        return f"`{{{{{key}.at_or_above}}}}`"
    base = SHAPE_FORM.get(shape, "{{key}}")
    return "`" + base.replace("key", key) + "`"


def _not_applicable(root: Path) -> Dict[str, str]:
    """Read NOT_APPLICABLE_KEYS from the binder rather than restating it."""
    text = (root / "pantheon-data-transformers/pantheon_transformers/vm_catalog"
            / "binder.py").read_text()
    out: Dict[str, str] = {}
    marker = "NOT_APPLICABLE_KEYS: Dict[str, str] = {"
    if marker in text:
        body = text.split(marker, 1)[1].split("\n}", 1)[0]
        for line in body.splitlines():
            line = line.strip()
            if line.startswith('"') and line.endswith("): ("):
                out[line.split('"')[1]] = "blocked — see binder.py"
            elif line.startswith('"') and '": (' in line:
                out[line.split('"')[1]] = "blocked — see binder.py"
    return out


def build(snap, keys) -> str:
    root = _torana_root()
    na = _not_applicable(root)
    _binder_form._na = tuple(na)

    verbs_by_key: Dict[str, List[str]] = keys.LEGAL_RENDER_VERBS_BY_KEY
    meanings: Dict[str, str] = getattr(keys, "VOCAB_MEANINGS", {})
    shapes: Dict[str, str] = snap.SHAPES
    defaults: Dict[str, Any] = snap.CONSERVATIVE_DEFAULTS
    nulls = set(getattr(snap, "KEYS_WITH_NULL_DEFAULT", set()))
    all_keys = sorted(snap.VOCABULARY_KEYS)

    L: List[str] = []
    add = L.append

    add("<!-- GENERATED FILE — DO NOT EDIT BY HAND. -->")
    add("<!-- Regenerate: python3 scripts/generate_vocabulary_contract.py -->")
    add("")
    add("# Vocabulary contract — the generator's reference before writing any SQL")
    add("")
    add("**Generated** from the two live registries. Hand-edits are discarded.")
    add("")
    add("| Source | What it supplies |")
    add("|---|---|")
    add("| `pantheon-data-transformers/.../vm_catalog/_vocabulary_snapshot.py` | "
        "conservative defaults, shapes |")
    add("| `pantheon-program-framework/.../vm_content/vocabulary_keys.py` | "
        "legal render verbs, meanings |")
    add("| `pantheon-data-transformers/.../vm_catalog/binder.py` | "
        "substitution order, `NOT_APPLICABLE_KEYS` |")
    add("")
    add(f"**{len(all_keys)} keys.** Both registries verified identical at "
        "generation time — this script refuses to emit if they diverge.")
    add("")
    add("---")
    add("")

    # ── The rule that comes before the table ────────────────────────────────
    add("## 1. Tenant-neutrality — the precondition, not a nice-to-have")
    add("")
    add("Every value encoding a tenant's **policy** — risk appetite, SLA windows, "
        "which statuses count as open — is a **placeholder**, bound per tenant at "
        "deployment. One SQL serves every tenant.")
    add("")
    add("`severity IN ('Critical','High')` embeds one customer's risk appetite as "
        "though it were a fact about the world. It passes reachability, it parses, "
        "and it is **wrong** — and the defect surfaces only at deployment, when the "
        "policy layer has nothing to bind.")
    add("")

    # ── Syntax ──────────────────────────────────────────────────────────────
    add("## 2. TWO syntaxes over ONE key set — getting this wrong fails at EXPLAIN")
    add("")
    add("| | catalog / corpus SQL ← **this skill** | app-template artifacts |")
    add("|---|---|---|")
    add("| Syntax | `{{key}}` `{{key.at_or_above}}` `{{key[expr]}}` "
        "`{{#toggle key}}` | `{{vocab:vm.<cat>.<sub>.<key>[.<verb>]}}` |")
    add("| Renderer | `vm_catalog/binder.py` → `bind_entry()` | "
        "`vm_content/vocab_render.py` |")
    add("")
    add("⚠️ The **key sets are identical**; the **syntaxes are not.** Corpus SQL uses "
        "the **bare binder form**. A `{{vocab:…}}` placeholder in corpus SQL is not "
        "resolved by the binder, survives binding, and reaches EXPLAIN as a syntax "
        "error. This has shipped once already.")
    add("")
    add("### Binder substitution order (`bind_entry`)")
    add("")
    add("1. blocks — `{{#toggle key}}…{{/toggle}}`, `{{#unless}}`, `{{#if}}`")
    add("2. ordered-enum — `{{key.at_or_above}}` → "
        "`SELECT unnest(ARRAY['Critical','High',…])`")
    add("3. key-map — `{{key[t.col]}}` → `CASE t.col WHEN … END`")
    add("4. scalar / selector-list — `{{key}}`; a SET renders as "
        "`SELECT unnest(ARRAY[…])`")
    add("5. `{{ tenant_id }}` / `{{tenant_id}}`")
    add("")
    add("Blocks are stripped **first** so placeholders inside a dropped block do not "
        "survive.")
    add("")
    add("⚠️ **A set renders as a set-returning SUBQUERY, not a bare `ARRAY[…]`** "
        "(SUPPLY_GRAPH_SPEC § 3.12 G-d). A bare array is valid only after "
        "`= ANY`/`<> ALL`; after `IN` Postgres rejects it "
        "(`operator does not exist: character varying = text[]`). The subquery form "
        "is valid after **all three**, so a set-valued key is executable wherever an "
        "author puts it. ⛔ An EMPTY set has no executable rendering at all — the "
        "binder REFUSES it; guard the clause with `{{#if key}}…{{/if}}`.")
    add("")

    # ── Three constraints ───────────────────────────────────────────────────
    add("## 3. Three constraints that silently break generated SQL")
    add("")
    add("1. **The key must be declared on the entry.** `bind_entry` only resolves "
        "keys listed in `entry.vocabulary_keys`. An undeclared key's placeholder "
        "survives binding.")
    if na:
        add(f"2. **`NOT_APPLICABLE_KEYS` must never be emitted** "
            f"({', '.join('`' + k + '`' for k in sorted(na))}). `bind_entry` "
            "**raises** rather than binding, because binding would silently return "
            "zero rows.")
    else:
        add("2. **`NOT_APPLICABLE_KEYS` must never be emitted.** Currently empty.")
    add(f"3. **Every key has a conservative default** ({len(defaults)}/"
        f"{len(all_keys)}, enforced by a startup assertion). Generated SQL must be "
        "correct **with defaults applied** — that is the unconfigured tenant's "
        "experience.")
    add("")

    # ── Deny list ───────────────────────────────────────────────────────────
    add("## 4. ⛔ DENY-LIST — policy-derived columns that must NEVER be read")
    add("")
    add("| Column | Why |")
    add("|---|---|")
    for col, why in DENYLIST.items():
        add(f"| `{col}` | {why} |")
    add("")
    add("**The vocabulary key always wins** — it is applied at bind time, while the "
        "column carries whatever policy was in force when the decoration last ran.")
    add("")
    add("```sql")
    add("-- ⛔ WRONG. Reachable, populated, passes every gate check, and silently")
    add("--    applies a stale policy.")
    add("WHERE v.vulnerability_due_date < NOW()")
    add("")
    add("-- ✅ RIGHT. Compute the deadline from the key + the row's own anchor.")
    add(f"WHERE {DENYLIST_REPLACEMENT} < NOW()")
    add("```")
    add("")
    add("⚠️ *\"Which vulnerabilities are overdue?\"* has an obvious wrong answer that "
        "looks completely correct. This is the single most likely trap.")
    add("")

    # ── Three-way test ──────────────────────────────────────────────────────
    add("## 5. The three-way literal test — do NOT template everything")
    add("")
    add("Before templating any literal, decide which of three it is:")
    add("")
    add("| Kind | Example | Action |")
    add("|---|---|---|")
    add("| **tenant policy** | `severity IN ('Critical','High')` | **bind** it |")
    add("| **definitional** | \"12-month trend\" — the window IS the question | "
        "**keep** the literal |")
    add("| **reporting window** | caller wants 7 vs 90 days | **expose** it, do "
        "not bind |")
    add("")
    add("⚠️ **Over-templating is its own failure.** A query where everything is a "
        "variable answers nothing specific and forces every caller to supply 20 "
        "values. A synthesized OUTPUT label (`'missing_team'`, `'verified'`) is "
        "never a policy literal — it is the query's own vocabulary.")
    add("")
    add("**Decision aid** — ask: *would two reasonable tenants disagree about this "
        "value, AND does the question stay the same question if they do?* Both yes "
        "→ bind. If changing it changes the question → definitional, keep it.")
    add("")

    # ── The table ───────────────────────────────────────────────────────────
    add("## 6. The key table")
    add("")
    add("`verbs` is the **closed** legal set for that key — a verb not listed is "
        "rejected. An **empty** verb list means the key is only ever a bare form "
        "(scalar, block toggle, or key-map); appending a verb to it produces an "
        "unbound hole.")
    add("")
    add("| key | meaning | value domain | conservative default | legal verbs | "
        "emit this form | use in |")
    add("|---|---|---|---|---|---|---|")
    for k in all_keys:
        shape = shapes.get(k, "scalar")
        verbs = verbs_by_key.get(k, [])
        default = defaults.get(k)
        mean = meanings.get(k, "").replace("|", "\\|")
        vtxt = ", ".join(f"`{v}`" for v in verbs) if verbs else "— *(none)*"
        form = _binder_form(k, shape, verbs)
        use = SHAPE_USAGE.get(shape, "")
        if k in na:
            use = "⛔ **NOT APPLICABLE — never emit**"
        add(f"| `{k}` | {mean} | {shape} | "
            f"{_fmt_default(default, k in nulls)} | {vtxt} | {form} | {use} |")
    add("")

    # ── Traps ───────────────────────────────────────────────────────────────
    add("## 7. Named traps")
    add("")
    sla_verbs = verbs_by_key.get("sla_window_by_severity", [])
    if not sla_verbs:
        add("- **`sla_window_by_severity` has NO legal verbs.** It is a dict and "
            "takes the **key-map form** `{{sla_window_by_severity[t.severity]}}`. "
            "Emitting `{{sla_window_by_severity.at_or_above}}` is plausible-looking "
            "and wrong — the binder leaves the hole unbound and it reaches EXPLAIN.")
    noverb = sorted(k for k in all_keys if not verbs_by_key.get(k))
    add(f"- **{len(noverb)} of {len(all_keys)} keys accept NO verb at all**: "
        + ", ".join(f"`{k}`" for k in noverb) + ". Check the table before "
        "suffixing anything.")
    add("- **Binding can CREATE a masking risk.** "
        "`COALESCE(unreachable_col, <conservative default>)` returns the "
        "platform's assumption as though it were measured. Bind the policy; do "
        "not paper over an unreachable column with its default.")
    add("- **A default must render correct SQL.** Generated SQL is judged with "
        "defaults applied — that is what an unconfigured tenant runs.")
    add("")

    add("## 8. Verify, do not predict")
    add("")
    add("```bash")
    add("python3 scripts/reachability_gate.py check --file /tmp/candidate.sql \\")
    add("    --scope platform")
    add("```")
    add("")
    add("The gate binds with the platform's **own** binder and conservative "
        "defaults, then re-parses. `BIND_ERROR` / `UNRESOLVED_PLACEHOLDER` means "
        "the placeholder is wrong — an authoring defect, not a SQL defect.")
    add("")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=None,
                    help="output path (default: ../references/vocabulary-contract.md)")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed file is stale (CI gate)")
    args = ap.parse_args()

    out = (Path(args.out) if args.out
           else Path(__file__).resolve().parent.parent / "references"
           / "vocabulary-contract.md")

    snap, keys = load_registries()
    text = build(snap, keys)

    if args.check:
        if not out.is_file():
            print(f"STALE: {out} does not exist", file=sys.stderr)
            return 1
        if out.read_text() != text:
            print(f"STALE: {out} differs from the registries. Regenerate:\n"
                  f"  python3 {Path(__file__).name}", file=sys.stderr)
            return 1
        print(f"OK: {out} is current ({len(snap.VOCABULARY_KEYS)} keys)")
        return 0

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(f"wrote {out}  ({len(snap.VOCABULARY_KEYS)} keys, {len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
