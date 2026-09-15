#!/usr/bin/env python3
"""
vm_program.py — the torana-vm skill's reconcile engine (terraform-style IaC for a
Torana VM/AppSec program).

Reads a declarative `artifacts.yaml` and reconciles a Torana workspace to match it —
workspace, policy-doc ingest, transformers, detection rules, dashboards+widgets,
KPI/attention cards, alert routes, schedulers — by driving the `torana` CLI. Verbs:

    vm_program.py --file <path/to/artifacts.yaml> plan     # diff desired vs live (no writes)
    vm_program.py --file <path/to/artifacts.yaml> apply    # create/update to match the file
    vm_program.py --file <path/to/artifacts.yaml> apply --prune   # + delete what's removed
    vm_program.py --file <path/to/artifacts.yaml> prune    # delete live artifacts not in the file
    vm_program.py --file <path/to/artifacts.yaml> import --out live.yaml   # live workspace -> yaml
    vm_program.py --file <path/to/artifacts.yaml> assess   # ASSESS: operational signals + drift -> health report
    vm_program.py --file <path/to/artifacts.yaml> delete   # tear the program down

Options: --yes (skip confirmations) · --dry-run (print CLI calls, hit nothing) ·
--workspace-id UUID (adopt an existing workspace) · --out PATH (import/assess output) ·
--window-days N (assess noisy-rule lookback).

PROVENANCE: this file is a snapshot of
`pantheon-playground/scripts/vm_workspace.py` (the canonical engine, which also runs
in playground "usecase mode"). Keep them in sync — edit the engine there, re-copy here.
The `usecases/` tree, `build`/`load-data`/`clear-data`/`refresh`/fleet-`list` commands,
and `_discover_usecases()` are PLAYGROUND-ONLY and inert in the skill (file mode never
touches them). The skill always invokes `--file` mode.

Original playground usage (still supported, unused by the skill):
    vm_program.py <usecase-name> apply|delete|list  (folder under usecases/)

Design notes
------------
* CREATE order (dependency-respecting):
    workspace -> policy -> transformers(topological) -> rules -> dashboards
    -> kpis -> attention_cards -> routes -> schedulers
* DELETE order is the strict reverse so nothing is removed while a dependent
  still references it.
* Idempotent: created IDs are tracked in a per-use-case state file
  (usecases/<usecase>/.state.json). Re-running `apply` updates in place.
* Named references (agents/playbooks/workflows for routes; transformers/rules for
  schedulers) are resolved at apply time, so the manifest stays portable.
* Program-prefix naming (single convention: '<prefix>_'). Every artifact created for a
  use case is stamped with that program's short prefix — vm-operations→`vmops_`,
  ciso-posture→`ciso_`, developer-operations→`devops_`, grc-compliance→`grc_`,
  zero-day-response→`zd_`. This applies UNIFORMLY to transformers, rules, dashboards,
  KPI cards, attention cards, alert routes, and schedulers, so any artifact is
  identifiable to its program at a glance. Transformers additionally NEED the prefix
  because they compile to dbt models in a tenant-global namespace (two workspaces that
  both define `scan_coverage_by_criticality` would otherwise collide); the prefix makes
  the model name globally unique and view references in dependent SQL are rewritten to
  match. `list` verifies every live artifact carries its program prefix.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
USECASES_DIR = SCRIPT_DIR.parent / "usecases"

UUID_RE = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")

# Phases for apply (create) — delete walks these in reverse.
CREATE_PHASES = [
    "workspace",
    "policy",
    "transformers",
    "rules",
    "dashboards",
    "kpis",
    "attention_cards",
    "routes",
    "schedulers",
]


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------
def info(msg: str) -> None:
    print(f"  [info]  {msg}")


def ok(msg: str) -> None:
    print(f"  [ok]    {msg}")


def warn(msg: str) -> None:
    print(f"  [warn]  {msg}")


def err(msg: str) -> None:
    print(f"  [error] {msg}", file=sys.stderr)
    sys.exit(1)


def section(title: str) -> None:
    print()
    print(f"── {title} " + "─" * max(0, 56 - len(title)))


# ---------------------------------------------------------------------------
# State file (per use case)
# ---------------------------------------------------------------------------
class State:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, Any] = {}
        if path.exists():
            try:
                self.data = json.loads(path.read_text())
            except Exception:
                self.data = {}

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, val: Any) -> None:
        self.data[key] = val
        self.path.write_text(json.dumps(self.data, indent=2))

    def delete(self, key: str) -> None:
        if key in self.data:
            del self.data[key]
            self.path.write_text(json.dumps(self.data, indent=2))

    def items_with_prefix(self, prefix: str) -> list[tuple[str, Any]]:
        return [(k, v) for k, v in self.data.items() if k.startswith(prefix)]

    def clear(self) -> None:
        self.data = {}
        self.path.write_text("{}\n")


# ---------------------------------------------------------------------------
# torana CLI wrapper
# ---------------------------------------------------------------------------
class Torana:
    # The CLI binary. torana-skill's bootstrap installs the wheel into a self-managed
    # venv and exports $TORANA (the binary path) without necessarily putting it on PATH,
    # so honour $TORANA when set; fall back to bare `torana` on PATH (dev/host).
    BIN = os.environ.get("TORANA", "torana")

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def run(self, args: list[str], *, input_file: Optional[Path] = None,
            check: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
        cmd = [self.BIN, *args]
        if self.dry_run:
            print(f"  [dry-run] {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.run(cmd, capture_output=capture, text=True, check=check)

    def json(self, args: list[str]) -> Any:
        """Run a command expected to emit JSON; return parsed or None."""
        if self.dry_run:
            print(f"  [dry-run] {self.BIN} {' '.join(args)}")
            return None
        proc = subprocess.run([self.BIN, *args], capture_output=True, text=True)
        try:
            return json.loads(proc.stdout)
        except Exception:
            return None


def _parse_labeled_json(text: str, label: str) -> Any:
    """The torana CLI prints key-value tables like `DEPENDENCIES [..]` / `TICK {..}`.
    Return the JSON value that follows `label` on its line, or None."""
    if not text:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(label):
            rest = stripped[len(label):].strip()
            try:
                return json.loads(rest)
            except Exception:
                return None
    return None


def _parse_field(text: str, field: str) -> str:
    """Pull a top-level scalar field from CLI JSON output (or a `FIELD value` line).
    Returns '' if not found."""
    if not text:
        return ""
    m = re.search(r'"' + re.escape(field) + r'"\s*:\s*"?([^",}\s]+)', text)
    if m:
        return m.group(1)
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith(field.upper()):
            return s[len(field):].strip()
    return ""


def extract_id(text: str) -> str:
    """Pull the first 'id': '<uuid>' from CLI JSON, else any bare UUID."""
    if not text:
        return ""
    m = re.search(r'"id"\s*:\s*"' + UUID_RE.pattern + '"', text)
    if m:
        return m.group(1)
    m = UUID_RE.search(text)
    return m.group(1) if m else ""


def write_tmp_yaml(obj: dict) -> Path:
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    yaml.safe_dump(obj, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    f.close()
    return Path(f.name)


def write_tmp_json(obj: dict) -> Path:
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(obj, f)
    f.close()
    return Path(f.name)


# ---------------------------------------------------------------------------
# Identity / auth (torana auth me) — every command prints who is logged in, and
# enforces the right identity per command (no silent switching).
#
# Why two identities: workspace artifacts (apply/delete/list) are TENANT-scoped
# and must be created as a tenant user. SDG data ops (load-data/clear-data) drive
# the replay control plane, which needs SUPER-ADMIN. The script never logs in/out
# or escalates — it checks `torana auth me`, prints it, and hard-blocks with the
# exact fix if the active identity is wrong for the command.
# ---------------------------------------------------------------------------
class Identity:
    def __init__(self, email: str, roles: list[str], tenant_id: str, base_url: str):
        self.email = email
        self.roles = roles or []
        self.tenant_id = tenant_id
        self.base_url = base_url

    @property
    def is_super_admin(self) -> bool:
        return "super_admin" in self.roles

    @property
    def is_tenant_user(self) -> bool:
        # A real tenant operator: has a tenant role and is NOT a super admin.
        return (not self.is_super_admin) and bool(
            {"tenant_user", "tenant_admin"} & set(self.roles)
        )

    def banner(self) -> str:
        role = "super_admin" if self.is_super_admin else ", ".join(self.roles) or "?"
        return (f"  logged in as: {self.email or '?'}  "
                f"[roles: {role}]\n"
                f"  tenant_id:    {self.tenant_id or '?'}\n"
                f"  platform:     {self.base_url or 'http://localhost'}")


def whoami(tor: "Torana") -> Optional[Identity]:
    """Return the current torana identity, or None if not logged in."""
    data = tor.json(["auth", "me", "--format", "json"])
    if not isinstance(data, dict) or not data.get("email"):
        return None
    return Identity(
        email=data.get("email", ""),
        roles=data.get("roles", []),
        tenant_id=data.get("tenant_id", ""),
        base_url=data.get("base_url", "http://localhost"),
    )


# ---------------------------------------------------------------------------
# Name resolution (agents / playbooks / workflows / suites)
# ---------------------------------------------------------------------------
class Resolver:
    """Resolves human-readable names to IDs at apply time. Cached per run."""

    def __init__(self, tor: Torana):
        self.tor = tor
        self._agents: Optional[dict[str, str]] = None
        self._playbooks: Optional[dict[str, str]] = None
        self._workflows: Optional[dict[str, str]] = None

    def _index(self, args: list[str]) -> dict[str, str]:
        data = self.tor.json(args) or []
        items = data if isinstance(data, list) else (
            data.get("items") or data.get("agents") or data.get("playbooks")
            or data.get("workflows") or []
        )
        out: dict[str, str] = {}
        for it in items:
            name = it.get("name")
            _id = it.get("id")
            if name and _id:
                out[name] = _id
        return out

    def agent(self, name: str) -> str:
        if self._agents is None:
            self._agents = self._index(["agents", "list", "--all", "--raw", "--format", "json"])
        return self._agents.get(name, "")

    def playbook(self, name: str) -> str:
        if self._playbooks is None:
            self._playbooks = self._index(["playbooks", "list", "--raw", "--format", "json"])
        return self._playbooks.get(name, "")

    def invalidate_playbooks(self) -> None:
        """Drop the memoized playbook index so a later lookup re-fetches. Call after
        creating new playbooks, before routes resolve their playbook destinations."""
        self._playbooks = None

    def workflow(self, name: str) -> str:
        if self._workflows is None:
            self._workflows = self._index(["workflows", "list", "--raw", "--format", "json"])
        return self._workflows.get(name, "")

    def by_type(self, dest_type: str, name: str) -> str:
        return {"agent": self.agent, "playbook": self.playbook,
                "workflow": self.workflow}.get(dest_type, lambda _n: "")(name)


# ---------------------------------------------------------------------------
# Topological sort for transformers (by depends_on)
# ---------------------------------------------------------------------------
def topo_sort(transformers: list[dict]) -> list[dict]:
    by_key = {t["key"]: t for t in transformers}
    ordered: list[dict] = []
    seen: set[str] = set()
    temp: set[str] = set()

    def visit(key: str):
        if key in seen:
            return
        if key in temp:
            raise ValueError(f"cyclic transformer dependency at '{key}'")
        temp.add(key)
        for dep in by_key.get(key, {}).get("depends_on", []) or []:
            if dep in by_key:
                visit(dep)
        temp.discard(key)
        seen.add(key)
        if key in by_key:
            ordered.append(by_key[key])

    for t in transformers:
        visit(t["key"])
    return ordered


# ---------------------------------------------------------------------------
# Builder — apply / delete / list, one use case
# ---------------------------------------------------------------------------
class Builder:
    # Short, stable per-use-case prefixes. Transformers compile to dbt models in a
    # TENANT-GLOBAL namespace (not per-workspace), so two workspaces that both define
    # e.g. `scan_coverage_by_criticality` collide at dbt compile time. We namespace
    # every transformer name + destination_table with this prefix so they are globally
    # unique, and rewrite the view references in dependent SQL to match.
    PREFIXES = {
        "vm-operations": "vmops",
        "ciso-posture": "ciso",
        "developer-operations": "devops",
        "grc-compliance": "grc",
        "zero-day-response": "zd",
        "cmdb-banking-vuln-posture": "cmdbvp",
        "cmdb-banking-shadow-assets": "cmdbsa",
        "cmdb-banking-account-compliance": "cmdbac",
    }

    def __init__(self, usecase: str, spec: dict, usecase_dir: Path, state: State,
                 tor: Torana, resolver: Resolver, workspace_id: str = ""):
        self.usecase = usecase
        self.spec = spec
        self.dir = usecase_dir
        self.state = state
        self.tor = tor
        self.resolver = resolver
        self.cli_workspace_id = workspace_id
        self.ws_id: str = ""
        # Prefix for global uniqueness of transformer/dbt-model names.
        self.prefix = self.PREFIXES.get(usecase, re.sub(r"[^a-z0-9]+", "", usecase.lower())[:8])
        # Map original transformer destination_table -> namespaced name. Rules/widgets/
        # KPIs/sibling-transformers reference views by destination_table; we rewrite those.
        self.view_rename: dict[str, str] = {}
        for t in spec.get("transformers", []):
            dt = t.get("destination_table", t["name"])
            self.view_rename[dt] = f"{self.prefix}_{dt}"

    def _ns(self, name: str) -> str:
        """Namespace a transformer/destination-table name with the use-case prefix."""
        return f"{self.prefix}_{name}"

    def _rewrite_view_refs(self, sql: str) -> str:
        """Rewrite references to transformer view names → their namespaced form.
        Whole-word (identifier-boundary) substitution so only the view tokens change."""
        out = sql
        # Replace longest names first to avoid partial-overlap issues.
        for original in sorted(self.view_rename, key=len, reverse=True):
            out = re.sub(rf"(?<![\w.]){re.escape(original)}(?![\w])",
                         self.view_rename[original], out)
        return out

    def _label(self, name: str) -> str:
        """Return an artifact's CLEAN, user-facing display/identity name — NO program prefix.
        Workspace-scoped artifacts (rules, dashboards, widgets, KPIs, attention cards, routes,
        schedulers) live in the program's OWN workspace, so the workspace is the ownership
        boundary and the name is the value shown in the UI — it must stay clean. (Only
        transformer destination_tables keep the prefix, via _ns, because they share a
        tenant-global table namespace and would otherwise collide across programs.) Any
        author-supplied program prefix is stripped so a re-authored name never carries a
        stale one. read_live_model reconciles these types by clean name within the program's
        workspace — see references/plan-apply.md 'ownership boundary'."""
        n = name.strip()
        for sep in (f"{self.prefix}_", f"{self.prefix}."):
            if n.lower().startswith(sep.lower()):
                n = n[len(sep):]
                break
        return n

    # ----- PLAN / READ-LIVE (terraform-style diff; NO writes) --------------

    _ROUTE_FILTERS = ("severity_levels", "source_rule_ids", "source_suite_ids",
                      "required_tags")

    @classmethod
    def _route_sig(cls, d: dict) -> str:
        """Canonical, order-independent signature of a route's OPERATIONAL config —
        the fields a user authors and the applier sends. Excludes destination_config's
        resolved id (environment-specific) but keeps destination_type. `match_all` is
        derived the SAME way on both sides (explicit, or implied by having no filter) so
        an unchanged route yields identical desired/live signatures. Used to diff + to
        decide update-on-exist."""
        def norm(v):
            return sorted(v) if isinstance(v, list) else v
        has_filter = any(d.get(f) for f in cls._ROUTE_FILTERS)
        # `enabled`/`stop_on_match` may be explicitly None in the YAML (key present,
        # value null) — coalesce None to the applier's default so desired == live.
        en, som = d.get("enabled"), d.get("stop_on_match")
        sig = {
            "enabled": True if en is None else bool(en),
            "priority": d.get("priority") if d.get("priority") is not None else 10,
            "stop_on_match": False if som is None else bool(som),
            "matching_operator": d.get("matching_operator", "all"),
            "max_executions_per_hour": d.get("max_executions_per_hour", 200),
            "match_all": bool(d.get("match_all")) or not has_filter,
            "destination_type": d.get("destination_type", ""),
        }
        for f in cls._ROUTE_FILTERS:
            sig[f] = norm(d.get(f) or [])
        return json.dumps(sig, sort_keys=True)

    @staticmethod
    def _canonical_sql(sql: str) -> str:
        """Normalize SQL for diffing: strip comments, collapse whitespace. Both plan
        sides are already view-ref-rewritten (the applier rewrites on write; the live
        record stores that form), so only comment/whitespace normalization is needed."""
        s = re.sub(r"--[^\n]*", "", sql or "")
        s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
        return re.sub(r"\s+", " ", s).strip()

    def resolve_ws(self) -> bool:
        """Resolve ws_id for a read-only op (plan) WITHOUT applying: local state cache
        first (fast path), else look up the workspace by name (reconstruct-from-live)."""
        if self.cli_workspace_id:
            self.ws_id = self.cli_workspace_id
            return True
        wid = self.state.get("workspace_id", "")
        if wid:
            data = self.tor.json(["workspace", wid, "get", "--format", "json"])
            if isinstance(data, dict) and data.get("id"):
                self.ws_id = wid
                return True
        name = (self.spec.get("workspace", {}) or {}).get("name", self.usecase)
        for w in (self.tor.json(["workspaces", "list", "--format", "json", "--raw"]) or []):
            if isinstance(w, dict) and w.get("name") == name:
                self.ws_id = w["id"]
                return True
        return False

    def read_live_model(self) -> tuple:
        """Read the live workspace (scoped by program prefix = ownership boundary § 3.3.4)
        into a normalized model, via the torana CLI. Returns ``(model, unreadable)`` —
        ``unreadable`` names kinds whose live read FAILED (CLI error/timeout), so plan can
        skip them instead of reporting false creates. ``Torana.json`` returns None on
        failure vs [] for genuinely-empty, which is how we tell them apart. SQL-bearing
        core types first (transformers, rules); other types added incrementally."""
        ws, pfx = self.ws_id, self.prefix + "_"
        model: dict[str, dict] = {"transformers": {}, "rules": {}, "kpis": {},
                                  "attention": {}, "schedulers": {}, "dashboards": {},
                                  "routes": {}}
        unreadable: set = set()

        tl = self.tor.json(["transformers", "list", "--workspace-id", ws,
                            "--format", "json", "--raw"])
        if tl is None:
            unreadable.add("transformer")
        else:
            for t in tl:
                name = str(t.get("name", ""))
                if not name.startswith(pfx):
                    continue
                full = self.tor.json(["transformer", t["id"], "get", "--format", "json"]) or {}
                full = full.get("data", full) if isinstance(full, dict) else {}
                model["transformers"][name] = {
                    "id": t["id"],
                    "destination_table": full.get("destination_table"),
                    "sql": self._canonical_sql(full.get("custom_sql") or ""),
                }

        rl = self.tor.json(["rules", "list", "--workspace-id", ws,
                            "--format", "json", "--raw"])
        if rl is None:
            unreadable.add("rule")
        else:
            for r in rl:
                name = str(r.get("name", ""))
                # Workspace-scoped ownership: every rule in the program's own workspace is
                # program-owned. Names are clean (no prefix) — match by clean name.
                full = self.tor.json(["rule", r["id"], "get", "--format", "json"]) or {}
                full = full.get("data", full) if isinstance(full, dict) else {}
                model["rules"][name] = {
                    "id": r["id"],
                    "sql": self._canonical_sql(full.get("sql_command") or ""),
                }

        # KPIs / attention live in the landing-page zones (read via the fixed
        # `kpi list` / `attention list`). Identity = the applier's INDEX id
        # (`{prefix}_kpi_{i}` / `{prefix}_att_{i}`), so plan matches desired[i] ↔ live i
        # and accurately predicts what apply (a whole-zone rewrite) would do.
        kl = self.tor.json(["workspace", ws, "kpi", "list", "--format", "json", "--raw"])
        if kl is None:
            unreadable.add("kpi")
        else:
            for k in kl:
                kid = str(k.get("id", ""))
                if not kid.startswith(pfx + "kpi_"):
                    continue
                ds = k.get("data_source") or {}
                sql = ds.get("query") if isinstance(ds, dict) else ds
                model["kpis"][kid] = {"sql": self._canonical_sql(sql or "")}

        al = self.tor.json(["workspace", ws, "attention", "list", "--format", "json", "--raw"])
        if al is None:
            unreadable.add("attention")
        else:
            for a in al:
                aid = str(a.get("id", ""))
                if not aid.startswith(pfx + "att_"):
                    continue
                cond = a.get("condition") or {}
                sql = cond.get("query") if isinstance(cond, dict) else cond
                model["attention"][aid] = {"sql": self._canonical_sql(sql or "")}

        # Schedulers (scheduled tasks) — identity = the namespaced task NAME
        # (`<prefix>_<sched name>`, from _label). The reconcilable field is the
        # cron string (`schedule_expression`); task_type/target are structural and
        # not diffed (a target change is a delete+recreate, not an in-place update).
        sl = self.tor.json(["schedulers", "tasks", "--workspace-id", ws,
                            "--all", "--format", "json", "--raw"])
        if sl is None:
            unreadable.add("scheduler")
        else:
            for s in sl:
                name = str(s.get("name", ""))
                # Workspace-scoped ownership — clean names, no prefix filter.
                model["schedulers"][name] = {
                    "id": s["id"],
                    "schedule_expression": (s.get("schedule_expression") or "").strip(),
                    "task_type": s.get("task_type", ""),
                }

        # Dashboards + their widgets. Identity: dashboard by namespaced name, widget by
        # namespaced name WITHIN a dashboard. A widget's SQL lives in its linked query
        # (`query <query_id> get` → sql_command), so we resolve it per widget. Widgets
        # are diffed on SQL + widget_type (the load-bearing fields); display_config is
        # left to the applier (the backend normalizes it → would cause false churn).
        dl = self.tor.json(["dashboards", "list", "--workspace-id", ws,
                            "--all", "--format", "json", "--raw"])
        if dl is None:
            unreadable.add("dashboard")
        else:
            qsql_cache: dict = {}
            for d in dl:
                dname = str(d.get("name", ""))
                # Workspace-scoped ownership — clean names, no prefix filter.
                full = self.tor.json(["dashboard", d["id"], "get", "--format", "json"]) or {}
                full = full.get("data", full) if isinstance(full, dict) else {}
                wmap: dict = {}
                for w in (full.get("widgets") or []):
                    wname, qid = str(w.get("name", "")), w.get("query_id")
                    if qid and qid not in qsql_cache:
                        q = self.tor.json(["query", qid, "get", "--format", "json"]) or {}
                        q = q.get("data", q) if isinstance(q, dict) else {}
                        qsql_cache[qid] = self._canonical_sql(q.get("sql_command") or "")
                    wmap[wname] = {
                        "id": w.get("id"),
                        "query_id": qid,
                        "widget_type": w.get("widget_type", ""),
                        "sql": qsql_cache.get(qid, ""),
                    }
                model["dashboards"][dname] = {"id": d["id"], "widgets": wmap}

        # Alert routes. Identity: namespaced route name. Diffed on the operational
        # signature (_route_sig) — priority/enabled/filters/destination_type — not the
        # resolved destination id (environment-specific).
        rr = self.tor.json(["alert-routes", "routing-rules", "--workspace-id", ws,
                            "--all", "--format", "json", "--raw"])
        if rr is None:
            unreadable.add("route")
        else:
            for r in rr:
                name = str(r.get("name", ""))
                # Workspace-scoped ownership — clean names, no prefix filter.
                model["routes"][name] = {"id": r.get("id"), "sig": self._route_sig(r)}
        return model, unreadable

    def plan(self) -> None:
        """Diff desired (artifacts.yaml, rendered to its live namespaced form) vs the
        live workspace. Prints a +create / ~update / -delete plan. Performs NO writes."""
        if not self.resolve_ws():
            err("No live workspace found for this program — run `apply` first.")
            return
        section("Plan — artifacts.yaml (desired) vs live workspace")
        live, unreadable = self.read_live_model()
        ops: list[tuple] = []

        desired_t = {self._ns(t["name"]):
                     self._canonical_sql(self._rewrite_view_refs(t["sql"].strip()))
                     for t in self.spec.get("transformers", [])}
        desired_r = {self._label(r["name"]):
                     self._canonical_sql(self._rewrite_view_refs((r.get("sql") or "").strip()))
                     for r in self.spec.get("rules", [])}
        # KPIs/attention: index-keyed to match the applier's `{prefix}_kpi_{i}` ids.
        desired_k = {f"{self.prefix}_kpi_{i}":
                     self._canonical_sql(self._rewrite_view_refs((k.get("sql") or "").strip()))
                     for i, k in enumerate(self.spec.get("kpis", []))}
        desired_a = {f"{self.prefix}_att_{i}":
                     self._canonical_sql(self._rewrite_view_refs((a.get("query") or "").strip()))
                     for i, a in enumerate(self.spec.get("attention_cards", []))}
        # Schedulers: keyed by namespaced name (matches _label / read_live_model),
        # compared on the cron string rather than SQL.
        desired_s = {self._label(s["name"]): (s.get("schedule_expression") or "").strip()
                     for s in self.spec.get("schedulers", [])}
        # Routes: keyed by namespaced name, compared on the operational signature.
        desired_ro = {self._label(r["name"]): self._route_sig(r)
                      for r in self.spec.get("routes", [])}
        # Dashboards: nested — {dash_label: {widget_label: (canonical_sql, widget_type)}}.
        desired_d: dict = {}
        for d in self.spec.get("dashboards", []):
            wmap = {}
            for w in d.get("widgets", []):
                wmap[self._label(w["name"])] = (
                    self._canonical_sql(self._rewrite_view_refs((w.get("sql") or "").strip())),
                    w.get("widget_type", ""),
                )
            desired_d[self._label(d["name"])] = wmap

        # (kind, desired-map, live-key, live-compare-field, change-reason)
        for kind, desired, livekey, cmp, reason in (
                ("transformer", desired_t, "transformers", "sql", "sql changed"),
                ("rule", desired_r, "rules", "sql", "sql changed"),
                ("kpi", desired_k, "kpis", "sql", "sql changed"),
                ("attention", desired_a, "attention", "sql", "sql changed"),
                ("scheduler", desired_s, "schedulers", "schedule_expression",
                 "schedule changed"),
                ("route", desired_ro, "routes", "sig", "config changed")):
            if kind in unreadable:
                warn(f"could not read live {kind}s (read error) — SKIPPING {kind}s in "
                     f"this plan (NOT reporting them as creates).")
                continue
            livemap = live[livekey]
            for n, val in desired.items():
                if n not in livemap:
                    ops.append(("create", kind, n, ""))
                elif val != livemap[n][cmp]:
                    ops.append(("update", kind, n, reason))
            for n in livemap:
                if n not in desired:
                    ops.append(("delete", kind, n, "not in artifacts.yaml"))

        # Dashboards + widgets (nested). Dashboard create/delete + per-widget
        # create/update/delete. Widget label carries its dashboard for readability.
        if "dashboard" in unreadable:
            warn("could not read live dashboards (read error) — SKIPPING dashboards in "
                 "this plan (NOT reporting them as creates).")
        else:
            live_d = live["dashboards"]
            for dl, wants in desired_d.items():
                if dl not in live_d:
                    ops.append(("create", "dashboard", dl, f"{len(wants)} widget(s)"))
                    continue
                livew = live_d[dl]["widgets"]
                for wl, (wsql, wtype) in wants.items():
                    if wl not in livew:
                        ops.append(("create", "widget", f"{dl} :: {wl}", ""))
                    elif wsql != livew[wl]["sql"] or wtype != livew[wl]["widget_type"]:
                        ops.append(("update", "widget", f"{dl} :: {wl}", "sql/type changed"))
                for wl in livew:
                    if wl not in wants:
                        ops.append(("delete", "widget", f"{dl} :: {wl}", "not in artifacts.yaml"))
            for dl in live_d:
                if dl not in desired_d:
                    ops.append(("delete", "dashboard", dl, "not in artifacts.yaml"))

        if not ops:
            ok("No changes — live matches artifacts.yaml.")
            return
        sym = {"create": "+", "update": "~", "delete": "-"}
        for action, kind, name, reason in ops:
            extra = f"   ({reason})" if reason else ""
            print(f"  {sym[action]} {action:6} {kind:12} {name}{extra}")
        n_c = sum(1 for o in ops if o[0] == "create")
        n_u = sum(1 for o in ops if o[0] == "update")
        n_d = sum(1 for o in ops if o[0] == "delete")
        print(f"\n  Plan: {n_c} to create, {n_u} to update, {n_d} to delete.")
        if n_d:
            warn("Deletes are destructive — run `apply --prune` to remove artifacts "
                 "no longer in artifacts.yaml.")

    def prune(self, yes: bool = False) -> None:
        """Delete live artifacts (scoped by program prefix) that are no longer in
        artifacts.yaml, in REVERSE-dependency order (rules before the transformers they
        read). KPIs/attention/pins are reconciled by apply's whole-zone landing rewrite,
        so they are NOT pruned as separate entities here. Gated: prints the deletes and
        requires confirmation (or --yes)."""
        if not self.ws_id and not self.resolve_ws():
            return
        live, unreadable = self.read_live_model()
        desired_t = {self._ns(t["name"]) for t in self.spec.get("transformers", [])}
        desired_r = {self._label(r["name"]) for r in self.spec.get("rules", [])}
        desired_s = {self._label(s["name"]) for s in self.spec.get("schedulers", [])}
        desired_d = {self._label(d["name"]) for d in self.spec.get("dashboards", [])}
        desired_dw = {self._label(d["name"]):
                      {self._label(w["name"]) for w in d.get("widgets", [])}
                      for d in self.spec.get("dashboards", [])}
        to_del: list[tuple] = []  # reverse-dependency: readers (dashboards/schedulers/
        #                            rules) before the transformers they read.
        # Dashboards/widgets first — widget SQL reads transformer views. For a KEPT
        # dashboard, drop only its orphaned widgets (removed from yaml); a whole orphan
        # dashboard is deleted (cascades its own widgets).
        if "dashboard" not in unreadable:
            for dname, dv in live["dashboards"].items():
                if dname not in desired_d:
                    to_del.append(("dashboard", dname, dv["id"]))
                else:
                    wants = desired_dw.get(dname, set())
                    for wname, wv in dv["widgets"].items():
                        if wname not in wants:
                            to_del.append(("widget", f"{dname} :: {wname}",
                                           (dv["id"], wv["id"])))
        # Alert routes — dispatch config; no view dependency, but drop with the other
        # readers (before transformers) for a stable order.
        desired_ro = {self._label(r["name"]) for r in self.spec.get("routes", [])}
        if "route" not in unreadable:
            to_del += [("route", n, v["id"]) for n, v in live["routes"].items()
                       if n not in desired_ro]
        # Schedulers — they READ a transformer's view, so drop them before the
        # transformer they target (a scheduler firing on a deleted view would error).
        if "scheduler" not in unreadable:
            to_del += [("scheduler", n, v["id"]) for n, v in live["schedulers"].items()
                       if n not in desired_s]
        if "rule" not in unreadable:
            to_del += [("rule", n, v["id"]) for n, v in live["rules"].items()
                       if n not in desired_r]
        if "transformer" not in unreadable:
            to_del += [("transformer", n, v["id"]) for n, v in live["transformers"].items()
                       if n not in desired_t]
        if not to_del:
            ok("Nothing to prune — no live artifacts outside artifacts.yaml.")
            return
        section("Prune — live artifacts no longer in artifacts.yaml")
        for kind, name, _ in to_del:
            print(f"  - delete {kind:12} {name}")
        if not yes:
            resp = input("\n  Proceed with these deletes? [y/N] ").strip().lower()
            if resp not in ("y", "yes"):
                warn("Aborted — nothing pruned.")
                return
        for kind, name, _id in to_del:
            if kind == "widget":
                # _id = (dashboard_id, widget_id): detach from the dashboard, then delete
                # the widget entity. Non-fatal if the detach 404s (already gone).
                did, wid = _id
                self.tor.run(["dashboard", did, "widgets", "remove", wid, "--yes"])
                proc = self.tor.run(["widget", wid, "delete", "--yes"])
            elif kind == "scheduler":
                # Schedulers have no singular group — delete via the plural command.
                proc = self.tor.run(["schedulers", "delete", _id, "--yes"])
            elif kind == "route":
                proc = self.tor.run(["alert-route", _id, "delete", "--yes"])
            elif kind == "dashboard":
                proc = self.tor.run(["dashboard", _id, "delete", "--yes"])
            else:
                # transformers / rules use their singular `<kind> <id> delete` group.
                proc = self.tor.run([kind, _id, "delete", "--yes"])
            if proc.returncode == 0:
                ok(f"Pruned {kind}: {name}")
            else:
                warn(f"Failed to prune {kind} {name}: {(proc.stdout + proc.stderr)[:120]}")

        # Pins are a derived projection (all of a program's widgets). If we pruned any
        # dashboard/widget, the home pinned_widgets zone now references a dead widget —
        # rebuild it from the survivors so a standalone `prune` leaves no dangling pin.
        pruned_dash = {name for k, name, _ in to_del if k == "dashboard"}
        pruned_wids = {i[1] for k, _, i in to_del if k == "widget"}
        if (pruned_dash or pruned_wids) and not self.tor.dry_run:
            survivors = []
            for dname, dv in live["dashboards"].items():
                if dname in pruned_dash:
                    continue
                for wname, wv in dv["widgets"].items():
                    if wv.get("id") in pruned_wids:
                        continue
                    survivors.append((wv.get("id"), wname, dv["id"]))
            pinned = [{"widget_id": wid, "title": wname, "position": i,
                       "dashboard_id": did}
                      for i, (wid, wname, did) in enumerate(sorted(survivors))]
            self._set_home_zone("pinned_widgets", "Dashboard Widgets",
                                {"pinned_widgets": pinned},
                                {"col": 0, "row": 11, "col_span": 48, "row_span": 8})
            ok(f"Home pins refreshed → {len(pinned)} widget(s) (dropped dangling pins)")

    # ----- IMPORT (live workspace -> artifacts.yaml; NO writes to platform) -

    def _deprefix(self, name: str) -> str:
        """Strip the program prefix (`<prefix>_`) → logical name used in the YAML.
        Inverse of _ns/_label. `vulnprio_vprio_x` → `vprio_x`; `vulnprio_title` → `title`."""
        p = self.prefix + "_"
        return name[len(p):] if name.startswith(p) else name

    def _unrewrite_view_refs(self, sql: str, live_dts: list) -> str:
        """Inverse of _rewrite_view_refs: replace each live namespaced view name
        (`<prefix>_<dt>`) back to its logical form (`<dt>`) as a whole-word token."""
        out = sql or ""
        for dt in sorted(live_dts, key=len, reverse=True):
            logical = self._deprefix(dt)
            if logical != dt:
                out = re.sub(rf"(?<![\w.]){re.escape(dt)}(?![\w])", logical, out)
        return out

    @staticmethod
    def _derive_depends_on(sql: str, sibling_logical: list) -> list:
        """Reconstruct depends_on: which OTHER transformer views this SQL references
        (whole-word). Order-independent; the applier topo-sorts."""
        deps = []
        for name in sibling_logical:
            if re.search(rf"(?<![\w.]){re.escape(name)}(?![\w])", sql or ""):
                deps.append(name)
        return deps

    def _imp_list(self, argv: list, label: str, errors: list) -> list:
        """List-read for import. `Torana.json` returns None on CLI/HTTP error vs [] for
        genuinely-empty — treat None as an ERROR (record it) and return []. This stops
        import from silently writing an EMPTY section when a read fails: a partial
        manifest fed back to `apply --prune` would delete everything that 'went missing'."""
        r = self.tor.json(argv)
        if r is None:
            errors.append(label)
            return []
        return r

    def do_import(self, out_path: str = "") -> None:
        """Read the live workspace (scoped by prefix) and serialize it back to an
        artifacts.yaml — the inverse of apply. De-prefixes names, un-rewrites view refs,
        derives depends_on. Covers workspace + transformers + rules + KPIs + attention +
        dashboards/widgets + schedulers (routes/pins: TODO — see SPEC § 4.5). ABORTS
        without writing if any section read errored (so it never emits a prune-unsafe
        partial). Writes to out_path or <usecase-dir>/imported-artifacts.yaml. NO writes
        to the platform."""
        if not self.resolve_ws():
            err("No live workspace found to import — apply first or check `torana auth me`.")
            return
        ws, pfx = self.ws_id, self.prefix + "_"
        errors: list = []
        section("Import — live workspace -> artifacts.yaml")

        wdata = self.tor.json(["workspace", ws, "get", "--format", "json"]) or {}
        wdata = wdata.get("data", wdata) if isinstance(wdata, dict) else {}
        spec: dict = {
            "usecase": self.usecase,
            "workspace": {
                "name": wdata.get("name", self.usecase),
                "description": (wdata.get("description") or "").strip(),
                "icon": wdata.get("icon", "fa-shield"),
                "type": wdata.get("type", "vulnerability_management"),
            },
            "transformers": [], "rules": [], "kpis": [], "attention_cards": [],
            "dashboards": [], "routes": [], "schedulers": [],
        }
        # id -> logical target_ref maps, populated as we read transformers/rules,
        # so schedulers can reconstruct their `target_ref` from the live target id.
        tid_to_logical: dict = {}
        rid_to_logical: dict = {}

        # transformers — fetch all first (need the full dt list to un-rewrite refs)
        tfulls = []
        for t in self._imp_list(["transformers", "list", "--workspace-id", ws,
                                 "--format", "json", "--raw"], "transformers", errors):
            if not str(t.get("name", "")).startswith(pfx):
                continue
            f = self.tor.json(["transformer", t["id"], "get", "--format", "json"]) or {}
            tfulls.append(f.get("data", f) if isinstance(f, dict) else {})
        live_dts = [f.get("destination_table") for f in tfulls if f.get("destination_table")]
        sibling_logical = [self._deprefix(f.get("destination_table") or f.get("name") or "")
                           for f in tfulls]
        for f in tfulls:
            logical = self._deprefix(f.get("name", ""))
            if f.get("id"):
                # target_ref points at the transformer's key (== its logical name)
                tid_to_logical[f["id"]] = logical
            sql = self._unrewrite_view_refs(f.get("custom_sql") or "", live_dts)
            spec["transformers"].append({
                "key": logical,
                "name": logical,
                "description": (f.get("description") or "").strip(),
                "semantic_description": (f.get("semantic_description") or "").strip(),
                "destination_table": self._deprefix(f.get("destination_table") or logical),
                "materialized": f.get("materialized", True),
                "source_tables": f.get("source_tables") or [],
                "unique_key": f.get("unique_key"),
                "depends_on": self._derive_depends_on(sql, [s for s in sibling_logical
                                                            if s != self._deprefix(f.get("destination_table") or "")]),
                "sql": sql,
            })

        # rules
        for r in self._imp_list(["rules", "list", "--workspace-id", ws,
                                 "--format", "json", "--raw"], "rules", errors):
            # Workspace-scoped ownership — clean names, no prefix filter.
            f = self.tor.json(["rule", r["id"], "get", "--format", "json"]) or {}
            f = f.get("data", f) if isinstance(f, dict) else {}
            logical = self._deprefix(f.get("name", ""))
            if f.get("id"):
                rid_to_logical[f["id"]] = logical
            spec["rules"].append({
                "key": logical, "name": logical,
                "severity": f.get("severity", "high"),
                "description": (f.get("description") or "").strip(),
                "alert_enabled": f.get("alert_enabled", True),
                "entity_type": f.get("entity_type", "vulnerability"),
                "identity_fields": f.get("identity_fields") or ["torana_vulnerability_id"],
                "sql": self._unrewrite_view_refs(f.get("sql_command") or "", live_dts),
            })

        # KPIs (landing zone) + attention
        for k in self._imp_list(["workspace", ws, "kpi", "list",
                                 "--format", "json", "--raw"], "kpis", errors):
            ds = k.get("data_source") or {}
            spec["kpis"].append({
                "title": self._deprefix(k.get("label", "")),
                "description": k.get("description", ""),
                "format": k.get("format", "number"),
                "icon": k.get("icon", "fa-chart-simple"),
                "sql": self._unrewrite_view_refs(
                    ds.get("query") if isinstance(ds, dict) else (ds or ""), live_dts),
            })
        for a in self._imp_list(["workspace", ws, "attention", "list",
                                 "--format", "json", "--raw"], "attention", errors):
            cond = a.get("condition") or {}
            spec["attention_cards"].append({
                "title": self._deprefix(a.get("title", "")),
                "description": a.get("description", ""),
                "severity": a.get("default_severity", "medium"),
                "trigger_when": cond.get("trigger_when", "count > 0") if isinstance(cond, dict) else "count > 0",
                "query": self._unrewrite_view_refs(
                    cond.get("query") if isinstance(cond, dict) else (cond or ""), live_dts),
            })

        # Dashboards + widgets — de-prefix names; each widget's SQL comes from its
        # linked query (un-rewritten back to logical view refs).
        qsql_cache: dict = {}
        for d in self._imp_list(["dashboards", "list", "--workspace-id", ws,
                                 "--all", "--format", "json", "--raw"], "dashboards", errors):
            dname = str(d.get("name", ""))
            # Workspace-scoped ownership — clean names, no prefix filter.
            full = self.tor.json(["dashboard", d["id"], "get", "--format", "json"]) or {}
            full = full.get("data", full) if isinstance(full, dict) else {}
            widgets = []
            for w in (full.get("widgets") or []):
                qid = w.get("query_id")
                if qid and qid not in qsql_cache:
                    q = self.tor.json(["query", qid, "get", "--format", "json"]) or {}
                    q = q.get("data", q) if isinstance(q, dict) else {}
                    qsql_cache[qid] = q.get("sql_command") or ""
                wlogical = self._deprefix(str(w.get("name", "")))
                widgets.append({
                    "key": wlogical, "name": wlogical,
                    "widget_type": w.get("widget_type", "table"),
                    "description": (w.get("description") or "").strip(),
                    "display_config": w.get("display_config") or {},
                    "sql": self._unrewrite_view_refs(qsql_cache.get(qid, ""), live_dts),
                })
            dlogical = self._deprefix(dname)
            spec["dashboards"].append({
                "key": dlogical, "name": dlogical,
                "description": (full.get("description") or "").strip(),
                "widgets": widgets,
            })

        # Alert routes — operational config round-trips cleanly; destination_ref is
        # best-effort (the resolved id from destination_config; often an EXTERNAL
        # agent/playbook we didn't create, so it can't be reversed to a logical name).
        for r in self._imp_list(["alert-routes", "routing-rules", "--workspace-id", ws,
                                 "--all", "--format", "json", "--raw"], "routes", errors):
            name = str(r.get("name", ""))
            # Workspace-scoped ownership — clean names, no prefix filter.
            dtype = r.get("destination_type", "")
            dcfg = r.get("destination_config") or {}
            dest_ref = dcfg.get(f"{dtype}_id", "") if isinstance(dcfg, dict) else ""
            entry = {
                "key": self._deprefix(name), "name": self._deprefix(name),
                "description": (r.get("description") or "").strip(),
                "destination_type": dtype,
                "destination_ref": dest_ref,
                "enabled": bool(r.get("enabled", True)),
                "priority": r.get("priority", 10),
                "stop_on_match": bool(r.get("stop_on_match", False)),
                "matching_operator": r.get("matching_operator", "all"),
                "max_executions_per_hour": r.get("max_executions_per_hour", 200),
            }
            for fld in self._ROUTE_FILTERS:
                if r.get(fld):
                    entry[fld] = r[fld]
            if r.get("match_all"):
                entry["match_all"] = True
            spec["routes"].append(entry)

        # Schedulers — de-prefix the name and reconstruct target_ref from the live
        # target id (transformer_id / rule_id) via the maps built above.
        for s in self._imp_list(["schedulers", "tasks", "--workspace-id", ws,
                                 "--all", "--format", "json", "--raw"], "schedulers", errors):
            name = str(s.get("name", ""))
            # Workspace-scoped ownership — clean names, no prefix filter.
            tt = s.get("task_type", "transformer")
            target_id = s.get(f"{tt}_id") or ""
            target_ref = (tid_to_logical.get(target_id) if tt == "transformer"
                          else rid_to_logical.get(target_id)) or ""
            spec["schedulers"].append({
                "name": self._deprefix(name),
                "description": (s.get("description") or "").strip(),
                "task_type": tt,
                "target_ref": target_ref,
                "schedule_type": s.get("schedule_type", "cron"),
                "schedule_expression": (s.get("schedule_expression") or "").strip(),
            })

        # Refuse to write a partial manifest: an empty section caused by a read ERROR
        # (not a genuine absence) would, if re-applied with --prune, delete everything
        # that section owns. Abort loud instead.
        if errors:
            err(f"Import ABORTED — live read failed for: {', '.join(sorted(set(errors)))}. "
                f"Nothing written (a partial manifest is prune-unsafe). Retry when the "
                f"platform is healthy (e.g. restart the owning service).")
            return
        dest = Path(out_path) if out_path else (self.dir / "imported-artifacts.yaml")
        dest.write_text(yaml.safe_dump(spec, sort_keys=False, width=100, allow_unicode=True))
        n_widgets = sum(len(d.get("widgets", [])) for d in spec["dashboards"])
        ok(f"Imported {len(spec['transformers'])} transformer(s), {len(spec['rules'])} rule(s), "
           f"{len(spec['kpis'])} KPI(s), {len(spec['attention_cards'])} attention card(s), "
           f"{len(spec['dashboards'])} dashboard(s)/{n_widgets} widget(s), "
           f"{len(spec['routes'])} route(s), {len(spec['schedulers'])} scheduler(s)")
        info(f"Wrote {dest}")
        if spec["routes"]:
            warn("Routes imported with destination_ref = the resolved id (may be an "
                 "EXTERNAL agent/playbook). Review destination_ref before re-applying.")
        info("Home pins are a derived projection of the widget set (rebuilt every apply) "
             "— not imported as authored artifacts.")

    # ----- ASSESS (operational signals + grounding drift; NO writes) --------

    # Skill-shipped starting thresholds; a program overrides them per-program in its
    # `grounding.health_defaults` block.
    _HEALTH_DEFAULTS = {
        "rule_noisy_alerts_per_day": 50,
        "widget_empty_after_days": 7,
        "kpi_stale_if_unchanged_days": 30,
    }

    @staticmethod
    def _rows_of(payload: Any) -> Optional[list]:
        """Pull the row list out of a query/render payload, tolerating the several
        shapes the CLI returns (`results` / `rows` / `items` / a bare list)."""
        if payload is None:
            return None
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for k in ("results", "rows", "items", "data"):
                v = payload.get(k)
                if isinstance(v, list):
                    return v
        return []

    def _scalar(self, sql: str) -> Any:
        """Run a KPI/metric SELECT live and return its single scalar value (first cell
        of the first row), or None if it errors/empties."""
        if not sql:
            return None
        r = self.tor.json(["datalake", "query", "--sql", sql, "--format", "json"])
        rows = self._rows_of(r)
        if not rows or not isinstance(rows[0], dict):
            return None
        vals = list(rows[0].values())
        return vals[0] if vals else None

    def assess(self, window_days: int = 7, out_path: str = "") -> None:
        """Read the live program's OPERATIONAL signals + grounding drift into a health
        report the skill reasons over. Read-only — gathers facts, proposes nothing (the
        model turns the report into artifacts.yaml diffs). Signals: per-rule alert volume
        (noisy?), per-widget rendered row count (empty/dead?), per-KPI live value vs the
        recorded baseline (moved/stale?), and entity-graph edge drift vs `grounding.graph`."""
        if not self.resolve_ws():
            err("No live workspace found to assess — apply first or check `torana auth me`.")
            return
        section("Assess — operational signals + grounding drift")
        live, unreadable = self.read_live_model()
        grounding = self.spec.get("grounding", {}) or {}
        hd = {**self._HEALTH_DEFAULTS, **(grounding.get("health_defaults") or {})}
        baselines = grounding.get("baselines") or {}
        report: dict = {
            "program": self.usecase, "workspace_id": self.ws_id,
            "window_days": window_days, "health_defaults": hd,
            "rules": [], "widgets": [], "kpis": [], "graph_drift": {}, "summary": {},
            "notes": [],
        }

        # Rules — alert volume. The CLI has no date filter, so `alert_total` is all-time;
        # the noisy heuristic compares it to (threshold/day × window). The model can
        # windowize via created_at if it needs precision.
        noisy_bar = hd["rule_noisy_alerts_per_day"] * max(window_days, 1)
        if "rule" in unreadable:
            report["notes"].append("rules unreadable (live read error) — skipped")
        for name, rv in live["rules"].items():
            env = self.tor.json(["alerts", "list", "--rule-id", rv["id"],
                                 "--workspace-id", self.ws_id, "--page-size", "1",
                                 "--format", "json"]) or {}
            total = env.get("total", 0) if isinstance(env, dict) else 0
            report["rules"].append({
                "name": self._deprefix(name), "id": rv["id"],
                "alert_total": total, "noisy": bool(total > noisy_bar),
            })

        # Widgets — render row counts (dead/empty widget?).
        if "dashboard" in unreadable:
            report["notes"].append("dashboards unreadable (live read error) — skipped")
        for dname, dv in live["dashboards"].items():
            for wname, wv in dv["widgets"].items():
                rendered = self.tor.json(["widget", wv["id"], "render", "--format", "json"])
                rows = self._rows_of(rendered)
                report["widgets"].append({
                    "dashboard": self._deprefix(dname), "name": self._deprefix(wname),
                    "id": wv["id"],
                    "rows": (len(rows) if rows is not None else None),
                    "empty": (rows == []), "error": (rendered is None),
                })

        # KPIs — recompute the live value and diff vs the recorded baseline (matched by
        # KPI id, e.g. `{prefix}_kpi_{i}`; the model can also map by title).
        for kid, kv in live["kpis"].items():
            val = self._scalar(kv["sql"])
            base = baselines.get(kid)
            entry: dict = {"id": kid, "live_value": val, "baseline": base}
            if isinstance(val, (int, float)) and isinstance(base, (int, float)) and base:
                entry["drift_pct"] = round((val - base) / base * 100.0, 1)
            report["kpis"].append(entry)

        # Graph drift — current edge-type counts vs the grounded snapshot.
        edges = self.tor.json(["entity-graph", "edges", "list", "--format", "json", "--raw"])
        now: dict = {}
        if isinstance(edges, list):
            for e in edges:
                t = (e.get("edge_type") or e.get("type") or e.get("relationship") or "?") \
                    if isinstance(e, dict) else "?"
                now[t] = now.get(t, 0) + 1
        elif edges is None:
            report["notes"].append("entity-graph edges unreadable — graph drift skipped")
        grounded_graph = grounding.get("graph") or {}
        report["graph_drift"] = {
            "now": now, "grounded": grounded_graph,
            "new_edge_types": sorted(t for t in now if t not in grounded_graph),
            "missing_edge_types": sorted(str(t) for t in grounded_graph if t not in now),
        }

        report["summary"] = {
            "noisy_rules": sum(1 for r in report["rules"] if r["noisy"]),
            "empty_widgets": sum(1 for w in report["widgets"] if w["empty"]),
            "error_widgets": sum(1 for w in report["widgets"] if w["error"]),
            "kpis_checked": len(report["kpis"]),
            "grounding_present": bool(grounding),
        }

        # Human-readable summary to stdout…
        s = report["summary"]
        ok(f"Rules: {len(report['rules'])} ({s['noisy_rules']} noisy)  ·  "
           f"Widgets: {len(report['widgets'])} ({s['empty_widgets']} empty, "
           f"{s['error_widgets']} error)  ·  KPIs: {s['kpis_checked']}")
        for r in report["rules"]:
            if r["noisy"]:
                warn(f"noisy rule '{r['name']}': {r['alert_total']} alerts (> {noisy_bar} bar)")
        for w in report["widgets"]:
            if w["empty"] or w["error"]:
                warn(f"{'error' if w['error'] else 'empty'} widget "
                     f"'{w['dashboard']} :: {w['name']}'")
        gd = report["graph_drift"]
        if gd["new_edge_types"] or gd["missing_edge_types"]:
            warn(f"graph drift — new: {gd['new_edge_types'] or '—'}  "
                 f"missing: {gd['missing_edge_types'] or '—'}")
        if not grounding:
            warn("no `grounding` block in artifacts.yaml — KPI/graph drift is limited; "
                 "capture grounding at build time so ASSESS can compare against it.")

        # …and the full machine-readable report as JSON (the model consumes this).
        dest = Path(out_path) if out_path else (self.dir / "assess-report.json")
        dest.write_text(json.dumps(report, indent=2, default=str))
        info(f"Wrote health report → {dest}")

    # ----- APPLY -----------------------------------------------------------
    def apply(self) -> None:
        self._apply_workspace()
        self._apply_policy()
        self._apply_transformers()
        self._apply_rules()
        self._apply_dashboards()
        self._apply_kpis()
        self._apply_attention()
        self._apply_home_pins()
        self._apply_playbooks()
        self._apply_routes()
        self._apply_schedulers()
        # Home page is now built — sweep so its KPI/attention values are populated
        # immediately (otherwise the page renders with empty values until first sweep).
        self._sweep()
        self._verify()

    # ----- BUILD (proposal mode) -------------------------------------------
    def build(self) -> None:
        """Build mode — the opposite of apply.

        apply() realises every artifact directly (bypassing the build flow). build()
        instead stands up the App and seeds a *proposal* into its Build page, then stops:
          1. create the workspace
          2. ingest the policy document (so the Advisor reasons against it)
          3. trigger the Program Advisor (bootstrap) with the use case's build-program
             markdown passed as `hints` — the Advisor produces proposal card(s) on the
             Build page steered by our build program.
        No transformers / rules / dashboards are created. The user then opens the Build
        page, clicks the proposal, and runs it to realise the artifacts through the
        normal build flow.
        """
        self._apply_workspace()
        self._apply_policy()
        self._seed_build_proposal()
        self._verify_build()

    def _build_program_text(self) -> str:
        """Return the build-program markdown to seed the proposal with.

        Source order:
          1. spec['build_program'] (explicit path under the use-case dir), else
          2. the first *.md under build-program/ (sorted — '1-*.md' wins for app #1).
        """
        explicit = self.spec.get("build_program")
        if explicit:
            p = (self.dir / explicit).resolve()
            if p.exists():
                return p.read_text(encoding="utf-8")
            warn(f"build_program path not found: {p} — falling back to build-program/")
        bp_dir = self.dir / "build-program"
        if bp_dir.is_dir():
            mds = sorted(bp_dir.glob("*.md"))
            if mds:
                return mds[0].read_text(encoding="utf-8")
        return ""

    def _seed_build_proposal(self) -> None:
        section("Step 3 — Seed Build Proposal (Program Advisor)")
        hints = self._build_program_text()
        if not hints:
            warn("No build-program markdown found — triggering Advisor with no hints.")
        else:
            info(f"Seeding Advisor with build program ({len(hints)} chars).")
        body = {"hints": hints, "force": True}
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(body, f)
        f.flush()
        f.close()
        info("Triggering Program Advisor (bootstrap) — proposals will appear on the Build page…")
        proc = self.tor.run([
            "workspace", self.ws_id, "advisor", "bootstrap",
            "--file", f.name, "--format", "json",
        ])
        if self.tor.dry_run:
            ok("[dry-run] would trigger advisor bootstrap with build-program hints")
            return
        # 202 async — the sweep runs in the background; proposals show up on the Build page.
        if proc.returncode == 0 or "triggered" in (proc.stdout + proc.stderr).lower():
            ok("Advisor bootstrap triggered — open the App's Build page to see the proposal "
               "card, then click it to build the artifacts.")
            self.state.set("build_mode", "proposal_seeded")
        else:
            warn(f"Advisor bootstrap may have failed — output: "
                 f"{proc.stdout[:200]}{proc.stderr[:200]}")

    def _verify_build(self) -> None:
        section("Verification (build mode)")
        ok(f"Workspace {self.ws_id} stood up in BUILD mode.")
        info("No artifacts were built. The Program Advisor was seeded with the build "
             "program; its proposal(s) appear on the App's Build page.")
        info("Next: open the App → Build → click the proposal → run it to realise the "
             "transformers, rules, dashboards, etc.")
        print(f"\n  Workspace ID: {self.ws_id}")
        print(f"  State file:   {self.state.path}")

    def _apply_workspace(self) -> None:
        section("Step 1 — Workspace")
        ws = self.spec.get("workspace", {})
        if self.cli_workspace_id:
            self.ws_id = self.cli_workspace_id
            info(f"Using existing workspace: {self.ws_id}")
            self.state.set("workspace_id", self.ws_id)
            return
        self.ws_id = self.state.get("workspace_id", "")
        if self.ws_id and not self.tor.dry_run:
            # Verify the tracked workspace still exists. If it was deleted out-of-band,
            # the state is STALE — don't trust it. Reset state and recreate, so apply
            # is self-healing (idempotent even after an external delete).
            data = self.tor.json(["workspace", self.ws_id, "get", "--format", "json"])
            if isinstance(data, dict) and data.get("id"):
                info(f"Workspace already exists: {self.ws_id}")
                return
            warn(f"Tracked workspace {self.ws_id} no longer exists (deleted "
                 "out-of-band) — resetting stale state and rebuilding.")
            self.state.clear()
            self.ws_id = ""
        elif self.ws_id:  # dry-run: trust state
            info(f"Workspace already exists: {self.ws_id}")
            return
        info(f"Creating workspace '{ws.get('name')}'…")
        proc = self.tor.run([
            "workspaces", "create",
            "--name", ws.get("name", self.usecase),
            "--description", ws.get("description", "")[:500],
            "--icon", ws.get("icon", "fa-shield"),
            "--type", ws.get("type", "vulnerability_management"),
            "--if-not-exists", "--format", "json",
        ])
        self.ws_id = extract_id(proc.stdout)
        if not self.ws_id and self.tor.dry_run:
            self.ws_id = "dry-run-ws"
        if not self.ws_id:
            err("Failed to create workspace — check `torana auth me`")
        ok(f"Workspace created: {self.ws_id}")
        self.state.set("workspace_id", self.ws_id)

    def _apply_policy(self) -> None:
        section("Step 2 — Policy Document")
        pol = self.spec.get("policy")
        if not pol:
            info("No policy declared — skipping")
            return
        if self.state.get("policy_doc"):
            info(f"Policy already ingested ({self.state.get('policy_doc')}) — skipping")
            return
        doc = (self.dir / pol["file"]).resolve()
        if not doc.exists():
            warn(f"Policy file not found: {doc} — skipping")
            return
        collection = pol.get("collection", "organization_policies")
        self._ensure_collection(collection, pol)
        info(f"Ingesting policy '{pol.get('title')}' into {collection}…")
        proc = self.tor.run([
            "rag", "upload", str(doc),
            "--title", pol.get("title", doc.stem),
            "--collection", pol.get("collection", "organization_policies"),
            "--document-type", pol.get("document_type", "policy"),
            "--version", str(pol.get("version", "1.0")),
            "--workspace-id", self.ws_id,
            "--format", "json",
        ])
        doc_id = extract_id(proc.stdout)
        if doc_id:
            self.state.set("policy_doc", doc_id)
            ok(f"Policy ingested: {doc_id}")
        else:
            warn(f"Could not ingest policy — output: {proc.stdout[:200]}{proc.stderr[:200]}")

    def _ensure_collection(self, name: str, pol: dict) -> None:
        """Create the RAG collection if it doesn't already exist. `rag upload` 404s when
        the target collection is missing (fresh tenants have none), so we look it up by
        name and create it first. Idempotent — a present collection is left untouched."""
        if self.tor.dry_run:
            info(f"[dry-run] would ensure RAG collection '{name}' exists")
            return
        existing = self.tor.json(["rag", "collections", "list", "--format", "json",
                                  "--raw"])
        names = []
        if isinstance(existing, list):
            names = [c.get("name") for c in existing if isinstance(c, dict)]
        elif isinstance(existing, dict):
            names = [c.get("name") for c in existing.get("items", [])
                     if isinstance(c, dict)]
        if name in names:
            info(f"RAG collection '{name}' exists — skipping create")
            return
        info(f"Creating RAG collection '{name}'…")
        desc = (pol.get("collection_description")
                or f"Org-specific policies for the {self.usecase} App "
                   f"(SLA targets, risk acceptance, remediation policy).")
        proc = self.tor.run([
            "rag", "collections", "create",
            "--name", name,
            "--description", desc,
            "--purpose", pol.get("collection_purpose", "policy_configuration"),
            "--document-type", pol.get("document_type", "policy"),
            "--format", "json",
        ])
        if proc.returncode == 0:
            ok(f"RAG collection '{name}' created")
        else:
            warn(f"Could not create collection '{name}' — output: "
                 f"{(proc.stdout + proc.stderr)[:200]}")

    def _apply_transformers(self) -> None:
        section("Step 3 — Transformers")
        transformers = self.spec.get("transformers", [])
        if not transformers:
            info("No transformers declared")
            return
        for t in topo_sort(transformers):
            self._apply_one_transformer(t)

    def _apply_one_transformer(self, t: dict) -> None:
        key = t["key"]
        skey = f"transformer_{key}"
        # Namespace the model name + destination_table; rewrite sibling view refs in SQL.
        body = {
            "name": self._ns(t["name"]),
            "description": (t.get("description") or "").strip(),
            "semantic_description": (t.get("semantic_description") or t.get("description") or "").strip(),
            "destination_table": self._ns(t.get("destination_table", t["name"])),
            "materialized": t.get("materialized", True),
            "workspace_id": self.ws_id,
            "source_tables": t.get("source_tables", []),
            "custom_sql": self._rewrite_view_refs(t["sql"].strip()),
        }
        # Option 3 (incremental materialization): forward an explicit natural row key for
        # row-projection transformers so the output materializes 'incremental' (merge on
        # this key) with maintained created_at/updated_at, letting detection rules
        # watermark it. Aggregates omit unique_key and stay full-rebuild 'table'.
        # See pantheon-detection-framework/docs/TRANSFORMER_INCREMENTAL_WATERMARK_DESIGN.md.
        if t.get("unique_key"):
            body["unique_key"] = t["unique_key"]
        existing = self.state.get(skey)
        f = write_tmp_yaml(body)
        tid = ""
        try:
            if existing:
                info(f"Transformer '{key}' exists ({existing}) — updating…")
                self.tor.run(["transformer", existing, "update", "--file", str(f)])
                tid = existing
                ok(f"Updated transformer: {key}")
            else:
                info(f"Creating transformer '{key}'…")
                proc = self.tor.run(["transformers", "create", "--file", str(f), "--format", "json"])
                tid = extract_id(proc.stdout)
                if not tid:
                    # 409 already-exists — API may echo transformer_id in the error body
                    m = re.search(r"transformer_id[:\s]+" + UUID_RE.pattern,
                                  proc.stdout + proc.stderr)
                    tid = m.group(1) if m else ""
                if tid:
                    self.state.set(skey, tid)
                    self.tor.run(["transformer", tid, "move",
                                  "--target-workspace-id", self.ws_id])
                    ok(f"Transformer '{key}': {tid}")
                else:
                    warn(f"Could not create transformer '{key}': "
                         f"{(proc.stdout + proc.stderr)[:200]}")
        finally:
            f.unlink(missing_ok=True)
        # Materialize the view NOW. A materialized transformer's relation does not
        # physically exist until it runs — and a dependent transformer's create-time
        # SQL validation (and later rule/widget SQL validation) queries the real
        # relation. Executing in topological order guarantees each base view exists
        # before anything references it.
        if tid and not self.tor.dry_run:
            info(f"Executing transformer '{key}' to materialize its view…")
            proc = self.tor.run(["transformer", tid, "execute-and-wait", "--format", "json"])
            if proc.returncode == 0:
                ok(f"Materialized: {key}")
            else:
                warn(f"Transformer '{key}' execute failed (dependents/rules may not "
                     f"validate): {(proc.stdout + proc.stderr)[:160]}")

    def _apply_rules(self) -> None:
        section("Step 4 — Detection Rules")
        for rule in self.spec.get("rules", []):
            self._apply_one_rule(rule)

    def _apply_one_rule(self, rule: dict) -> None:
        key = rule["key"]
        skey = f"rule_{key}"
        existing = self.state.get(skey)
        body = {
            "name": self._label(rule["name"]),
            "severity": rule.get("severity", "high"),
            "sql_command": self._rewrite_view_refs(rule["sql"].strip()),
            "description": (rule.get("description") or "").strip(),
            "workspace_id": self.ws_id,
            "alert_enabled": rule.get("alert_enabled", True),
            "entity_type": rule.get("entity_type", "vulnerability"),
            "identity_fields": rule.get("identity_fields", ["torana_vulnerability_id"]),
        }
        if existing:
            info(f"Rule '{key}' exists ({existing}) — updating…")
            self.tor.run(["rule", existing, "update",
                          "--name", body["name"],
                          "--severity", body["severity"],
                          "--sql", body["sql_command"],
                          "--description", body["description"]])
            ok(f"Updated rule: {key}")
            return
        info(f"Creating rule '{key}'…")
        f = write_tmp_json(body)
        try:
            proc = self.tor.run(["rules", "create", "--file", str(f),
                                 "--if-not-exists", "--format", "json"])
            rid = extract_id(proc.stdout)
            if rid:
                self.state.set(skey, rid)
                ok(f"Created rule: {key} ({rid})")
            else:
                warn(f"Could not create rule '{key}': {(proc.stdout + proc.stderr)[:200]}")
        finally:
            f.unlink(missing_ok=True)

    def _apply_dashboards(self) -> None:
        section("Step 5 — Dashboards")
        for dash in self.spec.get("dashboards", []):
            self._apply_one_dashboard(dash)

    def _apply_one_dashboard(self, dash: dict) -> None:
        key = dash["key"]
        skey = f"dashboard_{key}"
        if self.state.get(skey):
            did = self.state.get(skey)
            info(f"Dashboard '{key}' exists ({did}) — reconciling widgets")
            # Update-on-exist: update changed widgets' SQL/type + ADD new widgets.
            # Widget REMOVALS are deferred to `prune` (apply is non-destructive, matching
            # transformers/rules). Also re-captures widget ids for the pin step.
            self._reconcile_dashboard_widgets(did, dash)
            return
        widgets = []
        for i, w in enumerate(dash.get("widgets", [])):
            wname = self._label(w["name"])
            widgets.append({
                "name": wname,
                "widget_type": w["widget_type"],
                "query_name": f"{self.usecase}_{key}_{i}_{re.sub(r'[^a-z0-9]+', '_', w['name'].lower())}"[:60],
                "sql_command": self._rewrite_view_refs(w["sql"].strip()),
                "display_config": w.get("display_config", {}),
                "description": w.get("description", ""),
            })
        body = {
            "name": self._label(dash["name"]),
            "workspace_id": self.ws_id,
            "description": (dash.get("description") or "").strip(),
            "widgets": widgets,
        }
        info(f"Creating dashboard '{key}' ({len(widgets)} widgets)…")
        f = write_tmp_json(body)
        try:
            proc = self.tor.run(["dashboards", "create", "--file", str(f), "--format", "json"])
            did = extract_id(proc.stdout)
            if did:
                self.state.set(skey, did)
                # Capture EVERY created widget {id -> name} so ALL widgets can be
                # pinned to the home page (one pinned_widgets zone for the App).
                for wname, wid in self._created_widget_ids(proc.stdout).items():
                    self.state.set(f"pinwidget_{wid}", f"{did}|{wname}")
                ok(f"Dashboard '{key}': {did}")
            else:
                warn(f"Could not create dashboard '{key}': {(proc.stdout + proc.stderr)[:200]}")
        finally:
            f.unlink(missing_ok=True)

    @staticmethod
    def _created_widget_ids(stdout: str) -> dict:
        """Parse the bulk dashboard-create response for {widget_name -> widget_id}."""
        out = {}
        try:
            data = json.loads(stdout)
        except Exception:
            return out
        for w in (data.get("widgets") or []):
            if w.get("id") and w.get("name"):
                out[w["name"]] = w["id"]
        return out

    def _capture_existing_widgets(self, dashboard_id: str) -> None:
        """Fetch an existing dashboard's widgets and record their ids in state, so
        ALL widgets get pinned even when the dashboard already exists (re-apply path)."""
        if self.tor.dry_run:
            return
        data = self.tor.json(["workspace", self.ws_id, "dashboard", dashboard_id,
                              "get", "--format", "json"])
        for w in ((data or {}).get("widgets") or []):
            wid, wname = w.get("id"), w.get("name")
            if wid and wname:
                self.state.set(f"pinwidget_{wid}", f"{dashboard_id}|{wname}")

    def _reconcile_dashboard_widgets(self, did: str, dash: dict) -> None:
        """Update-on-exist for an already-created dashboard. For each desired widget:
        update its SQL (via the linked query) and/or widget_type when changed; ADD it
        (query + widget + attach) when new. Removals are handled by `prune`. Widget
        identity = namespaced name (`_label`). SQL is stored view-ref-rewritten, matching
        the create path + `read_live_model`."""
        if self.tor.dry_run:
            return
        full = self.tor.json(["dashboard", did, "get", "--format", "json"]) or {}
        full = full.get("data", full) if isinstance(full, dict) else {}
        live_by_name = {str(w.get("name", "")): w for w in (full.get("widgets") or [])}
        for i, w in enumerate(dash.get("widgets", [])):
            wname = self._label(w["name"])
            desired_sql = self._rewrite_view_refs(w["sql"].strip())
            desired_type = w["widget_type"]
            lw = live_by_name.get(wname)
            if not lw:
                if self._create_widget_on_dashboard(did, dash["key"], i, w):
                    ok(f"Widget '{wname}': added")
                continue
            # SQL drift → update the linked query.
            qid = lw.get("query_id")
            if qid:
                q = self.tor.json(["query", qid, "get", "--format", "json"]) or {}
                q = q.get("data", q) if isinstance(q, dict) else {}
                if self._canonical_sql(q.get("sql_command") or "") != \
                        self._canonical_sql(desired_sql):
                    proc = self.tor.run(["query", qid, "update", "--sql", desired_sql,
                                         "--format", "json"])
                    if proc.returncode == 0:
                        ok(f"Widget '{wname}': SQL updated")
                    else:
                        warn(f"Widget '{wname}': SQL update failed: "
                             f"{(proc.stdout + proc.stderr)[:160]}")
            # widget_type drift → update the widget.
            if lw.get("widget_type") != desired_type:
                wf = write_tmp_json({"widget_type": desired_type})
                try:
                    self.tor.run(["widget", lw["id"], "update", "--file", str(wf),
                                  "--format", "json"])
                    ok(f"Widget '{wname}': type → {desired_type}")
                finally:
                    wf.unlink(missing_ok=True)
        # Re-capture ALL widget ids (incl. any just-added) for the home-pin step.
        self._capture_existing_widgets(did)

    def _create_widget_on_dashboard(self, did: str, key: str, i: int, w: dict) -> str:
        """Create a standalone query + widget and attach it to an existing dashboard
        (3-step: `queries create` → `widgets create` → `dashboard <id> widgets add`).
        Returns the new widget id, or "" on failure."""
        wname = self._label(w["name"])
        qname = f"{self.usecase}_{key}_{i}_{re.sub(r'[^a-z0-9]+', '_', w['name'].lower())}"[:60]
        qbody = {"workspace_id": self.ws_id, "name": qname,
                 "sql_command": self._rewrite_view_refs(w["sql"].strip()),
                 "description": w.get("description", "")}
        qf = write_tmp_json(qbody)
        try:
            proc = self.tor.run(["queries", "create", "--file", str(qf), "--format", "json"])
            qid = extract_id(proc.stdout)
        finally:
            qf.unlink(missing_ok=True)
        if not qid:
            warn(f"Widget '{wname}': query create failed: {(proc.stdout + proc.stderr).strip()[:300]}")
            return ""
        wbody = {"workspace_id": self.ws_id, "name": wname, "query_id": qid,
                 "widget_type": w["widget_type"],
                 "display_config": w.get("display_config", {}),
                 "description": w.get("description", "")}
        wf = write_tmp_json(wbody)
        try:
            proc = self.tor.run(["widgets", "create", "--file", str(wf), "--format", "json"])
            wid = extract_id(proc.stdout)
        finally:
            wf.unlink(missing_ok=True)
        if not wid:
            # Surface the real API error (e.g. a per-type display_config requirement) instead
            # of a bare "failed" — otherwise the caller must reproduce the create to see why.
            warn(f"Widget '{wname}' ({w.get('widget_type')}): widget create failed: "
                 f"{(proc.stdout + proc.stderr).strip()[:300]}")
            return ""
        self.tor.run(["dashboard", did, "widgets", "add", wid, "--format", "json"])
        return wid

    _KPI_FORMAT = {"number": "number", "percent": "percentage",
                   "currency": "currency", "duration": "duration"}

    def _apply_kpis(self) -> None:
        """Build the kpi_bar zone via `home config set`. The landing-page renderer +
        sweep read KPIs from the kpi_bar ZONE (data_source.query), so we construct the
        zone directly rather than via `kpi add` (which only writes a top-level `kpis`
        mirror the renderer ignores)."""
        section("Step 6 — KPI Cards")
        kpis = self.spec.get("kpis", [])
        if not kpis:
            return
        cards = []
        for i, k in enumerate(kpis):
            cards.append({
                "id": f"{self.prefix}_kpi_{i}",
                "label": self._label(k["title"]),
                "icon": k.get("icon", "fa-chart-simple"),
                "format": self._KPI_FORMAT.get(k.get("format", "number"), "number"),
                "trend_enabled": False,
                "trend_period_days": 7,
                "description": k.get("description", ""),
                "data_source": {
                    "type": "sql_query",
                    "query": self._rewrite_view_refs(k["sql"].strip()),
                    "service": "datalake",
                },
            })
        self._set_home_zone("kpi_bar", "KPI Status Bar", {"kpis": cards},
                            {"col": 0, "row": 0, "col_span": 48, "row_span": 4})
        ok(f"{len(cards)} KPI card(s) configured (kpi_bar zone)")

    def _clear_kpis(self) -> None:
        data = self.tor.json(["workspace", self.ws_id, "kpi", "list", "--format", "json"])
        items = (data or {}).get("items", []) if isinstance(data, dict) else (data or [])
        for k in items:
            kid = k.get("id")
            if kid:
                self.tor.run(["workspace", self.ws_id, "kpi", "remove",
                              "--kpi-id", kid, "--yes"], capture=True)

    def _apply_attention(self) -> None:
        """Build the attention zone via `home config set`. Each card's condition is a
        proper {query, trigger_when} OBJECT (the landing-page sweep does
        condition.get('query') — a bare string crashes the sweep, which also kills the
        KPI bar). Rewritten atomically into the landing config's attention zone."""
        section("Step 7 — Attention Cards")
        cards = self.spec.get("attention_cards", [])
        if not cards:
            return
        templates = []
        for i, a in enumerate(cards):
            _desc = a.get("description", "")
            templates.append({
                "id": f"{self.prefix}_att_{i}",
                "title": self._label(a["title"]),
                "title_template": self._label(a["title"]),
                "description": _desc,
                # The landing-page sweep renders each card's BODY from `summary_template`
                # and its action bar from `action_template`, interpolating {count} (and any
                # other condition-query column) per workspace_sweep_scheduler. Emit both so
                # the card body is never blank; fall back to the description / a generic
                # prompt when the artifact didn't specify them.
                "summary_template": a.get("summary_template", _desc),
                "action_template": a.get("action_template", "Review the {count} affected finding(s)"),
                "default_severity": a.get("severity", "medium"),
                "icon": a.get("icon", "fa-exclamation-triangle"),
                "condition": {
                    "query": self._rewrite_view_refs((a.get("query") or "").strip()),
                    "trigger_when": a.get("trigger_when", "count > 0"),
                    "service": "datalake",
                },
            })
        self._set_home_zone("attention", "What Needs Your Attention",
                            {"attention_templates": templates},
                            {"col": 0, "row": 4, "col_span": 48, "row_span": 7})
        ok(f"{len(templates)} attention card(s) configured (with SQL conditions)")

    def _apply_home_pins(self) -> None:
        """Pin ALL of this App's widgets to the home page's pinned_widgets zone, via
        `home config set` (one atomic, idempotent write — replaces the zone's list with
        exactly the current widget set, so re-apply never duplicates and no stale pins
        survive). Widget {id->name} were captured during dashboard creation."""
        section("Step 8 — Home Page (Pinned Widgets)")
        pins = self.state.items_with_prefix("pinwidget_")
        if not pins:
            info("No widgets captured to pin (dashboards must be built first)")
            return
        pinned_widgets = []
        for i, (skey, val) in enumerate(sorted(pins)):
            wid = skey.replace("pinwidget_", "")
            did, _, wname = (val.partition("|") if "|" in val else ("", "", val))
            entry = {"widget_id": wid, "title": wname, "position": i}
            if did:
                entry["dashboard_id"] = did
            pinned_widgets.append(entry)
        self._set_home_zone("pinned_widgets", "Dashboard Widgets",
                            {"pinned_widgets": pinned_widgets},
                            {"col": 0, "row": 11, "col_span": 48, "row_span": 8})
        ok(f"{len(pinned_widgets)} widget(s) pinned to home page")

    def _set_home_zone(self, zone_type: str, label: str, zone_config: dict,
                       position: dict) -> None:
        """Read the landing config, replace (or create) the given zone with the
        provided config, and write it back via `home config set`. Atomic + idempotent;
        preserves other zones (kpi_bar, chat). Reliable single source of truth — avoids
        the per-item add/remove CLI churn."""
        if self.tor.dry_run:
            info(f"[dry-run] would set home zone '{zone_type}' ({label})")
            return
        cfg = self.tor.json(["workspace", self.ws_id, "home", "config", "dump",
                             "--format", "json"])
        if not isinstance(cfg, dict):
            warn(f"Could not read landing config — skipping {zone_type} zone")
            return
        zones = cfg.get("zones") or []
        # Drop any existing zones of this type (de-dupe), then append the rebuilt one.
        zones = [z for z in zones if z.get("type") != zone_type]
        zones.append({"type": zone_type, "label": label, "position": position,
                      "config": zone_config})
        cfg["zones"] = zones
        # The FE home component (workspace-home.component.ts buildZoneList) only enters
        # zone-based rendering when BOTH `grid` AND `zones` are present; without a top-level
        # `grid` it falls back to the flat format, finds no top-level kpis/pinned_widgets,
        # and shows the "Welcome / ready to be customized" placeholder. So always ensure a grid.
        if not cfg.get("grid"):
            cfg["grid"] = {"columns": 48, "gap_px": 12, "content_width_pct": 80}
        f = write_tmp_json({"landing_page": cfg})
        try:
            proc = self.tor.run(["workspace", self.ws_id, "home", "config", "set",
                                 "--file", str(f)])
            if proc.returncode != 0:
                warn(f"Failed to set {zone_type} zone: {(proc.stdout + proc.stderr)[:160]}")
        finally:
            f.unlink(missing_ok=True)

    def _sweep(self) -> None:
        """Trigger a landing-page sweep so the home page's KPI + attention values are
        (re)computed from the current transformer data and cached into
        workspace_landing_page_state. Without this the home renders configured zones but
        with stale/empty values until the next sweep fires. Tenant operation — safe to
        call from apply()/refresh() (both run as the tenant user)."""
        if self.tor.dry_run:
            info("[dry-run] would trigger landing-page sweep")
            return
        # refresh() doesn't run _apply_workspace(), so self.ws_id may be unset — fall
        # back to the tracked workspace id in state.
        ws_id = self.ws_id or self.state.get("workspace_id", "")
        if not ws_id:
            warn("No workspace id — skipping sweep")
            return
        info("Sweeping landing page (recompute KPI + attention values)…")
        proc = self.tor.run(["workspace", ws_id, "sweep", "--format", "json"])
        if proc.returncode != 0:
            warn(f"Sweep failed: {(proc.stdout + proc.stderr)[:160]}")
            return
        status = _parse_field(proc.stdout, "status")
        kpis = _parse_field(proc.stdout, "kpi_count")
        attn = _parse_field(proc.stdout, "attention_count")
        ok(f"Swept home page (status={status or 'ok'}"
           + (f", kpis={kpis}" if kpis else "")
           + (f", attention={attn}" if attn else "") + ")")

    def _apply_playbooks(self) -> None:
        """Create the workspace's playbooks BEFORE routes, so playbook-destination routes
        resolve and bind instead of deferring. Playbooks are workspace artifacts the
        script owns — creating one needs no live integration; it only DECLARES the
        providers it calls via tool_dependencies (e.g. ['slack']). The actual integration
        is wired separately by the user (integrations live outside the workspace) and is
        only required when the playbook EXECUTES, not when it is built."""
        section("Step 9 — Playbooks")
        playbooks = self.spec.get("playbooks", [])
        if not playbooks:
            info("No playbooks declared.")
            return
        for pb in playbooks:
            self._apply_one_playbook(pb)
        # New playbooks just landed — drop the resolver's cached playbook index so the
        # following route step sees them (the resolver memoizes `playbooks list`).
        self.resolver.invalidate_playbooks()

    def _apply_one_playbook(self, pb: dict) -> None:
        key = pb["key"]
        skey = f"playbook_{key}"
        name = self._label(pb["name"])
        if self.state.get(skey):
            info(f"Playbook '{key}' exists ({self.state.get(skey)}) — skipping create")
            return
        body = {
            "name": name,
            "description": (pb.get("description") or "").strip(),
            "instructions": (pb.get("instructions") or "").strip(),
            "workspace_id": self.ws_id,
            "tool_dependencies": pb.get("tool_dependencies", []),
            "input_parameters": pb.get("input_parameters", []),
            "tags": pb.get("tags", []),
        }
        info(f"Creating playbook '{key}'…")
        f = write_tmp_json(body)
        try:
            proc = self.tor.run(["playbooks", "create", "--file", str(f),
                                 "--format", "json"])
            pid = extract_id(proc.stdout)
            if pid:
                self.state.set(skey, pid)
                ok(f"Created playbook: {key} ({pid})")
            else:
                warn(f"Could not create playbook '{key}': "
                     f"{(proc.stdout + proc.stderr)[:200]}")
        finally:
            f.unlink(missing_ok=True)

    def _apply_routes(self) -> None:
        section("Step 10 — Alert Routes")
        for route in self.spec.get("routes", []):
            self._apply_one_route(route)

    def _apply_one_route(self, route: dict) -> None:
        key = route["key"]
        skey = f"route_{key}"
        if self.state.get(skey):
            # Reconcile in place: if the operational signature drifted, update those
            # fields. Destination is structural (a change = delete+recreate, out of scope).
            rid = self.state.get(skey)
            if not self.tor.dry_run:
                live = self.tor.json(["alert-route", rid, "get", "--format", "json"]) or {}
                live = live.get("data", live) if isinstance(live, dict) else {}
                if live and self._route_sig(live) != self._route_sig(route):
                    ubody: dict[str, Any] = {
                        "enabled": route.get("enabled", True),
                        "priority": route.get("priority", 10),
                        "stop_on_match": route.get("stop_on_match", False),
                        "matching_operator": route.get("matching_operator", "all"),
                        "max_executions_per_hour": route.get("max_executions_per_hour", 200),
                    }
                    for fld in self._ROUTE_FILTERS:
                        if route.get(fld):
                            ubody[fld] = route[fld]
                    if route.get("match_all") or not any(route.get(f) for f in
                                                         self._ROUTE_FILTERS):
                        ubody["match_all"] = True
                    uf = write_tmp_yaml(ubody)
                    try:
                        proc = self.tor.run(["alert-route", rid, "update", "--file",
                                             str(uf), "--format", "json"])
                        if proc.returncode == 0:
                            ok(f"Route '{key}': config updated")
                        else:
                            warn(f"Route '{key}': update failed: "
                                 f"{(proc.stdout + proc.stderr)[:160]}")
                    finally:
                        uf.unlink(missing_ok=True)
                    return
            info(f"Route '{key}' up to date ({self.state.get(skey)}) — skipping")
            return
        dest_type = route["destination_type"]
        dest_ref = route["destination_ref"]
        # Playbook destinations are workspace artifacts the script creates itself, with a
        # program-prefixed name (see _apply_playbooks). Resolve the prefixed name first so
        # routes bind to our own playbooks; fall back to the raw name for external
        # playbooks/agents/workflows the platform owns.
        if dest_type == "playbook":
            dest_id = (self.resolver.by_type("playbook", self._label(dest_ref))
                       or self.resolver.by_type("playbook", dest_ref))
        else:
            dest_id = self.resolver.by_type(dest_type, dest_ref)
        if not dest_id and not self.tor.dry_run:
            # The destination (agent/playbook/workflow) doesn't exist on the platform
            # yet. This is an EXTERNAL dependency, not a build failure — record it so
            # verify reports it as "deferred" rather than "missing".
            self.state.set(f"routedeferred_{key}", f"{dest_type}:{dest_ref}")
            warn(f"Route '{key}': {dest_type} '{dest_ref}' not found — deferred "
                 "(create the destination, then re-apply this route)")
            return
        self.state.delete(f"routedeferred_{key}")  # resolved now
        dest_cfg: dict[str, Any] = {f"{dest_type}_id": dest_id or "dry-run"}
        if dest_type == "agent":
            dest_cfg["interaction_mode"] = route.get("interaction_mode", "autonomous")
        elif dest_type == "playbook":
            dest_cfg.setdefault("input_mapping", {"alert_id": "$.id"})

        body = {
            "workspace_id": self.ws_id,
            "name": self._label(route["name"]),
            "description": (route.get("description") or "").strip(),
            "enabled": route.get("enabled", True),
            "priority": route.get("priority", 10),
            "stop_on_match": route.get("stop_on_match", False),
            "matching_operator": route.get("matching_operator", "all"),
            "destination_type": dest_type,
            "destination_config": dest_cfg,
            "max_executions_per_hour": route.get("max_executions_per_hour", 200),
        }
        # The routing model has no `alert_types` column — it filters via
        # source_rule_ids / source_suite_ids / severity_levels / required_tags, or
        # match_all for an intentional catch-all. A route must declare one of those or
        # the create endpoint's validator rejects it. We pass the real filter fields
        # through from artifacts.yaml and fall back to match_all when none is given.
        for fld in ("source_rule_ids", "source_suite_ids", "severity_levels",
                    "required_tags"):
            if route.get(fld):
                body[fld] = route[fld]
        has_filter = any(body.get(f) for f in
                         ("source_rule_ids", "source_suite_ids",
                          "severity_levels", "required_tags"))
        if route.get("match_all") or not has_filter:
            body["match_all"] = True
        info(f"Creating route '{key}' → {dest_type}:{dest_ref}…")
        f = write_tmp_yaml(body)
        try:
            proc = self.tor.run(["alert-routes", "create", "--file", str(f), "--format", "json"])
            rid = extract_id(proc.stdout)
            if rid:
                self.state.set(skey, rid)
                ok(f"Route '{key}': {rid}")
            else:
                warn(f"Could not create route '{key}': {(proc.stdout + proc.stderr)[:200]}")
        finally:
            f.unlink(missing_ok=True)

    def _apply_schedulers(self) -> None:
        section("Step 10 — Schedulers")
        for sched in self.spec.get("schedulers", []):
            self._apply_one_scheduler(sched)

    def _apply_one_scheduler(self, sched: dict) -> None:
        name = sched["name"]
        skey = f"scheduler_{re.sub(r'[^a-z0-9]+', '_', name.lower())}"
        if self.state.get(skey):
            # Reconcile in place: if the desired cron differs from live, update it
            # (idempotent re-apply / drift correction). task_type + target are
            # structural — a change there is out of scope for update (delete+recreate).
            sid = self.state.get(skey)
            if not self.tor.dry_run:
                live = self.tor.json(["schedulers", "get", sid, "--format", "json"]) or {}
                live = live.get("data", live) if isinstance(live, dict) else {}
                desired_expr = (sched.get("schedule_expression") or "").strip()
                if live and (live.get("schedule_expression") or "").strip() != desired_expr:
                    proc = self.tor.run(["schedulers", "update-task", sid,
                                         "--schedule-expression", desired_expr,
                                         "--format", "json"])
                    if proc.returncode == 0:
                        ok(f"Scheduler '{name}': schedule → {desired_expr}")
                    else:
                        warn(f"Scheduler '{name}': update failed: "
                             f"{(proc.stdout + proc.stderr)[:160]}")
                    return
            info(f"Scheduler '{name}' up to date ({self.state.get(skey)}) — skipping")
            return
        task_type = sched["task_type"]
        target_ref = sched.get("target_ref", "")
        # Resolve the target to an ID from state (transformer_/rule_ key).
        target_id = (self.state.get(f"transformer_{target_ref}")
                     or self.state.get(f"rule_{target_ref}") or "")
        if not target_id and not self.tor.dry_run:
            warn(f"Scheduler '{name}': target '{target_ref}' not found in state — skipping")
            return
        args = [
            "schedulers", "create-task",
            "--name", self._label(name),
            "--description", sched.get("description", ""),
            "--task-type", task_type,
            "--schedule-type", sched.get("schedule_type", "cron"),
            "--schedule-expression", sched["schedule_expression"],
            "--workspace-id", self.ws_id,
            "--is-enabled", "true",
            f"--{task_type}-id", target_id or "dry-run",
            "--format", "json",
        ]
        info(f"Creating scheduler '{name}' ({task_type}:{target_ref})…")
        proc = self.tor.run(args)
        sid = extract_id(proc.stdout)
        if sid:
            self.state.set(skey, sid)
            ok(f"Scheduler '{name}': {sid}")
        else:
            warn(f"Could not create scheduler '{name}': {(proc.stdout + proc.stderr)[:200]}")

    def _verify(self) -> None:
        section("Verification")
        if self.tor.dry_run:
            info("dry-run — skipping verification")
            return
        failed = False
        # workspace
        data = self.tor.json(["workspace", self.ws_id, "get", "--format", "json"])
        st = (data or {}).get("state", "unknown")
        if st in ("active", "ready"):
            ok(f"Workspace {self.ws_id} is {st}")
        else:
            warn(f"Workspace {self.ws_id} state='{st}'")
            failed = True
        # counts — ALL widgets get pinned to the home page
        declared_pins = sum(
            len(d.get("widgets", [])) for d in self.spec.get("dashboards", [])
        )
        # Routes deferred because their agent/playbook destination doesn't exist yet
        # are an EXTERNAL dependency, not a build failure.
        deferred_routes = len(self.state.items_with_prefix("routedeferred_"))
        for label, prefix, declared in [
            ("transformers", "transformer_", len(self.spec.get("transformers", []))),
            ("rules", "rule_", len(self.spec.get("rules", []))),
            ("dashboards", "dashboard_", len(self.spec.get("dashboards", []))),
            ("home-page pins", "pinwidget_", declared_pins),
            ("playbooks", "playbook_", len(self.spec.get("playbooks", []))),
            ("routes", "route_", len(self.spec.get("routes", []))),
            ("schedulers", "scheduler_", len(self.spec.get("schedulers", []))),
        ]:
            built = len(self.state.items_with_prefix(prefix))
            if declared == 0:
                continue
            if built >= declared:
                ok(f"{label}: {built}/{declared} built")
            elif label == "routes" and built + deferred_routes >= declared:
                # all accounted for: built + deferred (waiting on an external dest)
                info(f"{label}: {built}/{declared} built, {deferred_routes} deferred "
                     "(destination agent/playbook not on platform yet — not a failure)")
            else:
                warn(f"{label}: {built}/{declared} built")
                failed = True
        if self.state.get("policy_doc"):
            ok("policy document ingested")
        print()
        if failed:
            print("  ⚠  Some artifacts are missing — see warnings above.")
        elif deferred_routes:
            print(f"  ✓  All artifacts built. ({deferred_routes} alert route(s) deferred "
                  "until their Slack/WAF playbook exists — expected.)")
        else:
            print("  ✓  All declared artifacts built.")
        print()
        print(f"  Workspace ID: {self.ws_id}")
        print(f"  State file:   {self.state.path}")

    # ----- DELETE ----------------------------------------------------------
    def delete(self) -> None:
        # Reverse of CREATE_PHASES.
        self._delete_schedulers()
        self._delete_routes()
        self._delete_playbooks()
        self._delete_home_pins()
        self._delete_attention_and_kpis()
        self._delete_dashboards()
        self._delete_rules()
        self._delete_transformers()
        self._delete_policy()
        self._delete_workspace()
        self.state.clear()
        ok("State file cleared")

    def _del(self, skey: str, label: str, cmd: list[str]) -> None:
        _id = self.state.get(skey)
        if not _id:
            return
        info(f"Deleting {label} ({_id})…")
        proc = self.tor.run([a if a != "{id}" else _id for a in cmd])
        if self.tor.dry_run or proc.returncode == 0:
            ok(f"Deleted {label}")
        else:
            warn(f"Could not delete {label} (may already be gone)")
        self.state.delete(skey)

    def _delete_schedulers(self) -> None:
        section("Schedulers")
        for skey, _id in self.state.items_with_prefix("scheduler_"):
            self._del(skey, skey, ["schedulers", "delete", "{id}", "--yes"])

    def _delete_home_pins(self) -> None:
        section("Home Page Pins")
        ws = self.state.get("workspace_id", "")
        pins = self.state.items_with_prefix("pinwidget_")
        for skey, wname in pins:
            wid = skey.replace("pinwidget_", "")
            self.tor.run(["workspace", ws, "home", "unpin", "--widget-id", wid],
                         capture=True)
            self.state.delete(skey)
        if pins:
            ok(f"Unpinned {len(pins)} home-page widget(s)")

    def _delete_routes(self) -> None:
        section("Alert Routes")
        for skey, _id in self.state.items_with_prefix("route_"):
            self._del(skey, skey, ["alert-route", "{id}", "delete", "--yes"])

    def _delete_playbooks(self) -> None:
        section("Playbooks")
        for skey, _id in self.state.items_with_prefix("playbook_"):
            self._del(skey, skey, ["playbook", "{id}", "delete", "--yes"])

    def _delete_attention_and_kpis(self) -> None:
        # KPI bar, attention, and pinned-widget zones all live in the landing config
        # and are removed with the workspace delete — nothing to clear individually.
        return

    def _delete_dashboards(self) -> None:
        section("Dashboards")
        ws = self.state.get("workspace_id", "")
        for skey, _id in self.state.items_with_prefix("dashboard_"):
            info(f"Deleting {skey} ({_id})…")
            proc = self.tor.run(["workspace", ws, "dashboard", _id, "delete", "--yes"])
            if self.tor.dry_run or proc.returncode == 0:
                ok(f"Deleted {skey}")
            else:
                warn(f"Could not delete {skey}")
            self.state.delete(skey)

    def _delete_rules(self) -> None:
        section("Detection Rules")
        for skey, _id in self.state.items_with_prefix("rule_"):
            self._del(skey, skey, ["rule", "{id}", "delete", "--yes"])

    def _delete_transformers(self) -> None:
        section("Transformers")
        # Delete in REVERSE topological order so dependents go before their base.
        declared = self.spec.get("transformers", [])
        order = [t["key"] for t in topo_sort(declared)] if declared else []
        # state may contain transformers not in spec; append leftovers.
        state_keys = [k.replace("transformer_", "") for k, _ in
                      self.state.items_with_prefix("transformer_")]
        for k in state_keys:
            if k not in order:
                order.append(k)
        for key in reversed(order):
            self._del(f"transformer_{key}", f"transformer {key}",
                      ["transformer", "{id}", "delete", "--yes"])

    def _delete_policy(self) -> None:
        section("Policy Document")
        doc_id = self.state.get("policy_doc")
        if not doc_id:
            return
        # The torana CLI has no `rag document delete` verb — RAG documents cannot
        # be removed from the CLI today. We drop it from state (so a fresh apply
        # re-ingests) and leave the indexed copy in place. Re-ingesting the same
        # title creates a new version rather than a duplicate, so this is safe.
        warn(f"Policy document {doc_id} left in RAG (no CLI delete verb). "
             "Dropped from state; re-apply will re-ingest.")
        self.state.delete("policy_doc")

    def _delete_workspace(self) -> None:
        section("Workspace")
        ws = self.state.get("workspace_id")
        if not ws:
            return
        info(f"Deleting workspace {ws}…")
        proc = self.tor.run(["workspace", ws, "delete", "--yes"])
        if self.tor.dry_run or proc.returncode == 0:
            ok("Deleted workspace")
        else:
            warn("Could not delete workspace (may already be gone)")

    # ----- LIST (live system, reconciled against artifacts.yaml) -----------
    def list(self) -> None:
        ws = self.state.get("workspace_id") or self.cli_workspace_id
        section(f"{self.usecase} — live resources")
        if not ws:
            warn("No workspace in state. Run `apply` first.")
            return
        self.ws_id = ws
        data = self.tor.json(["workspace", ws, "get", "--format", "json"]) or {}
        print(f"\n  Workspace: {ws}")
        print(f"    name:  {data.get('name', '?')}")
        print(f"    state: {data.get('state', '?')}")

        self._list_reconcile(
            "Transformers",
            declared=[self._ns(t["name"]) for t in self.spec.get("transformers", [])],
            live=self._live_names(["transformers", "list", "--workspace-id", ws,
                                   "--raw", "--format", "json"], ("transformers", "items")),
        )
        self._list_reconcile(
            "Detection Rules",
            declared=[self._label(r["name"]) for r in self.spec.get("rules", [])],
            live=self._live_names(["workspace", ws, "rules", "--format", "json"],
                                  ("rules", "items")),
        )
        self._list_reconcile(
            "Dashboards",
            declared=[self._label(d["name"]) for d in self.spec.get("dashboards", [])],
            live=self._live_names(["workspace", ws, "dashboards", "--format", "json"],
                                  ("dashboards", "items")),
        )
        self._list_reconcile(
            "KPI Cards",
            declared=[self._label(k["title"]) for k in self.spec.get("kpis", [])],
            live=self._live_names(["workspace", ws, "kpi", "list", "--format", "json"],
                                  ("items",), name_keys=("label", "title")),
        )
        self._list_reconcile(
            "Attention Cards",
            declared=[self._label(a["title"]) for a in self.spec.get("attention_cards", [])],
            live=self._live_names(["workspace", ws, "attention", "list", "--format", "json"],
                                  ("items",), name_keys=("title",)),
        )
        # Routes + schedulers: fetch the LIVE name per tracked ID and verify the prefix.
        self._list_state_live(
            "Alert Routes", "route_",
            declared_total=len(self.spec.get("routes", [])),
            fetch=lambda _id: self._fetch_name(["alert-route", _id, "get", "--format", "json"]),
        )
        self._list_state_live(
            "Schedulers", "scheduler_",
            declared_total=len(self.spec.get("schedulers", [])),
            fetch=lambda _id: self._fetch_name(["schedulers", "get", _id, "--format", "json"]),
        )
        print()

    def _live_names(self, args: list[str], container_keys: tuple,
                    name_keys: tuple = ("name",)) -> list[str]:
        data = self.tor.json(args)
        if data is None:
            return []
        items = data if isinstance(data, list) else None
        if items is None and isinstance(data, dict):
            for ck in container_keys:
                if ck in data and isinstance(data[ck], list):
                    items = data[ck]
                    break
        items = items or []
        out = []
        for it in items:
            for nk in name_keys:
                if it.get(nk):
                    out.append(it[nk])
                    break
        return out

    def _list_reconcile(self, label: str, declared: list[str], live: list[str],
                        check_prefix: bool = True) -> None:
        print(f"\n  {label}:  ({len(live)} live / {len(declared)} declared)")
        live_set = set(live)
        for name in declared:
            present = name in live_set
            # Names are clean (workspace-scoped ownership) — present/missing is the signal.
            mark = "✓" if present else "✗ MISSING"
            print(f"    [{mark}] {name}")
        extra = live_set - set(declared)
        for name in sorted(extra):
            print(f"    [+] {name}  (not in artifacts.yaml)")
        if not declared and not live:
            print("    (none)")

    def _fetch_name(self, args: list[str]) -> str:
        d = self.tor.json(args) or {}
        return d.get("name", "") if isinstance(d, dict) else ""

    def _list_state_live(self, label: str, prefix: str, declared_total: int, fetch) -> None:
        """For state-tracked artifacts (routes, schedulers) fetch each one's LIVE name
        and list what's built vs declared (names are clean — workspace-scoped ownership)."""
        built = self.state.items_with_prefix(prefix)
        print(f"\n  {label}:  ({len(built)} built / {declared_total} declared)")
        live_names = []
        for skey, _id in built:
            name = fetch(_id) or "(name unavailable)"
            live_names.append(name)
            print(f"    [✓] {name}")
        if declared_total > len(built):
            print(f"    [✗] {declared_total - len(built)} declared not built "
                  "(e.g. unresolved playbook/agent destination — see apply warnings)")
        if not live_names and declared_total == 0:
            print("    (none)")

    # ----- REFRESH (re-materialise transformers against current data) ------
    def refresh(self) -> None:
        """Re-execute all of this App's transformers so their MATERIALISED tables
        reflect the data currently in the datalake.

        Why this exists: transformers with `materialized: true` compile to physical
        BASE TABLEs, not live views — they hold a SNAPSHOT from when the transformer
        last ran. `apply` runs them once (to make the table exist so dependent
        artifacts validate), but if data is loaded/changed afterwards the snapshot is
        stale. Run `refresh` after `load-data` (or any data change) to repopulate.
        Best practice is load-data → apply, but refresh makes any order correct.

        Tenant operation (transformers are tenant-scoped) — run as the tenant user.
        Executes in topological order so base views refresh before dependents.
        """
        section("Refresh transformers (re-materialise against current data)")
        declared = self.spec.get("transformers", [])
        if not declared:
            info("No transformers declared.")
            return
        ran = 0
        for t in topo_sort(declared):
            tid = self.state.get(f"transformer_{t['key']}")
            if not tid:
                warn(f"Transformer '{t['key']}' not in state — run `apply` first.")
                continue
            info(f"Executing '{t['key']}'…")
            proc = self.tor.run(["transformer", tid, "execute-and-wait", "--format", "json"])
            status = _parse_field(proc.stdout, "status")
            if self.tor.dry_run or (proc.returncode == 0 and status != "failed"):
                # `rows_affected` from this endpoint is a delta, not the result size —
                # query the materialised table for the real, meaningful row count.
                rows = self._materialized_rowcount(t.get("destination_table", t["name"]))
                ok(f"Refreshed: {t['key']}"
                   + (f" ({rows} rows)" if rows is not None else ""))
                ran += 1
            else:
                err_msg = _parse_field(proc.stdout, "error_message")
                warn(f"Refresh failed for '{t['key']}': "
                     f"{err_msg or (proc.stdout + proc.stderr)[:160]}")
        # Transformers re-materialised — sweep so the home page's KPI/attention values
        # reflect the fresh data (refresh is the canonical post-load-data tenant step).
        self._sweep()
        section("Done")
        print(f"\n  Refreshed {ran}/{len(declared)} transformer(s). Dashboards/KPIs/"
              "rules that read them now reflect current data, and the home page has "
              "been swept.")

    def _materialized_rowcount(self, dest_table: str) -> Optional[int]:
        """Best-effort count of the materialised transformer table (namespaced).
        playground-execute prints a `DATA [...]` line (not pure JSON)."""
        if self.tor.dry_run:
            return None
        view = self._ns(dest_table)
        proc = self.tor.run(["datalake", "playground-execute",
                             "--sql", f"SELECT COUNT(*) AS n FROM {view}", "--limit", "1"])
        rows = _parse_labeled_json(proc.stdout, "DATA")
        try:
            if isinstance(rows, list) and rows:
                return int(rows[0].get("n"))
        except Exception:
            pass
        return None

    # ----- SDG DATA (load-data / clear-data) -------------------------------
    def _dataset_id(self) -> str:
        """The SDG dataset id that feeds this use case. Prefer the explicit
        `dataset_id` field; fall back to the non-base element of dataset_scope."""
        did = self.spec.get("dataset_id")
        if did:
            return did
        scope = self.spec.get("dataset_scope", [])
        app = [s for s in scope if s != "novacraft-base-v1"]
        return app[0] if app else ""

    def load_data(self, tenant_id: str, start_phase: Optional[str],
                  clear: bool) -> None:
        """Replay this use case's SDG dataset into `tenant_id`. The dataset declares
        depends_on: [novacraft-base-v1] so the shared estate auto-loads first (or is
        skipped if already present). Mirrors the manual sequence:
            torana sdg replay start --dataset-id <id> --tenant-id <T> \\
              --start-phase t2 --normalized [--clear] --tick-mode manual
            torana sdg replay tick --tenant-id <T>
        """
        dataset_id = self._dataset_id()
        if not dataset_id:
            err(f"No dataset_id for use case '{self.usecase}' (set `dataset_id:` in "
                "artifacts.yaml).")
        section(f"Load SDG data — {dataset_id} → tenant {tenant_id}")
        # Stop any active replay for this tenant first (engine is one-per-tenant).
        self.tor.run(["sdg", "replay", "stop", "--tenant-id", tenant_id], capture=True)

        start_args = [
            "sdg", "replay", "start",
            "--dataset-id", dataset_id,
            "--tenant-id", tenant_id,
            "--normalized",
            "--tick-mode", "manual",
        ]
        if start_phase:
            start_args += ["--start-phase", start_phase]
        if clear:
            start_args.append("--clear")
        info(f"Starting replay ({'clear' if clear else 'no-clear/stack'}"
             f"{', phase ' + start_phase if start_phase else ''})…")
        proc = self.tor.run(start_args)
        if proc.returncode != 0:
            out = (proc.stdout + proc.stderr).strip()
            if "not found" in out.lower() or "404" in out:
                err(f"Dataset '{dataset_id}' is not registered. Seed it first as "
                    f"super-admin:\n     torana sdg datasets seed --force\n   ({out[:160]})")
            err(f"Replay start failed: {out[:300]}")
        # Report dependency resolution. The CLI prints a key-value table; the
        # DEPENDENCIES line carries a JSON array.
        for dep in _parse_labeled_json(proc.stdout, "DEPENDENCIES") or []:
            info(f"dependency {dep.get('dataset_id')}: {dep.get('action')}"
                 + (f" ({dep.get('records_pushed')} rows)"
                    if dep.get("records_pushed") else ""))
        ok("Replay started")

        # One manual tick performs the pre-history bulk sweep + the start phase window.
        info("Advancing one tick (bulk-loads pre-history + wake-up phase)…")
        tick = self.tor.run(["sdg", "replay", "tick", "--tenant-id", tenant_id])
        tk = _parse_labeled_json(tick.stdout, "TICK")
        pushed = str(tk.get("total_records", "")) if isinstance(tk, dict) else ""
        ok(f"Tick pushed{(' ' + pushed + ' records') if pushed else ''}")

        # Stop the replay — pushed rows persist in the datalake.
        self.tor.run(["sdg", "replay", "stop", "--tenant-id", tenant_id], capture=True)
        section("Done")
        print(f"\n  Loaded '{dataset_id}' (+ novacraft-base-v1) into tenant {tenant_id}.")
        print(f"  The {self.usecase} app's rules/transformers now have data.")
        print("\n  ⚠ REQUIRED NEXT STEP — log back in as the tenant user, then run:")
        print(f"      ./scripts/vm_workspace.py {self.usecase} refresh")
        print("  `refresh` re-materialises the transformers against the data you just")
        print("  loaded AND sweeps the home page (recomputes KPI/attention values).")
        print("  Without it the home page shows stale/empty values — load-data runs as")
        print("  super-admin and CANNOT sweep (sweep is a tenant-scoped operation).")

    def clear_data(self, tenant_id: str) -> None:
        """Clear this use case's SDG dataset rows from `tenant_id`'s datalake.
        Uses a start --clear (deletes only dataset_tag=<id>) then stop without ticking,
        so nothing is re-pushed. The shared novacraft-base-v1 and other apps are NOT
        touched (clear is per-dataset)."""
        dataset_id = self._dataset_id()
        if not dataset_id:
            err(f"No dataset_id for use case '{self.usecase}'.")
        section(f"Clear SDG data — {dataset_id} from tenant {tenant_id}")
        self.tor.run(["sdg", "replay", "stop", "--tenant-id", tenant_id], capture=True)
        info(f"Clearing rows tagged '{dataset_id}' (per-dataset; base + other apps "
             "untouched)…")
        proc = self.tor.run([
            "sdg", "replay", "start",
            "--dataset-id", dataset_id,
            "--tenant-id", tenant_id,
            "--normalized", "--clear",
            "--start-phase", "t2",
            "--tick-mode", "manual",
            "--skip-deps",          # do NOT auto-load the base just to clear this app
        ])
        # stop BEFORE ticking → clear ran at load, nothing reloaded.
        self.tor.run(["sdg", "replay", "stop", "--tenant-id", tenant_id], capture=True)
        if proc.returncode != 0:
            warn(f"Clear may not have run: {(proc.stdout + proc.stderr)[:200]}")
        else:
            ok(f"Cleared '{dataset_id}' rows from tenant {tenant_id}")
        section("Done")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def load_spec(usecase: str) -> tuple[dict, Path]:
    usecase_dir = USECASES_DIR / usecase
    if not usecase_dir.is_dir():
        err(f"Use case folder not found: {usecase_dir}")
    af = usecase_dir / "artifacts.yaml"
    if not af.exists():
        err(f"artifacts.yaml not found in {usecase_dir}")
    spec = yaml.safe_load(af.read_text())
    return spec, usecase_dir


def load_spec_from_file(path: str) -> tuple[str, dict, Path]:
    """Load an artifacts.yaml from an ARBITRARY path (skill / ad-hoc mode) — the
    file need not live under usecases/. Returns (usecase_label, spec, work_dir).
    The label (used for the workspace name + prefix fallback) comes from the spec's
    own `usecase` field, else the file's parent-dir name. The parent dir holds the
    per-program `.state.json` and receives import output — exactly like a usecase dir."""
    af = Path(path).expanduser().resolve()
    if not af.is_file():
        err(f"artifacts.yaml not found: {af}")
    spec = yaml.safe_load(af.read_text()) or {}
    label = spec.get("usecase") or af.parent.name
    return label, spec, af.parent


def confirm(prompt: str, yes: bool) -> bool:
    if yes:
        return True
    ans = input(f"  {prompt} [y/N] ").strip().lower()
    return ans == "y"


# Which identity each command requires. Artifacts are tenant-scoped; SDG data ops
# need super-admin. The script enforces this (no silent switching).
TENANT_COMMANDS = {"apply", "plan", "prune", "import", "assess", "build", "delete", "list", "refresh"}
ADMIN_COMMANDS = {"load-data", "clear-data"}


def _enforce_identity(command: str, ident: Optional[Identity], dry_run: bool) -> None:
    """Print who is logged in and hard-block if the identity is wrong for the command."""
    if ident is None:
        if dry_run:
            warn("Not logged in (dry-run — continuing).")
            return
        err("Not logged in. Run `torana auth login --email <you> --password <pw>` first, "
            "then `torana auth me` to confirm.")
    print(ident.banner())
    print()
    sys.stdout.flush()   # ensure the identity banner is visible BEFORE any err() on stderr
    if dry_run:
        return
    if command in ADMIN_COMMANDS and not ident.is_super_admin:
        err(
            f"'{command}' loads SDG data and requires SUPER-ADMIN.\n"
            f"   You are '{ident.email}' [roles: {', '.join(ident.roles) or '?'}].\n"
            "   Log in as a super-admin, then re-run:\n"
            "     torana auth login --email <super-admin-email> --password '<pw>'\n"
            f"     vm_workspace.py {sys.argv[1] if len(sys.argv) > 1 else '<usecase>'} "
            f"{command} --tenant-id <TENANT>"
        )
    if command in TENANT_COMMANDS and ident.is_super_admin:
        err(
            f"'{command}' builds TENANT-scoped artifacts and must run as a TENANT user "
            "(not super-admin), so they land in the right tenant.\n"
            f"   You are super-admin ('{ident.email}').\n"
            "   Log in as the tenant user, then re-run:\n"
            "     torana auth login --email <tenant-email> --password '<pw>'\n"
            f"     vm_workspace.py {sys.argv[1] if len(sys.argv) > 1 else '<usecase>'} "
            f"{command}"
        )


def _discover_usecases() -> list[str]:
    """List use-case folders (those containing an artifacts.yaml)."""
    if not USECASES_DIR.is_dir():
        return []
    return sorted(
        d.name for d in USECASES_DIR.iterdir()
        if d.is_dir() and (d / "artifacts.yaml").exists()
    )


_HELP_DESCRIPTION = """\
vm_workspace.py — build a complete Torana "App" (workspace) from a use case's
declarative artifacts.yaml, and load the synthetic data that makes it light up.

WHAT IT DOES
  Each use case under usecases/<name>/ pairs a written security program
  (policy/ + build-program/ narrative) with two machine files:
    • artifacts.yaml — the App build manifest (workspace, transformers, rules,
      dashboards+widgets, KPIs, attention cards, alert routes, schedulers, and
      the home page: KPI bar + attention + pinned widgets).
    • data.md        — the SDG synthetic-data spec the App's rules query.
  This script reconciles artifacts.yaml into a tenant (apply/list/delete) and
  replays the matching SDG dataset into a tenant (load-data/clear-data).

THE TWO-IDENTITY MODEL (enforced; the script never switches identity for you)
  • apply / list / delete  → run as the TENANT USER (artifacts are tenant-scoped).
  • load-data / clear-data → run as SUPER-ADMIN (SDG replay control plane).
                             --tenant-id is REQUIRED — there is no default (the
                             super-admin session tenant is the system tenant).
  Every run prints `torana auth me` and HARD-BLOCKS the wrong role with the exact
  `torana auth login` to run. So a full demo is two phases by two logins.

COMMANDS
  apply       Build/update the whole App in the logged-in tenant. Idempotent;
              dependency-ordered create (transformers materialised before the
              rules/widgets that read them); every artifact name is prefixed with
              the program tag (vmops_/ciso_/devops_/grc_/zd_).
  list        Per-app: live-reconcile what exists vs artifacts.yaml; verify every
              artifact carries its program prefix.
              With NO use case (`vm_workspace.py list`): FLEET status — for all 5
              apps, whether each workspace is present/absent/stale + artifact counts.
  delete      Tear down all tracked artifacts in reverse-dependency order, then
              clear local state.
  refresh     Re-run all transformers so their MATERIALISED tables reflect the
              data currently in the datalake. Materialised transformers are
              snapshot tables, not live views — run this after load-data (or any
              data change) so dashboards/KPIs/rules show current numbers.
  load-data   Replay this App's SDG dataset into --tenant-id. The shared
              novacraft-base-v1 estate auto-loads first (via the dataset's
              depends_on), then the App's scenario layers on top. Defaults to the
              t2 "wake-up" state. --no-clear/--stack to keep existing data.
  clear-data  Clear this App's dataset rows from --tenant-id (per-dataset: the
              shared base and other apps are untouched).

THE 'all' TARGET (fan-out)
  Use 'all' in place of a use-case name to run ANY command across every use case
  in one shot: `all apply`, `all delete`, `all refresh`, `all load-data
  --tenant-id <T>`, `all clear-data --tenant-id <T>`. The batch keeps going if a
  single app errors and prints a per-use-case summary at the end (exit 1 if any
  failed). Destructive batches (delete/clear-data) take ONE confirmation up front
  — or pass --yes. --workspace-id can't be combined with 'all'.

RECOMMENDED ORDER (avoids stale materialised transformers)
  1. (super-admin)  load-data   — get data into the tenant's datalake first
  2. (tenant user)  apply       — build the App; transformers materialise WITH data
  …or build-first then `refresh` after load-data. Either works; refresh makes any
  order correct.

ONE-TIME PREREQUISITE (super-admin)
  The on-disk SDG datasets must be registered once:
      torana sdg datasets seed --force
  load-data does NOT seed for you (it's a system-wide admin op); if a dataset
  isn't registered it tells you to run that command.
"""


def _epilog() -> str:
    ucs = _discover_usecases()
    uc_lines = "\n".join(f"    {u}" for u in ucs) or "    (none found under usecases/)"
    return f"""\
AVAILABLE USE CASES (folders with an artifacts.yaml under usecases/)
{uc_lines}

EXAMPLES
  # --- as the TENANT user (artifacts) ---
  torana auth login --email <tenant-email> --password '<password>'
  vm_workspace.py vm-operations apply           # build the App (+ home page)
  vm_workspace.py vm-operations list            # reconcile vs artifacts.yaml
  vm_workspace.py vm-operations delete --yes    # tear down

  # --- as SUPER-ADMIN (data), targeting the tenant you built into ---
  torana auth login --email <super-admin-email> --password '<password>'
  vm_workspace.py vm-operations load-data --tenant-id <TENANT_UUID>
  vm_workspace.py zero-day-response load-data --tenant-id <TENANT_UUID> --stack
  vm_workspace.py vm-operations clear-data --tenant-id <TENANT_UUID> --yes
  vm_workspace.py vm-operations load-data --tenant-id <TENANT_UUID> --start-phase t3

  # inspect the exact torana CLI calls without touching anything
  vm_workspace.py vm-operations apply --dry-run

  # --- 'all' fan-out: run one command across EVERY use case ---
  vm_workspace.py all apply                       # build all 5 apps (tenant user)
  vm_workspace.py all delete --yes                # tear all 5 down (tenant user)
  vm_workspace.py all load-data --tenant-id <T>   # load every dataset (super-admin)
  vm_workspace.py all clear-data --tenant-id <T> --yes
  # 'all' prints a per-use-case summary at the end and keeps going if one app fails;
  # one confirmation up front covers a batch delete/clear-data (or pass --yes).

See pantheon-playground/README.md → "Use-Case Workspaces" for the full guide.
"""


COMMANDS = ["apply", "delete", "list", "refresh", "load-data", "clear-data"]


class _HelpfulParser(argparse.ArgumentParser):
    """On ANY argument error (missing/invalid positional, bad flag), print the
    FULL help — not the one-line usage. A user hitting an error is trying to figure
    the tool out; give them everything from this layer on."""

    def error(self, message: str):
        sys.stderr.write(f"\nvm_workspace.py: {message}\n")
        sys.stderr.write("─" * 70 + "\n")
        self.print_help(sys.stderr)
        sys.exit(2)


def _reorder_positionals(argv: list[str]) -> list[str]:
    """Accept `<usecase> <command>` in EITHER order. If the first positional is a
    known command and the second is a known use case, swap them so the parser (and
    the rest of the script) sees the canonical order. Leaves flags untouched."""
    usecases = set(_discover_usecases()) | {"all"}
    positionals = [a for a in argv if not a.startswith("-")]
    if len(positionals) >= 2:
        first, second = positionals[0], positionals[1]
        if first in COMMANDS and second in usecases:
            # swap the two positionals in place within argv
            i1 = argv.index(first)
            i2 = argv.index(second, i1 + 1)
            argv = list(argv)
            argv[i1], argv[i2] = argv[i2], argv[i1]
    return argv


def fleet_list(dry_run: bool = False) -> None:
    """`vm_workspace.py list` (no use case) — fleet status across ALL use cases.
    For each app: is its workspace present in the system, and how many of its
    declared artifacts are live. Reconciles the local state file against the live
    platform (so it surfaces apps deleted out-of-band — stale state)."""
    tor = Torana(dry_run=dry_run)
    ident = whoami(tor)
    section("Fleet status — all use cases")
    if ident:
        print(ident.banner())
    print()
    ucs = _discover_usecases()
    if not ucs:
        warn("No use cases found under usecases/.")
        return
    hdr = f"  {'USE CASE':22} {'WORKSPACE':12} {'NAME':30} {'ARTIFACTS (live/declared)'}"
    print(hdr)
    print("  " + "─" * (len(hdr) - 2))
    for u in ucs:
        spec, usecase_dir = load_spec(u)
        state = State(usecase_dir / ".state.json")
        ws_id = state.get("workspace_id", "")
        # declared artifact total (transformers+rules+dashboards+routes+schedulers+kpis+attention)
        declared = (len(spec.get("transformers", [])) + len(spec.get("rules", []))
                    + len(spec.get("dashboards", [])) + len(spec.get("routes", []))
                    + len(spec.get("schedulers", [])) + len(spec.get("kpis", []))
                    + len(spec.get("attention_cards", [])))
        if not ws_id:
            print(f"  {u:22} {'— none —':12} {'(not applied)':30} {'0/' + str(declared)}")
            continue
        data = tor.json(["workspace", ws_id, "get", "--format", "json"])
        if not isinstance(data, dict) or not data.get("id"):
            # state points at a workspace that no longer exists (deleted out-of-band)
            print(f"  {u:22} {'STALE':12} {'(state→deleted ws)':30} "
                  f"{'?/' + str(declared)}   ⚠ run `delete` then re-apply, or rm "
                  f"{state.path.name}")
            continue
        # count live artifacts the script tracks (from state, but only those whose
        # workspace still exists — which we just confirmed)
        live = sum(1 for k, _ in state.data.items()
                   if any(k.startswith(p) for p in
                          ("transformer_", "rule_", "dashboard_", "route_",
                           "scheduler_")))
        wsname = (data.get("name") or "?")[:30]
        wsstate = data.get("state", "?")
        print(f"  {u:22} {wsstate:12} {wsname:30} ~{live}/{declared} tracked")
    print()
    print("  Run `vm_workspace.py <use-case> list` for the detailed per-app reconcile.")
    print()


def _run_command(builder: "Builder", command: str, args: argparse.Namespace,
                 yes: bool) -> None:
    """Execute ONE command for ONE use case (the per-use-case dispatch).

    Factored out of main() so the `all` target can loop it across every use case.
    `yes` is passed explicitly (not read from args) so batch runs can collect a
    single up-front confirmation and skip the per-use-case prompts."""
    state = builder.state
    if command == "apply":
        builder.apply()
        if getattr(args, "prune", False):
            builder.prune(yes)
        print("\n── Done ──")
    elif command == "plan":
        builder.plan()
    elif command == "prune":
        builder.prune(yes)
    elif command == "import":
        builder.do_import(getattr(args, "out", "") or "")
    elif command == "assess":
        builder.assess(window_days=getattr(args, "window_days", 7),
                       out_path=getattr(args, "out", "") or "")
    elif command == "build":
        builder.build()
        print("\n── Done (build mode — proposal seeded, no artifacts built) ──")
    elif command == "delete":
        tracked = state.data
        if not tracked:
            warn("State is empty — nothing tracked to delete.")
            return
        print("  Tracked resources:")
        for k, v in tracked.items():
            print(f"    {k}: {v}")
        if not confirm("Delete all of the above?", yes):
            print("Aborted.")
            return
        builder.delete()
        print("\n── Done ──  All tracked resources deleted.")
    elif command == "list":
        builder.list()
    elif command == "refresh":
        builder.refresh()
    elif command in ("load-data", "clear-data"):
        # --tenant-id is REQUIRED for these commands. They run as super-admin, whose
        # session tenant is the SYSTEM tenant — defaulting to it would silently load
        # demo data into the wrong place (it has, see the load-data-into-system-tenant
        # bug). There is no safe default: the operator must name the target tenant.
        tenant_id = args.tenant_id
        if not tenant_id:
            err("--tenant-id is required for "
                f"{command}. These run as super-admin and must target a real "
                "tenant explicitly — defaulting to your session tenant would load "
                "data into the system tenant.\n"
                f"  Example: vm_workspace.py {builder.usecase} {command} "
                "--tenant-id <TENANT_UUID>\n"
                "  List tenants with: torana tenants list")
        if command == "load-data":
            builder.load_data(tenant_id, start_phase=args.start_phase,
                              clear=not (args.no_clear or args.stack))
        else:
            if not confirm(
                    f"Clear '{builder._dataset_id()}' data from tenant {tenant_id}?",
                    yes):
                print("Aborted.")
                return
            builder.clear_data(tenant_id)


def _run_file_mode(argv: list) -> None:
    """Skill / ad-hoc entry: run one reconcile command against an arbitrary
    artifacts.yaml (`--file PATH`), with no dependency on the usecases/ tree.
    Keeps parsing isolated from the usecase parser (which needs a USECASE positional)."""
    fp = _HelpfulParser(prog="vm_workspace.py --file", add_help=True,
                        description="Reconcile an artifacts.yaml (skill / ad-hoc mode).")
    fp.add_argument("--file", required=True, metavar="PATH",
                    help="path to the artifacts.yaml to reconcile")
    fp.add_argument("command", choices=["apply", "plan", "prune", "import", "assess", "delete"],
                    metavar="COMMAND", help="apply | plan | prune | import | assess | delete")
    fp.add_argument("--yes", action="store_true", help="skip confirmation (delete/prune)")
    fp.add_argument("--dry-run", action="store_true", help="print CLI calls, hit nothing")
    fp.add_argument("--prune", action="store_true",
                    help="apply: also delete live artifacts no longer in the file")
    fp.add_argument("--out", default="", metavar="PATH",
                    help="import: where to write the yaml  ·  assess: where to write the JSON report")
    fp.add_argument("--window-days", type=int, default=7, metavar="N",
                    help="assess: noisy-rule lookback window in days (default 7)")
    fp.add_argument("--workspace-id", default="", metavar="UUID",
                    help="apply: adopt an existing workspace instead of creating one")
    args = fp.parse_args(argv)

    tor = Torana(dry_run=args.dry_run)
    resolver = Resolver(tor)
    ident = whoami(tor)
    _enforce_identity(args.command, ident, args.dry_run)   # file-mode = tenant-scoped
    uc, spec, work_dir = load_spec_from_file(args.file)
    state = State(work_dir / ".state.json")
    builder = Builder(uc, spec, work_dir, state, tor, resolver,
                      workspace_id=args.workspace_id)
    print(f"\n══════ {args.command.upper()}: {uc}  ({args.file}) ══════")
    _run_command(builder, args.command, args, args.yes or args.dry_run)


def main() -> None:
    # Skill / ad-hoc mode: `vm_workspace.py --file <path> <command>` (no usecases/ dep).
    if "--file" in sys.argv[1:]:
        _run_file_mode(sys.argv[1:])
        return

    # Fleet status: `vm_workspace.py list` with NO use case → status of all 5 apps.
    _argv = [a for a in sys.argv[1:] if not a.startswith("-")]
    if _argv == ["list"]:
        fleet_list(dry_run=("--dry-run" in sys.argv))
        return

    p = _HelpfulParser(
        prog="vm_workspace.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_HELP_DESCRIPTION,
        epilog=_epilog(),
    )
    p.add_argument("usecase", metavar="USECASE", nargs="?",
                   help="use case folder under usecases/ (see AVAILABLE USE CASES "
                        "below), or 'all' to run the command across every use case. "
                        "OMIT when using --file (skill / ad-hoc mode).")
    p.add_argument("command",
                   choices=["apply", "plan", "prune", "import", "assess", "build", "delete", "list", "refresh", "load-data", "clear-data"],
                   metavar="COMMAND",
                   help="apply | plan | prune | import | assess | list | delete | refresh "
                        "(tenant)  ·  load-data | clear-data  (super-admin)")
    p.add_argument("--file", default="", metavar="PATH",
                   help="run against an arbitrary artifacts.yaml (skill / ad-hoc mode) "
                        "instead of a usecases/ folder. Supports: apply | plan | prune | "
                        "import | delete. Omit the USECASE positional when using --file.")
    p.add_argument("--yes", action="store_true",
                   help="skip confirmation prompts (delete / clear-data)")
    p.add_argument("--dry-run", action="store_true",
                   help="print the torana CLI calls without hitting the API")
    p.add_argument("--prune", action="store_true",
                   help="apply: also DELETE live artifacts (by program prefix) that are no "
                        "longer in artifacts.yaml — terraform-style reconcile, reverse-"
                        "dependency order, confirmed (or pass --yes)")
    p.add_argument("--out", default="", metavar="PATH",
                   help="import: path to write the imported artifacts.yaml "
                        "(default: <usecase-dir>/imported-artifacts.yaml)  ·  "
                        "assess: path for the JSON health report (default: assess-report.json)")
    p.add_argument("--window-days", type=int, default=7, metavar="N",
                   help="assess: lookback window (days) for the noisy-rule signal (default 7)")
    p.add_argument("--workspace-id", default="", metavar="UUID",
                   help="apply: adopt an existing workspace instead of creating one")
    # --- SDG data options (load-data / clear-data) ---
    p.add_argument("--tenant-id", default="", metavar="UUID",
                   help="load-data/clear-data: REQUIRED — target tenant whose datalake "
                        "gets the data. No default (these run as super-admin; the "
                        "session tenant is the system tenant). List with "
                        "`torana tenants list`.")
    p.add_argument("--start-phase", default="t2", metavar="tN",
                   help="load-data: replay start phase (default t2 = wake-up state; "
                        "t3/t4 roll forward through remediation/closure)")
    p.add_argument("--no-clear", action="store_true",
                   help="load-data: do NOT clear this dataset's prior rows first")
    p.add_argument("--stack", action="store_true",
                   help="load-data: alias for --no-clear (stack onto existing tenant data)")
    # No args at all → print full help (clean exit 0). Any *partial/invalid* args
    # fall through to _HelpfulParser.error(), which prints full help to stderr.
    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(0)
    # Accept `<usecase> <command>` in either order before parsing.
    args = p.parse_args(_reorder_positionals(sys.argv[1:]))

    tor = Torana(dry_run=args.dry_run)
    resolver = Resolver(tor)

    # `all` is a fan-out target: run the command for EVERY use case in turn.
    is_batch = args.usecase == "all"
    if is_batch:
        targets = _discover_usecases()
        if not targets:
            err("No use cases found under usecases/ to run `all` against.")
        if args.workspace_id:
            err("--workspace-id adopts a single existing workspace and can't be "
                "combined with the 'all' target.")
    else:
        targets = [args.usecase]

    # Show who is logged in + enforce the right identity ONCE (identity is a
    # function of the command, not the use case — so one check covers the batch).
    ident = whoami(tor)
    _enforce_identity(args.command, ident, args.dry_run)

    # Batch destructive ops: take a SINGLE up-front confirmation covering every use
    # case, then run the rest unattended (otherwise the operator is prompted N times).
    # --dry-run touches nothing, so auto-confirm it (and avoid an EOF on piped stdin).
    yes = args.yes or args.dry_run
    if is_batch and args.command in ("delete", "clear-data") and not yes:
        if not confirm(f"{args.command} for ALL {len(targets)} use cases "
                       f"({', '.join(targets)})?", False):
            print("Aborted.")
            return
        yes = True

    results: list[tuple[str, str]] = []
    for uc in targets:
        spec, usecase_dir = load_spec(uc)
        state = State(usecase_dir / ".state.json")
        builder = Builder(uc, spec, usecase_dir, state, tor, resolver,
                          workspace_id=args.workspace_id)
        print(f"\n══════ {args.command.upper()}: {uc} ══════")
        if is_batch:
            # Keep going across the fleet if one use case errors; record + report at
            # the end. (err() raises SystemExit, which is NOT an Exception, so global
            # preconditions like a missing --tenant-id still abort the whole batch.)
            try:
                _run_command(builder, args.command, args, yes)
                results.append((uc, "ok"))
            except Exception as e:  # noqa: BLE001 — one bad app shouldn't kill the run
                warn(f"{uc}: {args.command} failed — {e}")
                results.append((uc, "FAILED"))
        else:
            _run_command(builder, args.command, args, yes)

    if is_batch:
        section(f"Batch {args.command} — summary ({len(targets)} use cases)")
        for uc, st in results:
            print(f"  {uc:24} {st}")
        if any(st == "FAILED" for _, st in results):
            sys.exit(1)


if __name__ == "__main__":
    main()
