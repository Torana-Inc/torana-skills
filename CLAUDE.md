# torana-skills — the customer artifact repo

**Everything under `plugins/` is GENERATED. Do not edit it here.**

This repo is what customers clone when they run:

```
/plugin marketplace add Torana-Inc/torana-skills
/plugin install torana@torana-skills
```

It holds the published artifact and the customer-facing README. It holds no build
tooling, because the same skills also ship as zips and the two packagers must not drift.

## Where the work happens

| Task | Where |
|---|---|
| Change a skill | `pantheon-cli/skills/<skill>/` |
| Change **which** skills ship | `audience:` in `pantheon-cli/skills-config.yaml` |
| Change what gets excluded from the package | `pantheon-cli/scripts/skill_packaging.py` |
| Build the plugin tree into this repo | `make -C pantheon-cli customer-plugin` |
| Build + commit + push this repo | `pantheon-deploy/scripts/publish-customer-skills.sh` |
| The release process | `pantheon-cli/docs/CUSTOMER_PLUGIN.md` |

A fix applied directly to `plugins/` is lost on the next build **and** invisible to every
other consumer of that skill — the Desktop zips, our dev boxes, the dogfood VM.

## What lives here, by hand

- `.claude-plugin/marketplace.json` — the marketplace manifest
- `plugins/torana/.claude-plugin/plugin.json` — plugin identity and **version**.
  Customers receive an update only when this version changes.
- `README.md` — the customer's install and first-run guide
- `LICENSE`

## Public or private?

**Private for now; the content is written to be public-safe either way.** Two separate
questions, and conflating them is the trap:

- Visibility decides who can *discover and install*. Private works — `/plugin marketplace
  add` uses the customer's own git credentials — at the cost of granting every customer
  developer read access to a `Torana-Inc` repo.
- Visibility does **not** decide who can *read the files*. Installing clones this
  repository onto the customer's machine. A private repo protects us from non-customers,
  not from customers. Anything we would not want a customer to read must not be in here,
  private or not.

Public is the likely end state (no access administration, and a scanner that produces
SARIF with no Torana account is a good front door), but it is irreversible in practice —
forks and caches outlive a visibility flip. Decide after the blockers in
`pantheon-cli/docs/CUSTOMER_PLUGIN_UPSTREAM_FIXES.md` are closed and two customers have
installed cold. Nothing about the install command changes when we flip it.
