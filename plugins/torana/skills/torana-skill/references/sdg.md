# SDG — replaying a captured dataset into a tenant's datalake

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap first.**

⛔ **SA only.** Every `torana sdg` command requires super-admin credentials
(`TORANA_PROFILE=SA`).

---

## What `sdg replay` is

A **dataset** (`torana sdg datasets list`) is a captured timeline — real or
synthetic events from providers (GitHub, GCP, Snyk, …) staged for playback,
not live data. **Replaying** it pushes that timeline's mock-provider traffic
into ONE tenant's integrations over time, so the rest of the platform (ETL,
rules, the inbox) sees it exactly as if a real integration were syncing.

Replay is keyed **per tenant** — one tenant has at most one active replay —
and every `sdg replay` command below except `start` and `all-status` takes
`--tenant-id` to say which one.

⚠️ **This is distinct from `sdg dataset <id> mock-replay`** (a separate,
side-effect-free NARRATED replay that writes to no datalake — useful for
walking through a dataset's story without touching any tenant's data). This
doc covers `sdg replay` only, the one that actually writes.

## The lifecycle

```bash
torana sdg datasets list                                    # find a dataset id/slug
torana sdg replay start --dataset-id classie-full-v1 --tenant-id <TID>
torana sdg replay status --tenant-id <TID>                   # ACTIVE, mock base URLs
torana sdg replay tick --tenant-id <TID>                     # manual mode only: advance one tick
torana sdg replay set-phase t2:start --tenant-id <TID>       # manual mode: jump to a phase
torana sdg replay set-speed 2 --tenant-id <TID>              # auto mode: 2x push speed
torana sdg replay stop --tenant-id <TID>
```

### `start`

```bash
torana sdg replay start --dataset-id ransomware-attack-v1 --tenant-id t1
torana sdg replay start --dataset-id ransomware-attack-v1 --tenant-id t1 --start-phase t2
torana sdg replay start --dataset-id ransomware-attack-v1 --tenant-id t1 --normalized --clear
```

Key options:
- `--tick-mode auto|manual` — `auto` runs a background push loop every
  `--tick-interval` seconds (default 30); `manual` only advances on an
  explicit `sdg replay tick` or `set-phase` call.
- `--speed N` (1–10) — event windows pushed per tick, auto mode.
- `--normalized` — also push `normalized.jsonl` events to the datalake
  (default off). Without it, replay only serves mock-provider HTTP traffic.
- `--clear` — delete this dataset's prior datalake rows for this tenant
  before replaying.
- `--capture-time-shift-seconds` — marker datasets only: shift every served
  timestamp forward/back by N seconds (whole minutes), to replay a real
  capture as if it happened now.

⭐ **Clear-only (wipe without replaying):** pair `--clear` with
`--no-normalized`, then stop immediately — this is the one-command way to
reset a dataset's datalake footprint for a tenant without pushing anything:

```bash
torana sdg replay start --dataset-id <id> --tenant-id <t> --clear --no-normalized
torana sdg replay stop  --tenant-id <t>
```

### `status` / `all-status`

```bash
torana sdg replay status --tenant-id <TID>       # one tenant: ACTIVE, MOCK BASE URLS
torana sdg replay all-status                      # every tenant with a replay engine
```

`status` on a tenant with no replay ever started still returns `ACTIVE: False`
and the dict of mock base URLs — it does not 404. `all-status` returns an
empty list when nothing anywhere is replaying.

### `set-phase` — the PHASE argument is a POSITION, not a label

```bash
torana sdg replay set-phase t2:start --tenant-id <TID>
torana sdg replay set-phase t2:end   --tenant-id <TID>
torana sdg replay set-phase start-of-time --tenant-id <TID>
torana sdg replay set-phase end-of-time   --tenant-id <TID>
```

⛔ **A bare `t2` is rejected.** A phase is a WINDOW, so the boundary is part
of the token: `t2:start` is the moment t2 begins (same as the dataset's
`default_start_phase: t2`); `t2:end` is everything through t2. Manual-mode
only. Forward jumps push the delta to the datalake if `--normalized` was set
on `start`.

### `tick` / `set-speed` — manual vs auto mode

`tick` advances a manual-mode replay by one step. `set-speed` changes an
**auto**-mode replay's push rate (1–10 windows per tick interval) without
restarting it — takes effect on the next tick boundary. **404s** if the
tenant has no active replay (the engine must exist first):

```bash
torana sdg replay tick --tenant-id <TID>
torana sdg replay set-speed 3 --tenant-id <TID>    # 3x normal speed
```

### `tick-history`

```bash
torana sdg replay tick-history --tenant-id <TID>
```

Every tick this tenant's replay has taken, oldest first — useful for
confirming a demo's timeline actually advanced rather than silently stalling.

### `stop`

```bash
torana sdg replay stop --tenant-id <TID>
```

Stops the tenant's replay engine. Idempotent — stopping an already-stopped
tenant is not an error.

## `--format json`

Every `sdg replay` command accepts `--format json` and returns the same
structure the table/text rendering summarizes — nothing is dropped, so a
script can poll `status --format json | jq .active` directly.
