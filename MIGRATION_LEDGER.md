# CSAO Stack Replacement — Migration Ledger

Running log of the architecture replacement (fake FastAPI shim + SQLite/JSON →
real FastAPI + PostgreSQL + [later] ARQ job queue + TypeScript/React
frontend). Newest entry on top. Don't rewrite prior entries — append a new
dated one describing what changed and current status.

Reference docs: `~/Desktop/CSAO_Architecture.md` (as-found architecture),
`~/Desktop/CSAO_TechStack_Proposal.md` (approved target stack, phased plan).

---

## 2026-08-12 — Account-vault test isolation fixed at the root cause; stale-artifact cleanup

**Test isolation, fixed properly (not worked around).** The account-vault
tests looked isolated -- each constructed `WorkbenchState(tmp_path /
"state.json")` with its own distinct `tmp_path` -- but `WorkbenchState`
was rewritten during the Postgres migration to always persist to the
single shared production row (hardcoded `id=1`) regardless of the `path`
argument, which is kept only for display/logging. Every one of those
tests, plus every test constructing `WorkbenchRuntime()` (which
internally builds its own `WorkbenchState()` the same way, zero args),
was actually reading and writing the real shared database the whole
time. This is what corrupted production state earlier in the session
(see the entry below).

Fix: `WorkbenchState.__init__` and `WorkbenchRuntime.__init__` both gained
a `state_id: int = 1` parameter, threaded through every `load`/`save`/
`update` call in place of the hardcoded `1`. Default unchanged (`1`) for
every real call site (`workbench/singletons.py`, `workbench/worker.py`) --
this is purely additive. Added `tests/conftest.py`'s `isolated_state_id`
fixture: yields a random id in a range that will never collide with
production's `1`, and deletes that row in teardown so repeated test runs
don't leave garbage rows behind either. Updated all 15 tests in
`tests/test_workbench_control_plane.py` to use it.

One test (`test_trust_center_view_model_exposes_tool_and_safety_validation`)
had been asserting on `tool_validation` containing "IAM Access Analyzer" --
that only ever passed because it was reading the real worker's real
reported status from the shared row. Properly isolated, a fresh row
correctly has no tool status until something reports one (matching the
Tools page's own "no status reported yet" empty state). Fixed by seeding
the isolated row with `check_external_tools()` output first, the same
way `workbench/worker.py`'s startup hook does it for real, rather than
asserting content that was only ever present by accident.

**Verified, not assumed:** confirmed the real production row's
`cloud_accounts` was empty before running the suite, ran all 15 tests
(all pass), then confirmed the production row was *still* empty
afterward and the `workbench_state` table still had exactly one row --
proving each test's row was created and cleaned up without ever touching
production data.

**Not in scope, left broken and documented rather than silently ignored:**
`tests/test_workbench_auth.py`'s 4 failures are a different bug --
`LocalAuthManager(tmp_path / "auth.db")` calls a constructor signature
that no longer exists (`LocalAuthManager.__init__(self)` takes no path
now either, same class of migration staleness). These fail at
construction, before writing anything, so they're inert rather than
corrupting -- unlike the account-vault tests, fixing the signature alone
wouldn't be enough; they'd need the same `state_id`-style isolation
before being fixed, or they'd start corrupting real user/session data
instead. `tests/test_ui_health.py` is broken more deeply: it tests a
`DEV_BOOTSTRAP_USERNAME` dev-mode bootstrap-user feature that no longer
exists anywhere in `workbench/app.py` at all -- the real first-run flow
is now the `/setup` page creating a real admin account. That's a rewrite
of a ~390-line test file testing removed functionality, not a quick fix;
left broken and documented rather than attempted piecemeal.

**Stale-artifact cleanup**, prompted by the same question:
- Removed `scripts/migrate_sqlite_auth_to_postgres.py` from the repo --
  its own docstring says "one-time migration... run once"; that migration
  already happened for this project, and nothing about a fresh clone
  (which starts straight on Postgres via `install.sh`) will ever need it
  again.
- Deleted two confirmed-dead local files on this dev machine (gitignored,
  never in git, so this has zero effect on a fresh clone either way):
  `output/workbench/auth.db` (the pre-migration SQLite file -- grepped
  the entire codebase for `auth.db`/`sqlite3` references first, found
  none) and `output/workbench/runtime_watchdog.jsonl` (733KB, zero code
  references anywhere, predates this session). Deliberately did **not**
  touch `.secret.key`, `.secret.keys.json(.bak)`, or
  `runtime_status.json(.bak)` -- checked first and confirmed these are
  still actively read/written (`core/file_utils.py`'s
  `atomic_write_bytes` refreshes every `.bak` on every write as an
  ongoing corruption-recovery backup, not one-time migration debris).
- Fixed real inaccuracies in three docs surfaced by the app's own Docs
  page (built earlier this session) that still claimed post-migration
  state lives in `output/workbench/state.json` / `auth.db` -- both
  false, both now Postgres: `workbench/README.md`, `CONFIGURATION_GUIDE.md`.
  `INSTALLATION.md`'s native setup steps were also missing the
  `alembic upgrade head` step entirely (a real functional gap: following
  those exact steps as written would hit missing-tables errors) and
  didn't mention `./install.sh` as the simpler path at all.

---

## 2026-08-12 — Full containerized deploy (`./install.sh`), plus two real bugs found while validating it

User asked for a genuinely turnkey deploy: clone the repo on another
machine, run one command, get a fully working instance with every
collector tool installed -- not the current state, where the web app
still required a native Python venv + `npm run build` on the host even
though `worker` was already fully containerized.

**Change:** added a `web` service to `docker-compose.yml` running the
same FastAPI app as native `workbench.serve`, from a new multi-stage
`Dockerfile` stage (`frontend-builder`, Node 22) that builds the React
SPA at image-build time -- no host Node/npm needed. `web` runs
`alembic upgrade head` on every start (idempotent, so safe) before
starting uvicorn. Rewrote `install.sh` (previously an apt-get/Ubuntu-only
script installing tools onto the host, stale since the Docker migration)
into a real one-command bootstrap: generates `.env` with a fresh
password if missing, then `docker compose up -d --build`, then polls
`/health` until ready. Fixed `.env.example`: it documented an async
`DATABASE_URL` variable that nothing in the codebase actually reads (the
app is 100% synchronous SQLAlchemy) -- traced this while investigating
*why* the native app worked without ever explicitly exporting `.env`
into its process environment; turns out `workbench/db/base.py` already
calls `load_dotenv()` itself, so this was always working correctly and
the async variable was simply dead/fictional documentation from earlier
in this project.

**Two real bugs found and fixed while actually testing this, not just
writing it:**

1. **The Tools-page terminal (`workbench/api/terminal.py`) would have
   been completely broken under this new deployment shape.** It works by
   running `docker exec` into the `worker` container -- fine when
   `workbench.serve` runs natively on the Docker host, which has
   `docker` and the daemon socket for free. Once the web app itself runs
   *inside* a container, neither exists there by default. Confirmed the
   gap directly (`docker exec csao_web which docker` → not found, no
   `/var/run/docker.sock`) before touching anything. Fixed by installing
   the Docker CLI (client binary only, from Docker's official static
   release, not the full `docker-ce`/daemon) in the Dockerfile, and
   mounting the host's `/var/run/docker.sock` into `web` in
   docker-compose.yml -- the standard "Docker-outside-of-Docker" pattern.
   Re-verified live afterward: `docker` resolves, `docker ps` from
   inside `web` lists every sibling container, and a real terminal
   session against Prowler through the fully-containerized stack
   returned real output.

2. **Running the pytest suite earlier this session corrupted the real,
   shared Postgres `workbench_state`.** `tests/test_workbench_control_plane.py`'s
   account-vault tests construct `WorkbenchState(tmp_path / "state.json")`,
   which *looks* isolated per test run -- but `WorkbenchState` was
   rewritten during the Postgres migration to always persist to the
   shared database regardless of the `path` argument (kept only for
   compatibility/logging). Every test run that got as far as
   `vault.save_account(...)` before failing on a since-stale JSON-file
   assertion left real, permanently-undecryptable fake accounts ("Prod
   AWS" x4, "Audit" x1) sitting in the actual `cloud_accounts` array,
   encrypted with a per-test-run key that gets deleted the moment
   pytest's `tmp_path` fixture cleans up. This surfaced as real 500s
   (`ValueError: Stored account credentials could not be decrypted with
   any trusted key`) on `/dashboard`, `/accounts`, and
   `/assessments/wizard-defaults` the moment those endpoints tried to
   enumerate accounts -- not a deployment-specific bug, but it was this
   validation pass that exposed it, so documenting it here. Fixed by
   deleting the 5 corrupted entries directly. **Not yet fixed at the
   root cause**: these account-vault tests still aren't actually
   isolated and will corrupt shared state again if run against a
   database anyone cares about. They need either a per-test Postgres
   schema/database or a way to inject an isolated state backend --
   flagging this clearly rather than re-running that test file again
   without one.

**Verified, end to end, not just written:** built the new `web` image
for real (multi-stage build completed, Docker CLI step confirmed via
`command -v docker` inside the build), stopped the native
`workbench.serve` process, brought up the containerized `web` in its
place, confirmed migrations ran automatically against the real database
(`alembic.runtime.migration` log lines, `\dt` shows all 5 tables), then
ran a full API sweep (dashboard, coverage, trust-center, findings,
checklist, threats, attack-paths, risk, evidence, wizard-defaults,
history, reports, accounts, settings, users, docs, access-requirements)
-- every endpoint 200 after the two fixes above. Confirmed the terminal
websocket works through the fully-containerized path specifically (not
just the native one already verified earlier), by opening a real
Prowler terminal session over `ws://` and reading back its actual
`--help` output.

**Known limitation, stated plainly:** this was validated by rebuilding
and recreating the `web` container against this machine's existing
Postgres/Redis/Neo4j *volumes*, not a literal from-empty-volumes fresh
clone (avoided wiping this session's live data unnecessarily). Every
individual piece a fresh clone depends on -- the image build, the
migration-on-startup, the full endpoint sweep, the terminal-via-socket
fix -- was verified directly; the one thing not literally re-proven is
an empty Postgres volume's very first `alembic upgrade head` run, though
that's the same idempotent command already confirmed working here.

---

## 2026-08-12 — Launch-tab IAM policy JSON, scoped to selected collectors and verified read-only

User asked for a section in the Assessments Launch tab that generates a
copy-paste-ready IAM policy JSON, curated to whichever collectors are
checked for that specific launch, with an explicit requirement that
nothing in it may be a write or execute action.

**Found before writing anything new:** `workbench/runtime.py`'s
`access_requirements_view_model()` already generated a complete,
well-formed `CSAO_Assessment_ReadOnly` IAM policy from
`collector_metadata.py`'s permission data, including a validation step
(`_validate_access_requirements_bundle`) -- it just had no frontend
consumer, and it scoped by whatever's enabled in `config.yaml` globally,
not by what's checked in a specific launch form. `LEAST_PRIVILEGE_DESIGN.md`
already documented this design; the code matched the doc, it just wasn't
wired into the UI.

**Before generating anything, audited every IAM action already in
`collector_metadata.py`** (not just trusted the name pattern): extracted
every unique action verb across all 7 collectors (~90 actions) -- only
`Describe`, `Get`, `List`, `Search`, and one `Generate` (
`iam:GenerateCredentialReport`) appear. Verified `GenerateCredentialReport`
specifically against AWS's own live documentation (fetched directly,
not from memory): AWS's `IAMReadOnlyAccess` managed policy places it in
the exact same `Allow` statement as `iam:Get*`/`iam:List*`, confirming AWS
itself treats it as read-only-safe despite the "Generate" verb. No other
verb (Put/Create/Update/Delete/Attach/Modify/etc.) exists anywhere in the
current permission data.

**Changes:**
- `workbench/runtime.py`: added `_is_read_only_action()` plus
  `READ_ONLY_ACTION_PREFIXES`/`READ_ONLY_ACTION_EXACT_EXCEPTIONS` as an
  explicit safety net wired into the existing validation function -- so a
  future permission added with a non-read verb fails validation loudly
  instead of silently shipping, rather than relying on "the current data
  happens to be clean." `access_requirements_view_model()` gained an
  optional `collector_keys` param: when provided, it overrides the
  config-enabled set so the generated policy reflects the analyst's
  actual per-launch selection instead of global config.
- `workbench/api/assessments.py`: `GET /assessments/access-requirements`
  now accepts an optional `collectors` query param (comma-separated keys).
- `pages/Assessments.tsx`: new "Required IAM Permissions" section in the
  launch form, live-scoped to whichever collector checkboxes are
  currently selected -- shows the generated policy JSON, a validation
  badge (visibly fails loud with the exact error if validation ever
  doesn't pass), copy-to-clipboard, and download-as-.json.
- `components/CopyButton.tsx`: recreated (had been deleted earlier this
  session when the Tools page moved from copy-paste commands to a real
  terminal) -- genuine second use case here.

**Verified, not assumed:** wrote an adversarial test feeding the verb
checker known write/execute/wildcard actions (`iam:PutRolePolicy`,
`ec2:TerminateInstances`, `s3:PutObject`, `ec2:*`, etc.) -- all correctly
rejected, zero false positives against the real read-only action set.
Confirmed via the live runtime that scoping to different collector
combinations produces genuinely different, correctly-filtered policies
(`aws_inventory` alone -> 5 statements; `prowler`+`steampipe` together ->
20 statements, 81 actions), and that `policy_validation.status` is `PASS`
in both cases. Ran the 4 pre-existing tests covering this function
(`test_access_requirements_*`) -- still pass unchanged, confirming the new
optional parameter doesn't alter default behavior.

**Full regression sweep after this change:** every existing API endpoint
(dashboard, findings, checklist, threats, attack-paths, risk,
recommendations, evidence, wizard-defaults, history, reports, accounts,
settings, users, trust-center, coverage, docs, docs reference tables)
still returns 200 with correct data. Trust Center / Tools tool-status
wiring re-verified specifically: all six tools (`aws`, `prowler`,
`steampipe`, `cloudsplaining`, `cartography`, `access-analyzer`) still
report `installed: true` with correct `key` fields, and the terminal
websocket backend still opens a real shell in the worker container and
responds to commands.

---

## 2026-08-12 — Pre-push functional review

Before pushing the Docs/Tools/Dashboard work, did a full pass: hit every
API endpoint with a live session (all 24 return correct status codes,
including a 404 for an unknown doc id), inspected the actual data shapes
feeding the new Dashboard charts (confirms the empty-state paths are
correct pre-assessment: `findings_by_severity` and `/risk` are empty with
no assessment run yet, `/coverage` and the checklist's MITRE tactics are
real static reference data so those two charts render immediately), and
grepped for dead references to everything deleted this session
(`Dataviz`, `CopyButton`, the old `manual_command`/`common_commands`
fields) -- none found.

Found and fixed three real bugs in `workbench/api/terminal.py`, all in
the newest and most security-sensitive code path (see findings reported
via code review): the websocket never closed when the underlying
`docker exec` process died, leaving a hung session with no visible error;
`subprocess.Popen(preexec_fn=os.setsid)` is documented by Python itself as
unsafe inside a multi-threaded process (swapped for `start_new_session=True`,
the safe native equivalent); and the auth-failure/unknown-tool close codes
were sent before `accept()`, so they never reached the client as real
close codes -- both showed identically as a bare HTTP 403 with no reason
given. Fixed by accepting first and writing an explanatory message before
closing. Re-verified live after the fixes: happy path (Prowler and
Steampipe help text + a real command round-trip), unauthenticated
rejection, and unknown-tool rejection all now behave correctly with
visible reasons.

---

## 2026-08-12 — Revision: dataviz merged into Dashboard, Tools gets a real terminal

Immediate follow-up correction to the entry directly below, per user
feedback that two specific choices weren't what they meant:

1. **Dataviz merged into Dashboard, `/dataviz` removed.** The standalone
   page was one extra click away from the one place people actually look
   first. All six charts (severity donut, health radar, coverage by
   domain, evidence coverage by service, top-10 risk findings, top MITRE
   tactics) now live directly on `/dashboard` alongside the existing KPI
   cards and severity bar chart. `pages/Dataviz.tsx` deleted; nav item and
   route removed.

2. **Tools page: replaced the copy-paste command panel with an actual
   in-browser terminal.** The user clarified "open the CLI" meant a real
   terminal that opens when you click a tool -- not commands to copy into
   your own terminal, and specifically not `docker exec` syntax shown to
   the analyst at all. This is a genuine reversal of the earlier
   AskUserQuestion answer (copy-paste panel), which turned out not to
   match what "the CLI opens" meant in practice.
   - `workbench/api/terminal.py` (new): a `WebSocket` route,
     `/api/v1/tools/{tool_key}/terminal`, restricted to `ANALYST`/
     `ADMINISTRATOR` roles (checked from the session cookie manually,
     since this is a raw execution surface -- more sensitive than any
     other endpoint in the app, so `READ_ONLY` is deliberately excluded).
     Allocates a PTY via `pty.openpty()` + `subprocess.Popen` (not
     `pty.fork()` -- forking the whole running asyncio/uvicorn process
     from inside itself is a known footgun; spawning a child via Popen
     with the pty's slave fd as its stdio is the safe version of the same
     pattern) running `docker exec -it csao_worker sh -c '<tool> --help;
     ...; exec sh'`. Bridges the PTY's master fd to the websocket in both
     directions via `asyncio`'s `add_reader`; a small JSON control channel
     over text frames handles terminal resize (`TIOCSWINSZ` on the master
     fd, which the pty/tty layer turns into `SIGWINCH` for the shell
     automatically).
   - `core/tool_check.py`: reworked `TOOL_MANUAL_USAGE` (command strings
     meant for copy-paste, now unwanted) into `TOOL_USAGE` (`purpose` +
     `help_command`, e.g. `"prowler --help"`) and added a stable `key`
     per tool (`aws`, `prowler`, `steampipe`, `cloudsplaining`,
     `cartography`, `access-analyzer`) used both in the API response and
     as the WebSocket path segment.
   - `pages/Tools.tsx`: cards now show purpose/status/version and a single
     "Open terminal" button -- no visible commands of any kind.
   - `components/ToolTerminal.tsx` (new): `@xterm/xterm` +
     `@xterm/addon-fit` in a Dialog. Sends keystrokes as binary frames
     (`TextEncoder`-encoded), resize as JSON text frames, matching the
     backend's framing convention; disposes the terminal and closes the
     socket on dialog close.
   - `frontend/vite.config.ts`: added `ws: true` to the `/api` proxy so
     the websocket also works through Vite's dev server, not just the
     production build (same-origin, no proxy needed there).
   - Deleted `components/CopyButton.tsx` -- no longer used anywhere.

Verified live: connected to `/tools/prowler/terminal` over a websocket
with a valid session cookie -- received Prowler's real `--help` output
first, then a typed `echo` command executed inside the worker container
and returned real output, confirming the PTY bridge works both
directions. `npm run build` clean after the rewrite.

Deployment note carried into this: the terminal execs into the `worker`
container by container name, so it only works when `workbench.serve`
runs on the same host as `docker compose` -- true for this setup, not
guaranteed in general (documented as a code comment in `terminal.py`).

---

## 2026-08-12 — Docs, Tools, and Dataviz pages

User feedback: the existing markdown docs (theory/methodology/permission
matrices) and MITRE/attack-path reference data lived only as files in the
repo, invisible from the app; there was no place to see which collector
tools were installed with a quick way to run them manually; and only one
chart existed anywhere in the SPA (the severity bar chart on Dashboard).
Asked for a Docs sidebar, a Tools sidebar, and a `/dataviz` page.

Before building the manual-tool-run feature, asked the user how "open the
CLI" should actually work, given the security tradeoff for a tool whose
whole premise is read-only safety. Chose: a copy-paste command panel
(exact `docker exec` commands with a copy button) over a guided run form
or a full interactive web terminal — zero new execution surface, nothing
runs from the browser.

**Backend:**
- `core/tool_check.py`: added `TOOL_MANUAL_USAGE`, a purpose + example
  `docker exec` command + a couple of common commands per tool, merged
  into each `tool_validation` row the worker already reports at startup —
  no new endpoint needed, `GET /trust-center` now just carries more per
  tool.
- `workbench/api/docs.py` (new): `GET /docs` (allow-listed list of every
  markdown doc, grouped by category), `GET /docs/{id}` (raw content, id
  is looked up against the allow-list server-side, not a filesystem path,
  so there's no traversal surface), `GET /docs/reference/mitre` (parses
  `data/mitre_mappings.yaml` into flat rows), `GET /docs/reference/attack-paths`
  (parses `data/attack_path_catalog.yaml`). Registered in `workbench/api/__init__.py`.
- No new endpoint for Dataviz — `/coverage` already existed server-side
  with no frontend consumer; everything else reuses `/dashboard`,
  `/risk`, `/checklist` (MITRE tactic frequency is aggregated client-side
  from `checklist_rows()`'s existing `mitre_mapping` field).

**Frontend:**
- Added `react-markdown` + `remark-gfm` (only new frontend dependency;
  nothing else existed for rendering markdown).
- `pages/Docs.tsx`: category sidebar (Guides / Security & Permissions /
  Audit Reports / Engineering Log, from `DOC_LIBRARY`) + a Reference/Theory
  section rendering the MITRE mapping table and the 15-entry attack path
  catalog as actual tables instead of dumping the YAML.
- `pages/Tools.tsx`: one card per collector tool — install status, version,
  purpose, and the manual-run command(s) with a copy button. Reuses
  `useTrustCenter()`, no new query hook needed for the core data.
- `pages/Dataviz.tsx`: severity donut, assessment health radar (5-axis,
  from the previously-buried `assessment_health_score`), checklist
  coverage by domain, evidence coverage by service, top-10 highest-risk
  findings, and top MITRE tactics by frequency — six charts, all built on
  data that already existed server-side.
- `components/CopyButton.tsx` (new, shared by Tools page).
- Nav (`Layout.tsx`) and routes (`App.tsx`): added Dataviz, Docs, Tools
  between Assessments/Reports and Admin.

Verified: `npm run build` (tsc + vite) clean, all three new API routes
return real data end to end (`/docs` lists 22 docs, `/docs/reference/mitre`
returns 72 rows, `/docs/reference/attack-paths` returns 15), and `/trust-center`
carries the new `manual_command`/`common_commands` fields after restarting
the worker (its bind-mounted code picked up the `tool_check.py` change
immediately — no image rebuild needed). All three new SPA routes
(`/app/docs`, `/app/tools`, `/app/dataviz`) serve 200.

---

## 2026-08-12 — Collector tools actually installed in the worker image (Docker-only)

Following the 2026-08-11 finding that no collector tool was actually
installed anywhere, the user asked to install Prowler/Steampipe/
Cloudsplaining/Cartography/AWS CLI for real, with installation automatic
for anyone who deploys this (not a manual per-machine setup step). Scoped
to the Docker `worker` image only (native `workbench.serve` stays
Python+boto3-only) since that's the only process that executes scans.

**What changed:**
- `requirements-collectors.txt` (new): `prowler`, `cloudsplaining`,
  `cartography`, pinned `okta==0.0.4`.
- `Dockerfile`: installs AWS CLI v2 and Steampipe from the official
  release artifacts, arch-aware (`TARGETARCH`).
- `docker-compose.yml`: added a `neo4j` service (Cartography's graph
  store); `worker` now depends on it.
- `config/config.yaml`: `cartography` enabled, `neo4j_uri` pointed at the
  compose service hostname.
- `core/tool_check.py` (new): shared `check_external_tools()`, used by
  both `runtime.py:external_tool_validation()` and the worker's new
  `startup()` hook.
- `workbench/worker.py`: `startup(ctx)` now actually does something — runs
  `check_external_tools()` once per worker start and writes the result
  into `workbench_state.tool_status` / `tool_status_checked_at`.
- `runtime.py` / `trust_center_view_model()`: reads tool status from that
  stored state instead of calling `shutil.which()` live from whichever
  process serves the request — fixes a real bug where Trust Center was
  checking the *web* host's tools, not the *worker's* (the process that
  actually runs scans).
- Frontend: Trust Center shows a "last checked" timestamp sourced from
  `tool_status_checked_at`, and an empty-state message if the worker
  hasn't reported yet.

**Bugs found and fixed while getting the build green:**

1. **Steampipe silently never installed.** Original install used
   `sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"`. If
   curl fails transiently, that pattern runs `sh -c ""` — trivially exits
   0, installs nothing, and the build reports success. Confirmed via
   `find / -iname 'steampipe*'` on the deployed container finding zero
   binaries. Fixed by downloading to a file, asserting non-empty, then
   executing — a real failure now fails the build loudly instead of
   silently no-op'ing.
2. **Cartography `ModuleNotFoundError: No module named 'okta.framework'`.**
   Cartography's Okta integration imports the pre-1.0 okta-sdk-python
   layout (`okta.framework.OktaError`), which the modern `okta` package no
   longer has — breaks on `import cartography.sync`, triggered by every
   `cartography` invocation regardless of whether Okta is used. Fixed by
   pinning `okta==0.0.4` (last version with the legacy layout). See
   https://github.com/lyft/cartography/issues/459 and
   https://github.com/okta/okta-sdk-python/issues/122.
3. **~30 minute apparent build "hang" with zero visible activity.** No
   `.dockerignore` existed, so every build sent the entire project
   directory as build context, including `venv/` (538MB) and
   `frontend/node_modules/` (286MB) — neither needed by the image.
   Added `.dockerignore`; context transfer dropped from 100+MB to under
   1MB. This was the actual cause of what looked like a stalled build.
4. **Image built successfully but stayed untagged/dangling.** First
   green build didn't get tagged `csao-main-worker:latest` automatically.
   Fixed by manually tagging the dangling image, then
   `docker compose up -d --force-recreate worker`. Later rebuilds tagged
   correctly on their own.
5. **Colima VM crashed mid-build, taking every container down at once** —
   CSAO's and, coincidentally, the user's unrelated `blazeup-aisec`
   project's, all with mixed exit codes within the same minute. Traced to
   sustained CPU/memory contention on the shared VM (both projects'
   containers competing for 4 CPU / 8GiB). Left the VM's network in a
   state where `raw.githubusercontent.com`'s Fastly CDN range was
   unreachable from inside the VM while working fine from the host
   directly and for every other destination tested (`github.com`,
   `pypi.org`) — a stale post-crash routing/network-namespace issue, not
   a real outage. Fixed with the user's explicit go-ahead: `colima
   restart` (didn't disrupt the `aisec-*` containers further since they
   were already down from the crash).
6. **Even after the Colima restart, Steampipe's official install script
   still failed** — once past the DNS/routing leg, its own single-shot,
   no-retry curl to fetch the release binary from
   `objects.githubusercontent.com` hit a mid-handshake TLS EOF, consistent
   with an MTU/packet-loss interaction with HTTP/2 framing on this VM's
   network path. Rather than depend on the upstream script's fragile
   networking, replaced it entirely: fetch the release tarball directly
   with the same retry-and-verify pattern used for AWS CLI, with
   `--http1.1` forced to avoid the HTTP/2 framing issue.
7. **Steampipe refuses to run as root**, and the whole image (and the
   `worker` compose service) runs as root with no `user:` override —
   would have broken not just `plugin install` at build time but every
   `steampipe query` call at actual scan time
   (`modules/steampipe_runner.py`). Rearchitecting the whole container to
   run non-root wasn't viable without also fixing write access to the
   root-owned bind-mounted `output/`/`logs/`/`cache/` directories, so
   instead: a dedicated `steampipe` user (UID 10001, its own `$HOME`
   outside the bind mount) runs only the steampipe binary. `steampipe` on
   `$PATH` is now a `setpriv`-based wrapper that drops privileges before
   exec'ing the real binary (renamed to `steampipe-bin`) — every existing
   `subprocess.run(["steampipe", ...])` call site keeps working
   unmodified, no application code changed.

**Verified in the running worker container:** `aws --version`, `prowler
--version`, `cloudsplaining --help`, `cartography --help`, `steampipe
--version`, and `steampipe plugin list` all work; the `aws` plugin shows
installed. `workbench_state.tool_status` in Postgres shows all six tools
(AWS CLI, Prowler, Steampipe, Cloudsplaining, Cartography, IAM Access
Analyzer) as `installed: true` with a fresh `tool_status_checked_at`.
Confirmed the same data reaches `GET /api/v1/trust-center` end to end
(verified via a temporary session token inserted directly into Postgres
and deleted immediately after).

**Not yet done:** the user has not been asked to restart their `aisec-*`
containers (stopped by the Colima crash, not by anything done here) —
that's their call, left alone deliberately.

---

## 2026-08-11 — Post-Phase-3 fix: Trust Center / collector "theory docs" gap

After the user confirmed the new `/app` UI loads, they reported not being
able to find tool-status/documentation info they expected, and asked
whether Prowler and the other collector tools were actually loaded. Two
real things, not user error:

1. **Confirmed directly**: none of Prowler, Steampipe, Cloudsplaining,
   Cartography, or the `aws` CLI are installed on this machine (`command -v`
   for each returns nothing). Only the Python framework + boto3 work today.
   `runtime.py:external_tool_validation()` already checks this via
   `shutil.which()` and was already wired into `trust_center_view_model()`
   (and thus already exposed at `GET /api/v1/trust-center`) — the backend
   was never the problem.
2. **Real frontend gap**: the Admin → Trust Center tab and the Assessments
   wizard's collector picker both existed from Phase 3 but the Trust Center
   tab rendered `JSON.stringify(data, null, 2)` as a raw blob instead of an
   actual UI, and the collector picker only showed bare `key`/`label`
   toggle buttons, discarding `description`/`permissions`/`services`/
   `mitre_mapping` that `collector_catalog()` already returns. Fixed:
   Trust Center now renders a proper tool-installation-status table
   (installed/version/read-only-mode/required per tool — this is where
   "is Prowler loaded" is answered), the read-only guarantee list, safety
   validation status, a permission matrix table, and the FAQ. The
   assessment wizard's collector picker now shows each tool's description
   and services inspected instead of a bare label.

No backend changes were needed — `types.ts` gained `CollectorInfo`,
`ToolValidationRow`, `PermissionMatrixRow`, `TrustCenterData` interfaces
matching the real API response (inspected via a scoped temp session before
writing the types, same discipline as the rest of Phase 3).

---

## 2026-08-11 — Phase 3: JSON API + React/TypeScript SPA, consolidated IA

**Status: backend + frontend built and verified via HTTP/API testing. SPA is
served additively at `/app` alongside the untouched legacy UI at `/` — NOT
yet cut over as the default. See "What's deliberately not done" below.**

Trigger: after Phase 2, the user said the app still didn't feel "stable"
and asked for research on how other tools structure their UI. That surfaced
that CSAO's ~19-page nav was the same "one screen per backend
endpoint/engine" anti-pattern the user had already diagnosed and fixed on
another project (`blazeup-aispm-ui-consolidation` memory: collapse to one
page + a detail drawer). Wiz/Orca/AWS Security Hub research confirmed the
same pattern industry-wide. Approved direction: consolidate to Dashboard,
one Findings Workspace (table + drawer replacing 8 separate facet pages),
Assessments, Reports, Admin — and rebuild the frontend in TypeScript/React
per the original tech-stack proposal, rather than a 1:1 template port.

### Backend: `workbench/api/` (JSON layer, strangler-fig alongside old HTML routes)

- Extracted `workbench/singletons.py` (shared `runtime`/`auth_manager`
  instances) so the new `workbench/api/*.py` routers and the legacy
  `workbench/app.py` HTML routes don't need to import each other
  (avoids a circular import).
- New routers, all thin JSON wrappers around **existing, unchanged**
  `workbench/runtime.py` methods — no new business logic:
  `auth.py` (login/logout/me/setup/password), `dashboard.py`,
  `findings.py` (findings + checklist + threats + attack-paths + risk +
  recommendations + evidence — co-located since they're all facets shown in
  the same drawer), `assessments.py`, `accounts.py`, `admin.py`
  (settings + users), `reports.py`. 40 endpoints total, mounted at
  `/api/v1/*`.
- `workbench/api/deps.py`: `get_current_user`/`require_role()` FastAPI
  dependencies returning real 401/403 JSON (not redirects) — the SPA reads
  `must_change_password` from `/auth/me` and routes client-side instead of
  the old path-allowlist approach.
- Exact response shapes for every `runtime.py` view-model method
  (`dashboard()`, `register_rows()`, `checklist_rows()`, `scenario_rows()`,
  `attack_path_graph()`, `risk_rows()`, `recommendation_rows()`,
  `report_rows()`, `account_records()`, `assessment_wizard_view_model()`,
  etc.) were extracted via a dedicated investigation before writing any
  frontend code, rather than guessing shapes from route code — this caught
  a real serialization bug in `register_rows()` (it embeds raw
  `Finding`/`RegisterEntry` dataclass instances under `row["finding"]`/
  `row["entry"]` for Jinja convenience; the API layer drops those two keys)
  and confirmed `report_rows()` is HTML-only today (globs `*.html`; no
  PDF/CSV fan-out exists despite `config.yaml`'s `generate_pdf`/
  `generate_csv` flags) — this directly resolved the "theory PDF dropdown"
  ambiguity: after two rounds of clarification, the user confirmed it meant
  a **MITRE ATT&CK technique/framework reference dropdown on findings**, not
  a report-format picker.

### Frontend: `frontend/` — Vite + React 18 + TypeScript

- shadcn/ui (Nova preset, Radix base) + Tailwind v4 + TanStack Query +
  React Router + Recharts. One real gotcha: `npx shadcn@latest init` wrote
  every component into a literal `./@/` directory at the project root
  instead of resolving the path alias to `./src` — had to move the files
  manually. Also hit a zsh footgun during verification: `for path in ...`
  as a loop variable name silently clobbers zsh's special `$path` array
  (mirrors `$PATH`), breaking `curl` mid-loop — not a bug in the app, just
  a shell scripting trap worth remembering.
- Consolidated IA implemented: `/dashboard` (KPI cards + severity chart),
  `/findings` (one filterable table + a `Sheet` drawer with tabs: Overview,
  Checklist, Threats, Attack Paths, Risk, Recommendations, Evidence, plus a
  **Framework Reference dropdown** aggregating MITRE tactics/techniques from
  the finding's matched checklist controls and threat scenarios, linking out
  to `attack.mitre.org`), `/assessments` (launch wizard + live progress via
  2.5s polling of `/assessments/active` + history table), `/reports`,
  `/admin` (tabs: Accounts/Settings/Users/Trust Center — Trust Center folded
  in per the consolidation plan instead of staying a separate nav item).
- Auth: cookie-based, same-origin, matching Phase 1's session mechanism
  exactly — `fetch(..., { credentials: 'include' })`, no token storage, no
  CORS. Vite dev server proxies `/api` to `127.0.0.1:2909` for local dev.
- Production build served by FastAPI at `/app` (`SPA_DIST_DIR` mount in
  `workbench/app.py`) — required `base: '/app/'` in `vite.config.ts` (build
  only, dev server stays at `/`) and `basename={import.meta.env.PROD ? '/app' : '/'}`
  on `BrowserRouter` so asset paths and client-side routing both resolve
  correctly once served under a sub-path instead of domain root.

### Verification performed (HTTP/API-level — see "not done" below for the gap)

- All 40 `/api/v1/*` endpoints curl-tested with a scoped temporary session
  (created directly in Postgres, cleaned up after each round) — correct
  JSON shapes, correct 401 when unauthenticated, old HTML routes (`/login`,
  `/dashboard`, `/accounts`) confirmed unaffected throughout.
- Full account CRUD (save → test → list → remove) exercised through the
  Vite dev proxy end-to-end, matching Phase 1/2's verification style.
- `tsc -b --noEmit` clean after every page added.
- Production build (`npm run build`) succeeds; built `index.html` correctly
  references `/app/assets/...`; `/app`, `/app/dashboard` (client route),
  `/app/assets/*.js`, `/app/favicon.svg` all confirmed 200 from the real
  FastAPI server, not just the dev proxy.

### What's deliberately NOT done

- **The old Jinja/HTMX UI at `/` was not retired.** This environment has no
  browser/screenshot tooling — everything above proves the API contracts
  and build pipeline are correct, but nothing has visually confirmed the
  React app actually **renders** correctly (a client-side exception would
  show a blank page to a real user while still returning HTTP 200 for
  `index.html`, which curl cannot detect). Per the user's repeated "is this
  stable" concern, retiring the one UI that's actually been visually used
  before someone opens the new one in a real browser would be the wrong
  risk trade. **Next step for the user: open `http://127.0.0.1:2909/app` and
  click through it.** Once confirmed, retiring `workbench/templates/`,
  `workbench/static/`, and the old HTML routes in `workbench/app.py` is a
  small, low-risk deletion pass (§3f in the approved plan).
- Bundle size warning: the SPA's JS bundle is 812KB (242KB gzipped) —
  Vite's own build output flagged this. Not fixed — route-based code
  splitting (`React.lazy`) is a reasonable follow-up, not urgent for an
  internal analyst tool.
- Attack-path candidates in the drawer are rendered as raw formatted JSON,
  not a graph visualization — the old `/attack-paths` page's graph UI
  (`static/js/attack-paths.js`) was the most bespoke piece of the legacy
  frontend and wasn't ported 1:1; a proper node/edge visualization
  (react-flow or similar) is a reasonable follow-up once the rest of the
  consolidation is confirmed to be the right direction.
- Known debt carried forward unchanged from Phases 1–2: the pytest suite
  needs a real Postgres test-fixture strategy; `scripts/ui_watchdog.py` is
  still broken.

**Next**: user visually confirms `/app` in a browser → retire old UI (§3f
finish) → optional follow-ups (code-splitting, attack-path graph
visualization) → done, no further phases planned beyond what's in
`~/Desktop/CSAO_TechStack_Proposal.md`.

---

## 2026-08-11 — Phase 2 complete: ARQ + Redis job queue, CLI/web dedup

**Status: done, verified end-to-end. Assessments now run in a containerized
ARQ worker instead of a thread in the web process.**

What changed:
- New `core/orchestrator.py`: the 14-stage engine-calling sequence that
  used to exist twice (main.py's `CloudSecurityOrchestrator.run()` and
  control_plane.py's `AssessmentRunner._run_assessment`) is now one function,
  `run_pipeline(config, assessment_id, stage_hook=..., cancel_check=...,
  validations=..., assessment_metadata=...)`. Verified line-by-line against
  both original implementations, including a non-obvious detail both had in
  common: a second, not-stage-marked `crown_jewel_engine.run(findings)` call
  between the checklist_validation and threat_validation stages.
- Fixed in passing: `"inventory"` was in `STAGES` but no code ever called
  its stage-hook, so it sat at NOT_RUN forever. Now marked COMPLETED
  alongside discovery (they share the same underlying data).
- `main.py` keeps only CLI-specific code (banner, dependency check, Rich
  console output) and calls `run_pipeline` once. `control_plane.py`'s
  `AssessmentRunner._run_assessment` (renamed `_run_assessment_body`) keeps
  only Postgres-state/audit/diagnostics code and also calls `run_pipeline`
  once. Verified both actually hit the identical failure point
  (`RuntimeError: AWS credential binding failed...`) when run without real
  AWS credentials, proving they're genuinely sharing code now, not just
  structurally similar.
- `core/base_module.py`'s existing subprocess-level cancellation (collectors
  poll `config["_cancel_check"]` to kill a running external tool mid-command)
  is preserved — `run_pipeline` sets `config["_cancel_check"] = cancel_check`
  internally. This was real pre-existing behavior discovered during the
  extraction, not something added — flagging because it means cancellation
  is actually finer-grained than "between stages only" for subprocess-based
  collectors specifically (Prowler/Steampipe/Cloudsplaining), even though
  the user's Phase 2 decision was "keep cooperative-flag-only, don't invest
  further" — that decision was about not adding *new* interruption points,
  and this pre-existing one required zero new code to keep.
- `AssessmentRunner.start()`/`.cancel()` keep their exact pre-Phase-2
  signatures. Internally, `start()` now does one `asyncio.run(self._enqueue(...))`
  call (opens an ARQ Redis pool, enqueues `run_assessment_job`, closes the
  pool) instead of spawning a `threading.Thread`. `workbench/runtime.py` and
  `workbench/app.py`'s route handlers needed **zero changes**.
- New `workbench/worker.py`: ARQ `WorkerSettings` + `run_assessment_job`,
  which constructs its own `WorkbenchState`/`AssessmentRunner` (both plain
  Postgres clients, safe to instantiate fresh per job) and runs the
  synchronous pipeline via `run_in_executor`. `max_jobs=1` as defense in
  depth alongside the existing Postgres-state RUNNING check.
- New `Dockerfile` (python:3.12-slim + WeasyPrint's runtime libs + apt retry
  loop — the Debian mirror was flaky twice during this build, hash mismatch
  then failed index fetch, both transient) and `docker-compose.yml` gained
  `redis` (redis:7-alpine) and `worker` (built from the new Dockerfile,
  bind-mounts the repo so code edits don't need an image rebuild) services.
  User chose the containerized-worker option over a manually-started venv
  process.
- `requirements.txt`: added `arq>=0.26.0`, `redis>=5.0.0`. Also changed
  `cryptography>=43.0.1` to `cryptography==43.0.1` (exact pin) after the
  Docker build hit the exact same "no prebuilt wheel, forces Rust source
  build" problem Phase 1 hit locally — pinning exactly prevents this
  recurring in any fresh install, container or not.
- `/health` and the app's `lifespan` startup check both gained a Redis
  ping alongside the existing Postgres check.

Deviation from the written plan: none of substance — this phase executed
close to as-planned. The one addition beyond the plan: the `_cancel_check`
propagation into `core/base_module.py` (see above) wasn't explicitly called
out in the approved plan but was necessary to avoid silently regressing
existing subprocess-cancellation behavior; discovered by grepping for all
consumers of `config["_cancel_check"]` before finalizing the extraction.

Known debt, unchanged from Phase 1 (not re-litigated, still true): the
pytest suite (`test_workbench_auth.py`, `test_workbench_control_plane.py`,
`test_ui_health.py`) still needs a real Postgres test-fixture strategy.
`scripts/ui_watchdog.py` is still broken (imports deleted `workbench/health.py`).

Verification performed (live):
- `docker compose ps`: postgres, adminer, redis, worker all up/healthy.
- Restarted the native web app; `/health` returns
  `{"status":"healthy","database":true,"redis":true,...}`.
- Logged in via a scoped temp session, created a test cloud account, marked
  it validated directly in Postgres (no real AWS credentials available in
  this sandbox), started a test assessment via `POST /api/assessments`.
- `docker compose logs worker` showed the job picked up in 0.67s and
  completed in 3.80s total, calling `_run_assessment_body` →
  `run_pipeline` → failing at `provider.authenticate()` exactly as expected
  without real AWS creds.
- Confirmed the failure (status=FAILED, full timeline, error message)
  landed in the *same* `workbench_state` Postgres row the web UI reads —
  proving the worker-writes/UI-reads contract holds across the process
  boundary, not just in-process.
- Ran `venv/bin/python main.py` standalone: hit the identical
  `RuntimeError: AWS credential binding failed...` at the identical line
  (`core/orchestrator.py:133`) as the web path — direct proof the CLI and
  web are now running the same code, not just similar code.
- Cleaned up all test artifacts (test account removed, temp session
  cleared) after verification.

Notable operational incident during this phase, worth remembering: after
restarting the web app the first time post-rebuild, it failed to become
reachable within `serve.py`'s 20-second startup window with no error
output. Running `uvicorn` directly (bypassing `serve.py`'s watchdog)
immediately afterward worked fine in ~2 seconds. Root cause: transient
system load right after the Docker build completed, not a code issue — a
plain retry via `serve.py` succeeded normally. If this recurs, try a direct
`uvicorn workbench.app:app` run first to distinguish "app is broken" from
"system was just slow that one time."

**Next: Phase 3** — TypeScript/React frontend replacing Jinja2/HTMX, per
the tech-stack proposal. Open items carried forward from that doc's §7:
cookie vs. JWT auth for the new SPA, UI component library choice.

---

## 2026-08-07 — Phase 1 complete: real FastAPI + PostgreSQL

**Status: done, verified end-to-end, live at http://127.0.0.1:2909.**

What changed:
- Deleted the vendored fake `fastapi/` package (a ~430-line hand-rolled ASGI
  clone that was shadowing the real pip-installed FastAPI due to uvicorn
  putting cwd first on `sys.path`) and the orphaned `uvicorn_compat.py`.
- Added PostgreSQL via `docker-compose.yml` (`postgres:16-alpine` + `adminer`
  on :8081), credentials in `.env` (gitignored).
- New `workbench/db/` package: `base.py` (sync SQLAlchemy engine/session via
  psycopg — sync was a deliberate choice, see below), `models.py` (`User`,
  `SessionToken`, `LoginAudit`, `WorkbenchStateRow`).
- Alembic set up (`alembic/`, sync engine, one autogenerated initial
  migration — `alembic upgrade head` to apply).
- `workbench/auth.py`: `LocalAuthManager` rewritten to use Postgres via
  SQLAlchemy instead of sqlite3 — **same public method names/signatures**,
  so no caller changes needed beyond the DB swap itself.
- `workbench/control_plane.py`: `WorkbenchState` class rewritten to persist
  to one singleton Postgres row (`workbench_state`, JSONB `data` column)
  instead of `output/workbench/state.json` — **same `.load()`/`.save()`/
  `.update(mutator)` contract**, so `AccountVault`, `AssessmentRunner`, and
  `WorkbenchRuntime` needed zero changes.
- `workbench/runtime.py`: fixed two spots that bypassed the `state_store`
  contract and read/wrote `output/workbench/state.json` directly
  (`_store_stage_state`, and one `execution_status` read in the reporting
  path) — now both go through `state_store.update()`/`.load()` like
  everywhere else.
- `workbench/app.py`: full rewrite against real FastAPI. Fixed the two real
  incompatibilities real Starlette/FastAPI have vs. the shim: (1)
  `TemplateResponse` now takes `request` as a required first positional arg
  (~40 call sites), (2) POST body fields now need explicit
  `Annotated[str, Form()]` — real FastAPI does not auto-bind POST body to
  bare `param: str = ""` the way the shim did (this would have silently
  eaten every form submission as empty values if left unfixed). Also fixed
  `request.path` → `request.url.path` (shim-only shortcut), removed the
  `internal_health_auth` bypass (dead code once health.py was removed).
- Deleted `workbench/health.py` + `workbench/stability.py` entirely (the
  self-probing startup/watchdog system) — their internals called shim-only
  APIs (`app._dispatch()`, `app.mounts`, `app.exception_callback`) that
  don't exist on real FastAPI, so they were not portable, only replaceable.
  Replaced with: a `lifespan` context manager doing one real `SELECT 1`
  against Postgres at startup, a plain `GET /health` doing the same check
  plus template/static existence checks, and a standard
  `@app.exception_handler(Exception)` logging via loguru. Removed
  `/health/ui`, `/runtime/status`, `/runtime-status` (pure self-probe
  artifacts). Trimmed `workbench/serve.py`'s reachability poll to
  `/health` + `/login` only.
- One-time migration: `scripts/migrate_sqlite_auth_to_postgres.py` copied
  the existing `shiva`/ADMINISTRATOR user + login_audit history from the
  legacy `output/workbench/auth.db` into Postgres (password hash copied
  as-is, no re-hash). Old `auth.db` left on disk untouched as a rollback
  reference. Sessions were **not** migrated (30-min tokens, not worth
  porting) — required one fresh login after cutover.

Deliberate deviations from the original written plan, and why:
1. **One JSONB `workbench_state` row instead of separate relational
   `CloudAccount`/`Assessment`/`AssessmentStage` tables.** `AccountVault`'s
   key-rotation + nested-metadata logic was intricate enough that fully
   normalizing it would have meant rewriting business logic, not just
   swapping storage — high risk for no immediate benefit since no real
   accounts/assessments existed yet to query relationally. Real
   normalization is a natural fit for Phase 2 anyway, once the job queue
   changes the run-state shape.
2. **`app.py` stayed one file**, not split into the originally-planned
   8 router files (`routers/{auth,pages,assessments,accounts,settings,
   users,api_misc,health}.py`). Same real-FastAPI outcome, less churn to
   review in one pass. Splitting is still a reasonable low-risk follow-up.
3. **Routes stayed plain sync `def`, not `async def` + `run_in_threadpool`
   for Argon2.** Starlette already runs sync path-operation functions in a
   thread pool automatically, so this gets the same non-blocking behavior
   with less code change. No async engine (asyncpg) actually needed yet —
   installed but unused; only the sync engine (psycopg) is wired up.

Known debt NOT fixed in this pass (flagged, not hidden):
- `tests/test_workbench_auth.py`, `tests/test_workbench_control_plane.py`,
  `tests/test_ui_health.py` all assumed per-test SQLite/file isolation via
  `tmp_path` — they will fail against shared Postgres now. Needs a real
  test-DB fixture (separate schema or truncate-between-tests) before
  they're trustworthy again.
- `scripts/ui_watchdog.py` imports from the now-deleted `workbench/health.py`
  — broken until rewritten or retired.

Verification performed (live, not just import-level):
- `curl /health` → real DB/template/static check, all PASS.
- `curl /docs` → real FastAPI Swagger UI, HTTP 200.
- Confirmed `import fastapi; fastapi.__file__` resolves to
  `venv/lib/python3.12/site-packages/fastapi`, not the deleted shim.
- Logged in via a scoped temporary session token, hit `/dashboard`,
  `/accounts`, `/settings`, `/users` (correctly listed migrated `shiva`
  user) — all 200 with expected content.
- Submitted the account-save form (profile auth, fake creds) → confirmed
  the Fernet-encrypted credential landed correctly inside
  `workbench_state.data->'cloud_accounts'` in Postgres, then deleted it.
- Server logs clean across all of the above, no tracebacks.

Local dev environment notes: Python 3.12 installed via Homebrew (system
default was 3.9, too old — `networkx>=3.3` requires 3.10+). `cryptography`
pinned to `43.0.1` in `requirements.txt` floor to avoid a Rust-source-build
version with no prebuilt wheel. Postgres via Docker Compose (not Supabase —
no external account needed), Swagger UI for API testing (not Postman).

**Next: Phase 2** — ARQ + Redis job queue to replace the `threading.Thread`-
based `AssessmentRunner`, and extract one shared orchestrator module so
`main.py` (CLI) and the worker call the same pipeline code instead of two
independently-maintained implementations.
