# Running the legacy ERP locally

A private copy of the existing ERP (Perfex on CodeIgniter 3.1.11, ADR-0025) on your own machine, so you can learn what it does without touching the client's server.

You need this before you can size a module, choose a cutover order, or record parity tests. Static analysis tells you what *exists*; only a running system tells you what it *does*.

## Setup

Requires Docker Desktop, running.

```bash
cd workspace/legacy-local
node setup.mjs
```

First run takes a few minutes (it pulls PHP and MySQL 8.0 images and builds). After that it is seconds.

Then open **<http://localhost:8080/admin/authentication>** — the staff login.

Do not use <http://localhost:8080>. It redirects to the *client portal* login, which
looks up `tblcontacts`, not `tblstaff`. The two forms look identical, and staff
credentials there fail with "Invalid username or password". If you see that, check
`tblactivity_log`: `Is Staff Member: No` means you are on the client door.

You need a staff login:

```bash
node reset-password.mjs someone@example.com "a-password"
```

Run it with an unknown address and it lists the active accounts.

The password lives only in the database volume. Any re-import — `node setup.mjs --fresh`, or a Compose project rename, which creates a new volume under the new name — starts from the dump again, so a password set with `reset-password.mjs` is gone and must be set again. If a login that worked yesterday fails today, run `reset-password.mjs` before suspecting anything else.

## What it does, and what it deliberately does not

| | |
|---|---|
| Web | PHP 8.2 + Apache, <http://localhost:8080> |
| Database | MySQL 8.0, `127.0.0.1:33061` — matching the live server version |
| Data | `cubepltech_cube.sql` beside the web root (preferred, 409 tables) or `sql/nextgen_latest_live.sql` (398 tables, 2 June 2026) as the fallback |

PHP 8.2 and MySQL 8.0 are chosen to match production. MySQL 8.0 matches the live server (the client's phpMyAdmin export reports 8.0.46); an older dump in the tree says MariaDB 10.4 but was taken from a developer machine. **Do not use XAMPP's PHP 8.3** — CodeIgniter 3 is not reliable on it.

Four safety properties, all deliberate:

1. **Your legacy tree is never edited.** The container reads a generated `app-config.php` bind-mounted over the real one. The file on disk is untouched.
2. **No production credential is used.** Database credentials are random per machine. `APP_ENC_KEY` is regenerated, so this copy *cannot* decrypt secrets stored in the production database — stored SMTP passwords and integration keys will fail here, which is the point.
3. **Nothing is exposed.** Both ports bind to `127.0.0.1` only. The database is on 33061 so it cannot collide with a local XAMPP MySQL.
4. **The client's server is never contacted.** The original config points the database at `localhost`, so there is no path to production even by accident.

`.env` and `app-config.local.php` are generated per machine and gitignored. Never commit them.

## Everyday use

```bash
docker compose logs -f legacy # watch errors while you click around
docker compose down           # stop
node setup.mjs --fresh        # wipe the database and reimport
```

`--fresh` is the one to remember. Break anything you like — approve things, post journals, delete records — then reset. That freedom is the reason this exists.

## Known gaps

- **The preferred dump (`cubepltech_cube.sql`) loads 409 tables** and is the client's own phpMyAdmin export. The fallback `sql/nextgen_latest_live.sql` is from 2 June 2026 with 398 tables, and `sql/` contains dated change folders up to 12 September 2026 that are not in it. For learning workflows the fallback is fine. For anything that must match production exactly, use the preferred dump or get a current one.
- **Outbound integrations do not work and should not.** Email, SMS and payment adapters have no valid credentials here. The Hikvision attendance sync and SAP imports point at systems this machine cannot reach.
- **`APP_CRON_KEY` is defined here** but is missing on the live system, where its absence leaves `/cron/index` publicly invocable.
- Sessions use the database driver (`tblsessions`), matching production. Do not switch to `files`: the `php:8.2-apache` image has an empty `session.save_path`, so the files driver silently bounces every login.

## Modules overlaid from erp-infra

The legacy tree stays untouched, but wave 0 needs one thing inside the legacy system: the `erp_sso` Perfex module that lets unmigrated screens accept erp-api's RS256 token (ADR-0030). It lives in `erp-infra/legacy/modules/erp_sso/` — erp-infra owns what gets deployed into the customer's Perfex — and `docker-compose.yml` bind-mounts that folder **read-only** at `/var/www/html/modules/erp_sso` inside the tree mount. Perfex's module scanner sees it like any other module; nothing is written under `erp-legacy`.

A module that is merely present does nothing: Perfex only `require`s the init file of a module with a `tblmodules` row and `active = 1`. `setup.mjs` and `erp-infra/scripts/local-up.mjs` therefore both end with

```bash
node activate-module.mjs erp_sso 0.1.0   # idempotent: inserts the row once, then just confirms it
```

which writes that row on the **local** database only (through `docker compose exec legacy-db`, credentials never leave the container) and prints `module erp_sso active`. Proof it runs: `curl -si -X POST http://localhost:8088/erp_sso/handoff` answers `401` JSON with `X-Erp-Sso: active` (a `403`/CSRF page or a missing header means the row is absent or the mount is empty). To switch it off, on `127.0.0.1:33061`: `UPDATE tblmodules SET active = 0 WHERE module_name = 'erp_sso'` — the next `setup.mjs`/`local-up` turns it back on. `node ../../../erp-infra/scripts/verify-erp-sso.mjs --live` proves the whole path with a throwaway Node-signed token.

## Part of the erp-local stack

The two services here are `legacy` (PHP + Apache) and `legacy-db` (MySQL), and the Compose project is `erp-local` (set by `COMPOSE_PROJECT_NAME` in the generated `.env`). `../../../erp-infra/compose/local.yml` includes this file and adds api, web, nginx, redis; `node ../../../erp-infra/scripts/local-up.mjs` brings up everything. Running `docker compose` here alone still works; Compose may warn about orphan containers (api, web, nginx, redis) — that is expected.

The rename on 2026-09-19 (services `db`/`web` → `legacy-db`/`legacy`, project `legacy-local` → `erp-local`) changed the volume name from `legacy-local_dbdata` to `erp-local_dbdata`, so the first `node setup.mjs` after it re-imports the dump. Delete the old data with `docker volume rm legacy-local_dbdata` when you no longer need it.

## Where this fits

This is the prerequisite for capturing what each module does. The recording of that behaviour doubles as the parity fixtures the cutover checklist in erp-docs `03-architecture/05-strangler-fig-migration.md` requires — documenting behaviour and generating parity tests are the same activity.

Start with `HR_MODULES_TRAINING_GUIDE.md` in the legacy tree: it already documents HR and projects to a good standard, and is the template for the modules that have no guide.
