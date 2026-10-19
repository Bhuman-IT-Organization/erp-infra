#!/usr/bin/env node
/**
 * Brings up the whole local stack (legacy, legacy-db, api, web, nginx, redis)
 * as Compose project `erp-local` from compose/local.yml, then waits until
 * Nginx answers for both the api and the web page.
 *
 * Usage:  node scripts/local-up.mjs [--dry-run] [--no-build] [--web-dev] [--help]
 *
 *   --dry-run   print every command this script would run, run nothing, exit 0
 *   --no-build  pass --no-build to `docker compose up` (reuse the last images)
 *   --web-dev   web dev mode (compose/local.web-dev.yml): no `web` container; Nginx sends web traffic
 *               to `next dev` on this laptop, started with `node scripts/web-dev.mjs`. Run without the
 *               flag to go back to the container.
 */

import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const LEGACY_LOCAL = resolve(ROOT, 'legacy-local')
const ERP_API = resolve(ROOT, '../erp-api')
const COMPOSE_FILE = 'compose/local.yml'
const NGINX = 'http://127.0.0.1:8088'

const argv = process.argv.slice(2)
const DRY_RUN = argv.includes('--dry-run')
const NO_BUILD = argv.includes('--no-build')
const WEB_DEV = argv.includes('--web-dev')
const WEB_DEV_FILE = 'compose/local.web-dev.yml'

if (argv.includes('--help') || argv.includes('-h')) {
  console.log(`
  Usage: node scripts/local-up.mjs [--dry-run] [--no-build] [--web-dev]

    --dry-run   print the commands, run nothing
    --no-build  do not rebuild the api and web images
    --web-dev   no web container: Nginx sends web traffic to next dev on this
                laptop (start it with: node scripts/web-dev.mjs). Hot reload, no rebuilds.

  Brings up legacy, legacy-db, api, web, nginx and redis as Compose project
  erp-local from ${COMPOSE_FILE}, renders env/local/*.env first, and waits for
  ${NGINX}/api/v1/health and ${NGINX}/status to answer 200.
`)
  process.exit(0)
}

const die = (msg) => { console.error(`\n  ${msg}\n`); process.exit(1) }
const step = (msg) => console.log(`  ${msg}`)

// BuildKit's default provenance attestation is timestamped, so a fully cached rebuild still
// yields a new image ID and Compose recreates the container on every run. Without it the
// second run is a no-op unless a source file changed (Compose 2.35 has no build.provenance key).
const BUILD_ENV = { ...process.env, BUILDX_NO_DEFAULT_ATTESTATIONS: '1' }

const run = (cmd, args, cwd) => {
  const line = [cmd, ...args].join(' ')
  if (DRY_RUN) { step(`would run: ${line}   (cwd ${cwd})`); return 0 }
  step(`$ ${line}`)
  // `shell` on Windows: corepack ships as corepack.cmd, which spawnSync cannot execute directly
  // (ENOENT) — the same reason erp-web's scripts/ui-add.mjs sets it. Every argument here is a bare
  // token, so shell quoting has nothing to mangle.
  return (
    spawnSync(cmd, args, {
      cwd,
      stdio: 'inherit',
      env: BUILD_ENV,
      shell: process.platform === 'win32',
    }).status ?? 1
  )
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const waitFor = async (url, timeoutMs, everyMs) => {
  if (DRY_RUN) { step(`would poll: ${url} until HTTP 200 (up to ${timeoutMs / 1000}s)`); return true }
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { redirect: 'manual' })
      if (res.status === 200) return true
    } catch { /* not up yet */ }
    await sleep(everyMs)
  }
  return false
}

console.log('\nerp-local — full local stack\n')

// b. preflight: the engine must answer, not just the CLI.
if (DRY_RUN) {
  step('would check: docker info')
} else {
  const info = spawnSync('docker', ['info'], { stdio: 'ignore' })
  if (info.status !== 0) die('Start Docker Desktop and wait for "Engine running", then re-run this.')
}

// c. legacy-local credentials exist? Otherwise its setup generates them (and loads the dump).
//    `.env` only proves credentials were generated, not that the dump import finished
//    (setup.mjs writes it before importing); the import itself is verified in step f.
//    A file that exists but lacks the keys setup.mjs always writes (seen on the first macOS run:
//    a stray .env without DB_USER) is treated as missing, not as present — setup.mjs keeps the
//    passwords it finds and regenerates the rest.
const REQUIRED_ENV_KEYS = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_ROOT_PASSWORD', 'LOCAL_ENC_KEY']
const envFile = resolve(LEGACY_LOCAL, '.env')
const envKeys = existsSync(envFile)
  ? new Set(readFileSync(envFile, 'utf8').split(/\r?\n/).map((l) => l.slice(0, l.indexOf('='))))
  : new Set()
const missingKeys = REQUIRED_ENV_KEYS.filter((k) => !envKeys.has(k))
if (missingKeys.length > 0) {
  step(existsSync(envFile)
    ? `legacy-local/.env incomplete (no ${missingKeys.join(', ')}): running its setup to complete it`
    : 'legacy-local/.env missing: running its setup first (generates credentials, imports the dump)')
  if (run('node', ['setup.mjs'], LEGACY_LOCAL) !== 0) die('legacy-local setup failed. See the output above.')
} else {
  step('legacy-local/.env present and complete')
}

// d. render env/local/*.env from those credentials.
if (run('node', ['scripts/render-local-env.mjs'], ROOT) !== 0) die('render-local-env failed.')

// e. up.
const upArgs = ['compose', '-f', COMPOSE_FILE, ...(WEB_DEV ? ['-f', WEB_DEV_FILE] : []), 'up', '-d', NO_BUILD ? '--no-build' : '--build']
if (run('docker', upArgs, ROOT) !== 0) die(`docker compose up failed. Next: docker compose -f ${COMPOSE_FILE} logs api web nginx`)
// e2. web dev mode: the override leaves `web` out of `up`, but a container from an earlier normal run
//     would keep running on its own. Stop and remove it so only `next dev` on the laptop answers.
if (WEB_DEV && run('docker', ['compose', '-f', COMPOSE_FILE, 'rm', '--stop', '--force', 'web'], ROOT) !== 0) die('Could not remove the web container for web dev mode. See the output above.')

// f. the legacy database must hold a completed import (review WR-07). setup.mjs records one in
//    `_local_import` only after the dump loaded end to end; a run that died half-way leaves no row.
//    Credentials stay inside the container: the query runs with its own MYSQL_* environment.
const importMarkerRows = () => {
  if (DRY_RUN) { step('would check: legacy-db has a row in _local_import'); return 1 }
  const res = spawnSync('docker', ['compose', '-f', COMPOSE_FILE, 'exec', '-T', 'legacy-db', 'sh', '-c',
    'exec mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -N -e "SELECT COUNT(*) FROM _local_import"'],
    { cwd: ROOT, encoding: 'utf8', env: BUILD_ENV })
  return res.status === 0 ? parseInt((res.stdout || '0').trim(), 10) || 0 : 0
}
if (importMarkerRows() === 0) {
  step('legacy-db has no completed-import marker: running legacy-local setup (imports the dump, or explains why it cannot)')
  if (run('node', ['setup.mjs'], LEGACY_LOCAL) !== 0) die('legacy-local setup failed. See the output above; a half-imported database needs: node setup.mjs --fresh   (in erp-infra/legacy-local)')
  if (importMarkerRows() === 0) die('legacy-local setup finished but recorded no completed import. Run: node setup.mjs --fresh   (in erp-infra/legacy-local)')
}
step('legacy-db import marker present')

// f2. the erp_sso module (legacy/modules/erp_sso, bind-mounted by legacy-local) needs its
//     tblmodules row or Perfex never loads it. Idempotent; existing machines get the row
//     without a re-import.
if (run('node', ['activate-module.mjs', 'erp_sso', '0.1.0'], LEGACY_LOCAL) !== 0) die('Could not activate the erp_sso module on the local legacy database. See the output above.')

// f3. apply erp-api's node-owned schema (ADR-0036). Tables the new system creates are not in the
//     client's dump, so they do not exist after an import: erp-api/prisma/sql/*.sql holds their
//     forward-only DDL and `corepack yarn db:apply` applies it with `prisma db execute`. It runs
//     HERE, after the import marker of step f, and not before the api image is built: the dump
//     import drops and recreates the whole database, so anything applied earlier is wiped. Every
//     statement is `CREATE TABLE IF NOT EXISTS`, so a second run is a no-op. A failure fails the
//     whole bring-up rather than surfacing later as a missing table at runtime.
if (run('corepack', ['yarn', 'db:apply'], ERP_API) !== 0) die(`Could not apply erp-api's node-owned schema (erp-api/prisma/sql). See the output above.\n  Next: cd ../erp-api && corepack yarn db:apply`)

// g. wait until Nginx routes both sides.
const apiOk = await waitFor(`${NGINX}/api/v1/health`, 180_000, 3_000)
if (!apiOk) die(`${NGINX}/api/v1/health did not return 200 within 180s.\n  Next: docker compose -f ${COMPOSE_FILE} logs api web nginx`)
// In web dev mode the web side is `next dev` on this laptop, which the developer starts next.
const webOk = WEB_DEV || (await waitFor(`${NGINX}/status`, 60_000, 3_000))
if (!webOk) die(`${NGINX}/status did not return 200 within 60s.\n  Next: docker compose -f ${COMPOSE_FILE} logs api web nginx`)

// h. where things are.
console.log(`
  ${DRY_RUN ? 'Dry run complete. Nothing was started.' : 'Ready.'}

    http://localhost:8088/admin/authentication  legacy (staff login)
    http://localhost:8088/status                erp-web page
    http://localhost:8088/api/v1/health         erp-api
    http://localhost:8080                       legacy directly
    127.0.0.1:33061                             MySQL
    127.0.0.1:63791                             Redis

  Stop with: node scripts/local-down.mjs
`)
if (WEB_DEV) console.log(`  Web dev mode: the web pages answer once you start the dev server.
  In a second terminal:  node scripts/web-dev.mjs
  Back to the web container:  node scripts/local-up.mjs
`)
