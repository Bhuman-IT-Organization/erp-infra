#!/usr/bin/env node
/**
 * Runs erp-web with hot reload (`next dev`) on this laptop's port 3000, for web dev mode.
 *
 * Usage:  node scripts/local-up.mjs --web-dev     (once: the stack, with Nginx pointing web at this laptop)
 *         node scripts/web-dev.mjs                (then: leave it running; Ctrl+C stops it)
 *
 * Open http://localhost:8088 as usual, never http://localhost:3000: only through Nginx do the login
 * cookie, the relative /api/v1 calls and the Perfex pages share one origin. A saved change in
 * erp-web shows in the browser within seconds; no rebuild.
 *
 * API_BASE_URL is the only server variable erp-web reads (src/lib/config/env.ts). Inside Compose it
 * is http://nginx; here, on the laptop, the same Nginx is http://localhost:8088.
 */
import { spawn, spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ERP_WEB = resolve(HERE, '../../erp-web')
const NGINX = 'http://127.0.0.1:8088'
const API_BASE_URL = 'http://localhost:8088'
const PORT = '3000'

const die = (msg) => { console.error(`\n  ${msg}\n`); process.exit(1) }

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`
  Usage: node scripts/web-dev.mjs
  Runs \`corepack yarn dev\` in ../erp-web on port ${PORT} with API_BASE_URL=${API_BASE_URL}.
  Start the stack first with: node scripts/local-up.mjs --web-dev
`)
  process.exit(0)
}

if (!existsSync(resolve(ERP_WEB, 'package.json'))) die(`erp-web not found at ${ERP_WEB}. The folders must sit side by side.`)
if (!existsSync(resolve(ERP_WEB, 'node_modules'))) die('erp-web has no node_modules. Run first:  cd ../erp-web && corepack yarn install')

// The stack must be up, or every page fails with a confusing proxy error.
try {
  const res = await fetch(`${NGINX}/api/v1/health`, { signal: AbortSignal.timeout(5_000) })
  if (!res.ok) throw new Error(String(res.status))
} catch {
  die(`Nothing answers at ${NGINX}. Start the stack first:  node scripts/local-up.mjs --web-dev`)
}

// Is the `web` container still serving? Then Nginx is not in dev mode and your changes would not show.
const running = spawnSync('docker', ['compose', '-f', 'compose/local.yml', 'ps', '--status', 'running', '--services'],
  { cwd: resolve(HERE, '..'), encoding: 'utf8' })
if (running.status === 0 && running.stdout.split(/\r?\n/).includes('web')) {
  die('The web container is still running, so Nginx is not in dev mode.\n  Run first:  node scripts/local-up.mjs --web-dev')
}


console.log(`
  ==========================================
       ERP LOCAL DEVELOPMENT SERVER
  ==========================================

  Main ERP login:
    http://localhost:8088/admin/authentication

  ERP status:
    http://localhost:8088/status

  Predefined Replies:
    http://localhost:8088/setup/predefined-replies

  Swagger API documentation:
    http://localhost:8088/api/v1/docs

  OpenAPI JSON:
    http://localhost:8088/api/v1/openapi.json

  API health:
    http://localhost:8088/api/v1/health

  Frontend dev server:
    http://localhost:${PORT}

  Browse the ERP using port 8088.
  Press Ctrl+C to stop the frontend.

  To return to normal mode:
    node scripts/local-up.mjs

  ==========================================
`)



// `shell` on Windows: corepack ships as corepack.cmd (the same reason local-up.mjs sets it).
const child = spawn('corepack', ['yarn', 'dev', '--port', PORT], {
  cwd: ERP_WEB,
  stdio: 'inherit',
  env: { ...process.env, API_BASE_URL },
  shell: process.platform === 'win32',
})
child.on('exit', (code) => process.exit(code ?? 0))
