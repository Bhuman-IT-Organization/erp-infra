#!/usr/bin/env node
/**
 * Stops the local stack (Compose project erp-local).
 *
 * Usage:  node scripts/local-down.mjs [--volumes]
 *
 *   --volumes   also delete the volumes, INCLUDING the legacy database
 *               (erp-local_dbdata); the next local-up re-imports the dump
 */

import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const COMPOSE_FILE = 'compose/local.yml'

const argv = process.argv.slice(2)
const VOLUMES = argv.includes('--volumes')

if (argv.includes('--help') || argv.includes('-h')) {
  console.log(`
  Usage: node scripts/local-down.mjs [--volumes]

    --volumes   also delete the volumes, including the legacy database
`)
  process.exit(0)
}

const args = ['compose', '-f', COMPOSE_FILE, 'down']
if (VOLUMES) {
  console.warn('\n  WARNING: --volumes deletes erp-local_dbdata, the legacy database. The next local-up re-imports the dump (a few minutes).\n')
  args.push('-v')
}

console.log(`  $ docker ${args.join(' ')}`)
const res = spawnSync('docker', args, { cwd: ROOT, stdio: 'inherit' })
process.exit(res.status ?? 1)
