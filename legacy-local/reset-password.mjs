#!/usr/bin/env node
/**
 * Sets a staff password on the LOCAL copy only.
 *
 * Legacy hashes are phpass with portable = false, which is bcrypt $2a$ at
 * cost 8 (ADR-0025). phpass verifies with crypt($password, $stored), which
 * accepts a $2y$ hash just as well, so PHP's own password_hash at cost 8
 * produces something the application will accept.
 *
 * Usage:  node reset-password.mjs <email> <new-password>
 */

import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mysqlLiteral } from './lib.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const [email, password] = process.argv.slice(2)

if (!email || !password) {
  console.error('\n  Usage: node reset-password.mjs <email> <new-password>\n')
  process.exit(1)
}

const envPath = resolve(HERE, '.env')
if (!existsSync(envPath)) {
  console.error('\n  No .env found. Run: node setup.mjs\n')
  process.exit(1)
}

const env = Object.fromEntries(
  readFileSync(envPath, 'utf8').split('\n').filter(Boolean).map((l) => {
    const i = l.indexOf('=')
    return [l.slice(0, i), l.slice(i + 1)]
  })
)

const run = (args, opts = {}) =>
  spawnSync('docker', ['compose', ...args], { cwd: HERE, encoding: 'utf8', ...opts })

const hashed = run(['exec', '-T', 'legacy', 'php', '-r',
  `echo password_hash(${JSON.stringify(password)}, PASSWORD_BCRYPT, ['cost' => 8]);`])

const hash = (hashed.stdout || '').trim()
if (!hash.startsWith('$2')) {
  console.error('\n  Could not generate a hash. Is the stack running? (docker compose ps)\n')
  process.exit(1)
}

// Values are rendered as escaped MySQL literals (review WR-06): a JSON.stringify/replace
// swap does not escape single quotes, so o'brien@example.com broke or injected the statement.
const sql = `UPDATE tblstaff SET password = ${mysqlLiteral(hash)} WHERE email = ${mysqlLiteral(email)};
SELECT ROW_COUNT() AS updated;`

const res = run(['exec', '-T', 'legacy-db', 'mysql', `-u${env.DB_USER}`, `-p${env.DB_PASSWORD}`, env.DB_NAME, '-N', '-e', sql])

const updated = parseInt((res.stdout || '0').trim().split(/\s+/).pop(), 10)
if (updated > 0) {
  console.log(`\n  Password set for ${email}. Sign in at http://localhost:8080/admin\n`)
} else {
  console.log(`\n  No staff row matched ${email}. Existing accounts:\n`)
  const list = run(['exec', '-T', 'legacy-db', 'mysql', `-u${env.DB_USER}`, `-p${env.DB_PASSWORD}`, env.DB_NAME,
    '-N', '-e', 'SELECT email FROM tblstaff WHERE active = 1 LIMIT 20;'])
  console.log((list.stdout || '').split('\n').filter(Boolean).map((e) => `    ${e}`).join('\n') + '\n')
}
