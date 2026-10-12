#!/usr/bin/env node
/**
 * Activates a Perfex module on the LOCAL legacy database only (127.0.0.1:33061,
 * reached through `docker compose exec legacy-db`, never any other host).
 *
 * Perfex only loads the init file of a module that has a tblmodules row with
 * active = 1; a module that is merely present under modules/ (for example the
 * erp_sso overlay bind-mounted from erp-infra) does nothing until this row
 * exists. This is what Setup -> Modules -> Activate writes, done from the
 * command line so setup.mjs and erp-infra's local-up can run it.
 *
 * Idempotent: inserts the row when missing (id = MAX(id) + 1, the dump's DDL
 * has no AUTO_INCREMENT on tblmodules.id), otherwise sets active = 1 and the
 * version. Prints what it did. Credentials stay inside the container's
 * environment and are never printed.
 *
 * Usage:  node activate-module.mjs <module_name> <version>
 */

import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mysqlLiteral } from './lib.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const [name, version] = process.argv.slice(2)

const die = (msg) => { console.error(`\n  ${msg}\n`); process.exit(1) }

if (!name || !version) die('Usage: node activate-module.mjs <module_name> <version>')
if (!/^[a-z_]+$/.test(name)) die(`Refusing module name ${JSON.stringify(name)}: only [a-z_] is allowed (a Perfex module directory name).`)
if (!/^\d+\.\d+\.\d+$/.test(version)) die(`Refusing version ${JSON.stringify(version)}: expected x.y.z.`)

if (!existsSync(resolve(HERE, '.env'))) die('No .env found. Run: node setup.mjs')

// Runs SQL as the database user; the credentials are read from the container's own MYSQL_* environment.
const query = (sql) =>
  spawnSync(
    'docker',
    ['compose', 'exec', '-T', 'legacy-db', 'sh', '-c',
     'exec mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -N -e "$1"', 'sh', sql],
    { cwd: HERE, encoding: 'utf8' }
  )

const n = mysqlLiteral(name)
const v = mysqlLiteral(version)

// The INSERT selects from a derived table so the NOT EXISTS guard is evaluated on the
// single computed row (a WHERE on the aggregate query itself would still yield one row).
const sql = [
  `SELECT COUNT(*) FROM tblmodules WHERE module_name = ${n};`,
  `INSERT INTO tblmodules (id, module_name, installed_version, active)
     SELECT x.id, ${n}, ${v}, 1
     FROM (SELECT COALESCE(MAX(id), 0) + 1 AS id FROM tblmodules) AS x
     WHERE NOT EXISTS (SELECT 1 FROM tblmodules WHERE module_name = ${n});`,
  `UPDATE tblmodules SET active = 1, installed_version = ${v} WHERE module_name = ${n};`,
  `SELECT COUNT(*), MAX(active) FROM tblmodules WHERE module_name = ${n};`
].join('\n')

const res = query(sql)
if (res.status !== 0) {
  die(`Could not write tblmodules on the local database. Is the stack running? (docker compose ps)\n${(res.stderr || '').trim()}`)
}

const lines = (res.stdout || '').trim().split('\n').filter(Boolean)
const before = parseInt(lines[0], 10) || 0
const [rowsAfter, active] = (lines[lines.length - 1] || '').split('\t').map((x) => parseInt(x, 10) || 0)

if (rowsAfter !== 1 || active !== 1) {
  die(`module ${name} is NOT active (rows: ${rowsAfter}, active: ${active}). Inspect tblmodules on 127.0.0.1:33061.`)
}

console.log(`  module ${name} active (${before === 0 ? 'row inserted' : 'row already present'}, version ${version})`)
