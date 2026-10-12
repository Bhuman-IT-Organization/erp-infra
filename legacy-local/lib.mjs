/**
 * Pure helpers shared by setup.mjs and reset-password.mjs. No I/O, so they can be tested
 * without Docker.
 */

const MYSQL_ESCAPES = {
  '\0': '\\0',
  '\b': '\\b',
  '\t': '\\t',
  '\n': '\\n',
  '\r': '\\r',
  '\x1a': '\\Z',
  "'": "\\'",
  '"': '\\"',
  '\\': '\\\\'
}

/**
 * Renders a value as a single-quoted MySQL string literal using the same escapes as
 * mysql_real_escape_string (review WR-06). The server must not run with NO_BACKSLASH_ESCAPES,
 * which the local legacy-db does not (its sql-mode is NO_ENGINE_SUBSTITUTION,ALLOW_INVALID_DATES).
 */
export function mysqlLiteral(value) {
  return `'${String(value).replace(/[\0\b\t\n\r\x1a'"\\]/g, (c) => MYSQL_ESCAPES[c])}'`
}

/** Name of the marker table setup.mjs writes only after a dump import finished (review WR-07). */
export const IMPORT_MARKER_TABLE = '_local_import'

/** Number of `CREATE TABLE` statements in a dump: what a complete import must leave behind. */
export function countCreateTables(dumpText) {
  return (dumpText.match(/^CREATE TABLE\b/gm) || []).length
}

/**
 * Decides what setup.mjs does with the database it found. Pure, so the branches are tested.
 *
 * @param {object} state
 * @param {boolean} state.fresh            --fresh was given (the volume has just been removed)
 * @param {number}  state.tableCount       tables in the schema now, excluding the marker table
 * @param {number}  state.dumpTables       CREATE TABLE statements in the dump about to be used
 * @param {string}  state.dumpSha256       sha256 of that dump
 * @param {null|{dumpSha256: string, tableCount: number}} state.marker
 *                                         the last completed import, or null when none was recorded
 * @returns {{action: 'import'|'skip'|'adopt'|'abort', reason: string}}
 */
export function importDecision({ fresh, tableCount, dumpTables, dumpSha256, marker }) {
  if (fresh || tableCount === 0) {
    return { action: 'import', reason: fresh ? '--fresh given' : 'database is empty' }
  }
  if (marker !== null) {
    if (marker.dumpSha256 === dumpSha256 && marker.tableCount === tableCount) {
      return { action: 'skip', reason: `this dump was imported completely (${tableCount} tables)` }
    }
    if (marker.dumpSha256 !== dumpSha256) {
      return {
        action: 'abort',
        reason: 'the dump on disk differs from the one that was imported; the dump has no DROP TABLE statements, so it cannot be loaded over the existing tables'
      }
    }
    return {
      action: 'abort',
      reason: `the completed import recorded ${marker.tableCount} tables but the database now has ${tableCount}`
    }
  }
  if (tableCount === dumpTables) {
    // Imported before the marker existed and the count is exactly what the dump creates:
    // treat it as complete and record it, so this branch is taken once per machine.
    return { action: 'adopt', reason: `${tableCount} tables match the dump and predate the completion marker` }
  }
  return {
    action: 'abort',
    reason: `the database has ${tableCount} tables, the dump creates ${dumpTables}, and no completed import is recorded: an earlier import did not finish`
  }
}
