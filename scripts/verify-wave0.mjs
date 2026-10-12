#!/usr/bin/env node
/**
 * The wave-0 end-to-end proof, run over the wire through Nginx (http://localhost:8088) against
 * the running local stack (`node scripts/local-up.mjs` first). One Node process, one cookie jar,
 * three systems: erp-api (login, JWKS, refresh, me, logout, legacy-sso, health), the erp_sso
 * Perfex module (handoff) and a real Perfex screen (/admin/), plus the Next.js login page's
 * contract and the ADR-0030 routing exceptions.
 *
 * What it proves (SC-1, SC-2, ADR-0031):
 *    1  JWKS through Nginx; gzipped ONCE by the api (Nginx passes it through); health stays raw
 *    2  wrong password -> 401 ERP-AUTH-0001 (problem+json)
 *    3  login -> 200 accessToken (RS256, kid published, iss/aud/sub) + erp_refresh + erp_csrf +
 *       erp_session_present cookies; Path=/ proven by sending it to a legacy path (ADR-0032)
 *    4  the row is re-hashed to bcrypt cost 12 and last_ip touched
 *    5  PHP crypt() inside the legacy container accepts the re-hashed row (Perfex's own check path)
 *    6  GET me with the bearer -> 200; without -> 401 ERP-AUTH-0004
 *    7  refresh rotates (and re-sets erp_session_present); the replayed old cookie -> 401
 *       ERP-AUTH-0003; the first access token dies
 *    8  GET /admin/ with no session -> Perfex's own 307 to the login (no screen without a handoff)
 *    9  handoff without a token -> 401 ERP-SSO-0001; forged HS256 -> 401; real bearer -> 204 + sp_session
 *   10  GET /admin/ with that session -> 200 and the sidebar logout link, no password field
 *   11  GET /admin/authentication -> 302 /login; GET /login with no cookies -> the form; with
 *       erp_session_present -> the card's skeleton (ADR-0038: the page asks the api first);
 *       GET /api/v1/branding -> 200 (companyName, logos under /uploads/company/) and the page renders it (W0-05)
 *   12  timesheets issuer -> 410; the attendance issuer still routes to legacy (ADR-0030)
 *   13  logout -> 204, erp_refresh and erp_session_present cleared, the token is dead
 *   16  logout-all -> 204 with all three cookies cleared (ADR-0032). Listed and executed here,
 *       right after 13: step 15 locks the account, so the login it needs must happen before it.
 *   14  breaker: stop legacy -> legacy-sso 503 ERP-UPSTREAM-0001 + Retry-After, the second 503 in
 *       < 1 s (no connection attempt), health `checks.breakers.legacy = open` with status ok;
 *       start legacy (+ restart nginx) -> ready again after the half-open window, health closed
 *   15  lockout: five wrong passwords -> the fifth is 429 ERP-AUTH-0006 + Retry-After; the right
 *       password is refused too while locked
 *   17  W1-06 (wave 1): /setup/staff and /setup/roles (/staff and /roles until plan 04.2-29) answer 200
 *       from web and 302 to /login?next=… without a session; every bookmark form of Perfex's staff and roles screens redirects to the Node page
 *       with a RELATIVE Location (the record paths through a digits-only regex capture); ?legacy=1
 *       still reaches Perfex on every one; Perfex's write paths for the tables Node now owns answer
 *       403 ERP-LEGACY-0403 — the core four plus 15 permission-write methods over the seven modules
 *       in all four CI3 URL forms — while the modal READS beside them and every path brief §9 keeps
 *       (role_changed, remove_staff_profile_image, staff/delete, the own-profile pages) still reach
 *       Perfex. Listed and executed here, before 15, because that step locks the account.
 *       Every closed path answers the same 403 in any letter case and behind every CI3 alias
 *       (/index.php/<p>, /index.php?/<p>, /?/<p>, /index.php/?/<p>), a raw `..` answers 400, nested
 *       aliases and the sibling reads still reach Perfex, and a Perfex page through index.php answers
 *       as without it (17m to 17t, quick 260929-hdy).
 *   18  Phase 3.2: GET /api/v1/branding carries `formats` (the eight keys, decimalPlaces 2); the
 *       members CSV export answers 200 text/csv, attachment staff-members-<date>.csv, a UTF-8 BOM,
 *       no-store — status, headers and three bytes only, the body is never printed — and 401 without
 *       a bearer. When the target row lacks `staff.members.view`, the step grants it for the run and
 *       the restore deletes that row. Executed before 15, like 16 and 17.
 *   19  Perfex's staff logout (ADR-0038): GET /admin/authentication/logout -> 302 /logout?from=legacy,
 *       relative; /logout?from=legacy -> the signing-out state and no Sign out button (it signs out on
 *       arrival); ?legacy=1 still reaches Perfex. Listed here, executed right after 11, like 16-18 out
 *       of order; every request is sent without cookies, so no session of the run is ended.
 *   20  W2A-01, the Expense Categories pilot (plan 04.1-07): /setup/expense-categories answers 200 from
 *       web signed in and a relative 302 to /login?next=... without a session; every GET and HEAD of
 *       Perfex's list (/admin/expenses/categories, with a trailing slash, with ?legacy=1: no escape,
 *       D-16) redirects to it with a RELATIVE Location, while Perfex's DataTable POST still reaches
 *       Perfex; Perfex's delete (/admin/expenses/delete_category) answers 403 ERP-LEGACY-0403 naming
 *       managedAt /setup/expense-categories for GET and POST, in any letter case and behind every CI3
 *       alias; the two kept co-writers (the expense form's inline add, the timesheets add in its four
 *       MX URL forms) and the expense and accounting screens still reach Perfex (D-14, D-17); and
 *       /api/v1/expense-categories answers 401 without a bearer and 200 or 403 by the row's
 *       administrator flag. Executed after 18 and before 15, like 16-18 out of order. Every request
 *       to a Perfex write path is sent WITHOUT a session and with id 999999 where the path takes an
 *       id, so a regression answers Perfex's own 307 to its login and never writes.
 *   21  quick 261001-m42 (Phase 4.4 D-08 and D-52): timesheets::setting_zkbio_time is refused 403
 *       ERP-LEGACY-0403 for every method, in all four MX URL forms, any letter case and behind every CI3
 *       alias; every URL of the timesheets API controllers (api, api_timesheets,
 *       api_timesheets_controller, login) answers the ADR-0030 410 with and without a Perfex session;
 *       /sync_data/* answers only the company network (allowed from the host, refused from 127.0.0.1
 *       with a forged X-Forwarded-For, which is honoured only from the loopback); the rendered
 *       allow-list is what the running Nginx carries. Executed after 20 and before 15.
 *   22  W2A-02, Taxes (plan 04.1-13): /setup/taxes answers 200 from web signed in and a relative 302 to
 *       /login?next=... without a session; every GET and HEAD of Perfex's list (/admin/taxes, with a
 *       trailing slash, /index, /index/, with ?legacy=1: no escape, D-16) redirects to it with a
 *       RELATIVE Location, while Perfex's DataTable POST still reaches Perfex; Perfex's manage and delete
 *       answer 403 ERP-LEGACY-0403 naming managedAt /setup/taxes for GET and POST, in any letter case and
 *       behind every CI3 alias; the read helper tax_name_exists, the Subscriptions screens (the D-20
 *       co-writer, asserted NOT refused), the taxes dropdown, the invoice and expense screens and
 *       accounting's tax mapping still reach Perfex (D-13, D-17, D-20); and /api/v1/taxes answers 401
 *       without a bearer and 200 or 403 by the row's administrator flag. Executed after 21 and before
 *       15. Every request to a Perfex write path is sent WITHOUT a session and with id 999999 where the
 *       path takes an id, so a regression answers Perfex's own 307 to its login and never writes.
 *   24  W2A-03, Cost Centers (plan 04.1-20): /setup/cost-centers answers 200 from web signed in and a
 *       relative 302 to /login?next=... without a session; every GET and HEAD of Perfex's list
 *       (/admin/cost_centers, with a trailing slash, /index, /index/, with ?legacy=1: no escape, D-16)
 *       redirects to it with a RELATIVE Location, while a POST to the list still reaches Perfex (a read);
 *       Perfex's create, edit and delete (its one writer, D-27, open to every staff member by address,
 *       D-26) answer 403 ERP-LEGACY-0403 naming managedAt /setup/cost-centers for GET and POST, in any
 *       letter case and behind every CI3 alias; every reader of the table (the purchase request, order,
 *       quotation and shipping-charge screens, the expense form, fixed_equipment's asset creation) is
 *       asserted NOT refused and still reaches Perfex (D-13, D-17); and /api/v1/cost-centers answers 401
 *       without a bearer and 200 or 403 by the row's administrator flag. Executed after 22 and before
 *       15. Every request to a Perfex write path is sent WITHOUT a session and with id 999999 where the
 *       path takes an id, so a regression answers Perfex's own 307 to its login and never writes.
 *   26  W2C, the Email screens and the mail sender (plan 04.3-11): /setup/email-templates, /setup/email-templates/1,
 *       /setup/sent-emails, /setup/sent-emails/1 and /setup/email-status answer 200 from web signed in and a
 *       relative 302 to /login?next=<the encoded path> without a session; Perfex's own /admin/emails and
 *       /admin/settings?group=email still reach Perfex, never refused or redirected (D-03); /api/v1/mail/status
 *       answers 401 without a bearer and, with the run's bearer, 200 with no SMTP user name or password in the
 *       body for an administrator row, else 403 ERP-AUTH-0005; for an administrator row the status page's test
 *       (POST /api/v1/mail/status/test with an Idempotency-Key) answers 202 { id } and lands in Mailpit with the
 *       Message-ID <mail-<id>@localhost> within 30 s, and the step deletes that Mailpit message (a
 *       non-administrator row prints a note instead, never a PASS). Executed after 24 and before 15. The test
 *       goes to the target row's own address, which the local stack's SMTP_HOST (mailpit) catches; only ids,
 *       statuses and routes are printed, never an address, a subject or a body.
 *   27  W2A-04, Payment Modes (plan 04.1-25): /setup/payment-modes answers 200 from web signed in and a
 *       relative 302 to /login?next=... without a session; every GET and HEAD of Perfex's list
 *       (/admin/paymentmodes, with a trailing slash, /index, /index/, with ?legacy=1: no escape, D-16)
 *       redirects to it with a RELATIVE Location, while Perfex's DataTable POST still reaches Perfex (a
 *       read); Perfex's manage, delete, change_payment_mode_status and change_payment_mode_show_to_client_status
 *       (its one writer, D-32; the show-to-client path, which no screen calls, refused with the others, D-35)
 *       answer 403 ERP-LEGACY-0403 naming managedAt /setup/payment-modes for GET and POST, in any letter case
 *       and behind every CI3 alias; every reader of the table (invoices and their record-payment form,
 *       payments, the expense form, credit notes, the payment-modes report, accounting's payment-mode
 *       mapping, purchase orders, purchase invoices and their payments, order returns, fixed_equipment's
 *       orders, timesheets' requisition detail and the exports module) is asserted NOT refused and still
 *       reaches Perfex (D-13, D-17, D-32); and /api/v1/payment-modes answers 401 without a bearer and 200
 *       or 403 by the row's administrator flag. Executed after 26 and before 15. Every request to a Perfex
 *       write path is sent WITHOUT a session and with id 999999 where the path takes one, so a regression
 *       answers Perfex's own 307 to its login and never writes.
 *   29  W2A-05, Currencies (plan 04.1-30): /setup/currencies answers 200 from web signed in and a relative
 *       302 to /login?next=... without a session; every GET and HEAD of Perfex's list (/admin/currencies,
 *       with a trailing slash, /index, /index/, with ?legacy=1: no escape, D-16) redirects to it with a
 *       RELATIVE Location, while Perfex's DataTable POST still reaches Perfex (a read); Perfex's manage,
 *       delete and make_base_currency (its one writer, D-38; make-base is a GET link) answer 403
 *       ERP-LEGACY-0403 naming managedAt /setup/currencies for GET and POST, in any letter case and behind
 *       every CI3 alias; get_currency_symbol on the same controller (as written, in 3 letter-case forms and
 *       behind the 6 CI3 aliases) and every reader of the table (misc/get_currency, the invoice, estimate,
 *       proposal, expense, credit note, subscription and customer forms, purchase orders, vendors and
 *       purchase settings, warehouse, accounting and hr_payroll settings, hr_profile's base-currency name,
 *       fixed_equipment's locations and the exports module) are asserted NOT refused and NOT redirected
 *       and still reach Perfex (D-13, D-17, D-38); and /api/v1/currencies answers 401 without a bearer and
 *       200 or 403 by the row's administrator flag. Executed after 27 and before 15. Every request to a
 *       Perfex write path is sent WITHOUT a session and with id 999999 where the path takes one, so a
 *       regression answers Perfex's own 307 to its login and never writes.
 *   30  quick 261005-fdl: warehouse::wh_delete_error_file_day_before (a URL-chosen file delete with no
 *       permission check) is refused 403 ERP-LEGACY-0403 for every method, in all four MX URL forms, any
 *       letter case and behind every CI3 alias, sent with no argument or only the made-up folder
 *       zz-made-up and no session; a longer method name and warehouse's report, stock import and delivery
 *       screens still reach Perfex. Never run red live: the red proof is offline. Executed after 29 and
 *       before 15.
 *   31  Security closure (plan 04.7-01; 4.7 D-24, lead decision F6): Perfex's four unauthenticated
 *       warehouse_client routes (shipment_detail, stock_export_pdf, client_packing_list_pdf,
 *       client_update_shipment_status) and the ungated staff update_shipment_status answer 404 with X-Erp-Route
 *       web from Nginx for every method, in all four MX URL forms, any letter case and behind every CI3 alias,
 *       while the signed-in customer's shipments list, the e-mailed shipment_detail_hash link and the staff
 *       delivery screens still reach Perfex (D-25).
 *       Every request is sent WITHOUT a session and with id 999999. The two writing routes are sent only in their
 *       zero- and one-argument forms, where PHP 8.2 raises ArgumentCountError before any statement, and
 *       client_update_shipment_status is never sent to Perfex: 31b sends it only after 31a passed and the closure
 *       regex read from ../nginx/local/default.conf matched every path it would send, else it fails "not sent".
 *       Executed after 30 and before 15.
 *   32  The staff and roles addresses (plan 04.2-29; STATE Q9): the old Node addresses /staff and /roles and their
 *       pages answer a RELATIVE 301 to the same page under /setup with the query kept, from web; a rest of path
 *       outside [A-Za-z0-9_-] segments (an encoded CR LF, a space) answers 404 with no Location and no Set-Cookie,
 *       and a 61-character path that a backtracking rewrite would choke on answers 404 within 2 s (ReDoS);
 *       /setup/staff and /setup/roles and their pages answer from web (a 302 to /login?next=... without a session,
 *       200 signed in); Perfex's staff and roles screens redirect to the /setup address, and the identity refusal
 *       names /setup/staff and /setup/roles. Executed after 31 and before 15; every request but the two signed-in
 *       page reads is sent WITHOUT a session, with id 999999.
 *   33  Security closure (plan 04.8-01; 4.8 D-19): Perfex's ungated warehouse adjust route (Warehouse::adjust, which
 *       applies any loss adjustment's counted numbers to stock by id with no permission, approval or state check)
 *       answers 404 with X-Erp-Route web from Nginx for every method, in all four MX URL forms, any letter case and
 *       behind every CI3 alias, while adjustment_fill_multiple_serial_number_modal, two longer names and
 *       accounting's own adjustment route still reach Perfex. adjust is never sent to Perfex before the closure is
 *       proven: 33a sends nothing unless the closure regex read from ../nginx/local/default.conf compiles and
 *       matches every plain path, else it fails "not sent". Every request is sent WITHOUT a session and with id
 *       999999. Executed after 32 and before 15.
 *
 * The test account is ONE staff row of the LOCAL copy: `--email <email>` or, by default, the active
 * row with the highest staffid (never staffid 1). Its `password`, `last_login` and `last_ip` are
 * read first and restored byte for byte in `finally` — on success, on failure and on Ctrl-C —
 * together with the deletion of every Redis key the run created (by exact name, never a FLUSH)
 * and the restart of `legacy`/`nginx` if the breaker step stopped them. The throwaway password is
 * random, hashed at bcrypt cost 10 INSIDE the legacy container (the label/cost of the live rows,
 * so the re-hash path is exercised) and passed to PHP as an environment variable, never on a
 * command line. No hash, password, token or e-mail address is ever printed (T-1.3-57).
 *
 * Usage:  node scripts/verify-wave0.mjs [--email <email>] [--no-breaker] [--keep-stack] [--help]
 *   --email <email>  target this active staff row instead of the highest staffid
 *   --no-breaker     skip step 14, for hosts where stopping a container mid-run is unwelcome; the
 *                    in-process proof of the same behaviour is erp-api's auth.controller.e2e.spec.ts
 *   --keep-stack     reserved (no-op today: the stack is always left running)
 *
 * Recovery if a run dies before the restore (should not happen):
 *   node legacy-local/reset-password.mjs <email> <password>
 *   docker compose -f compose/local.yml start legacy && docker compose -f compose/local.yml restart nginx
 *
 * No dependency beyond node:*; the MySQL literal helper comes from erp-infra/legacy-local/lib.mjs.
 */

import { spawnSync } from 'node:child_process'
import { createHmac, randomBytes } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gunzipSync } from 'node:zlib'
import { mysqlLiteral } from '../legacy-local/lib.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const COMPOSE_FILE = 'compose/local.yml'
const NGINX = 'http://localhost:8088'
const LEGACY_DIRECT = 'http://localhost:8080'
// Mailpit's REST API (the local mail catcher, README `## Mail (local)`); step 26e reads and deletes its own message there.
const MAILPIT = process.env.MAILPIT_API_URL ?? 'http://127.0.0.1:18025'
const MAILPIT_WAIT_MS = 30_000
const PROBLEM = 'application/problem+json'
const TARGET_PREFIX = '$2y$12$'
const SEED_COST = 10
const LOCKOUT_THRESHOLD = 5
const BREAKER_STEP_BUDGET_MS = 60_000

// --- flags ------------------------------------------------------------------

const argv = process.argv.slice(2)
if (argv.includes('--help') || argv.includes('-h')) {
  console.log(`
  Usage: node scripts/verify-wave0.mjs [--email <email>] [--no-breaker] [--keep-stack]

    --email <email>  target this active staff row (default: the active row with the highest staffid)
    --no-breaker     skip the breaker step (no container is stopped)
    --keep-stack     reserved; the stack is always left running

  Runs the wave-0 proof through http://localhost:8088 and restores the test row, its Redis keys
  and the stack in every case. Needs: node scripts/local-up.mjs
`)
  process.exit(0)
}
const NO_BREAKER = argv.includes('--no-breaker')
const EMAIL_FLAG = argv.includes('--email') ? argv[argv.indexOf('--email') + 1] : null
if (argv.includes('--email') && (!EMAIL_FLAG || EMAIL_FLAG.startsWith('--'))) {
  console.error('--email needs a value')
  process.exit(1)
}

// --- reporting ----------------------------------------------------------------

const steps = []
/** Last line of defence for T-1.3-57: no e-mail, bcrypt hash or JWT ever reaches the terminal. */
const redact = (s) => String(s)
  .replace(/\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}/g, '<hash>')
  .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>')
  .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '<jwt>')
const check = (name, ok, detail) => {
  const d = redact(detail ?? '')
  steps.push({ name, ok: Boolean(ok), detail: d })
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ok ? '' : ` — ${d}`}`)
  return Boolean(ok)
}
const skip = (name) => { console.log(`SKIP ${name}`) }
const note = (msg) => console.log(`     ${msg}`)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// --- docker compose helpers ---------------------------------------------------

const compose = (args, opts = {}) =>
  spawnSync('docker', ['compose', '-f', COMPOSE_FILE, ...args], { cwd: ROOT, encoding: 'utf8', ...opts })

/** Runs SQL with the legacy-db container's own credentials (never on our command line). */
const sql = (statement) => {
  const res = compose(['exec', '-T', '-e', `SQL=${statement}`, 'legacy-db', 'sh', '-c',
    'exec mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -N -r --batch -e "$SQL"'])
  if (res.status !== 0) throw new Error(`mysql failed (${res.status}): ${(res.stderr || '').split('\n').filter((l) => !/Using a password/.test(l)).join(' ').trim()}`)
  return (res.stdout || '').split('\n').filter((l) => l.length > 0).map((l) => l.split('\t'))
}
const sqlValue = (v) => (v === 'NULL' ? 'NULL' : mysqlLiteral(v))

/** Runs a PHP program (stdin) in the legacy container with values passed as environment variables. */
const php = (program, env = {}) => {
  const envArgs = Object.entries(env).flatMap(([k, v]) => ['-e', `${k}=${v}`])
  return compose(['exec', '-T', ...envArgs, 'legacy', 'php'], { input: program })
}
const phpHash = (plaintext, cost) => {
  const res = php(`<?php echo password_hash(getenv("P"), PASSWORD_BCRYPT, ["cost" => (int) getenv("C")]);`, { P: plaintext, C: String(cost) })
  const hash = (res.stdout || '').trim()
  if (res.status !== 0 || !hash.startsWith('$2y$')) throw new Error('password_hash in the legacy container failed (is the stack up?)')
  return hash
}
/** Perfex verifies with crypt($password, $stored) (phpass, portable = false): exit 0 when it matches. */
const phpCrypt = (hash, plaintext) => {
  const res = php(`<?php exit(hash_equals(getenv("H"), crypt(getenv("P"), getenv("H"))) ? 0 : 1);`, { H: hash, P: plaintext })
  return res.status
}

const redis = (...args) => {
  const res = compose(['exec', '-T', 'redis', 'redis-cli', '-n', '1', ...args])
  if (res.status !== 0) throw new Error(`redis-cli failed: ${(res.stderr || '').trim()}`)
  return (res.stdout || '').split('\n').map((l) => l.trim()).filter(Boolean)
}

// --- HTTP: cookie jar over Node 22 fetch, and a raw client for the compression checks ---------

const jar = new Map() // name -> { value, path }
const storeCookies = (response) => {
  for (const line of response.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split(';').map((s) => s.trim())
    const eq = pair.indexOf('=')
    const name = pair.slice(0, eq)
    const value = pair.slice(eq + 1)
    const attr = Object.fromEntries(attrs.map((a) => { const i = a.indexOf('='); return i < 0 ? [a.toLowerCase(), true] : [a.slice(0, i).toLowerCase(), a.slice(i + 1)] }))
    const maxAge = attr['max-age'] !== undefined ? parseInt(attr['max-age'], 10) : null
    const expired = (maxAge !== null && maxAge <= 0) || (attr.expires && new Date(attr.expires).getTime() < Date.now())
    if (expired) jar.delete(name)
    else jar.set(name, { value, path: attr.path || '/' })
  }
}
const cookieHeader = (path) =>
  [...jar.entries()].filter(([, c]) => path === c.path || path.startsWith(c.path.endsWith('/') ? c.path : `${c.path}/`) || c.path === '/')
    .map(([n, c]) => `${n}=${c.value}`).join('; ')

/** Attributes of a Set-Cookie line for `name` on this response (the LAST one, as a browser would keep). */
const setCookieOf = (response, name) => {
  const lines = response.headers.getSetCookie().filter((l) => l.startsWith(`${name}=`))
  if (lines.length === 0) return null
  const [pair, ...attrs] = lines[lines.length - 1].split(';').map((s) => s.trim())
  return { value: pair.slice(pair.indexOf('=') + 1), attrs: attrs.map((a) => a.toLowerCase()), count: lines.length }
}

/** The `Max-Age` of a `setCookieOf` result as a number, or null when the line carries none. */
const maxAgeOf = (cookie) => {
  const attr = cookie?.attrs.find((a) => a.startsWith('max-age='))
  return attr ? parseInt(attr.slice('max-age='.length), 10) : null
}
/** The cookie NAMES the jar would send to `path` — how `Path=/` is proven (ADR-0032). */
const cookieNamesFor = (path) => cookieHeader(path).split('; ').filter(Boolean).map((c) => c.split('=')[0])

/**
 * One request through Nginx. `cookies` (a string) replaces the jar for this call; `bearer` adds the
 * Authorization header. Redirects are never followed. Returns status, headers, text and parsed JSON.
 */
const http = async (method, path, { body, headers = {}, bearer, cookies } = {}) => {
  const h = { ...headers }
  if (body !== undefined) h['content-type'] = 'application/json'
  if (bearer) h.authorization = `Bearer ${bearer}`
  const cookie = cookies !== undefined ? cookies : cookieHeader(path)
  if (cookie) h.cookie = cookie
  const started = Date.now()
  const res = await fetch(`${NGINX}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual', cache: 'no-store' })
  const ms = Date.now() - started
  if (cookies === undefined) storeCookies(res)
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { /* not JSON */ }
  return { status: res.status, headers: res.headers, text, json, ms, res }
}

/** Raw GET with node:http — no transparent gzip decoding, so Content-Encoding and the bytes are visible. */
const rawGet = (path, headers = {}) => new Promise((resolvePromise, reject) => {
  const url = new URL(`${NGINX}${path}`)
  const req = httpRequest({ host: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method: 'GET', headers }, (res) => {
    const chunks = []
    res.on('data', (c) => chunks.push(c))
    res.on('end', () => resolvePromise({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
  })
  req.on('error', reject)
  req.end()
})

/**
 * One request through Nginx with `path` sent VERBATIM (quick 260929-hdy). fetch parses the URL (WHATWG),
 * which resolves `..` before sending, so a probe of /admin/roles/../delete/1 through `http()` would test
 * /admin/delete/1; node:http sends the request line as given. Never sends a cookie; a POST carries
 * content-length 0. `headers.get(name)` mirrors fetch's Headers.get (case-insensitive, an array joined
 * with ', ', null when absent), so step 17's routeOf, locOf, isClosed and stillLegacy work on it unchanged.
 */
const rawHttp = (method, path, headers = {}) => new Promise((resolvePromise, reject) => {
  const { hostname, port } = new URL(NGINX)
  const h = { ...headers }
  delete h.cookie
  if (method === 'POST') h['content-length'] = '0'
  const req = httpRequest({ host: hostname, port, path, method, headers: h }, (res) => {
    const chunks = []
    res.on('data', (c) => chunks.push(c))
    res.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8')
      let json = null
      try { json = JSON.parse(text) } catch { /* not JSON */ }
      const get = (name) => {
        const v = res.headers[String(name).toLowerCase()]
        if (v === undefined) return null
        return Array.isArray(v) ? v.join(', ') : String(v)
      }
      resolvePromise({ status: res.statusCode, headers: { get }, text, json })
    })
  })
  req.on('error', reject)
  req.end()
})

/**
 * One request sent from 127.0.0.1 INSIDE the nginx container (quick 261001-m42). The geo block behind
 * /sync_data/* honours X-Forwarded-For only from the loopback (`proxy 127.0.0.1;`), so this is the one
 * client that can present a non-company address to Nginx on a laptop where every host request comes from
 * the Docker gateway, inside the private ranges. The request text travels base64-encoded in an env var,
 * never as a raw CRLF on argv. `holdSeconds` keeps nc's stdin open: busybox nc closes the connection at
 * stdin EOF, which is fine for an answer Nginx gives at once (a `return`), but for a proxied request
 * Nginx then sees the client go away and drops the upstream answer. Returns the shape of rawHttp
 * (`headers.get` lower-cased, null when absent), so routeOf, isClosed and probeLine work on it; an empty
 * answer is status 0. Synchronous: failuresOf awaits whatever `send` returns.
 */
const fromNginx = (method, path, xff, holdSeconds = 0) => {
  const lines = [`${method} ${path} HTTP/1.0`, 'Host: localhost:8088', `X-Forwarded-For: ${xff}`]
  if (method === 'POST') lines.push('Content-Length: 0')
  const b64 = Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'utf8').toString('base64')
  const res = compose(['exec', '-T', '-e', `REQ=${b64}`, 'nginx', 'sh', '-c', holdSeconds
    ? `{ printf "%s" "$REQ" | base64 -d; sleep ${holdSeconds}; } | nc -w 5 127.0.0.1 80`
    : 'printf "%s" "$REQ" | base64 -d | nc -w 5 127.0.0.1 80'])
  const raw = res.stdout || ''
  const split = raw.indexOf('\r\n\r\n')
  const head = split < 0 ? raw : raw.slice(0, split)
  const text = split < 0 ? '' : raw.slice(split + 4)
  const [statusLine = '', ...headerLines] = head.split('\r\n')
  const status = parseInt(statusLine.split(' ')[1], 10) || 0
  const headerMap = new Map()
  for (const line of headerLines) {
    const i = line.indexOf(':')
    if (i < 0) continue
    const name = line.slice(0, i).trim().toLowerCase()
    const value = line.slice(i + 1).trim()
    headerMap.set(name, headerMap.has(name) ? `${headerMap.get(name)}, ${value}` : value)
  }
  let json = null
  try { json = JSON.parse(text) } catch { /* not JSON */ }
  return { status, headers: { get: (name) => headerMap.get(String(name).toLowerCase()) ?? null }, text, json }
}

const waitFor = async (url, status, timeoutMs, everyMs = 1000) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url, { redirect: 'manual', cache: 'no-store' })
      await r.text()
      if (r.status === status) return true
    } catch { /* not up yet */ }
    await sleep(everyMs)
  }
  return false
}

// --- JWT helpers ----------------------------------------------------------------

const b64url = (input) => Buffer.from(input).toString('base64url')
const decodeJwt = (token) => {
  const [h, p] = token.split('.')
  return { header: JSON.parse(Buffer.from(h, 'base64url').toString('utf8')), payload: JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) }
}
/** An HS256 token signed with an arbitrary secret: what an algorithm-confusion attacker would send. */
const forgeHs256 = (payload, kid) => {
  const data = `${b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid }))}.${b64url(JSON.stringify(payload))}`
  return `${data}.${b64url(createHmac('sha256', 'not-the-key').update(data).digest())}`
}

const isProblem = (r, code) => (r.headers.get('content-type') || '').startsWith(PROBLEM) && r.json?.code === code

// --- state shared with the restore --------------------------------------------------

const state = {
  staffId: null,
  email: null,
  original: null,      // { password, last_login, last_ip } as mysql printed them ('NULL' for NULL)
  seeded: false,
  redisKeys: new Set(),
  stoppedLegacy: false,
  grantedStaffView: false, // step 18 inserted tblstaff_permissions (staff, view) for the target row
  restored: false,
}

const restore = async () => {
  if (state.restored) return
  state.restored = true
  console.log('\nrestore')
  try {
    if (state.seeded && state.original) {
      const { password, last_login, last_ip } = state.original
      sql(`UPDATE tblstaff SET password = ${sqlValue(password)}, last_login = ${sqlValue(last_login)}, last_ip = ${sqlValue(last_ip)} WHERE staffid = ${state.staffId}`)
      const [row] = sql(`SELECT password, IFNULL(last_login, 'NULL'), IFNULL(last_ip, 'NULL') FROM tblstaff WHERE staffid = ${state.staffId}`)
      const same = row && row[0] === password && row[1] === last_login && row[2] === last_ip
      check('restore: staff row password, last_login and last_ip back to their original bytes', same, 'row differs from the pre-run values')
      note(`restored: prefix unchanged (${row && row[0].startsWith(TARGET_PREFIX) ? 'cost-12 bcrypt, as before the run' : 'not a cost-12 hash, as before the run'})`)
    }
    if (state.grantedStaffView) {
      sql(`DELETE FROM tblstaff_permissions WHERE staff_id = ${state.staffId} AND feature = 'staff' AND capability = 'view'`)
      const [[leftText]] = sql(`SELECT COUNT(*) FROM tblstaff_permissions WHERE staff_id = ${state.staffId} AND feature = 'staff' AND capability = 'view'`)
      check('restore: the staff/view row step 18 granted is deleted (the target row holds what it held before)', leftText === '0', `${leftText} left`)
    }
    if (state.staffId !== null) {
      for (const sid of redis('SMEMBERS', `auth:user:${state.staffId}:sessions`)) state.redisKeys.add(`auth:sess:${state.staffId}:${sid}`)
      state.redisKeys.add(`auth:user:${state.staffId}:sessions`)
      state.redisKeys.add(`auth:perm:${state.staffId}`)
      if (state.email) state.redisKeys.add(`auth:lockout:${state.email.toLowerCase()}`)
      // `auth:user:{id}:version` is deliberately NOT deleted: it is a counter that only ever grows,
      // and the api keeps it in a 5 s L1 cache (TIMINGS.auth.versionCacheMs). Deleting it while
      // the api still holds the old number lets the next login mint a token whose `ver` the
      // reuse-detection INCR lands on again, and step 7's "first token dies" check then fails on
      // a back-to-back run. Leaving the counter is harmless; deleting it is a race.
      const keys = [...state.redisKeys]
      redis('DEL', ...keys)
      const left = redis('EXISTS', ...keys)
      check(`restore: ${keys.length} Redis auth keys deleted by name (sessions, permissions, lockout, revocations; the version counter stays)`, left[0] === '0', `EXISTS -> ${left[0]}`)
    }
  } catch (e) {
    check('restore: database and Redis', false, e.message)
  }
  if (state.stoppedLegacy) {
    try {
      const start = compose(['start', 'legacy'], { stdio: 'inherit' })
      const apache = await waitFor(`${LEGACY_DIRECT}/admin/authentication`, 200, 90_000)
      const nginx = compose(['restart', 'nginx'], { stdio: 'inherit' })
      const health = await waitFor(`${NGINX}/api/v1/health`, 200, 60_000)
      check('restore: legacy started, nginx restarted, health 200 through nginx', start.status === 0 && apache && nginx.status === 0 && health,
        `start ${start.status}, apache ${apache}, nginx ${nginx.status}, health ${health}`)
      state.stoppedLegacy = !(start.status === 0 && apache)
    } catch (e) {
      check('restore: stack', false, e.message)
    }
  }
}

process.on('SIGINT', () => {
  console.log('\ninterrupted — restoring before exit')
  restore().finally(() => process.exit(130))
})

// --- the proof --------------------------------------------------------------------

const main = async () => {
  const started = Date.now()
  console.log('\nverify-wave0 — the wave-0 login proof through http://localhost:8088\n')

  // Preconditions: the stack answers, the row exists.
  const health0 = await http('GET', '/api/v1/health')
  if (health0.status !== 200 || health0.json?.checks?.redis !== 'ok') throw new Error(`stack not ready: /api/v1/health ${health0.status} (run node scripts/local-up.mjs)`)

  const where = EMAIL_FLAG ? `email = ${mysqlLiteral(EMAIL_FLAG)} AND active = 1` : 'active = 1'
  const rows = sql(`SELECT staffid, email, password, IFNULL(last_login, 'NULL'), IFNULL(last_ip, 'NULL') FROM tblstaff WHERE ${where} ORDER BY staffid DESC LIMIT 1`)
  if (rows.length === 0) throw new Error(EMAIL_FLAG ? 'no ACTIVE staff row with that e-mail' : 'no active staff row in the local copy')
  const [[staffIdText, email, password, lastLogin, lastIp]] = rows
  state.staffId = parseInt(staffIdText, 10)
  state.email = email
  state.original = { password, last_login: lastLogin, last_ip: lastIp }
  if (state.staffId === 1) throw new Error('refusing to use staffid 1 (the administrator); pass --email for another active account')
  note(`target: staffid ${state.staffId} (active, ${EMAIL_FLAG ? 'by --email' : 'highest staffid'}); original hash kept for the restore`)

  // Seed: a random throwaway password at the live rows' cost, hashed in the legacy container.
  const pw = randomBytes(18).toString('base64url')
  const seedHash = phpHash(pw, SEED_COST)
  sql(`UPDATE tblstaff SET password = ${mysqlLiteral(seedHash)} WHERE staffid = ${state.staffId}`)
  state.seeded = true
  state.redisKeys.add(`auth:lockout:${email.toLowerCase()}`)

  const login = async (password) => http('POST', '/api/v1/auth/login', { body: { email, password } })
  // Status, content type and the problem code only: a success body would carry the user's e-mail.
  const problemDetail = (r) => `${r.status} ${r.headers.get('content-type') || 'no content-type'} ${r.json?.code || `body ${r.text.length} B`}`

  // 1. JWKS + compress-once ------------------------------------------------------------
  const jwks = await http('GET', '/.well-known/jwks.json')
  const key0 = jwks.json?.keys?.[0]
  check('1 GET /.well-known/jwks.json -> 200 from the api with an RSA key and a kid',
    jwks.status === 200 && jwks.headers.get('x-erp-route') === 'api' && key0?.kty === 'RSA' && typeof key0?.kid === 'string' && key0.kid.length > 0,
    `${jwks.status} route=${jwks.headers.get('x-erp-route')} kty=${key0?.kty}`)
  const kid = key0?.kid ?? ''
  const gz = await rawGet('/.well-known/jwks.json', { 'accept-encoding': 'gzip' })
  let inflated = null
  try { inflated = JSON.parse(gunzipSync(gz.body).toString('utf8')) } catch { /* not gzip */ }
  check('1 JWKS with Accept-Encoding: gzip -> Content-Encoding: gzip, compressed by the api and passed through Nginx once; gunzips to the same kid (ADR-0031 §6)',
    gz.status === 200 && gz.headers['content-encoding'] === 'gzip' && inflated?.keys?.[0]?.kid === kid,
    `${gz.status} content-encoding=${gz.headers['content-encoding']} ${gz.body.length} bytes, inflated kid ${inflated?.keys?.[0]?.kid === kid ? 'equal' : 'differs'}`)
  const hz = await rawGet('/api/v1/health', { 'accept-encoding': 'gzip' })
  let healthRaw = null
  try { healthRaw = JSON.parse(hz.body.toString('utf8')) } catch { /* not JSON */ }
  check('1 GET /api/v1/health with Accept-Encoding: gzip -> no Content-Encoding (below the compression threshold), JSON body',
    hz.status === 200 && hz.headers['content-encoding'] === undefined && healthRaw?.status === 'ok',
    `${hz.status} content-encoding=${hz.headers['content-encoding']} ${hz.body.length} bytes`)

  // 2. wrong password (sent without the jar: the 401 also sets erp_csrf, and a login that
  //    already carries the secret cookie reuses it instead of setting it again — step 3
  //    must see the first Set-Cookie) ---------------------------------------------------
  const wrong = await http('POST', '/api/v1/auth/login', { body: { email, password: `wrong-${pw}` }, cookies: '' })
  check('2 POST login with a wrong password -> 401 ERP-AUTH-0001 as application/problem+json from the api',
    wrong.status === 401 && isProblem(wrong, 'ERP-AUTH-0001') && wrong.headers.get('x-erp-route') === 'api', problemDetail(wrong))

  // 3. login -----------------------------------------------------------------------------
  const first = await login(pw)
  const body = first.json ?? {}
  check('3 POST login -> 200 with accessToken, csrfToken and user.staffId of the target row',
    first.status === 200 && typeof body.accessToken === 'string' && typeof body.csrfToken === 'string' && body.user?.staffId === state.staffId,
    `${first.status} ${first.json ? `keys ${Object.keys(first.json).join(',')}` : `body ${first.text.length} B`}`)
  let jwt = null
  try { jwt = decodeJwt(body.accessToken) } catch { /* no token */ }
  check('3 accessToken is RS256 with the published kid, iss erp-api, aud erp-web, sub = staffId',
    jwt?.header.alg === 'RS256' && jwt?.header.kid === kid && jwt?.payload.iss === 'erp-api' && jwt?.payload.aud === 'erp-web' && jwt?.payload.sub === String(state.staffId),
    `alg=${jwt?.header.alg} kid ${jwt?.header.kid === kid ? 'matches' : 'differs'} iss=${jwt?.payload.iss} aud=${jwt?.payload.aud}`)
  const refreshCookie = setCookieOf(first.res, 'erp_refresh')
  const csrfCookie = setCookieOf(first.res, 'erp_csrf')
  check('3 Set-Cookie erp_refresh: HttpOnly, SameSite=Strict, Path=/api/v1/auth/refresh, no Secure (local http)',
    refreshCookie && refreshCookie.attrs.includes('httponly') && refreshCookie.attrs.includes('samesite=strict') && refreshCookie.attrs.includes('path=/api/v1/auth/refresh') && !refreshCookie.attrs.includes('secure'),
    refreshCookie ? refreshCookie.attrs.join('; ') : 'cookie missing')
  check('3 Set-Cookie erp_csrf: Path=/api/v1/auth, HttpOnly, SameSite=Strict',
    csrfCookie && csrfCookie.attrs.includes('path=/api/v1/auth') && csrfCookie.attrs.includes('httponly') && csrfCookie.attrs.includes('samesite=strict'),
    csrfCookie ? csrfCookie.attrs.join('; ') : 'cookie missing')
  const presentCookie = setCookieOf(first.res, 'erp_session_present')
  check('3 Set-Cookie erp_session_present: value 1, HttpOnly, SameSite=Lax, Path=/, the same Max-Age as erp_refresh, no Secure (local http) (ADR-0032)',
    presentCookie && presentCookie.value === '1' && presentCookie.attrs.includes('httponly') && presentCookie.attrs.includes('samesite=lax')
      && presentCookie.attrs.includes('path=/') && !presentCookie.attrs.includes('secure')
      && maxAgeOf(presentCookie) !== null && maxAgeOf(presentCookie) === maxAgeOf(refreshCookie),
    presentCookie ? `${presentCookie.attrs.join('; ')} (erp_refresh max-age=${maxAgeOf(refreshCookie)})` : 'cookie missing')
  // The whole point of `Path=/`, and the one thing Fastify inject cannot show: the browser sends
  // the presence flag to a LEGACY path, while the refresh credential stays on its own path.
  const legacyNames = cookieNamesFor('/admin/')
  const legacyHit = await rawGet('/admin/', { cookie: cookieHeader('/admin/') })
  check('3 Path=/ on the wire: the jar sends erp_session_present — and NOT erp_refresh — to the legacy path /admin/ through Nginx (ADR-0032)',
    legacyNames.includes('erp_session_present') && !legacyNames.includes('erp_refresh') && legacyHit.headers['x-erp-route'] === 'legacy',
    `route=${legacyHit.headers['x-erp-route']} cookies sent: ${legacyNames.join(',') || 'none'}`)
  if (jwt?.payload.sid) state.redisKeys.add(`auth:sess:${state.staffId}:${jwt.payload.sid}`)
  let accessToken = body.accessToken
  let csrfToken = body.csrfToken

  // 4. the row was re-hashed and touched ------------------------------------------------
  const [[prefix4, lastIp4, lastLogin4, hash4]] = sql(`SELECT LEFT(password, 7), IFNULL(last_ip, 'NULL'), IFNULL(last_login, 'NULL'), password FROM tblstaff WHERE staffid = ${state.staffId}`)
  check('4 tblstaff row re-hashed to bcrypt cost 12 on login and last_ip/last_login touched',
    prefix4 === TARGET_PREFIX && lastIp4 !== 'NULL' && lastIp4.length > 0 && lastLogin4 !== 'NULL',
    `prefix ${prefix4 === TARGET_PREFIX ? 'is cost 12' : 'is not cost 12'}, last_ip ${lastIp4 === 'NULL' || lastIp4.length === 0 ? 'empty' : 'set'}, last_login ${lastLogin4 === 'NULL' ? 'NULL' : 'set'}`)

  // 5. PHP crypt() accepts it -------------------------------------------------------------
  check('5 PHP crypt() in the legacy container accepts the re-hashed row with the password (Perfex phpass::CheckPassword path)',
    phpCrypt(hash4, pw) === 0, 'crypt() did not match')
  check('5 PHP crypt() rejects the re-hashed row with a wrong password',
    phpCrypt(hash4, `wrong-${pw}`) === 1, 'crypt() matched a wrong password')

  // 6. me ----------------------------------------------------------------------------------------
  const me = await http('GET', '/api/v1/auth/me', { bearer: accessToken })
  check('6 GET /api/v1/auth/me with the bearer -> 200, staffId matches, permissions is an array',
    me.status === 200 && me.json?.staffId === state.staffId && Array.isArray(me.json?.permissions),
    `${me.status} permissions=${Array.isArray(me.json?.permissions) ? me.json.permissions.length : 'missing'}`)
  const anon = await http('GET', '/api/v1/auth/me')
  check('6 GET /api/v1/auth/me without a bearer -> 401 ERP-AUTH-0004', anon.status === 401 && isProblem(anon, 'ERP-AUTH-0004'), problemDetail(anon))

  // 7. refresh rotation and reuse ------------------------------------------------------------
  const oldRefresh = jar.get('erp_refresh')?.value
  const rotated = await http('POST', '/api/v1/auth/refresh', { headers: { 'x-csrf-token': csrfToken } })
  const newRefresh = setCookieOf(rotated.res, 'erp_refresh')
  check('7 POST refresh with the jar and x-csrf-token -> 200 with a NEW erp_refresh and a new accessToken',
    rotated.status === 200 && newRefresh && newRefresh.value !== oldRefresh && typeof rotated.json?.accessToken === 'string' && rotated.json.accessToken !== accessToken,
    `${rotated.status} ${rotated.json?.code || ''} cookie ${newRefresh ? (newRefresh.value === oldRefresh ? 'unchanged' : 'rotated') : 'missing'}`)
  const rotatedPresent = setCookieOf(rotated.res, 'erp_session_present')
  check('7 refresh re-sets erp_session_present beside the rotated erp_refresh, with a fresh Max-Age (it slides with the refresh token, ADR-0032)',
    rotatedPresent && rotatedPresent.value === '1' && rotatedPresent.attrs.includes('path=/') && rotatedPresent.attrs.includes('samesite=lax')
      && rotatedPresent.attrs.includes('httponly') && maxAgeOf(rotatedPresent) === maxAgeOf(newRefresh),
    rotatedPresent ? `${rotatedPresent.attrs.join('; ')} (erp_refresh max-age=${maxAgeOf(newRefresh)})` : 'cookie missing')
  const replay = await http('POST', '/api/v1/auth/refresh', { headers: { 'x-csrf-token': csrfToken }, cookies: `erp_refresh=${oldRefresh}; erp_csrf=${jar.get('erp_csrf')?.value}` })
  check('7 replay of the OLD erp_refresh -> 401 ERP-AUTH-0003 (reuse detected, family revoked)', replay.status === 401 && isProblem(replay, 'ERP-AUTH-0003'), problemDetail(replay))
  let dead = await http('GET', '/api/v1/auth/me', { bearer: accessToken })
  for (let i = 0; i < 12 && dead.status !== 401; i += 1) { await sleep(500); dead = await http('GET', '/api/v1/auth/me', { bearer: accessToken }) }
  check('7 the FIRST access token on /me after the reuse -> 401 ERP-AUTH-0004 (user version bumped)', dead.status === 401 && isProblem(dead, 'ERP-AUTH-0004'), problemDetail(dead))
  jar.delete('erp_refresh')
  const second = await login(pw)
  if (second.status !== 200) throw new Error(`re-login after the reuse test failed: ${problemDetail(second)}`)
  accessToken = second.json.accessToken
  csrfToken = second.json.csrfToken
  try { state.redisKeys.add(`auth:sess:${state.staffId}:${decodeJwt(accessToken).payload.sid}`) } catch { /* ignore */ }
  const [[prefix7, hash7]] = sql(`SELECT LEFT(password, 7), password FROM tblstaff WHERE staffid = ${state.staffId}`)
  check('7 second login: the row is still the cost-12 hash and was not re-hashed again', prefix7 === TARGET_PREFIX && hash7 === hash4,
    `prefix ${prefix7 === TARGET_PREFIX ? 'cost 12' : 'changed'}, hash ${hash7 === hash4 ? 'identical' : 'changed'}`)

  // 8. no session -> no screen ---------------------------------------------------------------------
  const noSession = await http('GET', '/admin/', { cookies: '' })
  const loc8 = noSession.headers.get('location') || ''
  check('8 GET /admin/ with no cookies -> Perfex redirects to its login (307/302, Location contains authentication) from legacy',
    (noSession.status === 307 || noSession.status === 302) && /authentication/.test(loc8) && noSession.headers.get('x-erp-route') === 'legacy',
    `${noSession.status} location=${loc8} route=${noSession.headers.get('x-erp-route')}`)

  // 9. handoff ------------------------------------------------------------------------------------------
  const noToken = await http('POST', '/erp_sso/handoff')
  check('9 POST /erp_sso/handoff without a bearer -> 401 ERP-SSO-0001', noToken.status === 401 && noToken.text.includes('ERP-SSO-0001'), `${noToken.status} ${noToken.json?.code || `body ${noToken.text.length} B`}`)
  const forged = forgeHs256({ ...(jwt?.payload ?? {}), sub: String(state.staffId), iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 }, kid)
  const forgedHandoff = await http('POST', '/erp_sso/handoff', { bearer: forged })
  check('9 POST /erp_sso/handoff with a forged HS256 token -> 401 (alg confusion rejected)', forgedHandoff.status === 401, `${forgedHandoff.status}`)
  const forgedMe = await http('GET', '/api/v1/auth/me', { bearer: forged })
  check('9 GET /api/v1/auth/me with the forged HS256 token -> 401', forgedMe.status === 401, `${forgedMe.status}`)
  const handoff = await http('POST', '/erp_sso/handoff', { bearer: accessToken })
  const sp = setCookieOf(handoff.res, 'sp_session')
  check('9 POST /erp_sso/handoff with the real bearer -> 204 + Set-Cookie sp_session (last of the CI session cookies)',
    handoff.status === 204 && sp !== null, `${handoff.status} sp_session ${sp ? `set (${sp.count} Set-Cookie)` : 'missing'}`)

  // 10. a Perfex screen without a second login ---------------------------------------------------------
  let admin = await http('GET', '/admin/')
  if ((admin.status === 302 || admin.status === 307) && !/authentication/.test(admin.headers.get('location') || '')) {
    const next = new URL(admin.headers.get('location'), NGINX)
    admin = await http('GET', `${next.pathname}${next.search}`)
  }
  check('10 GET /admin/ with the handed-off session -> 200 Perfex screen with the sidebar logout link and no password field (SC-2)',
    admin.status === 200 && admin.text.includes('admin/authentication/logout') && !admin.text.includes('name="password"') && admin.headers.get('x-erp-route') === 'legacy',
    `${admin.status} logout-link=${admin.text.includes('admin/authentication/logout')} password-field=${admin.text.includes('name="password"')} route=${admin.headers.get('x-erp-route')}`)

  // 11. the Perfex login redirects to the Next.js page ----------------------------------------------------
  const authPage = await http('GET', '/admin/authentication')
  check('11 GET /admin/authentication -> 302 to /login (ADR-0030 decision 1)',
    authPage.status === 302 && (authPage.headers.get('location') || '').endsWith('/login'), `${authPage.status} location=${authPage.headers.get('location')}`)
  const loginPage = await http('GET', '/login', { cookies: '' })
  check('11 GET /login with no cookies -> 200 from web with the login form in the HTML (no api call needed)', loginPage.status === 200 && loginPage.headers.get('x-erp-route') === 'web' && loginPage.text.includes('data-testid="login-form"'),
    `${loginPage.status} route=${loginPage.headers.get('x-erp-route')} form=${loginPage.text.includes('data-testid="login-form"')}`)
  // ADR-0038: the jar holds erp_session_present since step 3, so the page asks the api before any form.
  const resumePage = await http('GET', '/login')
  const resumeSkeleton = resumePage.text.includes('data-testid="login-resume-pending"')
  const resumeForm = resumePage.text.includes('data-testid="login-form"')
  check("11 GET /login with erp_session_present -> 200 from web with the login card's skeleton and no form (ADR-0038: the page asks the api first)",
    resumePage.status === 200 && resumePage.headers.get('x-erp-route') === 'web' && resumeSkeleton && !resumeForm,
    `${resumePage.status} route=${resumePage.headers.get('x-erp-route')} skeleton=${resumeSkeleton} form=${resumeForm}`)
  // W0-05 multibrand: the page shows THIS customer's brand, read from its own settings rows.
  const brand = await http('GET', '/api/v1/branding')
  const logoOk = (u) => u === null || (typeof u === 'string' && u.startsWith('/uploads/company/'))
  check('11 GET /api/v1/branding -> 200 with a non-empty companyName and logoUrl/logoDarkUrl null or under /uploads/company/ (W0-05)',
    brand.status === 200 && typeof brand.json?.companyName === 'string' && brand.json.companyName.length > 0 && logoOk(brand.json?.logoUrl) && logoOk(brand.json?.logoDarkUrl),
    `${brand.status} companyName=${brand.json?.companyName ? 'set' : 'empty'} logoUrl=${brand.json?.logoUrl === null ? 'null' : typeof brand.json?.logoUrl} logoDarkUrl=${brand.json?.logoDarkUrl === null ? 'null' : typeof brand.json?.logoDarkUrl}`)
  const brandMarker = loginPage.text.includes('data-testid="brand-logo"') ? 'brand-logo' : loginPage.text.includes('data-testid="brand-name"') ? 'brand-name' : null
  check('11 /login HTML renders the brand (data-testid brand-logo or brand-name)', brandMarker !== null, 'neither marker in the HTML')
  if (brandMarker) note(`brand rendered as ${brandMarker}`)

  // 19. Perfex's staff logout (ADR-0038), right after 11. Every request is sent without cookies, so no
  //     session of this run is ended; the sign-out itself runs in the browser (LogoutButton `auto`).
  const perfexLogout = await http('GET', '/admin/authentication/logout', { cookies: '' })
  check("19 GET /admin/authentication/logout -> 302 /logout?from=legacy, relative (Perfex's staff logout signs out of both systems, ADR-0038)",
    perfexLogout.status === 302 && perfexLogout.headers.get('location') === '/logout?from=legacy',
    `${perfexLogout.status} location=${perfexLogout.headers.get('location')} route=${perfexLogout.headers.get('x-erp-route')}`)
  const autoLogout = await http('GET', '/logout?from=legacy', { cookies: '' })
  const autoPending = autoLogout.text.includes('data-testid="logout-auto-pending"')
  const autoButton = autoLogout.text.includes('data-testid="logout-button"')
  check('19 GET /logout?from=legacy -> 200 from web with the signing-out state and no Sign out button (it signs out on arrival)',
    autoLogout.status === 200 && autoLogout.headers.get('x-erp-route') === 'web' && autoPending && !autoButton,
    `${autoLogout.status} route=${autoLogout.headers.get('x-erp-route')} signing-out=${autoPending} button=${autoButton}`)
  const legacyLogout = await http('GET', '/admin/authentication/logout?legacy=1', { cookies: '' })
  check('19 GET /admin/authentication/logout?legacy=1 -> Perfex (X-Erp-Route legacy, its redirect to its login)',
    [302, 303, 307].includes(legacyLogout.status) && legacyLogout.headers.get('x-erp-route') === 'legacy',
    `${legacyLogout.status} location=${legacyLogout.headers.get('location')} route=${legacyLogout.headers.get('x-erp-route')}`)

  // 12. ADR-0030 exceptions ---------------------------------------------------------------------------------
  const ts = await http('POST', '/timesheets/api/login')
  check('12 POST /timesheets/api/login -> 410 ERP-LEGACY-0410 (timesheets issuer switched off, ADR-0030)', ts.status === 410 && ts.json?.code === 'ERP-LEGACY-0410', `${ts.status} ${ts.json?.code || `body ${ts.text.length} B`}`)
  const att = await http('POST', '/api/auth/login', { cookies: '' })
  check('12 POST /api/auth/login routes to legacy (attendance issuer untouched, ADR-0030): X-Erp-Route legacy, not 410/502',
    att.headers.get('x-erp-route') === 'legacy' && ![410, 502].includes(att.status), `${att.status} route=${att.headers.get('x-erp-route')}`)

  // 13. logout ------------------------------------------------------------------------------------------------
  try { state.redisKeys.add(`auth:revoked:${decodeJwt(accessToken).payload.jti}`) } catch { /* ignore */ }
  const logout = await http('POST', '/api/v1/auth/logout', { bearer: accessToken, headers: { 'x-csrf-token': csrfToken } })
  const cleared = setCookieOf(logout.res, 'erp_refresh')
  check('13 POST logout with bearer + x-csrf-token -> 204 and erp_refresh cleared',
    logout.status === 204 && cleared !== null && cleared.value === '' && (cleared.attrs.includes('max-age=0') || cleared.attrs.some((a) => a.startsWith('expires=') && new Date(a.slice(8)).getTime() < Date.now())),
    `${logout.status} ${cleared ? cleared.attrs.join('; ') : 'no Set-Cookie erp_refresh'}`)
  const clearedPresent = setCookieOf(logout.res, 'erp_session_present')
  const isCleared = (c) => c !== null && c.value === '' && (c.attrs.includes('max-age=0') || c.attrs.some((a) => a.startsWith('expires=') && new Date(a.slice(8)).getTime() < Date.now()))
  check('13 the same logout response clears erp_session_present on Path=/ (one helper clears both, ADR-0032)',
    isCleared(clearedPresent) && clearedPresent.attrs.includes('path=/'),
    clearedPresent ? clearedPresent.attrs.join('; ') : 'no Set-Cookie erp_session_present')
  const afterLogout = await http('GET', '/api/v1/auth/me', { bearer: accessToken })
  check('13 GET /me with the logged-out token -> 401', afterLogout.status === 401, `${afterLogout.status}`)

  // 16. logout-all (ADR-0032's follow-up). It runs HERE, right after 13, because step 15 locks the
  //     account and the step needs one more login; it carries the next free number and renumbers
  //     nothing. A fresh session, then logout-all: 204 and all three cookies cleared.
  const relogin = await login(pw)
  if (relogin.status !== 200) throw new Error(`re-login before the logout-all step failed: ${problemDetail(relogin)}`)
  const allToken = relogin.json.accessToken
  const allCsrf = relogin.json.csrfToken
  try { state.redisKeys.add(`auth:sess:${state.staffId}:${decodeJwt(allToken).payload.sid}`) } catch { /* ignore */ }
  try { state.redisKeys.add(`auth:revoked:${decodeJwt(allToken).payload.jti}`) } catch { /* ignore */ }
  check('16 the new login set erp_session_present again (Path=/, SameSite=Lax)',
    setCookieOf(relogin.res, 'erp_session_present')?.attrs.includes('path=/') === true,
    'cookie missing on the re-login')
  const logoutAll = await http('POST', '/api/v1/auth/logout-all', { bearer: allToken, headers: { 'x-csrf-token': allCsrf } })
  const allRefresh = setCookieOf(logoutAll.res, 'erp_refresh')
  const allPresent = setCookieOf(logoutAll.res, 'erp_session_present')
  check('16 POST logout-all with bearer + x-csrf-token -> 204 with erp_refresh AND erp_session_present cleared (ADR-0032)',
    logoutAll.status === 204 && isCleared(allRefresh) && isCleared(allPresent) && allPresent.attrs.includes('path=/'),
    `${logoutAll.status} erp_refresh[${allRefresh ? allRefresh.attrs.join('; ') : 'missing'}] erp_session_present[${allPresent ? allPresent.attrs.join('; ') : 'missing'}]`)
  const afterLogoutAll = await http('GET', '/api/v1/auth/me', { bearer: allToken })
  check('16 GET /me with the logged-out-all token -> 401', afterLogoutAll.status === 401, `${afterLogoutAll.status}`)

  // 14. breaker (ADR-0031) -------------------------------------------------------------------------------------
  if (NO_BREAKER) {
    skip('breaker (--no-breaker)')
  } else {
    const t0 = Date.now()
    const third = await login(pw)
    if (third.status !== 200) throw new Error(`re-login before the breaker step failed: ${problemDetail(third)}`)
    const bearer = third.json.accessToken
    try { state.redisKeys.add(`auth:sess:${state.staffId}:${decodeJwt(bearer).payload.sid}`) } catch { /* ignore */ }
    const ready = await http('GET', '/api/v1/auth/legacy-sso', { bearer })
    const hClosed = await http('GET', '/api/v1/health')
    check('14a GET legacy-sso -> 200 { status: ready } and health checks.breakers.legacy = closed',
      ready.status === 200 && ready.json?.status === 'ready' && ready.headers.get('x-erp-route') === 'api' && hClosed.json?.checks?.breakers?.legacy === 'closed',
      `${ready.status} ${JSON.stringify(ready.json)} breaker=${hClosed.json?.checks?.breakers?.legacy}`)

    const stop = compose(['stop', 'legacy'], { stdio: 'inherit' })
    state.stoppedLegacy = true
    check('14b docker compose stop legacy', stop.status === 0, `exit ${stop.status}`)

    // The probe cache (5 s) and the volume threshold (2 locally) mean the first calls after the stop
    // may still answer from cache or as a plain upstream failure; poll until the breaker is open.
    let open = null
    let calls = 0
    const deadline = Date.now() + 40_000
    while (Date.now() < deadline) {
      calls += 1
      open = await http('GET', '/api/v1/auth/legacy-sso', { bearer })
      if (open.status === 503 && open.json?.code === 'ERP-UPSTREAM-0001') break
      await sleep(500)
    }
    const retryAfter = open?.headers.get('retry-after') || ''
    check('14c GET legacy-sso with legacy stopped -> 503 ERP-UPSTREAM-0001 (problem+json) with an integer Retry-After',
      open?.status === 503 && isProblem(open, 'ERP-UPSTREAM-0001') && /^[1-9]\d*$/.test(retryAfter),
      `${open ? problemDetail(open) : 'no response'} retry-after=${retryAfter} after ${calls} call(s)`)
    const retryAfterS = parseInt(retryAfter, 10) || 10
    const openAgain = await http('GET', '/api/v1/auth/legacy-sso', { bearer })
    check('14c second GET legacy-sso -> 503 again in < 1000 ms (breaker open: no connection attempt, no backoff — load shedding)',
      openAgain.status === 503 && openAgain.json?.code === 'ERP-UPSTREAM-0001' && openAgain.ms < 1000, `${openAgain.status} ${openAgain.json?.code} in ${openAgain.ms} ms`)
    const hOpen = await http('GET', '/api/v1/health')
    check('14c GET /api/v1/health -> 200 status ok with checks.breakers.legacy = open (an open breaker never degrades the api)',
      hOpen.status === 200 && hOpen.json?.status === 'ok' && hOpen.json?.checks?.breakers?.legacy === 'open', `${hOpen.status} ${hOpen.text}`)

    const start = compose(['start', 'legacy'], { stdio: 'inherit' })
    const apache = await waitFor(`${LEGACY_DIRECT}/admin/authentication`, 200, 90_000)
    const nginxRestart = compose(['restart', 'nginx'], { stdio: 'inherit' })
    const healthBack = await waitFor(`${NGINX}/api/v1/health`, 200, 60_000)
    state.stoppedLegacy = !(start.status === 0 && apache)
    check('14d docker compose start legacy (Apache answers on :8080), restart nginx, health 200 through :8088 again',
      start.status === 0 && apache && nginxRestart.status === 0 && healthBack, `start ${start.status} apache ${apache} nginx ${nginxRestart.status} health ${healthBack}`)

    await sleep((retryAfterS + 1) * 1000)
    let recovered = await http('GET', '/api/v1/auth/legacy-sso', { bearer })
    for (let i = 0; i < 10 && recovered.status !== 200; i += 1) { await sleep(1000); recovered = await http('GET', '/api/v1/auth/legacy-sso', { bearer }) }
    const hRecovered = await http('GET', '/api/v1/health')
    check('14e after the half-open window GET legacy-sso -> 200 { status: ready } and health checks.breakers.legacy = closed',
      recovered.status === 200 && recovered.json?.status === 'ready' && hRecovered.json?.checks?.breakers?.legacy === 'closed',
      `${recovered.status} ${JSON.stringify(recovered.json)} breaker=${hRecovered.json?.checks?.breakers?.legacy}`)
    const stepMs = Date.now() - t0
    check(`breaker: open after legacy stop (retry-after ${retryAfterS}s), recovered after half-open; step took ${Math.round(stepMs / 1000)} s`, stepMs < BREAKER_STEP_BUDGET_MS, `${stepMs} ms > ${BREAKER_STEP_BUDGET_MS} ms`)
  }

  // 17. W1-06: the staff and roles cutover (plan 03.1-09). It runs HERE, before step 15, for the same
  //     reason step 16 does: step 15 locks the account and this step needs one more login. It carries
  //     the next free number and renumbers nothing.
  //
  //     Two of the ten paths are proven WITHOUT a Perfex session on purpose. `remove_staff_profile_image`
  //     and `delete` really act when a signed-in Perfex reaches them — the first nulls `tblstaff
  //     .profile_image` and deletes the member's upload directory, neither of which this script restores.
  //     Perfex's own 307 to its login IS the proof the path reached Perfex, which is the only claim the
  //     step makes about them; the lead exercises the modal itself at the checkpoint.
  const cutover = await login(pw)
  if (cutover.status !== 200) throw new Error(`re-login before the cutover step failed: ${problemDetail(cutover)}`)
  const cutToken = cutover.json.accessToken
  try { state.redisKeys.add(`auth:sess:${state.staffId}:${decodeJwt(cutToken).payload.sid}`) } catch { /* ignore */ }
  const cutHandoff = await http('POST', '/erp_sso/handoff', { bearer: cutToken })
  note(`cutover step: Perfex session for the ?legacy=1 reads ${cutHandoff.status === 204 ? 'obtained' : `NOT obtained (handoff ${cutHandoff.status})`}`)

  const routeOf = (r) => r.headers.get('x-erp-route')
  const locOf = (r) => r.headers.get('location') || ''
  const REFUSAL = 'ERP-LEGACY-0403'
  /** A closed write path: an unambiguous 403 carrying the refusal code, never a 200 and never a redirect. */
  const isClosed = (r) => r.status === 403 && routeOf(r) === 'web' && r.json?.code === REFUSAL
  /** A path that still belongs to Perfex: legacy answered it, and Nginx did not close or redirect it. */
  // The Node screens moved to /setup/staff and /setup/roles in plan 04.2-29.
  const stillLegacy = (r) => routeOf(r) === 'legacy' && !r.text.includes(REFUSAL) && !(r.status === 302 && locOf(r).startsWith('/setup/staff'))

  // Plan 04.2-29: the pages are /setup/staff and /setup/roles; the old /staff and /roles answer 301 (step 32).
  const staffPage = await http('GET', '/setup/staff')
  check('17a GET /setup/staff signed in (erp_session_present in the jar) -> 200 from web through Nginx',
    staffPage.status === 200 && routeOf(staffPage) === 'web', `${staffPage.status} route=${routeOf(staffPage)}`)
  const rolesPage = await http('GET', '/setup/roles')
  check('17b GET /setup/roles signed in -> 200 from web through Nginx',
    rolesPage.status === 200 && routeOf(rolesPage) === 'web', `${rolesPage.status} route=${routeOf(rolesPage)}`)
  const anonStaff = await http('GET', '/setup/staff', { cookies: '' })
  check('17c GET /setup/staff with NO session cookie -> 302 to /login?next=%2Fsetup%2Fstaff from proxy.ts, with a RELATIVE Location (D-22)',
    anonStaff.status === 302 && locOf(anonStaff) === '/login?next=%2Fsetup%2Fstaff' && routeOf(anonStaff) === 'web',
    `${anonStaff.status} location=${locOf(anonStaff)} route=${routeOf(anonStaff)}`)

  // The list paths: every bookmark form of each, each a RELATIVE Location so :8088 survives (P8). Targets under /setup since plan 04.2-29.
  const listRedirects = [
    ['/admin/staff', '/setup/staff'], ['/admin/staff/', '/setup/staff'], ['/admin/staff/index', '/setup/staff'], ['/admin/staff/index/', '/setup/staff'],
    ['/admin/roles', '/setup/roles'], ['/admin/roles/', '/setup/roles'], ['/admin/roles/index', '/setup/roles'], ['/admin/roles/index/', '/setup/roles'],
  ]
  const listResults = []
  for (const [from, to] of listRedirects) {
    const r = await http('GET', from, { cookies: '' })
    listResults.push({ from, to, status: r.status, location: locOf(r), route: routeOf(r) })
  }
  check(`17d a plain GET of every bookmark form of the Perfex staff and roles lists -> 302 with a relative Location to the Node screen (${listRedirects.length} paths)`,
    listResults.every((r) => r.status === 302 && r.location === r.to && r.route === 'web'),
    listResults.map((r) => `${r.from} -> ${r.status} ${r.location || 'no Location'} (${r.route})`).join(' | '))

  // The record paths: the regex capture, which the /admin/authentication precedent does not exercise.
  // Targets under /setup since plan 04.2-29.
  const recordRedirects = [
    [`/admin/staff/member/${state.staffId}`, `/setup/staff/${state.staffId}`],
    [`/admin/staff/member/${state.staffId}/`, `/setup/staff/${state.staffId}`],
    ['/admin/staff/member', '/setup/staff/new'],
    ['/admin/roles/role/3', '/setup/roles/3'],
    ['/admin/roles/role', '/setup/roles/new'],
  ]
  const recordResults = []
  for (const [from, to] of recordRedirects) {
    const r = await http('GET', from, { cookies: '' })
    recordResults.push({ from, to, status: r.status, location: locOf(r), route: routeOf(r) })
  }
  const memberById = recordResults[0]
  check('17e GET /admin/staff/member/<id> -> 302 to /setup/staff/<id>: the digits-only regex capture, relative Location',
    memberById.status === 302 && memberById.location === `/setup/staff/${state.staffId}` && memberById.route === 'web',
    `${memberById.status} location=${memberById.location} route=${memberById.route}`)
  check('17f every other record form redirects too: /admin/staff/member/<id>/, /admin/staff/member -> /setup/staff/new, /admin/roles/role/<id> -> /setup/roles/<id>, /admin/roles/role -> /setup/roles/new',
    recordResults.slice(1).every((r) => r.status === 302 && r.location === r.to && r.route === 'web'),
    recordResults.slice(1).map((r) => `${r.from} -> ${r.status} ${r.location || 'no Location'} (${r.route})`).join(' | '))

  // ?legacy=1 (ADR-0030's escape hatch) still reaches Perfex on every one of them.
  const legacyEscape = []
  for (const [from] of [...listRedirects, ...recordRedirects]) {
    const r = await http('GET', `${from}?legacy=1`, { cookies: '' })
    legacyEscape.push({ from, status: r.status, route: routeOf(r), location: locOf(r) })
  }
  check(`17g every staff and roles path with ?legacy=1 stays on Perfex: X-Erp-Route legacy and no redirect to the Node screen (${legacyEscape.length} paths, no session — Perfex's own 307 to its login is the proof it arrived)`,
    legacyEscape.every((r) => r.route === 'legacy' && !r.location.startsWith('/setup/staff') && !r.location.startsWith('/setup/roles')), // plan 04.2-29
    legacyEscape.map((r) => `${r.from} -> ${r.status} (${r.route})`).join(' | '))
  const legacyList = await http('GET', '/admin/staff?legacy=1')
  check('17g GET /admin/staff?legacy=1 WITH the handed-off Perfex session -> legacy answers it, not Nginx (the page the lead opens at the checkpoint)',
    stillLegacy(legacyList), `${legacyList.status} route=${routeOf(legacyList)} location=${locOf(legacyList) || '-'}`)

  // The closed write paths. The core four first (brief §3.1).
  const coreWrites = [
    ['POST', `/admin/staff/member/${state.staffId}`],
    ['POST', '/admin/staff/member'],
    ['POST', `/admin/staff/member/${state.staffId}?legacy=1`],
    ['POST', '/admin/roles/role/3'],
    ['POST', '/admin/roles/role'],
    ['GET', `/admin/staff/change_staff_status/${state.staffId}/0`],
    ['GET', '/admin/roles/delete/3'],
  ]
  const coreResults = []
  for (const [method, path] of coreWrites) {
    const r = await http(method, path)
    coreResults.push({ method, path, status: r.status, route: routeOf(r), code: r.json?.code ?? null, closed: isClosed(r) })
  }
  check(`17h Perfex's core write paths for the tables Node owns are CLOSED: 403 ${REFUSAL} with X-Erp-Route web, never a 200 and never a redirect (${coreWrites.length} paths, including one with ?legacy=1 — the escape hatch is a read, not a write)`,
    coreResults.every((r) => r.closed),
    coreResults.map((r) => `${r.method} ${r.path} -> ${r.status}${r.code ? `/${r.code}` : ''} (${r.route})`).join(' | '))

  // The seven modules' permission-write endpoints, in all four CI3 URL forms.
  const MODULE_WRITES = [
    ['fixed_equipment', 'update_permissions'], ['fixed_equipment', 'delete_permission'],
    ['hr_payroll', 'hr_payroll_update_permissions'], ['hr_payroll', 'delete_hr_payroll_permission'],
    ['hr_profile', 'update_staff_permission'], ['hr_profile', 'hr_profile_update_permissions'], ['hr_profile', 'delete_hr_profile_permission'],
    ['purchase', 'purchase_update_permissions'], ['purchase', 'delete_purchase_permission'],
    ['quality', 'quality_update_permissions'], ['quality', 'delete_quality_permission'],
    ['timesheets', 'update_permissions'], ['timesheets', 'delete_permission'],
    ['warehouse', 'warehouse_update_permissions'], ['warehouse', 'delete_warehouse_permission'],
  ]
  const moduleFailures = []
  let moduleChecked = 0
  for (const [mod, method] of MODULE_WRITES) {
    for (const path of [`/admin/${mod}/${mod}/${method}/${state.staffId}`, `/admin/${mod}/${method}/${state.staffId}`, `/${mod}/${mod}/${method}/${state.staffId}`, `/${mod}/${method}/${state.staffId}`]) {
      const r = await http('POST', path)
      moduleChecked += 1
      if (!isClosed(r)) moduleFailures.push(`${path} -> ${r.status}${r.json?.code ? `/${r.json.code}` : ''} (${routeOf(r)})`)
    }
  }
  check(`17i every module permission-WRITE endpoint is closed: ${MODULE_WRITES.length} methods over the seven modules, each in all four CI3 URL forms (${moduleChecked} requests) -> 403 ${REFUSAL}, X-Erp-Route web. Four of them a non-administrator can reach in Perfex, and timesheets::update_permissions has no gate at all`,
    moduleFailures.length === 0, `${moduleFailures.length} not closed: ${moduleFailures.slice(0, 6).join(' | ')}`)

  // ...and the READS beside them are untouched, so the modals still open.
  const MODULE_READS = [
    '/admin/fixed_equipment/permission_modal', '/admin/fixed_equipment/permission_table',
    '/admin/hr_payroll/permission_modal', '/admin/hr_payroll/hr_payroll_permission_table',
    '/admin/hr_profile/permission_modal', '/admin/hr_profile/hr_profile_permission_table', '/admin/hr_profile/hr_role_changed/3',
    '/admin/purchase/permission_modal', '/admin/purchase/permission_table',
    '/admin/quality/permission_modal', '/admin/quality/quality_permission_table', '/admin/quality/role_changed/3',
    '/admin/timesheets/permission_modal', '/admin/timesheets/timesheet_permission_table',
    '/admin/warehouse/permission_modal', '/admin/warehouse/warehouse_permission_table',
  ]
  const readFailures = []
  for (const path of MODULE_READS) {
    const r = await http('POST', path)
    if (!stillLegacy(r)) readFailures.push(`${path} -> ${r.status} (${routeOf(r)})`)
  }
  check(`17j the modals themselves still OPEN: the ${MODULE_READS.length} permission_modal / *_permission_table / role_changed READS beside those writes are untouched and still answered by Perfex`,
    readFailures.length === 0, `${readFailures.length} closed by mistake: ${readFailures.join(' | ')}`)

  const roleChanged = await http('GET', `/admin/staff/role_changed/3`)
  check('17k GET /admin/staff/role_changed/<id> still reaches Perfex (read-only, called by the seven modules\' permission modals — brief §9)',
    stillLegacy(roleChanged), `${roleChanged.status} route=${routeOf(roleChanged)}`)
  const stillPerfex = []
  for (const [method, path] of [['GET', `/admin/staff/remove_staff_profile_image/${state.staffId}`], ['POST', '/admin/staff/delete'], ['GET', '/admin/staff/profile'], ['GET', '/admin/staff/edit_profile'], ['GET', '/admin/hr_profile/member/3/training']]) {
    const r = await http(method, path, { cookies: '' })
    stillPerfex.push({ method, path, status: r.status, route: routeOf(r), ok: stillLegacy(r) })
  }
  check(`17l the paths this plan must NOT have touched still reach Perfex: remove_staff_profile_image, staff/delete, the member's own profile pages and hr_profile's member/3/training tab (${stillPerfex.length} paths, no session so nothing is executed: the 307 to Perfex's own login is the proof)`,
    stillPerfex.every((r) => r.ok), stillPerfex.map((r) => `${r.method} ${r.path} -> ${r.status} (${r.route})`).join(' | '))

  // 17m to 17t (quick 260929-hdy): the refusals above hold under every URL CodeIgniter 3 routes to the
  //     same method. PHP method names are case-insensitive (and on the local case-insensitive disk so are
  //     the directory and controller segments), CI3 routes /index.php/<p>, /index.php?/<p>, /?/<p> and
  //     /index.php/?/<p> to <p>, and it DROPS raw `..` segments, so the case-sensitive `^~` refusals were
  //     reachable from Perfex (found 2026-09-29). Every request here is sent WITHOUT a session
  //     (`cookies: ''` or rawHttp) and every id is 999999, a row that does not exist: a regression then
  //     answers Perfex's own 307 to its login and can never write, and remove_staff_profile_image and
  //     staff/delete never act (the reason 17l is sessionless). The exceptions are read-only: the three
  //     dashboard GETs of 17s use the jar, and 17r's redirects and ?legacy=1 reads use the row's staffId
  //     and role 3, which 17d to 17g already send.
  const NO_ID = 999999
  const CORE_CLOSED = [
    ['GET', `/admin/staff/change_staff_status/${NO_ID}/0`],
    ['GET', `/admin/roles/delete/${NO_ID}`],
    ['POST', `/admin/staff/member/${NO_ID}`],
    ['POST', '/admin/staff/member'],
    ['POST', `/admin/roles/role/${NO_ID}`],
    ['POST', '/admin/roles/role'],
  ]
  // Letter-case forms: the method segment upper-cased, every segment ucfirst (as CI3 loads the class), the whole path upper-cased.
  const methodUpper = (p) => p.split('/').map((s, i) => (i === 3 ? s.toUpperCase() : s)).join('/')
  const mixedCase = (p) => p.split('/').map((s) => (/[a-z]/i.test(s) ? `${s[0].toUpperCase()}${s.slice(1).toLowerCase()}` : s)).join('/')
  const allUpper = (p) => p.toUpperCase()
  // CI3 alias forms (system/core/URI.php:213-231): the index.php path form, the query form and its variants.
  const ALIAS_FORMS = [
    (p) => `/index.php${p}`, (p) => `/Index.php${p}`, (p) => `/index.php?${p}`,
    (p) => `/?${p}`, (p) => `/index.php/?${p}`, (p) => `/index.php?${p.toUpperCase()}`,
  ]
  const probeLine = (method, path, r) => `${method} ${path} -> ${r.status} (${routeOf(r)})${locOf(r) ? ` ${locOf(r)}` : ''}`
  /** Sends each [method, path, ok?] with `send` and returns the failing ones as `METHOD path -> status (route)`. */
  const failuresOf = async (requests, ok, send = (method, path) => http(method, path, { cookies: '' })) => {
    const failures = []
    for (const [method, path, own] of requests) {
      const r = await send(method, path)
      if (!(own ?? ok)(r)) failures.push(probeLine(method, path, r))
    }
    return failures
  }
  const failDetail = (failures, what) => `${failures.length} ${what}: ${failures.slice(0, 6).join(' | ')}`

  const coreBypass = CORE_CLOSED.flatMap(([method, p]) => [methodUpper, mixedCase, allUpper, ...ALIAS_FORMS].map((form) => [method, form(p)]))
  const coreBypassFailures = await failuresOf(coreBypass, isClosed)
  check(`17m every closed core path answers the same 403 ${REFUSAL} with X-Erp-Route web in any letter case (method upper-cased, every segment ucfirst, the whole path upper-cased) and behind every CI3 alias (/index.php/, /Index.php/, /index.php?/, /?/, /index.php/?/, the query form upper-cased) (${coreBypass.length} requests, no session)`,
    coreBypassFailures.length === 0, failDetail(coreBypassFailures, 'not closed'))

  const moduleBypass = MODULE_WRITES.flatMap(([mod, method]) => {
    const p = `/admin/${mod}/${method}/${NO_ID}`
    return [methodUpper(p), `/index.php${p}`, `/index.php?${p}`, `/?${p}`].map((u) => ['POST', u])
  })
  const moduleBypassFailures = await failuresOf(moduleBypass, isClosed)
  check(`17n every module permission-WRITE method answers the same 403 ${REFUSAL} upper-cased and behind /index.php/, /index.php?/ and /?/ (${MODULE_WRITES.length} methods, ${moduleBypass.length} POSTs, no session)`,
    moduleBypassFailures.length === 0, failDetail(moduleBypassFailures, 'not closed'))

  // Raw `..` needs rawHttp (fetch would resolve it away); the query forms keep their dots through fetch.
  const isMalformed = (r) => r.status === 400 && routeOf(r) === 'web'
  const rawDots = [
    ['GET', `/admin/roles/../delete/${NO_ID}`],
    ['GET', `/admin/staff/../change_staff_status/${NO_ID}/0`],
    ['POST', `/admin/staff/../member/${NO_ID}`],
    ['GET', `/admin/roles/delete/${NO_ID}/..`],
  ]
  const malformedQueries = [
    ['GET', `/index.php?/admin/roles/../delete/${NO_ID}`],
    ['GET', `/index.php?//admin/roles/delete/${NO_ID}`],
    ['GET', `/index.php?/admin//roles/delete/${NO_ID}`],
    ['GET', `/?/admin/./roles/delete/${NO_ID}`],
  ]
  const malformedFailures = [
    ...await failuresOf(rawDots, isMalformed, rawHttp),
    ...await failuresOf(malformedQueries, isMalformed),
  ]
  check(`17o a raw \`..\` segment in the path, and an empty, \`.\` or \`..\` segment in the query form, answer 400 with X-Erp-Route web and never reach Perfex (CI3 drops those segments, so /admin/roles/../delete/<id> is Roles::delete there) (${rawDots.length + malformedQueries.length} requests, no session)`,
    malformedFailures.length === 0, failDetail(malformedFailures, 'not 400 web'))

  const nested = [
    `/index.php/index.php/admin/roles/delete/${NO_ID}`,
    `/index.php?/index.php/admin/roles/delete/${NO_ID}`,
    `/?/index.php/admin/roles/delete/${NO_ID}`,
    `/index.php?/?/admin/roles/delete/${NO_ID}`,
    `/?/?/admin/roles/delete/${NO_ID}`,
    `/index.php?/index.php?/admin/roles/delete/${NO_ID}`,
    `/index.php?/admin/roles/%64elete/${NO_ID}`,
  ].map((path) => ['GET', path])
  const nestedFailures = await failuresOf(nested, (r) => routeOf(r) === 'legacy' && !r.text.includes(REFUSAL) && !locOf(r).includes('/admin/authentication'))
  check(`17p a nested alias or a percent-encoded method is left to Perfex, which answers it as before: X-Erp-Route legacy, never the refusal, and never an admin method's 307 to /admin/authentication (${nested.length} requests, no session)`,
    nestedFailures.length === 0, failDetail(nestedFailures, 'changed'))

  const siblings = [
    ['POST', '/index.php/admin/staff/delete'],
    ['POST', '/index.php?/admin/staff/delete'],
    ['POST', '/admin/staff/DELETE'],
    ['GET', '/index.php/admin/staff/role_changed/3'],
    ['GET', '/index.php?/admin/staff/role_changed/3'],
    ['GET', '/admin/staff/ROLE_CHANGED/3'],
    ['GET', `/index.php/admin/staff/remove_staff_profile_image/${NO_ID}`],
    ['GET', `/index.php?/admin/staff/remove_staff_profile_image/${NO_ID}`],
    ['GET', '/index.php/admin/staff/profile'],
    ['GET', '/index.php/admin/staff/edit_profile'],
    ['GET', '/index.php/admin/hr_profile/member/3/training'],
    ...MODULE_READS.map((p) => ['POST', `/index.php${p}`]),
  ]
  const siblingFailures = await failuresOf(siblings, stillLegacy)
  check(`17q the paths W1-06 left on Perfex stay there through /index.php and in upper case: staff/delete, role_changed, remove_staff_profile_image, the own-profile pages, hr_profile's member/3/training tab and the ${MODULE_READS.length} module permission READS (${siblings.length} requests, no session)`,
    siblingFailures.length === 0, failDetail(siblingFailures, 'moved'))

  const redirectsTo = (to) => (r) => r.status === 302 && locOf(r) === to && routeOf(r) === 'web'
  // Targets under /setup since plan 04.2-29.
  const readsPerfex = (r) => routeOf(r) === 'legacy' && !locOf(r).startsWith('/setup/staff') && !locOf(r).startsWith('/setup/roles')
  const aliasRedirects = [
    ['GET', '/index.php/admin/staff', redirectsTo('/setup/staff')],
    ['GET', '/index.php?/admin/roles', redirectsTo('/setup/roles')],
    ['GET', `/admin/staff/MEMBER/${state.staffId}`, redirectsTo(`/setup/staff/${state.staffId}`)],
    ['GET', '/index.php?/admin/roles/role/3', redirectsTo('/setup/roles/3')],
    ['GET', '/index.php/admin/staff?legacy=1', readsPerfex],
    ['GET', `/index.php?/admin/staff/member/${state.staffId}?legacy=1`, readsPerfex],
    ['GET', `/admin/staff/MEMBER/${state.staffId}?legacy=1`, readsPerfex],
    ['GET', '/index.php/admin/roles/role/3?legacy=1', readsPerfex],
    ['POST', '/index.php/admin/staff', stillLegacy],
  ]
  const aliasRedirectFailures = await failuresOf(aliasRedirects, null)
  check(`17r through an alias or in upper case a plain GET still redirects to the Node screen with the same relative Location, ?legacy=1 still reads Perfex, and Perfex's DataTable POST to the list still reaches it (${aliasRedirects.length} requests, no session)`,
    aliasRedirectFailures.length === 0, failDetail(aliasRedirectFailures, 'differ'))

  const dashboard = await http('GET', '/admin/')
  const dashboardForms = []
  for (const path of ['/index.php/admin/', '/index.php?/admin/']) {
    const r = await http('GET', path)
    if (!(r.status === dashboard.status && routeOf(r) === 'legacy')) dashboardForms.push(probeLine('GET', path, r))
  }
  const front = await http('GET', '/', { cookies: '' })
  const frontForms = ['/index.php', '/index.php?foo=bar', '/index.php/', '/index.php?/']
  for (const path of frontForms) {
    const r = await http('GET', path, { cookies: '' })
    if (!(r.status === front.status && locOf(r) === locOf(front) && routeOf(r) === 'legacy')) dashboardForms.push(probeLine('GET', path, r))
  }
  check(`17s Perfex's own pages keep working through index.php: /index.php/admin/ and /index.php?/admin/ with the Perfex session answer as /admin/ does (${dashboard.status}), and ${frontForms.join(', ')} answer as / does (${front.status}), all from legacy`,
    routeOf(dashboard) === 'legacy' && routeOf(front) === 'legacy' && dashboardForms.length === 0,
    `/admin/ -> ${dashboard.status} (${routeOf(dashboard)}), / -> ${front.status} (${routeOf(front)}); ${failDetail(dashboardForms, 'differ')}`)

  const aliasLocations = [
    ['GET', '/index.php/admin/authentication', (r) => r.status === 302 && locOf(r) === '/login'],
    ['GET', '/index.php/admin/authentication?legacy=1', (r) => r.status === 200 && routeOf(r) === 'legacy'],
    ['POST', '/index.php/erp_sso/handoff', (r) => r.status === 401 && routeOf(r) === 'legacy'],
    ['GET', '/index.php/api/v1/health', (r) => r.status === 200 && routeOf(r) === 'api'],
    ['GET', '/index.php/timesheets/api/x', (r) => r.status === 410 && r.json?.code === 'ERP-LEGACY-0410'],
  ]
  const aliasLocationFailures = await failuresOf(aliasLocations, null)
  check(`17t every other location applies to its index.php alias: = /admin/authentication (302 /login, ?legacy=1 legacy), ^~ /erp_sso/ (401 legacy), ^~ /api/v1/ (200 api) and the ADR-0030 410 on /timesheets/api/ (${aliasLocations.length} requests, no session)`,
    aliasLocationFailures.length === 0, failDetail(aliasLocationFailures, 'differ'))

  // 18. Phase 3.2 (plan 03.2-19): branding formats and the members CSV export. It runs HERE, before
  //     step 15, for the reason 16 and 17 do (it needs one more login); it renumbers nothing. Shapes
  //     and headers only: the CSV body is never printed or kept, just its first three bytes (T-3.2-85).
  //     The export's gate is `staff.members.view`. When the target row holds neither it nor the
  //     administrator flag, the step grants `tblstaff_permissions (staff, view)` for the run and the
  //     restore deletes exactly that row; the login after the grant rebuilds the permission snapshot.
  const FORMAT_KEYS = ['dateFormat', 'timeFormat', 'thousandSeparator', 'decimalSeparator', 'decimalPlaces', 'removeDecimalsOnZero', 'timeZone', 'currency']
  const branding = await http('GET', '/api/v1/branding')
  const formats = branding.json?.formats
  const missingFormats = formats !== null && typeof formats === 'object' ? FORMAT_KEYS.filter((k) => !(k in formats)) : FORMAT_KEYS
  check('18a GET /api/v1/branding -> 200 with formats carrying the eight Perfex format keys, decimalPlaces 2 (D-33, D-44)',
    branding.status === 200 && missingFormats.length === 0 && formats.decimalPlaces === 2,
    `${branding.status} missing [${missingFormats.join(', ')}] decimalPlaces ${formats?.decimalPlaces === 2 ? '2' : 'not 2'}`)

  const [[heldText]] = sql(`SELECT COUNT(*) FROM tblstaff_permissions WHERE staff_id = ${state.staffId} AND feature = 'staff' AND capability = 'view'`)
  const [[adminText]] = sql(`SELECT admin FROM tblstaff WHERE staffid = ${state.staffId}`)
  if (heldText === '0' && adminText !== '1') {
    sql(`INSERT INTO tblstaff_permissions (staff_id, feature, capability) VALUES (${state.staffId}, 'staff', 'view')`)
    state.grantedStaffView = true
    note('export step: staff/view granted to the target row for this run (the restore deletes it)')
  }
  const exporter = await login(pw)
  if (exporter.status !== 200) throw new Error(`re-login before the export step failed: ${problemDetail(exporter)}`)
  const exportToken = exporter.json.accessToken
  try { state.redisKeys.add(`auth:sess:${state.staffId}:${decodeJwt(exportToken).payload.sid}`) } catch { /* ignore */ }
  // One translated label per column, as the web sends them (D-42); neutral words, never customer data.
  const EXPORT = `/api/v1/identity/members/export?${['Id', 'First name', 'Last name', 'Email', 'Role', 'Active', 'Last login'].map((h) => `header=${encodeURIComponent(h)}`).join('&')}`
  const csv = await rawGet(EXPORT, { authorization: `Bearer ${exportToken}` })
  const disposition = String(csv.headers['content-disposition'] ?? '')
  const firstBytes = csv.body.subarray(0, 3).toString('hex')
  check('18b GET /api/v1/identity/members/export with the bearer -> 200 text/csv, content-disposition attachment staff-members-<date>.csv, a UTF-8 BOM, cache-control no-store (D-26)',
    csv.status === 200 && String(csv.headers['content-type'] ?? '').startsWith('text/csv') &&
      /^attachment; filename="staff-members-\d{4}-\d{2}-\d{2}\.csv"$/.test(disposition) &&
      firstBytes === 'efbbbf' && csv.headers['cache-control'] === 'no-store',
    `${csv.status} ${csv.headers['content-type']} disposition=${disposition} first=${firstBytes} cache-control=${csv.headers['cache-control']}`)
  const anonymousExport = await http('GET', EXPORT, { cookies: '' })
  check('18c the same export without a bearer -> 401 ERP-AUTH-0004 (T-3.2-86)',
    anonymousExport.status === 401 && isProblem(anonymousExport, 'ERP-AUTH-0004'), problemDetail(anonymousExport))

  // 20. W2A-01: the Expense Categories cutover (plan 04.1-07). It runs HERE, after 18 and before 15, for
  //     the reason 16 to 18 do (15 locks the account); it renumbers nothing and needs no login of its own:
  //     20a reads the page with the jar step 18's login filled, and 20g reuses step 18's token and the
  //     administrator flag it read. Every request to a Perfex write path is sent WITHOUT a session and
  //     with id 999999 where the path takes one (NO_ID, as 17m to 17t), so a regression answers Perfex's
  //     own 307 to its login and can never write. D-14's two co-writers stay on Perfex, so 20f asserts
  //     they are NOT refused; only Perfex's delete is (20e).
  const SETUP_LIST = '/setup/expense-categories'
  /** A path that still belongs to Perfex: legacy answered it, and Nginx did not refuse it or redirect it to a Setup list. */
  const setupLegacy = (r) => routeOf(r) === 'legacy' && !r.text.includes(REFUSAL) && !(r.status === 302 && locOf(r).startsWith('/setup/'))

  const setupPage = await http('GET', SETUP_LIST)
  check('20a GET /setup/expense-categories signed in (erp_session_present in the jar) -> 200 from web through Nginx',
    setupPage.status === 200 && routeOf(setupPage) === 'web', `${setupPage.status} route=${routeOf(setupPage)}`)
  const anonSetup = await http('GET', SETUP_LIST, { cookies: '' })
  check('20b GET /setup/expense-categories with NO session cookie -> 302 to /login?next=%2Fsetup%2Fexpense-categories from proxy.ts, with a RELATIVE Location (T-4.1-12)',
    anonSetup.status === 302 && locOf(anonSetup) === '/login?next=%2Fsetup%2Fexpense-categories' && routeOf(anonSetup) === 'web',
    `${anonSetup.status} location=${locOf(anonSetup)} route=${routeOf(anonSetup)}`)

  const setupListForms = ['/admin/expenses/categories', '/admin/expenses/categories/', '/admin/expenses/categories?legacy=1']
  const setupListRedirects = setupListForms.flatMap((p) => [['GET', p], ['HEAD', p]])
  const setupListFailures = await failuresOf(setupListRedirects, (r) => r.status === 302 && locOf(r) === SETUP_LIST && routeOf(r) === 'web')
  check(`20c every GET and HEAD of Perfex's expense categories list, with a trailing slash and with ?legacy=1 (no escape, D-16), -> 302 with the RELATIVE Location ${SETUP_LIST} and X-Erp-Route web (${setupListRedirects.length} requests, no session)`,
    setupListFailures.length === 0, failDetail(setupListFailures, 'differ'))

  const dataTable = await http('POST', '/admin/expenses/categories', { cookies: '' })
  check('20d POST /admin/expenses/categories (Perfex\'s own DataTable read) still reaches Perfex: X-Erp-Route legacy, never refused, never redirected (no session: Perfex\'s own answer is the proof it arrived)',
    setupLegacy(dataTable), probeLine('POST', '/admin/expenses/categories', dataTable))

  const deleteCategory = [`/admin/expenses/delete_category/${NO_ID}`, '/admin/expenses/delete_category']
  const deleteForms = deleteCategory.flatMap((p) => [p, ...[methodUpper, mixedCase, allUpper, ...ALIAS_FORMS].map((form) => form(p))])
  const deleteRequests = deleteForms.flatMap((p) => [['GET', p], ['POST', p]])
  const deleteFailures = await failuresOf(deleteRequests, (r) => isClosed(r) && r.json?.managedAt === SETUP_LIST)
  check(`20e Perfex's delete_category answers 403 ${REFUSAL} with X-Erp-Route web and managedAt ${SETUP_LIST} for GET and POST, as written, in 3 letter-case forms and behind the 6 CI3 aliases (${deleteRequests.length} requests, no session, id ${NO_ID})`,
    deleteFailures.length === 0, failDetail(deleteFailures, 'not refused'))

  const coWriters = [
    ['POST', '/admin/expenses/category'],
    ['POST', methodUpper('/admin/expenses/category')],
    ['POST', '/index.php/admin/expenses/category'],
    ...['/admin/timesheets/add_expense_category', '/admin/timesheets/timesheets/add_expense_category', '/timesheets/add_expense_category', '/timesheets/timesheets/add_expense_category']
      .flatMap((p) => [['GET', p], ['POST', p]]),
    ['GET', '/admin/expenses'],
    ['GET', '/admin/expenses/expense'],
    ['GET', '/admin/accounting/expense_category_mapping'],
  ]
  const coWriterFailures = await failuresOf(coWriters, setupLegacy)
  check(`20f what W2A-01 leaves on Perfex stays there (D-14, D-17): the expense form's inline add (POST /admin/expenses/category, upper-cased and through /index.php/), the timesheets add in its four MX URL forms (GET and POST), /admin/expenses, /admin/expenses/expense and /admin/accounting/expense_category_mapping (${coWriters.length} requests, no session)`,
    coWriterFailures.length === 0, failDetail(coWriterFailures, 'moved'))

  const categoriesAnon = await http('GET', '/api/v1/expense-categories', { cookies: '' })
  const categoriesAuthed = await http('GET', '/api/v1/expense-categories', { cookies: '', bearer: exportToken })
  const isAdminRow = adminText === '1'
  const authedOk = isAdminRow ? categoriesAuthed.status === 200 : categoriesAuthed.status === 403 && isProblem(categoriesAuthed, 'ERP-AUTH-0005')
  check(`20g GET /api/v1/expense-categories without a bearer -> 401 ERP-AUTH-0004 from api; with the run's bearer -> ${isAdminRow ? '200 (the target row is an administrator)' : '403 ERP-AUTH-0005 (the target row is not an administrator: the list is administrators only)'}`,
    categoriesAnon.status === 401 && isProblem(categoriesAnon, 'ERP-AUTH-0004') && routeOf(categoriesAnon) === 'api' && authedOk && routeOf(categoriesAuthed) === 'api',
    `without: ${problemDetail(categoriesAnon)} (${routeOf(categoriesAnon)}); with: ${categoriesAuthed.status}${categoriesAuthed.json?.code ? `/${categoriesAuthed.json.code}` : ''} (${routeOf(categoriesAuthed)})`)

  // 21. quick 261001-m42 (Phase 4.4 D-08 and D-52): two live Perfex gaps closed at Nginx and one
  //     unauthenticated URL restricted. It runs HERE, after 20 and before 15, for the reason 16 to 20 do
  //     (15 locks the account); it renumbers nothing and needs no login of its own: 21d hands off step
  //     18's token. Why each request is safe:
  //     - every setting_zkbio_time request is sessionless: a regression reaches Perfex's AdminController,
  //       which answers its 307/302 to /admin/authentication and never runs the method (it writes ANY
  //       tbloptions row);
  //     - the signed-in API requests of 21d carry no body: the only writer among them,
  //       Api_timesheets::login_post, requires username and password through form validation before it
  //       touches tblstaff.token, so an empty body fails there; the Login controller calls an undefined
  //       method and API_timesheets_Controller is abstract;
  //     - no /sync_data/attendance form is EVER sent from the host: the host reaches Nginx from the Docker
  //       gateway, inside the private ranges, so after the fix it is allowed and would run the sync. The
  //       attendance forms are sent only by fromNginx with a forged non-company X-Forwarded-For, which the
  //       fixed Nginx refuses, and only after 21f proves the legacy container has no MSSQL driver (the
  //       sync connects to MSSQL before any MySQL write, so without a driver it dies before writing).
  const lastUpper = (p) => p.replace(/[^/]+$/, (s) => s.toUpperCase())
  const MX = (x) => [`/admin/timesheets/${x}`, `/admin/timesheets/timesheets/${x}`, `/timesheets/${x}`, `/timesheets/timesheets/${x}`]
  const isGone = (r) => r.status === 410 && routeOf(r) === 'legacy' && r.json?.code === 'ERP-LEGACY-0410'
  const tsLegacy = (r) => routeOf(r) === 'legacy' && !r.text.includes(REFUSAL) && r.status !== 410
  const API_PATHS = ['api', 'api_timesheets', 'api_timesheets_controller', 'login'].flatMap((c) => MX(`${c}/login`))

  const zkPaths = MX('setting_zkbio_time').flatMap((p) => [p, lastUpper(p), mixedCase(p), allUpper(p), ...ALIAS_FORMS.map((form) => form(p))])
  const zkRequests = [
    ...zkPaths.flatMap((p) => [['GET', p], ['POST', p]]),
    ...['PUT', 'DELETE', 'PATCH', 'OPTIONS'].map((m) => [m, '/admin/timesheets/setting_zkbio_time']),
    ['GET', '/admin/timesheets/setting_zkbio_time/'],
    ['GET', `/admin/timesheets/setting_zkbio_time/${NO_ID}`],
    ['HEAD', '/admin/timesheets/setting_zkbio_time', (r) => r.status === 403 && routeOf(r) === 'web'],
  ]
  const zkFailures = await failuresOf(zkRequests, isClosed)
  check(`21a timesheets::setting_zkbio_time answers 403 ${REFUSAL} with X-Erp-Route web for every method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) in all four MX URL forms, any letter case and behind every CI3 alias (${zkRequests.length} requests, no session; D-08)`,
    zkFailures.length === 0, failDetail(zkFailures, 'not refused'))

  const neighbours = [
    ...['/admin/timesheets/setting?group=zkbio_time', '/admin/timesheets/setting?group=zkbio_employee', '/admin/timesheets/setting_timekeeper',
      '/admin/timesheets/setting_zkbio_timex', '/admin/timesheets/zkbio_employee_table', '/admin/timesheets/api_document', '/timesheets/api_document',
      '/timesheets/apix/1', '/admin/timesheets/timekeeping', '/admin/proposals/sync_data', '/admin/sync_data/status'].map((p) => ['GET', p]),
    ['POST', '/admin/timesheets/setting_timekeeper'],
  ]
  const neighbourFailures = await failuresOf(neighbours, tsLegacy)
  check(`21b the neighbours stay on Perfex: the ZKTeco settings tab, setting_timekeeper, a longer method name, zkbio_employee_table, api_document, /timesheets/apix, timekeeping, /admin/proposals/sync_data and /admin/sync_data/status answer from legacy, never refused and never 410 (${neighbours.length} requests, no session)`,
    neighbourFailures.length === 0, failDetail(neighbourFailures, 'moved'))

  const apiRequests = [
    ...API_PATHS.flatMap((p) => [p, mixedCase(p), allUpper(p), ...ALIAS_FORMS.map((form) => form(p))]).map((p) => ['GET', p]),
    ...API_PATHS.map((p) => ['POST', p]),
    ['GET', '/timesheets/api_timesheets'],
    ['GET', '/TIMESHEETS/LOGIN'],
  ]
  const apiFailures = await failuresOf(apiRequests, isGone)
  check(`21c every URL of the timesheets API controllers (api, api_timesheets, api_timesheets_controller, login) in the four MX URL forms, any letter case and behind every CI3 alias answers the ADR-0030 410 ERP-LEGACY-0410 with X-Erp-Route legacy (${apiRequests.length} requests, no session; brief §10 Q1)`,
    apiFailures.length === 0, failDetail(apiFailures, 'not 410'))

  const tsHandoff = await http('POST', '/erp_sso/handoff', { bearer: exportToken })
  const tsAdmin = await http('GET', '/admin/')
  const tsLive = tsHandoff.status === 204 && routeOf(tsAdmin) === 'legacy' && !([301, 302, 303, 307, 308].includes(tsAdmin.status) && locOf(tsAdmin).includes('authentication'))
  const signedInRequests = API_PATHS.flatMap((p) => [p, allUpper(p)]).flatMap((p) => [['GET', p], ['POST', p]])
  const signedInFailures = await failuresOf(signedInRequests, isGone, (method, path) => http(method, path))
  check(`21d the same API URLs WITH a live Perfex session (step 18's token handed off): every one still answers the 410 (${signedInRequests.length} requests, GET and POST with no body, as written and upper-cased)`,
    tsLive && signedInFailures.length === 0,
    `session: handoff ${tsHandoff.status}, /admin/ ${tsAdmin.status} (${routeOf(tsAdmin)}); ${failDetail(signedInFailures, 'not 410')}`)

  const syncCanonical = await http('GET', '/sync_data/status', { cookies: '' })
  const syncForms = []
  for (const path of ['/Sync_Data/Status', '/SYNC_DATA/STATUS', '/index.php/sync_data/status', '/index.php?/sync_data/status', '/?/sync_data/status', '/index.php/?/sync_data/status']) {
    syncForms.push([path, await http('GET', path, { cookies: '' })])
  }
  syncForms.push(['/sync_data/status with x-forwarded-for 203.0.113.7 from the host', await http('GET', '/sync_data/status', { cookies: '', headers: { 'x-forwarded-for': '203.0.113.7' } })])
  syncForms.push(['/sync_data/status from 127.0.0.1 in nginx with x-forwarded-for 10.20.30.40', fromNginx('GET', '/sync_data/status', '10.20.30.40', 2)])
  const syncDiffers = syncForms.filter(([, r]) => !(r.status === syncCanonical.status && routeOf(r) === 'legacy' && !r.text.includes(REFUSAL)))
    .map(([path, r]) => probeLine('GET', path, r))
  check(`21e /sync_data/status from an allowed source is Perfex's answer: from the host (the Docker gateway, inside the company network) as written, in two letter-case forms and behind the CI3 aliases, with a forged X-Forwarded-For that Nginx ignores from the host, and from inside the container with a company address (${syncForms.length + 1} requests, no session; D-52)`,
    syncCanonical.status === 200 && routeOf(syncCanonical) === 'legacy' && syncDiffers.length === 0,
    `/sync_data/status -> ${syncCanonical.status} (${routeOf(syncCanonical)}); ${failDetail(syncDiffers, 'differ')}`)

  const driverProbe = php('<?php exit((function_exists("sqlsrv_connect") || extension_loaded("pdo_sqlsrv") || extension_loaded("pdo_dblib") || extension_loaded("odbc") || extension_loaded("mssql")) ? 1 : 0);')
  const denied = [
    ...['/sync_data/attendance', '/sync_data/attendance?days=1', '/Sync_Data/Attendance', '/SYNC_DATA/ATTENDANCE', '/index.php/sync_data/attendance',
      '/index.php?/sync_data/attendance', '/?/sync_data/attendance', '/index.php/?/sync_data/attendance', '/sync_data/status', '/sync_data'].map((p) => ['GET', p]),
    ['POST', '/sync_data/attendance'],
  ]
  if (driverProbe.status !== 0) {
    check(`21f /sync_data/* from a non-company address answers 403 ${REFUSAL} with X-Erp-Route web`, false, 'an MSSQL driver is loaded in legacy: the attendance probes were not sent')
  } else {
    const deniedFailures = await failuresOf(denied, isClosed, (method, path) => fromNginx(method, path, '203.0.113.7'))
    check(`21f /sync_data/* from a non-company address (127.0.0.1 inside the nginx container with X-Forwarded-For 203.0.113.7, honoured only from the loopback) answers 403 ${REFUSAL} with X-Erp-Route web, as written, in two letter-case forms, behind the CI3 aliases and for POST (${denied.length} requests, no session; sent only after the legacy container proved it has no MSSQL driver; D-52)`,
      deniedFailures.length === 0, failDetail(deniedFailures, 'not refused'))
  }

  const NETWORK_FILE = resolve(ROOT, 'nginx/local/snippets/company-network.conf')
  const networkLines = existsSync(NETWORK_FILE)
    ? readFileSync(NETWORK_FILE, 'utf8').split('\n').map((l) => l.trim()).filter((l) => /^[0-9./]+ 1;$/.test(l))
    : []
  const running = compose(['exec', '-T', 'nginx', 'nginx', '-T'])
  const runningText = `${running.stdout || ''}`
  const missingNetworks = networkLines.filter((l) => !runningText.split('\n').some((r) => r.trim() === l))
  const hasGeo = runningText.includes('geo $erp_company_network')
  const hasProxy = /proxy\s+127\.0\.0\.1;/.test(runningText)
  check(`21g the running Nginx carries the rendered company-network allow-list: nginx/local/snippets/company-network.conf exists with at least one range, and nginx -T shows geo $erp_company_network, proxy 127.0.0.1 and every range of the file`,
    networkLines.length > 0 && running.status === 0 && hasGeo && hasProxy && missingNetworks.length === 0,
    `file ${existsSync(NETWORK_FILE) ? `${networkLines.length} ranges` : 'absent'}, nginx -T exit ${running.status}, geo ${hasGeo}, proxy ${hasProxy}, ${missingNetworks.length} ranges missing from the running config`)

  // 22. W2A-02: the Taxes cutover (plan 04.1-13; the plan calls it 21, which quick 261001-m42 took first).
  //     It runs HERE, after 21 and before 15, for the reason 16 to 21 do (15 locks the account); it
  //     renumbers nothing and needs no login of its own: 22a reads the page with the jar step 18's login
  //     filled, and 22g reuses step 18's token and the administrator flag it read. Every request to a
  //     Perfex write path is sent WITHOUT a session and with id 999999 where the path takes one (NO_ID),
  //     so a regression answers Perfex's own 307 to its login and can never write. D-20's co-writer
  //     (Subscriptions' Stripe-rate insert) stays on Perfex, so 22f asserts it is NOT refused; only
  //     Perfex's manage and delete are (22e).
  const TAXES_LIST = '/setup/taxes'

  const taxesPage = await http('GET', TAXES_LIST)
  check('22a GET /setup/taxes signed in (erp_session_present in the jar) -> 200 from web through Nginx',
    taxesPage.status === 200 && routeOf(taxesPage) === 'web', `${taxesPage.status} route=${routeOf(taxesPage)}`)
  const anonTaxes = await http('GET', TAXES_LIST, { cookies: '' })
  check('22b GET /setup/taxes with NO session cookie -> 302 to /login?next=%2Fsetup%2Ftaxes from proxy.ts, with a RELATIVE Location',
    anonTaxes.status === 302 && locOf(anonTaxes) === '/login?next=%2Fsetup%2Ftaxes' && routeOf(anonTaxes) === 'web',
    `${anonTaxes.status} location=${locOf(anonTaxes)} route=${routeOf(anonTaxes)}`)

  const taxesListForms = ['/admin/taxes', '/admin/taxes/', '/admin/taxes/index', '/admin/taxes/index/', '/admin/taxes?legacy=1']
  const taxesListRedirects = taxesListForms.flatMap((p) => [['GET', p], ['HEAD', p]])
  const taxesListFailures = await failuresOf(taxesListRedirects, (r) => r.status === 302 && locOf(r) === TAXES_LIST && routeOf(r) === 'web')
  check(`22c every GET and HEAD of Perfex's taxes list, with a trailing slash, as /index and /index/ and with ?legacy=1 (no escape, D-16), -> 302 with the RELATIVE Location ${TAXES_LIST} and X-Erp-Route web (${taxesListRedirects.length} requests, no session)`,
    taxesListFailures.length === 0, failDetail(taxesListFailures, 'differ'))

  const taxesDataTable = [['POST', '/admin/taxes'], ['POST', '/admin/taxes/index']]
  const taxesDataTableFailures = await failuresOf(taxesDataTable, setupLegacy)
  check('22d POST /admin/taxes and POST /admin/taxes/index (Perfex\'s own DataTable read) still reach Perfex: X-Erp-Route legacy, never refused, never redirected (no session: Perfex\'s own answer is the proof it arrived)',
    taxesDataTableFailures.length === 0, failDetail(taxesDataTableFailures, 'moved'))

  const taxesWrites = ['/admin/taxes/manage', `/admin/taxes/delete/${NO_ID}`, '/admin/taxes/delete']
  const taxesWriteForms = taxesWrites.flatMap((p) => [p, ...[methodUpper, mixedCase, allUpper, ...ALIAS_FORMS].map((form) => form(p))])
  const taxesWriteRequests = taxesWriteForms.flatMap((p) => [['GET', p], ['POST', p]])
  const taxesWriteFailures = await failuresOf(taxesWriteRequests, (r) => isClosed(r) && r.json?.managedAt === TAXES_LIST)
  check(`22e Perfex's taxes manage and delete answer 403 ${REFUSAL} with X-Erp-Route web and managedAt ${TAXES_LIST} for GET and POST, as written, in 3 letter-case forms and behind the 6 CI3 aliases (${taxesWriteRequests.length} requests, no session, id ${NO_ID})`,
    taxesWriteFailures.length === 0, failDetail(taxesWriteFailures, 'not refused'))

  const taxesReaders = [
    ['POST', '/admin/taxes/tax_name_exists'],
    ['GET', '/admin/subscriptions'],
    ['GET', '/admin/subscriptions/create'],
    ['POST', '/admin/subscriptions/create'],
    ['GET', '/admin/misc/get_taxes_dropdown_template'],
    ['GET', '/admin/invoices/invoice'],
    ['GET', '/admin/expenses/expense'],
    ['GET', '/admin/accounting/tax_mapping'],
  ]
  const taxesReaderFailures = await failuresOf(taxesReaders, setupLegacy)
  check(`22f what W2A-02 leaves on Perfex stays there (D-13, D-17, D-20): the read helper tax_name_exists, the Subscriptions list and create (GET and POST; the recorded co-writer, never refused), the taxes dropdown template, the invoice and expense forms and accounting's tax mapping (${taxesReaders.length} requests, no session)`,
    taxesReaderFailures.length === 0, failDetail(taxesReaderFailures, 'moved'))

  const taxesAnon = await http('GET', '/api/v1/taxes', { cookies: '' })
  const taxesAuthed = await http('GET', '/api/v1/taxes', { cookies: '', bearer: exportToken })
  const taxesAuthedOk = isAdminRow ? taxesAuthed.status === 200 : taxesAuthed.status === 403 && isProblem(taxesAuthed, 'ERP-AUTH-0005')
  check(`22g GET /api/v1/taxes without a bearer -> 401 ERP-AUTH-0004 from api; with the run's bearer -> ${isAdminRow ? '200 (the target row is an administrator)' : '403 ERP-AUTH-0005 (the target row is not an administrator: the list is administrators only)'}`,
    taxesAnon.status === 401 && isProblem(taxesAnon, 'ERP-AUTH-0004') && routeOf(taxesAnon) === 'api' && taxesAuthedOk && routeOf(taxesAuthed) === 'api',
    `without: ${problemDetail(taxesAnon)} (${routeOf(taxesAnon)}); with: ${taxesAuthed.status}${taxesAuthed.json?.code ? `/${taxesAuthed.json.code}` : ''} (${routeOf(taxesAuthed)})`)

  // 24. W2A-03: the Cost Centers cutover (plan 04.1-20). It runs HERE, after 22 and before 15, for the
  //     reason 16 to 22 do (15 locks the account); it renumbers nothing and needs no login of its own:
  //     24a reads the page with the jar step 18's login filled, and 24g reuses step 18's token and the
  //     administrator flag it read. Every request to a Perfex write path is sent WITHOUT a session and
  //     with id 999999 where the path takes one (NO_ID), so a regression answers Perfex's own 307 to its
  //     login and can never write. Perfex's one writer is its own screen (D-27: create, edit, delete,
  //     refused in 24e); every reader stays on Perfex, so 24f asserts each is NOT refused (D-13, D-17).
  const COST_CENTERS_LIST = '/setup/cost-centers'

  const costCentersPage = await http('GET', COST_CENTERS_LIST)
  check('24a GET /setup/cost-centers signed in (erp_session_present in the jar) -> 200 from web through Nginx',
    costCentersPage.status === 200 && routeOf(costCentersPage) === 'web', `${costCentersPage.status} route=${routeOf(costCentersPage)}`)
  const anonCostCenters = await http('GET', COST_CENTERS_LIST, { cookies: '' })
  check('24b GET /setup/cost-centers with NO session cookie -> 302 to /login?next=%2Fsetup%2Fcost-centers from proxy.ts, with a RELATIVE Location',
    anonCostCenters.status === 302 && locOf(anonCostCenters) === '/login?next=%2Fsetup%2Fcost-centers' && routeOf(anonCostCenters) === 'web',
    `${anonCostCenters.status} location=${locOf(anonCostCenters)} route=${routeOf(anonCostCenters)}`)

  const costCentersListForms = ['/admin/cost_centers', '/admin/cost_centers/', '/admin/cost_centers/index', '/admin/cost_centers/index/', '/admin/cost_centers?legacy=1']
  const costCentersListRedirects = costCentersListForms.flatMap((p) => [['GET', p], ['HEAD', p]])
  const costCentersListFailures = await failuresOf(costCentersListRedirects, (r) => r.status === 302 && locOf(r) === COST_CENTERS_LIST && routeOf(r) === 'web')
  check(`24c every GET and HEAD of Perfex's cost centers list, with a trailing slash, as /index and /index/ and with ?legacy=1 (no escape, D-16), -> 302 with the RELATIVE Location ${COST_CENTERS_LIST} and X-Erp-Route web (${costCentersListRedirects.length} requests, no session)`,
    costCentersListFailures.length === 0, failDetail(costCentersListFailures, 'differ'))

  const costCentersListPosts = [['POST', '/admin/cost_centers'], ['POST', '/admin/cost_centers/index']]
  const costCentersListPostFailures = await failuresOf(costCentersListPosts, setupLegacy)
  check('24d POST /admin/cost_centers and POST /admin/cost_centers/index still reach Perfex (its list is an inline table, so a non-GET is a read): X-Erp-Route legacy, never refused, never redirected (no session: Perfex\'s own answer is the proof it arrived)',
    costCentersListPostFailures.length === 0, failDetail(costCentersListPostFailures, 'moved'))

  const costCentersWrites = ['/admin/cost_centers/create', `/admin/cost_centers/edit/${NO_ID}`, `/admin/cost_centers/delete/${NO_ID}`]
  const costCentersWriteForms = costCentersWrites.flatMap((p) => [p, ...[methodUpper, mixedCase, allUpper, ...ALIAS_FORMS].map((form) => form(p))])
  const costCentersWriteRequests = costCentersWriteForms.flatMap((p) => [['GET', p], ['POST', p]])
  const costCentersWriteFailures = await failuresOf(costCentersWriteRequests, (r) => isClosed(r) && r.json?.managedAt === COST_CENTERS_LIST)
  check(`24e Perfex's cost centers create, edit and delete answer 403 ${REFUSAL} with X-Erp-Route web and managedAt ${COST_CENTERS_LIST} for GET and POST, as written, in 3 letter-case forms and behind the 6 CI3 aliases (${costCentersWriteRequests.length} requests, no session, id ${NO_ID}; D-26, D-27)`,
    costCentersWriteFailures.length === 0, failDetail(costCentersWriteFailures, 'not refused'))

  const costCentersReaders = [
    '/admin/purchase/pur_request',
    '/admin/purchase/pur_order',
    '/admin/purchase/estimate',
    '/admin/purchase/shipping_charges',
    '/admin/purchase/shipping_charge_form',
    '/admin/expenses/expense',
    '/admin/fixed_equipment/asset_creation',
  ].map((p) => ['GET', p])
  const costCentersReaderFailures = await failuresOf(costCentersReaders, setupLegacy)
  check(`24f every reader of tblcost_centers stays on Perfex (D-13, D-17): the purchase request, order, quotation and shipping-charge screens, the expense form and fixed_equipment's asset creation, never refused, never redirected (${costCentersReaders.length} requests, no session)`,
    costCentersReaderFailures.length === 0, failDetail(costCentersReaderFailures, 'moved'))

  const costCentersAnon = await http('GET', '/api/v1/cost-centers', { cookies: '' })
  const costCentersAuthed = await http('GET', '/api/v1/cost-centers', { cookies: '', bearer: exportToken })
  const costCentersAuthedOk = isAdminRow ? costCentersAuthed.status === 200 : costCentersAuthed.status === 403 && isProblem(costCentersAuthed, 'ERP-AUTH-0005')
  check(`24g GET /api/v1/cost-centers without a bearer -> 401 ERP-AUTH-0004 from api; with the run's bearer -> ${isAdminRow ? '200 (the target row is an administrator)' : '403 ERP-AUTH-0005 (the target row is not an administrator: the list is administrators only)'}`,
    costCentersAnon.status === 401 && isProblem(costCentersAnon, 'ERP-AUTH-0004') && routeOf(costCentersAnon) === 'api' && costCentersAuthedOk && routeOf(costCentersAuthed) === 'api',
    `without: ${problemDetail(costCentersAnon)} (${routeOf(costCentersAnon)}); with: ${costCentersAuthed.status}${costCentersAuthed.json?.code ? `/${costCentersAuthed.json.code}` : ''} (${routeOf(costCentersAuthed)})`)

  // 26. W2C: the Email screens and the mail sender on the wire (plan 04.3-11). It runs HERE, after 24 and
  //     before 15, for the reason 16 to 24 do (15 locks the account); it renumbers nothing and needs no login
  //     of its own: 26a reads the screens with the jar step 18's login filled, and 26d and 26e reuse step 18's
  //     token and the administrator flag it read. Perfex's email screens are probed WITHOUT a session (D-03:
  //     they stay Perfex's, so its own 307 to its login is the proof they arrived). 26e sends ONE status test
  //     to the target row's own address, caught by Mailpit (the local stack's SMTP_HOST), and deletes that
  //     Mailpit message; it prints ids, statuses and routes only (T-4.3-35).
  const EMAIL_SCREENS = ['/setup/email-templates', '/setup/email-templates/1', '/setup/sent-emails', '/setup/sent-emails/1', '/setup/email-status']
  const PERFEX_EMAIL_SCREENS = ['/admin/emails', '/admin/settings?group=email']
  /** The status answer must never name an SMTP credential (D-02, T-4.3-06): neither the variables nor a key. */
  const SMTP_SECRET = /SMTP_USERNAME|SMTP_PASSWORD|"(?:password|username)"\s*:/i

  const emailPageFailures = await failuresOf(EMAIL_SCREENS.map((p) => ['GET', p]), (r) => r.status === 200 && routeOf(r) === 'web', (method, path) => http(method, path))
  check(`26a GET ${EMAIL_SCREENS.join(', ')} signed in (erp_session_present in the jar) -> 200 from web through Nginx (C4, Pitfall 3)`,
    emailPageFailures.length === 0, failDetail(emailPageFailures, 'differ'))
  const emailAnonFailures = await failuresOf(EMAIL_SCREENS.map((p) => ['GET', p, redirectsTo(`/login?next=${encodeURIComponent(p)}`)]), null)
  check('26b the same five with NO session cookie -> 302 to /login?next=<the encoded path> from proxy.ts, with a RELATIVE Location and X-Erp-Route web (T-4.3-17)',
    emailAnonFailures.length === 0, failDetail(emailAnonFailures, 'differ'))
  const perfexEmailFailures = await failuresOf(PERFEX_EMAIL_SCREENS.map((p) => ['GET', p]), setupLegacy)
  check(`26c Perfex's own email screens (${PERFEX_EMAIL_SCREENS.join(', ')}) still reach Perfex: X-Erp-Route legacy, never refused, never redirected to /setup (D-03, T-4.3-34; no session)`,
    perfexEmailFailures.length === 0, failDetail(perfexEmailFailures, 'moved'))

  const mailStatusAnon = await http('GET', '/api/v1/mail/status', { cookies: '' })
  const mailStatus = await http('GET', '/api/v1/mail/status', { cookies: '', bearer: exportToken })
  const mailStatusSecret = SMTP_SECRET.test(mailStatus.text)
  const mailStatusOk = isAdminRow ? mailStatus.status === 200 && mailStatus.json !== null : mailStatus.status === 403 && isProblem(mailStatus, 'ERP-AUTH-0005')
  check(`26d GET /api/v1/mail/status without a bearer -> 401 ERP-AUTH-0004 from api; with the run's bearer -> ${isAdminRow ? '200 (the target row is an administrator)' : '403 ERP-AUTH-0005 (the target row is not an administrator: the status is administrators only)'}, and the body names no SMTP user name or password (T-4.3-06)`,
    mailStatusAnon.status === 401 && isProblem(mailStatusAnon, 'ERP-AUTH-0004') && routeOf(mailStatusAnon) === 'api' && mailStatusOk && !mailStatusSecret && routeOf(mailStatus) === 'api',
    `without: ${problemDetail(mailStatusAnon)} (${routeOf(mailStatusAnon)}); with: ${mailStatus.status}${mailStatus.json?.code ? `/${mailStatus.json.code}` : ''} (${routeOf(mailStatus)}), credential name ${mailStatusSecret ? 'PRESENT' : 'absent'}`)

  if (isAdminRow) {
    const accepted = await http('POST', '/api/v1/mail/status/test', { cookies: '', bearer: exportToken, headers: { 'idempotency-key': randomBytes(16).toString('hex') } })
    const testId = accepted.json?.id
    const sentAt = Date.now()
    let mailpitIds = []
    let pollError = ''
    if (accepted.status === 202 && /^\d+$/.test(String(testId))) {
      const query = encodeURIComponent(`message-id:"<mail-${testId}@localhost>"`)
      while (mailpitIds.length === 0 && Date.now() - sentAt < MAILPIT_WAIT_MS) {
        try {
          const found = await (await fetch(`${MAILPIT}/api/v1/search?query=${query}`, { signal: AbortSignal.timeout(5_000) })).json()
          mailpitIds = (found.messages ?? []).map((m) => m.ID)
        } catch (e) {
          pollError = e.name
        }
        if (mailpitIds.length === 0) await sleep(1000)
      }
    }
    const deliveredMs = Date.now() - sentAt
    let deleted = 'not attempted'
    if (mailpitIds.length > 0) {
      try {
        const res = await fetch(`${MAILPIT}/api/v1/messages`, { method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ IDs: mailpitIds }), signal: AbortSignal.timeout(5_000) })
        deleted = String(res.status)
      } catch (e) {
        deleted = e.name
      }
    }
    check(`26e POST /api/v1/mail/status/test with the run's bearer and an Idempotency-Key -> 202 { id } from api; Mailpit holds exactly one message with the Message-ID <mail-<id>@localhost> within ${MAILPIT_WAIT_MS / 1000} s, and the step deletes it through Mailpit's REST (W2C-01, T-4.3-35)`,
      accepted.status === 202 && routeOf(accepted) === 'api' && mailpitIds.length === 1 && deleted === '200',
      `${accepted.status}${accepted.json?.code ? `/${accepted.json.code}` : ''} (${routeOf(accepted)}) id ${testId ?? 'none'}; Mailpit ${mailpitIds.length} message(s) after ${deliveredMs} ms${pollError ? `, last poll error ${pollError}` : ''}; delete ${deleted}`)
    note(`26e: the status test reached Mailpit ${mailpitIds.length > 0 ? `after ${deliveredMs} ms` : 'not at all'}`)
  } else {
    note('26e skipped: the target row is not an administrator')
  }

  // 27. W2A-04: the Payment Modes cutover (plan 04.1-25). It runs HERE, after 26 and before 15, for the
  //     reason 16 to 26 do (15 locks the account); it renumbers nothing and needs no login of its own:
  //     27a reads the page with the jar step 18's login filled, and 27g reuses step 18's token and the
  //     administrator flag it read. Every request to a Perfex write path is sent WITHOUT a session and
  //     with id 999999 where the path takes one (NO_ID), so a regression answers Perfex's own 307 to its
  //     login and can never write. Perfex's one writer is its own screen (D-32: manage, delete and both
  //     toggles, the show-to-client one among them, D-35, refused in 27e); every reader stays on Perfex,
  //     so 27f asserts each is NOT refused (D-13, D-17, D-32).
  const PAYMENT_MODES_LIST = '/setup/payment-modes'

  const paymentModesPage = await http('GET', PAYMENT_MODES_LIST)
  check('27a GET /setup/payment-modes signed in (erp_session_present in the jar) -> 200 from web through Nginx',
    paymentModesPage.status === 200 && routeOf(paymentModesPage) === 'web', `${paymentModesPage.status} route=${routeOf(paymentModesPage)}`)
  const anonPaymentModes = await http('GET', PAYMENT_MODES_LIST, { cookies: '' })
  check('27b GET /setup/payment-modes with NO session cookie -> 302 to /login?next=%2Fsetup%2Fpayment-modes from proxy.ts, with a RELATIVE Location',
    anonPaymentModes.status === 302 && locOf(anonPaymentModes) === '/login?next=%2Fsetup%2Fpayment-modes' && routeOf(anonPaymentModes) === 'web',
    `${anonPaymentModes.status} location=${locOf(anonPaymentModes)} route=${routeOf(anonPaymentModes)}`)

  const paymentModesListForms = ['/admin/paymentmodes', '/admin/paymentmodes/', '/admin/paymentmodes/index', '/admin/paymentmodes/index/', '/admin/paymentmodes?legacy=1']
  const paymentModesListRedirects = paymentModesListForms.flatMap((p) => [['GET', p], ['HEAD', p]])
  const paymentModesListFailures = await failuresOf(paymentModesListRedirects, (r) => r.status === 302 && locOf(r) === PAYMENT_MODES_LIST && routeOf(r) === 'web')
  check(`27c every GET and HEAD of Perfex's payment modes list, with a trailing slash, as /index and /index/ and with ?legacy=1 (no escape, D-16), -> 302 with the RELATIVE Location ${PAYMENT_MODES_LIST} and X-Erp-Route web (${paymentModesListRedirects.length} requests, no session)`,
    paymentModesListFailures.length === 0, failDetail(paymentModesListFailures, 'differ'))

  const paymentModesDataTable = [['POST', '/admin/paymentmodes'], ['POST', '/admin/paymentmodes/index']]
  const paymentModesDataTableFailures = await failuresOf(paymentModesDataTable, setupLegacy)
  check('27d POST /admin/paymentmodes and POST /admin/paymentmodes/index (Perfex\'s own DataTable read) still reach Perfex: X-Erp-Route legacy, never refused, never redirected (no session: Perfex\'s own answer is the proof it arrived)',
    paymentModesDataTableFailures.length === 0, failDetail(paymentModesDataTableFailures, 'moved'))

  const paymentModesWrites = [
    '/admin/paymentmodes/manage',
    `/admin/paymentmodes/delete/${NO_ID}`,
    `/admin/paymentmodes/change_payment_mode_status/${NO_ID}/0`,
    `/admin/paymentmodes/change_payment_mode_show_to_client_status/${NO_ID}/0`,
  ]
  const paymentModesWriteForms = paymentModesWrites.flatMap((p) => [p, ...[methodUpper, mixedCase, allUpper, ...ALIAS_FORMS].map((form) => form(p))])
  const paymentModesWriteRequests = paymentModesWriteForms.flatMap((p) => [['GET', p], ['POST', p]])
  const paymentModesWriteFailures = await failuresOf(paymentModesWriteRequests, (r) => isClosed(r) && r.json?.managedAt === PAYMENT_MODES_LIST)
  check(`27e Perfex's payment modes manage, delete, change_payment_mode_status and change_payment_mode_show_to_client_status answer 403 ${REFUSAL} with X-Erp-Route web and managedAt ${PAYMENT_MODES_LIST} for GET and POST, as written, in 3 letter-case forms and behind the 6 CI3 aliases (${paymentModesWriteRequests.length} requests, no session, id ${NO_ID}; D-32, D-35)`,
    paymentModesWriteFailures.length === 0, failDetail(paymentModesWriteFailures, 'not refused'))

  const paymentModesReaders = [
    '/admin/invoices',
    '/admin/invoices/record_payment',
    '/admin/payments',
    '/admin/expenses/expense',
    '/admin/credit_notes',
    '/admin/reports/report_by_payment_modes',
    '/admin/accounting/payment_mode_mapping',
    '/admin/purchase/purchase_order',
    `/admin/purchase/purchase_invoice/${NO_ID}`,
    `/admin/purchase/payment_invoice/${NO_ID}`,
    '/admin/purchase/order_returns',
    '/admin/fixed_equipment/order_manual',
    `/admin/timesheets/requisition_detail/${NO_ID}`,
    '/admin/exports',
  ].map((p) => ['GET', p])
  const paymentModesReaderFailures = await failuresOf(paymentModesReaders, setupLegacy)
  check(`27f every reader of tblpayment_modes stays on Perfex (D-13, D-17, D-32): invoices and their record-payment form, payments, the expense form, credit notes, the payment-modes report, accounting's payment-mode mapping, purchase orders, purchase invoices and their payments, order returns, fixed_equipment's orders, timesheets' requisition detail and the exports module, never refused, never redirected (${paymentModesReaders.length} requests, no session)`,
    paymentModesReaderFailures.length === 0, failDetail(paymentModesReaderFailures, 'moved'))

  const paymentModesAnon = await http('GET', '/api/v1/payment-modes', { cookies: '' })
  const paymentModesAuthed = await http('GET', '/api/v1/payment-modes', { cookies: '', bearer: exportToken })
  const paymentModesAuthedOk = isAdminRow ? paymentModesAuthed.status === 200 : paymentModesAuthed.status === 403 && isProblem(paymentModesAuthed, 'ERP-AUTH-0005')
  check(`27g GET /api/v1/payment-modes without a bearer -> 401 ERP-AUTH-0004 from api; with the run's bearer -> ${isAdminRow ? '200 (the target row is an administrator)' : '403 ERP-AUTH-0005 (the target row is not an administrator: the list is administrators only)'}`,
    paymentModesAnon.status === 401 && isProblem(paymentModesAnon, 'ERP-AUTH-0004') && routeOf(paymentModesAnon) === 'api' && paymentModesAuthedOk && routeOf(paymentModesAuthed) === 'api',
    `without: ${problemDetail(paymentModesAnon)} (${routeOf(paymentModesAnon)}); with: ${paymentModesAuthed.status}${paymentModesAuthed.json?.code ? `/${paymentModesAuthed.json.code}` : ''} (${routeOf(paymentModesAuthed)})`)

  // 29. W2A-05: the Currencies cutover (plan 04.1-30). It runs HERE, after 27 and before 15, for the reason
  //     16 to 27 do (15 locks the account); it renumbers nothing and needs no login of its own: 29a reads the
  //     page with the jar step 18's login filled, and 29g reuses step 18's token and the administrator flag it
  //     read. Every request to a Perfex write path is sent WITHOUT a session and with id 999999 where the path
  //     takes one (NO_ID), so a regression answers Perfex's own 307 to its login and can never write. Perfex's
  //     one writer is its own screen (D-38: manage, delete and make_base_currency, the last a GET link, refused
  //     in 29e); get_currency_symbol on the same controller and every reader of the table stay on Perfex, so
  //     29f asserts each is NOT refused and NOT redirected (D-13, D-17, D-38).
  const CURRENCIES_LIST = '/setup/currencies'

  const currenciesPage = await http('GET', CURRENCIES_LIST)
  check('29a GET /setup/currencies signed in (erp_session_present in the jar) -> 200 from web through Nginx',
    currenciesPage.status === 200 && routeOf(currenciesPage) === 'web', `${currenciesPage.status} route=${routeOf(currenciesPage)}`)
  const anonCurrencies = await http('GET', CURRENCIES_LIST, { cookies: '' })
  check('29b GET /setup/currencies with NO session cookie -> 302 to /login?next=%2Fsetup%2Fcurrencies from proxy.ts, with a RELATIVE Location',
    anonCurrencies.status === 302 && locOf(anonCurrencies) === '/login?next=%2Fsetup%2Fcurrencies' && routeOf(anonCurrencies) === 'web',
    `${anonCurrencies.status} location=${locOf(anonCurrencies)} route=${routeOf(anonCurrencies)}`)

  const currenciesListForms = ['/admin/currencies', '/admin/currencies/', '/admin/currencies/index', '/admin/currencies/index/', '/admin/currencies?legacy=1']
  const currenciesListRedirects = currenciesListForms.flatMap((p) => [['GET', p], ['HEAD', p]])
  const currenciesListFailures = await failuresOf(currenciesListRedirects, (r) => r.status === 302 && locOf(r) === CURRENCIES_LIST && routeOf(r) === 'web')
  check(`29c every GET and HEAD of Perfex's currencies list, with a trailing slash, as /index and /index/ and with ?legacy=1 (no escape, D-16), -> 302 with the RELATIVE Location ${CURRENCIES_LIST} and X-Erp-Route web (${currenciesListRedirects.length} requests, no session)`,
    currenciesListFailures.length === 0, failDetail(currenciesListFailures, 'differ'))

  const currenciesDataTable = [['POST', '/admin/currencies'], ['POST', '/admin/currencies/index']]
  const currenciesDataTableFailures = await failuresOf(currenciesDataTable, setupLegacy)
  check('29d POST /admin/currencies and POST /admin/currencies/index (Perfex\'s own DataTable read) still reach Perfex: X-Erp-Route legacy, never refused, never redirected (no session: Perfex\'s own answer is the proof it arrived)',
    currenciesDataTableFailures.length === 0, failDetail(currenciesDataTableFailures, 'moved'))

  const currenciesWrites = [
    '/admin/currencies/manage',
    `/admin/currencies/delete/${NO_ID}`,
    `/admin/currencies/make_base_currency/${NO_ID}`,
  ]
  const currenciesWriteForms = currenciesWrites.flatMap((p) => [p, ...[methodUpper, mixedCase, allUpper, ...ALIAS_FORMS].map((form) => form(p))])
  const currenciesWriteRequests = currenciesWriteForms.flatMap((p) => [['GET', p], ['POST', p]])
  const currenciesWriteFailures = await failuresOf(currenciesWriteRequests, (r) => isClosed(r) && r.json?.managedAt === CURRENCIES_LIST)
  check(`29e Perfex's currencies manage, delete and make_base_currency answer 403 ${REFUSAL} with X-Erp-Route web and managedAt ${CURRENCIES_LIST} for GET and POST, as written, in 3 letter-case forms and behind the 6 CI3 aliases (${currenciesWriteRequests.length} requests, no session, id ${NO_ID}; D-38)`,
    currenciesWriteFailures.length === 0, failDetail(currenciesWriteFailures, 'not refused'))

  const currencySymbol = `/admin/currencies/get_currency_symbol/${NO_ID}`
  const currenciesReaders = [
    currencySymbol,
    ...[methodUpper, mixedCase, allUpper, ...ALIAS_FORMS].map((form) => form(currencySymbol)),
    `/admin/misc/get_currency/${NO_ID}`,
    '/admin/invoices/invoice',
    '/admin/estimates/estimate',
    '/admin/proposals/proposal',
    '/admin/expenses/expense',
    '/admin/credit_notes/credit_note',
    '/admin/subscriptions/create',
    '/admin/clients/client',
    '/admin/purchase/pur_order',
    '/admin/purchase/vendor',
    '/admin/purchase/setting',
    '/admin/warehouse/setting',
    '/admin/accounting/setting',
    '/admin/hr_payroll/setting',
    '/admin/hr_profile/get_base_currency_name',
    '/admin/fixed_equipment/locations',
    '/admin/exports',
  ].map((p) => ['GET', p])
  const currenciesReaderFailures = await failuresOf(currenciesReaders, setupLegacy)
  check(`29f get_currency_symbol (as written, in 3 letter-case forms and behind the 6 CI3 aliases) and every reader of tblcurrencies stay on Perfex (D-13, D-17, D-38): misc/get_currency, the invoice, estimate, proposal, expense, credit note, subscription and customer forms, purchase orders, vendors and purchase settings, warehouse, accounting and hr_payroll settings, hr_profile's base-currency name, fixed_equipment's locations and the exports module, never refused, never redirected (${currenciesReaders.length} requests, no session)`,
    currenciesReaderFailures.length === 0, failDetail(currenciesReaderFailures, 'moved'))

  const currenciesAnon = await http('GET', '/api/v1/currencies', { cookies: '' })
  const currenciesAuthed = await http('GET', '/api/v1/currencies', { cookies: '', bearer: exportToken })
  const currenciesAuthedOk = isAdminRow ? currenciesAuthed.status === 200 : currenciesAuthed.status === 403 && isProblem(currenciesAuthed, 'ERP-AUTH-0005')
  check(`29g GET /api/v1/currencies without a bearer -> 401 ERP-AUTH-0004 from api; with the run's bearer -> ${isAdminRow ? '200 (the target row is an administrator)' : '403 ERP-AUTH-0005 (the target row is not an administrator: the list is administrators only)'}`,
    currenciesAnon.status === 401 && isProblem(currenciesAnon, 'ERP-AUTH-0004') && routeOf(currenciesAnon) === 'api' && currenciesAuthedOk && routeOf(currenciesAuthed) === 'api',
    `without: ${problemDetail(currenciesAnon)} (${routeOf(currenciesAnon)}); with: ${currenciesAuthed.status}${currenciesAuthed.json?.code ? `/${currenciesAuthed.json.code}` : ''} (${routeOf(currenciesAuthed)})`)

  // 30. quick 261005-fdl: warehouse::wh_delete_error_file_day_before refused at Nginx. It runs HERE, after 29 and
  //     before 15. SAFETY: an unrefused request runs Perfex's unlink loop over a URL-chosen folder prefix, so this
  //     step was never run red against the live stack; the red proof is offline (the location is absent on the
  //     base, and the regex was matched against every form below). Every request is sent WITHOUT a session, so a
  //     regression still meets AdminController's redirect to the login before the method runs, and carries no
  //     argument or only the made-up folder zz-made-up, which globs nothing.
  /** A module method's four MX URL forms: /admin/<m>/<x>, /admin/<m>/<m>/<x>, /<m>/<x>, /<m>/<m>/<x>. */
  const WH_MX = (m, x) => [`/admin/${m}/${x}`, `/admin/${m}/${m}/${x}`, `/${m}/${x}`, `/${m}/${m}/${x}`]
  const FDL = 'wh_delete_error_file_day_before'
  const nameUpper = (p) => p.replace(FDL, FDL.toUpperCase())
  const fdlPaths = WH_MX('warehouse', FDL).flatMap((p) => [p, `${p}/0/zz-made-up`])
    .flatMap((p) => [p, ...[nameUpper, mixedCase, allUpper, ...ALIAS_FORMS].map((form) => form(p))])
  const fdlRequests = [
    ...fdlPaths.flatMap((p) => [['GET', p], ['POST', p]]),
    ...WH_MX('warehouse', `${FDL}/`).map((p) => ['GET', p]),
    ...['PUT', 'DELETE', 'PATCH', 'OPTIONS'].map((m) => [m, `/admin/warehouse/${FDL}/0/zz-made-up`]),
    ['HEAD', `/admin/warehouse/${FDL}`, (r) => r.status === 403 && routeOf(r) === 'web'],
  ]
  const fdlFailures = await failuresOf(fdlRequests, isClosed)
  check(`30a warehouse::wh_delete_error_file_day_before answers 403 ${REFUSAL} with X-Erp-Route web for every method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) in all four MX URL forms, with no argument, a trailing slash or the made-up folder zz-made-up, in 3 letter-case forms and behind the 6 CI3 aliases (${fdlRequests.length} requests, no session)`,
    fdlFailures.length === 0, failDetail(fdlFailures, 'not refused'))

  const fdlNeighbours = [
    `/admin/warehouse/${FDL}x`, `/admin/warehouse/warehouse/${FDL}x`, '/admin/warehouse/manage_report', '/warehouse/manage_report',
    '/admin/warehouse/manage_purchase', '/admin/warehouse/manage_delivery',
  ].map((p) => ['GET', p])
  const fdlNeighbourFailures = await failuresOf(fdlNeighbours, tsLegacy)
  check(`30b the neighbours stay on Perfex: a longer method name and warehouse's report, stock import and delivery screens answer from legacy, never refused (${fdlNeighbours.length} requests, no session)`,
    fdlNeighbourFailures.length === 0, failDetail(fdlNeighbourFailures, 'moved'))

  // 31. The four unauthenticated warehouse_client routes and the ungated staff update_shipment_status
  //     closed at Nginx (plan 04.7-01; 4.7 D-24, lead decision F6). It runs HERE, after 30 and before 15, for the
  //     reason 16 to 30 do (15 locks the account); it renumbers nothing and needs no login. Why each request is safe:
  //     - every request is sessionless and every id is 999999 (NO_ID), a row that does not exist;
  //     - the two writing routes are sent only in their zero- and one-argument forms, never a two-argument one:
  //       client_update_shipment_status takes two arguments and update_shipment_status three, so on a regression
  //       PHP 8.2 raises ArgumentCountError before any statement of either method runs;
  //     - client_update_shipment_status (no sign-in check in Perfex; it writes any shipment's status and a timeline
  //       line) is sent only when 31a found no failure AND the closure regex read from ../nginx/local/default.conf
  //       (the file the container serves) compiles and matches every plain path 31b sends; otherwise 31b fails
  //       with "not sent" and no request of it leaves;
  //     - update_shipment_status is an AdminController method: without a session a regression meets Perfex's
  //       sign-in redirect before the method runs.
  const isNotFoundWeb = (r) => r.status === 404 && routeOf(r) === 'web'
  const forms = (p) => [p, lastUpper(p), mixedCase(p), allUpper(p), ...ALIAS_FORMS.map((form) => form(p))]
  /** One name's requests: GET and POST of every MX form in every spelling, the bare path and its slash, the other methods. */
  const shipClosureRequests = (plain, bare, argForm) => [
    ...plain.flatMap(forms).flatMap((p) => [['GET', p], ['POST', p]]),
    ...bare.map((p) => ['GET', p]),
    ...['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].map((m) => [m, argForm]),
  ]

  const SHIP_READ_NAMES = ['shipment_detail', 'stock_export_pdf', 'client_packing_list_pdf']
  const shipClosureReadRequests = SHIP_READ_NAMES.flatMap((name) => shipClosureRequests(
    WH_MX('warehouse', `warehouse_client/${name}/${NO_ID}`),
    [`/warehouse/warehouse_client/${name}`, `/warehouse/warehouse_client/${name}/`],
    `/warehouse/warehouse_client/${name}/${NO_ID}`,
  ))
  const shipClosureReadFailures = await failuresOf(shipClosureReadRequests, isNotFoundWeb)
  check(`31a warehouse_client shipment_detail, stock_export_pdf and client_packing_list_pdf answer 404 with X-Erp-Route web for every method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) in all four MX URL forms, any letter case and behind every CI3 alias (${shipClosureReadRequests.length} requests, no session; D-24)`,
    shipClosureReadFailures.length === 0, failDetail(shipClosureReadFailures, 'not closed'))

  // 31b: the write route, behind the proven closure. The guard reads the regex from the file Nginx serves (Task 2 of
  //     plan 04.7-01 proves the container's copy has the same sha256) and tests the plain paths; Nginx unwraps the
  //     CI3 aliases before any location is chosen, so the alias forms need no static test.
  const shipClosureWritePlain = [
    ...WH_MX('warehouse', 'warehouse_client/client_update_shipment_status'),
    ...WH_MX('warehouse', 'warehouse_client/client_update_shipment_status/product_delivered'),
  ]
  const shipClosureWriteBare = ['/warehouse/warehouse_client/client_update_shipment_status/']
  let shipClosureGuardReason = shipClosureReadFailures.length === 0 ? null : '31a did not pass'
  if (!shipClosureGuardReason) {
    const conf = readFileSync(new URL('../nginx/local/default.conf', import.meta.url), 'utf8')
    const line = conf.split('\n').find((l) => /^\s*location ~\* "/.test(l) && l.includes('warehouse_client/(?:shipment_detail'))
    const source = line ? line.slice(line.indexOf('location ~* "') + 'location ~* "'.length, line.lastIndexOf('"')) : null
    let section = null
    try { section = source ? new RegExp(source, 'i') : null } catch { section = null }
    if (!section) shipClosureGuardReason = 'the closure location is not in ../nginx/local/default.conf or does not compile'
    else if (![...shipClosureWritePlain, ...shipClosureWriteBare].every((p) => section.test(p))) shipClosureGuardReason = 'the closure regex does not match every plain path'
  }
  const shipClosureWriteRequests = shipClosureGuardReason ? [] : shipClosureRequests(shipClosureWritePlain, shipClosureWriteBare, '/warehouse/warehouse_client/client_update_shipment_status/product_delivered')
  const shipClosureWriteFailures = shipClosureGuardReason ? [] : await failuresOf(shipClosureWriteRequests, isNotFoundWeb)
  check(`31b warehouse_client client_update_shipment_status, in its zero- and one-argument forms only, answers 404 with X-Erp-Route web for every method in all four MX URL forms, any letter case and behind every CI3 alias (${shipClosureGuardReason ? 0 : shipClosureWriteRequests.length} requests, no session; sent only after 31a and the static regex test; D-24)`,
    !shipClosureGuardReason && shipClosureWriteFailures.length === 0,
    shipClosureGuardReason ? `not sent: the write route is probed only behind a proven closure (${shipClosureGuardReason})` : failDetail(shipClosureWriteFailures, 'not closed'))

  const shipClosureStaffRequests = [
    ...WH_MX('warehouse', 'update_shipment_status'),
    ...WH_MX('warehouse', 'update_shipment_status/product_delivered'),
  ].flatMap(forms).flatMap((p) => [['GET', p], ['POST', p]])
  const shipClosureStaffFailures = await failuresOf(shipClosureStaffRequests, isNotFoundWeb)
  check(`31c the staff update_shipment_status, in its zero- and one-argument forms only, answers 404 with X-Erp-Route web for GET and POST in all four MX URL forms, any letter case and behind every CI3 alias (${shipClosureStaffRequests.length} requests, no session; F6)`,
    shipClosureStaffFailures.length === 0, failDetail(shipClosureStaffFailures, 'not closed'))

  const shipClosureNeighbours = [
    ...['/warehouse/warehouse_client', '/admin/warehouse/warehouse_client'].map((c) => `${c}/shipments`),
    '/warehouse/warehouse_client/shipment_detail_hash/zz-made-up-hash',
    `/admin/warehouse/shipment_detail/${NO_ID}`,
    `/admin/warehouse/stock_export_pdf/${NO_ID}`,
    '/admin/warehouse/manage_delivery',
    `/admin/warehouse/view_delivery/${NO_ID}`,
    `/admin/warehouse/packing_list_pdf/${NO_ID}`,
    `/warehouse/warehouse_client/shipment_detailx/${NO_ID}`,
    '/admin/warehouse/update_shipment_statusx',
  ].map((p) => ['GET', p])
  const shipClosureNeighbourFailures = await failuresOf(shipClosureNeighbours, (r) => routeOf(r) === 'legacy')
  check(`31d the neighbours still reach Perfex: shipments under both client prefixes, the e-mailed shipment_detail_hash link, the staff shipment_detail, stock_export_pdf, manage_delivery, view_delivery and packing_list_pdf, and two longer names (${shipClosureNeighbours.length} requests, GET, no session; D-24, D-25, D-26)`,
    shipClosureNeighbourFailures.length === 0, failDetail(shipClosureNeighbourFailures, 'moved'))

  // 32. The staff and roles addresses (plan 04.2-29; STATE Q9): the Node screens live at /setup/staff and /setup/roles,
  //     and the old /staff and /roles answer a permanent redirect. It runs HERE, after 31 and before 15, for the reason
  //     16 to 31 do (15 locks the account); it needs no login of its own: 32c's signed-in read uses the jar step 18's
  //     login filled. Every other request is sent WITHOUT a session (rawHttp, the path verbatim) and with id 999999
  //     (NO_ID), so a regression answers Perfex's own 307 to its login and can never write.
  const sessionless = (method, path) => rawHttp(method, path)
  const movedTo = (to) => (r) => r.status === 301 && locOf(r) === to && routeOf(r) === 'web'

  const oldAddresses = [
    ['/staff', '/setup/staff'], ['/staff?tab=x', '/setup/staff?tab=x'], [`/staff/${NO_ID}`, `/setup/staff/${NO_ID}`],
    ['/roles', '/setup/roles'], ['/roles/new', '/setup/roles/new'],
  ].map(([p, to]) => ['GET', p, movedTo(to)])
  const oldFailures = await failuresOf(oldAddresses, null, sessionless)
  check(`32a every old Node address answers 301 with X-Erp-Route web and the RELATIVE Location of the same page under /setup, the query kept: /staff[...] -> /setup/staff[...], /roles[...] -> /setup/roles[...] (${oldAddresses.length} requests, no session; Q9)`,
    oldFailures.length === 0, failDetail(oldFailures, 'differ'))

  /** Never reflected: 404 from Nginx, no Location and no Set-Cookie header. */
  const notReflected = (r) => r.status === 404 && routeOf(r) === 'web' && !r.headers.get('location') && !r.headers.get('set-cookie')
  const reflectProbes = ['/staff/a%0d%0aSet-Cookie:x', '/roles/a%20b'].map((p) => ['GET', p])
  const reflectFailures = await failuresOf(reflectProbes, notReflected, sessionless)
  const REDOS_PATH = `/staff/${'a'.repeat(60)}!`
  const redosStarted = Date.now()
  const redos = await rawHttp('GET', REDOS_PATH)
  const redosMs = Date.now() - redosStarted
  check(`32b a rest of path outside [A-Za-z0-9_-] segments is never reflected: an encoded CR LF and an encoded space -> 404 web with no Location and no Set-Cookie; /staff/ with 60 \`a\` and \`!\` -> 404 web within 2 s, never a 500 (the rewrite regex is linear; ${redosMs} ms) (${reflectProbes.length + 1} requests, no session; T-4.2-143, T-4.2-147)`,
    reflectFailures.length === 0 && notReflected(redos) && redosMs < 2000,
    `${failDetail(reflectFailures, 'differ')}; ${probeLine('GET', REDOS_PATH, redos)} in ${redosMs} ms`)

  const nodePages = ['/setup/staff', `/setup/staff/${NO_ID}`, '/setup/roles', '/setup/roles/new']
  const anonPageFailures = await failuresOf(nodePages.map((p) => ['GET', p, redirectsTo(`/login?next=${encodeURIComponent(p)}`)]), null)
  const signedInPages = ['/setup/staff', '/setup/roles'].map((p) => ['GET', p])
  const menuPageFailures = await failuresOf(signedInPages, (r) => r.status === 200 && routeOf(r) === 'web', (method, path) => http(method, path))
  check(`32c the /setup addresses are web's: ${nodePages.length} pages under /setup/staff and /setup/roles with NO session cookie -> 302 to /login?next=<the encoded path> from proxy.ts, relative; ${signedInPages.length} of them signed in (the jar) -> 200 from web`,
    anonPageFailures.length === 0 && menuPageFailures.length === 0,
    `${failDetail(anonPageFailures, 'differ')}; signed in: ${failDetail(menuPageFailures, 'differ')}`)

  const perfexScreens = [
    ['/admin/staff', '/setup/staff'], [`/admin/roles/role/${NO_ID}`, `/setup/roles/${NO_ID}`],
  ].map(([p, to]) => ['GET', p, redirectsTo(to)])
  const perfexScreenFailures = await failuresOf(perfexScreens, null, sessionless)
  check(`32d Perfex's screens land on the /setup address: /admin/staff -> /setup/staff, /admin/roles/role/<id> -> /setup/roles/<id>: 302, RELATIVE, X-Erp-Route web (${perfexScreens.length} requests, no session)`,
    perfexScreenFailures.length === 0, failDetail(perfexScreenFailures, 'differ'))

  const identityRefusal = ['GET', `/admin/roles/delete/${NO_ID}`, (r) => isClosed(r) && (r.json?.title ?? '').includes('managed at /setup/staff and /setup/roles')]
  const identityRefusalFailures = await failuresOf([identityRefusal], null, sessionless)
  check(`32e the identity refusal's title names /setup/staff and /setup/roles: 403 ${REFUSAL}, X-Erp-Route web (1 request, no session, id ${NO_ID}; T-4.2-146)`,
    identityRefusalFailures.length === 0, failDetail(identityRefusalFailures, 'differ'))

  // 33. Perfex's ungated adjust route closed at Nginx (plan 04.8-01; 4.8 D-19). It runs HERE, after 32 and
  //     before 15, for the reason 16 to 32 do (15 locks the account); it renumbers nothing and needs no login. Why
  //     each request is safe:
  //     - Warehouse::adjust (Warehouse.php:3903-3909) runs change_adjust, which sets every line's batch to the counted
  //       number for the adjustment id in the URL with no permission, approval or state check. No 33a request is
  //       built until the closure regex read from ../nginx/local/default.conf (the file the container serves; plan
  //       04.8-01 Task 2 proves the container's copy has the same sha256) compiles and matches every plain path 33a
  //       sends; otherwise 33a fails with "not sent" and no request of it leaves. Nginx unwraps the CI3 aliases
  //       before any location is chosen, so the alias forms need no static test;
  //     - every request is sessionless: adjust is an AdminController method, so a regression meets Perfex's sign-in
  //       redirect before the method runs;
  //     - every id is 999999 (NO_ID), which names no adjustment, so change_adjust would loop over no line.
  const ADJUST_MARK = String.raw`warehouse/)?adjust(?:/|$)`
  const adjustClosurePlain = [...WH_MX('warehouse', `adjust/${NO_ID}`), ...WH_MX('warehouse', 'adjust')]
  const adjustClosureBare = '/warehouse/adjust/'
  let adjustClosureGuardReason = null
  {
    const conf = readFileSync(new URL('../nginx/local/default.conf', import.meta.url), 'utf8')
    const line = conf.split('\n').find((l) => /^\s*location ~\* "/.test(l) && l.includes(ADJUST_MARK))
    const source = line ? line.slice(line.indexOf('location ~* "') + 'location ~* "'.length, line.lastIndexOf('"')) : null
    let section = null
    try { section = source ? new RegExp(source, 'i') : null } catch { section = null }
    if (!section) adjustClosureGuardReason = 'the closure location is not in ../nginx/local/default.conf or does not compile'
    else if (![...adjustClosurePlain, adjustClosureBare].every((p) => section.test(p))) adjustClosureGuardReason = 'the closure regex does not match every plain path'
  }
  const adjustClosureRequests = adjustClosureGuardReason ? [] : [
    ...adjustClosurePlain.flatMap(forms).flatMap((p) => [['GET', p], ['POST', p]]),
    ['GET', adjustClosureBare],
    ...['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].map((m) => [m, `/warehouse/adjust/${NO_ID}`]),
  ]
  const adjustClosureFailures = adjustClosureGuardReason ? [] : await failuresOf(adjustClosureRequests, isNotFoundWeb)
  check(`33a warehouse adjust answers 404 with X-Erp-Route web for every method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) in all four MX URL forms, with an id, without one and with a trailing slash, any letter case and behind every CI3 alias (${adjustClosureRequests.length} requests, no session; D-19; sent only after the static regex test)`,
    !adjustClosureGuardReason && adjustClosureFailures.length === 0,
    adjustClosureGuardReason ? `not sent: adjust is probed only behind a proven closure (${adjustClosureGuardReason})` : failDetail(adjustClosureFailures, 'not closed'))

  const adjustClosureNeighbours = [
    '/admin/warehouse/adjustment_fill_multiple_serial_number_modal',
    `/admin/warehouse/adjustx/${NO_ID}`,
    '/admin/warehouse/adjust_x',
    '/admin/accounting/adjustment',
  ].map((p) => ['GET', p])
  const adjustClosureNeighbourFailures = await failuresOf(adjustClosureNeighbours, (r) => routeOf(r) === 'legacy')
  check(`33b the neighbours still reach Perfex: adjustment_fill_multiple_serial_number_modal (the serial modal), two longer names (adjustx, adjust_x) and accounting's own adjustment route (${adjustClosureNeighbours.length} requests, GET, no session; D-19)`,
    adjustClosureNeighbourFailures.length === 0, failDetail(adjustClosureNeighbourFailures, 'moved'))

  // 15. lockout (last: it locks the target account until the restore clears the key) ------------------
  const responses = []
  for (let i = 0; i < LOCKOUT_THRESHOLD; i += 1) responses.push(await login(`wrong-${pw}-${i}`))
  const fifth = responses[LOCKOUT_THRESHOLD - 1]
  check(`15 ${LOCKOUT_THRESHOLD} wrong passwords: attempts 1-${LOCKOUT_THRESHOLD - 1} -> 401 ERP-AUTH-0001, attempt ${LOCKOUT_THRESHOLD} -> 429 ERP-AUTH-0006 with Retry-After (app lockout, not Nginx)`,
    responses.slice(0, -1).every((r) => r.status === 401 && isProblem(r, 'ERP-AUTH-0001')) && fifth.status === 429 && isProblem(fifth, 'ERP-AUTH-0006') && /^[1-9]\d*$/.test(fifth.headers.get('retry-after') || ''),
    `statuses ${responses.map((r) => `${r.status}${r.json?.code ? `/${r.json.code}` : ''}`).join(' ')} retry-after=${fifth.headers.get('retry-after')}`)
  const locked = await login(pw)
  check('15 the CORRECT password while locked -> 429 ERP-AUTH-0006 (no increment, still refused)', locked.status === 429 && isProblem(locked, 'ERP-AUTH-0006'), problemDetail(locked))

  note(`wall time ${Math.round((Date.now() - started) / 1000)} s`)
}

// --- run -----------------------------------------------------------------------------------

let fatal = null
try {
  await main()
} catch (e) {
  fatal = e
  check('run completed without an exception', false, e.message)
} finally {
  await restore()
}

const passed = steps.filter((s) => s.ok).length
const failed = steps.filter((s) => !s.ok)
console.log(`\n${passed} PASS, ${failed.length} FAIL${NO_BREAKER ? ', breaker step skipped' : ''}`)
for (const f of failed) console.log(`  FAIL ${f.name} — ${f.detail}`)
if (fatal?.stack && failed.length > 0) console.log(`\n${fatal.stack.split('\n').slice(0, 4).join('\n')}`)
process.exit(failed.length === 0 ? 0 : 1)
