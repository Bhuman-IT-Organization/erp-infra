#!/usr/bin/env node
/**
 * Proves the erp_sso module's cryptographic path inside the real PHP runtime,
 * with a Node-signed token, before (and independent of) the api's JWKS.
 *
 * Node generates an ephemeral RSA key pair, signs test tokens, and pipes a PHP
 * program into the `legacy` container that loads the vendored php-jwt 5.x plus
 * the module's config and library and reports what it decoded. Asserted:
 *
 *   PEM      Erp_sso_jwks::jwkToPem(n, e) equals Node's SPKI export byte for byte
 *   SUB      a valid RS256 token decodes and yields sub = 1
 *   HS256    an HS256 token (alg confusion, HMAC with the public PEM) is rejected
 *   SIG      an RS256 token from a different key pair is rejected
 *   EXP      an expired token is rejected
 *   KID      a token with an unknown kid is rejected
 *   CACHE    keys() serves a cached JWKS when the fetch URL is unreachable
 *
 * With --live the same ephemeral key is published as the module's JWKS cache file
 * inside the container (written as www-data at ERP_SSO_JWKS_CACHE, removed at the
 * end) and the real request path is exercised through Nginx:
 *
 *   LIVE-204   POST /erp_sso/handoff with the valid token -> 204 + Set-Cookie sp_session
 *   LIVE-ADMIN GET /admin/ with that cookie -> 200 (a Perfex screen, no login redirect)
 *   LIVE-401   HS256, expired and unknown-kid tokens -> 401 ERP-SSO-0001
 *
 * Usage:  node scripts/verify-erp-sso.mjs [--mounted] [--live] [--staff <id>]
 *   --mounted  require the library from /var/www/html/modules/erp_sso (the bind
 *              mount) instead of inlining the working-tree source
 *   --live     also run the request-path proofs above (module must be activated)
 *   --staff    staffid used as `sub` for --live (default 1; must be active)
 *
 * No dependency beyond node:crypto; nothing is written outside the container's
 * temp dir, and every file it writes there is removed before exit. The ephemeral
 * private key never leaves this process.
 */

import { spawnSync } from 'node:child_process'
import { createHmac, generateKeyPairSync, sign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const MODULE = resolve(ROOT, 'legacy/modules/erp_sso')
const COMPOSE_FILE = 'compose/local.yml'
const NGINX = 'http://127.0.0.1:8088'
const argv = process.argv.slice(2)
const MOUNTED = argv.includes('--mounted')
const LIVE = argv.includes('--live')
const STAFF = argv.includes('--staff') ? argv[argv.indexOf('--staff') + 1] : '1'
if (!/^\d+$/.test(STAFF)) { console.error('--staff must be a numeric staffid'); process.exit(1) }
const KID = 'test-kid'

const b64url = (input) => Buffer.from(input).toString('base64url')
const jwt = (header, payload, signer) => {
  const data = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`
  return `${data}.${signer(data)}`
}

// --- keys and tokens (Node side) -------------------------------------------

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const other = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = publicKey.export({ format: 'jwk' })           // { kty, n, e }
const spki = publicKey.export({ type: 'spki', format: 'pem' })

const now = Math.floor(Date.now() / 1000)
const claims = { iss: 'erp-api', aud: 'erp-web', sub: STAFF, sid: 's-test', iat: now, exp: now + 300 }
const rs256 = (key) => (data) => b64url(sign('sha256', Buffer.from(data), key))

const tokens = {
  JWT: jwt({ alg: 'RS256', typ: 'JWT', kid: KID }, claims, rs256(privateKey)),
  JWT_HS256: jwt({ alg: 'HS256', typ: 'JWT', kid: KID }, claims,
    (data) => b64url(createHmac('sha256', spki).update(data).digest())),
  JWT_OTHER_KEY: jwt({ alg: 'RS256', typ: 'JWT', kid: KID }, claims, rs256(other.privateKey)),
  JWT_EXPIRED: jwt({ alg: 'RS256', typ: 'JWT', kid: KID }, { ...claims, iat: now - 600, exp: now - 300 }, rs256(privateKey)),
  JWT_WRONG_KID: jwt({ alg: 'RS256', typ: 'JWT', kid: 'not-published' }, claims, rs256(privateKey))
}

// --- the PHP program (container side) --------------------------------------

const inlinePhp = (file) => readFileSync(resolve(MODULE, file), 'utf8').replace(/^<\?php\s*/, '')

const libraryLoad = MOUNTED
  ? `require_once '/var/www/html/modules/erp_sso/config/erp_sso.php';
require_once '/var/www/html/modules/erp_sso/libraries/Erp_sso_jwks.php';`
  : `${inlinePhp('config/erp_sso.php')}
${inlinePhp('libraries/Erp_sso_jwks.php')}`

const program = `<?php
define('BASEPATH', '/var/www/html/system/');
define('APPPATH', '/var/www/html/application/');
// The proof's own JWKS URL (unreachable, so the cache path is what is exercised) and its
// own cache file, so the running module's cache in /tmp is never touched by this script.
define('ERP_SSO_JWKS_URL', 'http://127.0.0.1:9/.well-known/jwks.json');
define('ERP_SSO_JWKS_CACHE', sys_get_temp_dir() . '/erp_sso_jwks.verify-' . getmypid() . '.json');
require_once APPPATH . 'third_party/php-jwt/JWT.php';
require_once APPPATH . 'third_party/php-jwt/BeforeValidException.php';
require_once APPPATH . 'third_party/php-jwt/ExpiredException.php';
require_once APPPATH . 'third_party/php-jwt/SignatureInvalidException.php';
${libraryLoad}
use App\\Firebase\\JWT\\JWT;

$pem = Erp_sso_jwks::jwkToPem(getenv('JWK_N'), getenv('JWK_E'));
echo 'PEM:' . base64_encode($pem) . "\\n";
$keys = [${JSON.stringify(KID)} => $pem];

$payload = JWT::decode(getenv('JWT'), $keys, ['RS256']);
echo 'SUB:' . $payload->sub . "\\n";

$attempt = function ($label, $token) use ($keys) {
    try {
        JWT::decode($token, $keys, ['RS256']);
        echo $label . ":accepted\\n";
    } catch (\\Throwable $e) {
        echo $label . ':rejected ' . get_class($e) . ': ' . $e->getMessage() . "\\n";
    }
};
$attempt('HS256', getenv('JWT_HS256'));
$attempt('SIG', getenv('JWT_OTHER_KEY'));
$attempt('EXP', getenv('JWT_EXPIRED'));
$attempt('KID', getenv('JWT_WRONG_KID'));

// Cache path: a JWKS written where the module caches it is served when the fetch fails,
// on the normal read and on the forced (unknown-kid) refetch alike.
file_put_contents(ERP_SSO_JWKS_CACHE, json_encode(['keys' => [[
    'kty' => 'RSA', 'kid' => ${JSON.stringify(KID)}, 'n' => getenv('JWK_N'), 'e' => getenv('JWK_E'), 'alg' => 'RS256', 'use' => 'sig',
]]]));
$lib = new Erp_sso_jwks();
$fromCache = $lib->keys();
$forced = $lib->keys(true);
@unlink(ERP_SSO_JWKS_CACHE);
$ok = isset($fromCache[${JSON.stringify(KID)}], $forced[${JSON.stringify(KID)}])
    && $fromCache[${JSON.stringify(KID)}] === $pem && $forced[${JSON.stringify(KID)}] === $pem;
echo 'CACHE:' . ($ok ? 'used' : 'miss') . "\\n";
`

// --- run it -----------------------------------------------------------------

const envArgs = Object.entries({ JWK_N: jwk.n, JWK_E: jwk.e, ...tokens }).flatMap(([k, v]) => ['-e', `${k}=${v}`])
const res = spawnSync('docker', ['compose', '-f', COMPOSE_FILE, 'exec', '-T', ...envArgs, 'legacy', 'php'],
  { cwd: ROOT, input: program, encoding: 'utf8' })

if (res.status !== 0) {
  console.error(res.stdout)
  console.error(res.stderr)
  console.error('\n  FAIL: php exited with', res.status, '(is the stack up? node scripts/local-up.mjs)\n')
  process.exit(1)
}

const out = res.stdout
const line = (prefix) => (out.split('\n').find((l) => l.startsWith(prefix + ':')) || '').slice(prefix.length + 1)

let failures = 0
const check = (name, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`)
  if (!ok) failures++
}

const pemFromPhp = Buffer.from(line('PEM'), 'base64').toString('utf8')
check('jwkToPem equals Node exportSPKI byte for byte', pemFromPhp === spki, `${spki.length} bytes`)
check(`RS256 token decodes to sub ${STAFF}`, line('SUB') === STAFF, `SUB:${line('SUB')}`)
check('HS256 token rejected (alg confusion)', line('HS256').startsWith('rejected'), line('HS256'))
check('foreign-key signature rejected', line('SIG').startsWith('rejected') && line('SIG').includes('SignatureInvalidException'), line('SIG'))
check('expired token rejected', line('EXP').startsWith('rejected') && line('EXP').includes('ExpiredException'), line('EXP'))
check('unknown kid rejected', line('KID').startsWith('rejected') && line('KID').includes('"kid" invalid'), line('KID'))
check('cached JWKS served when the fetch fails (plain and forced)', line('CACHE') === 'used', `CACHE:${line('CACHE')}`)

if (res.stderr.trim()) console.error(res.stderr)

// --- request path through Nginx (--live) -----------------------------------
//
// The module's real cache file is written as www-data (the PHP user; /tmp is sticky, so a
// root-owned file could never be replaced by the module later) and removed in `finally`.

if (LIVE) {
  const cacheSh = (script) => spawnSync('docker',
    ['compose', '-f', COMPOSE_FILE, 'exec', '-T', '-u', 'www-data', 'legacy', 'sh', '-c', script],
    { cwd: ROOT, encoding: 'utf8', input: JSON.stringify({ keys: [{ kty: 'RSA', kid: KID, n: jwk.n, e: jwk.e, alg: 'RS256', use: 'sig' }] }) })
  const CACHE = 'P="${ERP_SSO_JWKS_CACHE:-/tmp/erp_sso_jwks.json}"'

  // CodeIgniter starts a (anonymous) session on every request, so an sp_session cookie is
  // always set; sess_regenerate(true) adds a second Set-Cookie with the new id, and the LAST
  // one is the session that carries the staff keys. Whether a cookie is a staff session is
  // decided by what /admin/ does with it, not by its presence.
  const handoff = async (token) => {
    const r = await fetch(`${NGINX}/erp_sso/handoff`, {
      method: 'POST', redirect: 'manual', cache: 'no-store',
      headers: token ? { authorization: `Bearer ${token}` } : {}
    })
    const cookies = r.headers.getSetCookie().filter((c) => c.startsWith('sp_session='))
    return { status: r.status, cookie: cookies.length ? cookies[cookies.length - 1].split(';')[0] : null, body: await r.text() }
  }
  const adminWith = async (cookie) => {
    const r = await fetch(`${NGINX}/admin/`, { redirect: 'manual', cache: 'no-store', headers: cookie ? { cookie } : {} })
    return { status: r.status, body: await r.text() }
  }

  try {
    const w = cacheSh(`${CACHE}; cat > "$P" && echo written "$P"`)
    if (w.status !== 0) { console.error(w.stderr); throw new Error('could not write the JWKS cache file in the container') }

    const ok = await handoff(tokens.JWT)
    check('LIVE-204  POST handoff with the valid token -> 204 + Set-Cookie sp_session',
      ok.status === 204 && ok.cookie !== null, `${ok.status}${ok.cookie ? ' sp_session set' : ' no sp_session cookie'}`)

    const admin = ok.cookie ? await adminWith(ok.cookie) : { status: 0, body: '' }
    check('LIVE-ADMIN GET /admin/ with that cookie -> 200 (Perfex screen, no login redirect)',
      admin.status === 200 && /authentication\/logout/i.test(admin.body), `${admin.status}`)

    for (const [name, token] of [['HS256', tokens.JWT_HS256], ['expired', tokens.JWT_EXPIRED], ['unknown kid', tokens.JWT_WRONG_KID], ['foreign key', tokens.JWT_OTHER_KEY]]) {
      const r = await handoff(token)
      const a = r.cookie ? await adminWith(r.cookie) : { status: 0 }
      check(`LIVE-401  POST handoff with ${name} token -> 401 ERP-SSO-0001; its cookie opens no staff session`,
        r.status === 401 && r.body.includes('ERP-SSO-0001') && a.status >= 300 && a.status < 400, `${r.status}, /admin/ with its cookie -> ${a.status}`)
    }
  } catch (e) {
    check('LIVE  request path', false, e.message)
  } finally {
    const rm = cacheSh(`${CACHE}; rm -f "$P" && echo removed "$P"`)
    console.log(`      ${(rm.stdout || rm.stderr).trim()}`)
  }
}

process.exit(failures === 0 ? 0 : 1)
