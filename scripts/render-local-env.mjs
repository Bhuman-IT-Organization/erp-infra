#!/usr/bin/env node
/**
 * Renders env/local/templates/*.tmpl into env/local/<name> (gitignored).
 *
 * First source: erp-infra/legacy-local/.env, which setup.mjs
 * generates per machine with random local credentials (ADR-0014: env files
 * live only in erp-infra; ADR-0011: the sibling layout is fixed, so the
 * relative path is stable).
 *
 * Second source: computed values (the RSA signing key), generated once per
 * machine into env/local/auth-jwt-private.pem (gitignored, mode 0600) and
 * rendered as {{AUTH_JWT_PRIVATE_KEY_PEM_B64}} — the base64 of the PKCS8 PEM
 * on one line, the shape erp-api's env schema expects.
 *
 * Third output: nginx/local/snippets/company-network.conf (gitignored), the Nginx allow-list for /sync_data/*, from ERP_COMPANY_NETWORKS.
 *
 * This script never prints a value.
 *
 * Usage:  node scripts/render-local-env.mjs [--rotate-jwt-key]
 *   --rotate-jwt-key   delete and regenerate the signing key; every local
 *                      session becomes invalid, which is the point of rotating.
 */

import { generateKeyPairSync } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const LEGACY_LOCAL = resolve(ROOT, 'legacy-local')
const LEGACY_ENV = resolve(LEGACY_LOCAL, '.env')
const TEMPLATES = resolve(ROOT, 'env/local/templates')
const OUT = resolve(ROOT, 'env/local')
const KEY_FILE = resolve(OUT, 'auth-jwt-private.pem')

// Keys whose value goes into a URL and therefore must be percent-encoded.
const URL_ENCODED = new Set(['DB_PASSWORD'])

const args = new Set(process.argv.slice(2))
const ROTATE = args.has('--rotate-jwt-key')
for (const a of args) {
  if (a !== '--rotate-jwt-key') die(`Unknown argument: ${a}`)
}

function die(msg) { console.error(`\n  ${msg}\n`); process.exit(1) }

if (!existsSync(LEGACY_ENV)) {
  die('Run: node legacy-local/setup.mjs (it generates the local database credentials)')
}

const values = Object.fromEntries(
  readFileSync(LEGACY_ENV, 'utf8')
    .split('\n')
    .map((l) => l.replace(/\r$/, ''))
    .filter((l) => l.trim() !== '' && !l.trimStart().startsWith('#'))
    .map((l) => {
      const i = l.indexOf('=')
      return i === -1 ? [l, ''] : [l.slice(0, i), l.slice(i + 1)]
    })
)

// The company-network allow-list for Nginx (quick 261001-m42, Phase 4.4 D-52): /sync_data/* answers only from these
// ranges. Per deployment: ERP_COMPANY_NETWORKS in the renderer's environment, IPv4 addresses or CIDRs separated by
// commas or spaces; unset means the private ranges and loopback. Each entry becomes an Nginx `geo` line, so anything
// else stops the render here, before any file is written. The value is not a secret, but it is still never printed.
// ponytail: IPv4 only (the stack listens on IPv4); add an IPv6 pattern when a deployment needs one.
const DEFAULT_COMPANY_NETWORKS = '10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8'
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const IPV4_OR_CIDR = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}(?:/(?:3[0-2]|[12]?\\d))?$`)
const companyNetworks = (process.env.ERP_COMPANY_NETWORKS ?? DEFAULT_COMPANY_NETWORKS).split(/[\s,]+/).filter(Boolean)
if (companyNetworks.length === 0) die('ERP_COMPANY_NETWORKS is set but empty: give at least one IPv4 address or CIDR, or unset it for the private ranges')
if (!companyNetworks.every((n) => IPV4_OR_CIDR.test(n))) die('ERP_COMPANY_NETWORKS: every entry must be an IPv4 address or CIDR (a.b.c.d or a.b.c.d/n)')

// Computed values: the per-machine RSA signing key (ADR-0005: RS256; ADR-0014: never in git).
if (ROTATE && existsSync(KEY_FILE)) {
  unlinkSync(KEY_FILE)
  console.log('removed env/local/auth-jwt-private.pem (--rotate-jwt-key)')
}
if (!existsSync(KEY_FILE)) {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
  console.log('generated env/local/auth-jwt-private.pem (RSA 2048, PKCS8; gitignored)')
} else {
  console.log('reusing env/local/auth-jwt-private.pem')
}
values.AUTH_JWT_PRIVATE_KEY_PEM_B64 = Buffer.from(readFileSync(KEY_FILE)).toString('base64')

const templates = readdirSync(TEMPLATES).filter((f) => f.endsWith('.tmpl')).sort()
if (templates.length === 0) die(`No *.tmpl files under ${TEMPLATES}`)

for (const file of templates) {
  const name = file.slice(0, -'.tmpl'.length)
  const source = readFileSync(resolve(TEMPLATES, file), 'utf8').replace(/\r\n/g, '\n')
  const rendered = source.replace(/\{\{([A-Z0-9_]+)\}\}/g, (_, key) => {
    const value = values[key]
    if (value === undefined || value === '') {
      die(`${file}: placeholder {{${key}}} has no value in ${LEGACY_ENV} or the computed values`)
    }
    return URL_ENCODED.has(key) ? encodeURIComponent(value) : value
  })
  writeFileSync(resolve(OUT, name), rendered.endsWith('\n') ? rendered : `${rendered}\n`, 'utf8')
  console.log(`wrote env/local/${name}`)
}

const NETWORK_FILE = resolve(ROOT, 'nginx/local/snippets/company-network.conf')
writeFileSync(NETWORK_FILE, [
  '# Rendered by scripts/render-local-env.mjs from ERP_COMPANY_NETWORKS (quick 261001-m42). Gitignored: do not edit.',
  ...companyNetworks.map((n) => `${n} 1;`),
  '',
].join('\n'), 'utf8')
console.log(`wrote nginx/local/snippets/company-network.conf (${companyNetworks.length} ranges)`)
