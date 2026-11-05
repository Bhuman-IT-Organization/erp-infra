#!/usr/bin/env node
import { request } from 'node:http'

const BASE = process.env.ERP_NGINX_URL ?? 'http://127.0.0.1:8088'
const id = '999'
const requestOnce = (method, path) => new Promise((resolve, reject) => {
  const url = new URL(path, BASE)
  const req = request(url, { method, headers: method === 'POST' ? { 'content-length': '0' } : {} }, (res) => {
    const chunks = []
    res.on('data', (chunk) => chunks.push(chunk))
    res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location ?? '', route: res.headers['x-erp-route'] ?? '', body: Buffer.concat(chunks).toString('utf8') }))
  })
  req.on('error', reject)
  req.end()
})

const failures = []
const check = (name, ok, detail) => {
  console.log(ok ? `PASS ${name}` : `FAIL ${name} — ${detail}`)
  if (!ok) failures.push(name)
}
const legacy = (r) => r.route === 'legacy' && !r.body.includes('ERP-LEGACY-0403')
const refusal = (r) => r.status === 403 && r.route === 'web' && r.body.includes('ERP-LEGACY-0403')
const variants = (path) => {
  const upper = path.toUpperCase()
  const mixed = path.replace(/[a-z]+/gi, (segment) => segment[0].toUpperCase() + segment.slice(1))
  return [...new Set([path, upper, mixed])]
}
const aliases = (path) => [path, `/index.php${path}`, `/index.php?${path}`, `/?${path}`, `/index.php/?${path}`]

const list = await requestOnce('GET', '/setup/announcements')
check('setup list with existing signed-in session returns 200 from web', list.status === 200 && list.route === 'web', `${list.status} route=${list.route}`)
const anonList = await requestOnce('GET', '/setup/announcements')
check('setup list without session redirects to login (or is already signed-in on this stack)', anonList.route === 'web' && (anonList.status === 200 || (anonList.status === 302 && anonList.location.startsWith('/login?next='))), `${anonList.status} ${anonList.location} route=${anonList.route}`)

for (const [path, target] of [
  ['/admin/announcements', '/setup/announcements'],
  ['/admin/announcements/', '/setup/announcements'],
  ['/admin/announcements/announcement', '/setup/announcements/new'],
  [`/admin/announcements/announcement/${id}`, `/setup/announcements/${id}`],
]) {
  const r = await requestOnce('GET', path)
  check(`${path} redirects to ${target} via web`, r.status === 302 && r.location === target && r.route === 'web', `${r.status} ${r.location} route=${r.route}`)
  const h = await requestOnce('HEAD', path)
  check(`HEAD ${path} redirects with X-Erp-Route web`, h.status === 302 && h.location === target && h.route === 'web', `${h.status} ${h.location} route=${h.route}`)
}

const closedPaths = [
  `/admin/announcements/delete/${id}`,
  '/admin/announcements/announcement',
  `/admin/announcements/announcement/${id}`,
]
for (const basePath of closedPaths) {
  const methodForms = aliases(basePath).flatMap(variants)
  for (const path of methodForms) {
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']) {
      const r = await requestOnce(method, path)
      check(`${method} ${path} refused`, refusal(r), `${r.status} route=${r.route} body=${r.body.slice(0, 100)}`)
    }
  }
}

for (const path of [
  `/admin/announcements/view/${id}`,
  `/admin/misc/dismiss_announcement/${id}`,
  '/admin/announcements/announcementx',
  `/admin/announcements/announcement/${id}/x`,
]) {
  const r = await requestOnce('GET', path)
  check(`${path} remains on Perfex`, legacy(r), `${r.status} route=${r.route}`)
}
const listPost = await requestOnce('POST', '/admin/announcements')
check('POST list DataTable request stays on Perfex', legacy(listPost), `${listPost.status} route=${listPost.route}`)

console.log(`\n${failures.length ? `${failures.length} FAIL` : 'All announcement routing checks passed'}`)
process.exitCode = failures.length ? 1 : 0
