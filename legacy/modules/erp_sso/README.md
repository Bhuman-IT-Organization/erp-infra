# erp_sso — Node JWT bridge for Perfex (wave 0)

A drop-in Perfex module that lets the unmigrated legacy screens accept the RS256 access token issued by erp-api (ADR-0005, ADR-0030). No core file of the legacy system is edited; the module is an overlay, activated and deactivated like any other Perfex module (ADR-0024's read-only posture).

## What it does

On Perfex's `app_init` action (fired by `App_Controller` for every request, before `AdminController` checks `is_staff_logged_in()`), the listener in `erp_sso.php`:

1. does nothing when a staff session already exists (it never elevates or replaces one), or when the request carries no `Authorization: Bearer …`;
2. verifies the token with the **vendored** `application/third_party/php-jwt` (5.x, `App\Firebase\JWT`): signature RS256 only (the algorithm list is the module's, never the token header's), `kid` looked up in the JWKS fetched from erp-api's `/.well-known/jwks.json`, `exp`/`iat`/`nbf` with a 5 s leeway, then `iss` and `aud` checked by the module (php-jwt 5 does not);
3. maps `sub` to `tblstaff.staffid` — the row must exist and be `active = 1` — regenerates the CodeIgniter session id and sets the two keys Perfex's own login sets, `staff_user_id` and `staff_logged_in`. The database session driver then emits `Set-Cookie: sp_session`, and every later navigation is a normal Perfex session.

Any failure is silent: no session is opened and Perfex's own redirect or 401 follows. The module never answers 401 from the listener, never fails open (no JWKS → no session), and never logs a token (`log_activity` records the api's `sid` only).

`POST /erp_sso/handoff` (controller `Erp_sso`, extends `App_Controller`) is the one-time handoff the Next.js login page calls after a successful `/api/v1/auth/login`: with a valid bearer it answers `204` (the session cookie is set by then); otherwise `401` with `{"code":"ERP-SSO-0001","title":"No valid bearer token"}`; any method other than POST answers `405`. The URI is CSRF-excluded through `config/csrf_exclude_uris.php` — the bearer is the anti-CSRF factor. The `405` on `GET` is also the readiness signal erp-api's `legacy` probe uses (Perfex answers `404` when the module is not active), and the listener adds `X-Erp-Sso: active` to that route's responses as a liveness marker.

## Files

| File | Role |
|---|---|
| `erp_sso.php` | module header, php-jwt requires, `erp_sso_bearer()`, the `app_init` listener |
| `config/erp_sso.php` | settings (below); each constant may be overridden by an environment variable of the same name |
| `config/csrf_exclude_uris.php` | `['erp_sso/handoff']`, merged by Perfex at `pre_system` |
| `controllers/Erp_sso.php` | `handoff()` |
| `libraries/Erp_sso_jwks.php` | JWKS fetch (3 s timeout) + file cache, `jwkToPem(n, e)`, `base64UrlDecode()` |
| `install.php` | no-op: no tables, no options |

## Settings (`config/erp_sso.php`)

| Constant | Default | Change per environment? |
|---|---|---|
| `ERP_SSO_JWKS_URL` | `http://api:3000/.well-known/jwks.json` (Compose network) | **yes** — the public origin of erp-api on the customer's host |
| `ERP_SSO_ISSUER` | `erp-api` | only if erp-api's `AUTH_JWT_ISSUER` changes |
| `ERP_SSO_AUDIENCE` | `erp-web` | only if erp-api's `AUTH_JWT_AUDIENCE` changes |
| `ERP_SSO_JWKS_TTL` | `3600` s | no |
| `ERP_SSO_LEEWAY` | `5` s | no |
| `ERP_SSO_REFETCH_MIN_INTERVAL` | `60` s — floor between two forced refetches on an unknown `kid` | no |
| `ERP_SSO_JWKS_CACHE` | `<system temp dir>/erp_sso_jwks.json` | no — the temp dir needs no writable `application/cache/` and works on cPanel |

JWKS policy: served from the cache while younger than the TTL; an unknown `kid` forces one refetch (key rotation on the api side), rate-limited by the interval above; a failed fetch falls back to the cached copy whatever its age; no cache and no fetch → no keys → no session.

JWKS transport: **ext-curl** (Perfex requires it), with the `http://` stream wrapper only as a fallback when curl is absent. The customer's cPanel-generated `php.ini` in the web root sets `allow_url_fopen = Off` for the web SAPI, and the local `php:apache` image reads that same file (Apache's working directory is the web root), so a `file_get_contents()` fetch fails silently under Apache while the CLI proof passes. Found by `scripts/verify-wave0.mjs` (01.3-09): the first real handoff answered 401 until the fetch moved to curl.

## Delivery

**Locally** the folder is bind-mounted read-only into the legacy container at `/var/www/html/modules/erp_sso` by `erp-infra/legacy-local/docker-compose.yml`, on top of the untouched legacy tree, and activated by `node activate-module.mjs erp_sso 0.1.0` in that folder (an idempotent `tblmodules` row on the local database; `setup.mjs` and `erp-infra/scripts/local-up.mjs` both run it). Perfex only `require`s the init file of an **activated** module, so the mount alone does nothing.

**On the customer's cPanel host** (Phase 5 wires the upload): upload this folder to `modules/erp_sso/`, set `ERP_SSO_JWKS_URL` (edit the constant or set the environment variable), then Setup → Modules → Activate. Roll back with Deactivate (the row flips to `active = 0`; the folder can then be deleted). No core file is touched either way.

## Proving it

- `node scripts/verify-erp-sso.mjs` (from `erp-infra`, stack up) pipes a PHP program into the legacy container with a token signed by an ephemeral Node key: the PEM built by `jwkToPem` equals Node's `exportSPKI` byte for byte; RS256 decodes; HS256 (alg confusion), a foreign key, an expired token and an unknown `kid` are rejected; a cached JWKS is served when the fetch fails. `--mounted` loads the library through the bind mount instead of the working tree.
- Through Nginx: `curl -X POST http://localhost:8088/erp_sso/handoff` → `401` JSON (not a CSRF page); `GET` → `405`; `/admin/` without a token still redirects to the login.
- The end-to-end handoff with a real erp-api token is `scripts/verify-wave0.mjs` (Phase 1.3 plan 09).

## Never

- log, echo or persist a token; `log_activity` gets the `sid` only;
- read the JWKS URL, issuer or audience from the request;
- accept an algorithm other than RS256, or a token whose `sub` is not an active staff row;
- upgrade the vendored php-jwt: `Api_token.php` and the timesheets module depend on the 5.x `decode($jwt, $key, $allowed_algs)` signature.
