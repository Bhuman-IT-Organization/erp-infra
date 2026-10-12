<?php

defined('BASEPATH') or exit('No direct script access allowed');

/*
 * erp_sso settings. Each constant may be pre-defined (for example by a proof
 * script) or overridden through the process environment (Docker `environment:`
 * on the local stack); the literal is the value for the Compose network.
 *
 * On the customer's host, ERP_SSO_JWKS_URL is the public origin of erp-api
 * (https://<host>/.well-known/jwks.json) — the only value that changes per
 * environment. Issuer and audience are the erp-api AUTH_JWT_ISSUER /
 * AUTH_JWT_AUDIENCE values and must match the token's `iss` / `aud` exactly.
 */

if (!defined('ERP_SSO_JWKS_URL')) {
    define('ERP_SSO_JWKS_URL', getenv('ERP_SSO_JWKS_URL') ?: 'http://api:3000/.well-known/jwks.json');
}

if (!defined('ERP_SSO_ISSUER')) {
    define('ERP_SSO_ISSUER', getenv('ERP_SSO_ISSUER') ?: 'erp-api');
}

if (!defined('ERP_SSO_AUDIENCE')) {
    define('ERP_SSO_AUDIENCE', getenv('ERP_SSO_AUDIENCE') ?: 'erp-web');
}

// Seconds a fetched JWKS is served from the cache before it is fetched again.
if (!defined('ERP_SSO_JWKS_TTL')) {
    define('ERP_SSO_JWKS_TTL', (int) (getenv('ERP_SSO_JWKS_TTL') ?: 3600));
}

// Seconds of clock skew tolerated on exp/iat/nbf (php-jwt JWT::$leeway).
if (!defined('ERP_SSO_LEEWAY')) {
    define('ERP_SSO_LEEWAY', (int) (getenv('ERP_SSO_LEEWAY') ?: 5));
}

// Minimum seconds between two forced refetches (unknown `kid`), so a stream of
// garbage tokens with random kids cannot turn every request into an HTTP call.
if (!defined('ERP_SSO_REFETCH_MIN_INTERVAL')) {
    define('ERP_SSO_REFETCH_MIN_INTERVAL', (int) (getenv('ERP_SSO_REFETCH_MIN_INTERVAL') ?: 60));
}

// Cache file. The system temp dir needs no writable application/cache/ and
// works unchanged on cPanel; the file holds public keys only.
if (!defined('ERP_SSO_JWKS_CACHE')) {
    define('ERP_SSO_JWKS_CACHE', getenv('ERP_SSO_JWKS_CACHE') ?: sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'erp_sso_jwks.json');
}
