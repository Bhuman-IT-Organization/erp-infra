<?php

defined('BASEPATH') or exit('No direct script access allowed');

/*
Module Name: ERP SSO (Node JWT bridge)
Description: Accepts RS256 access tokens issued by erp-api (ADR-0005, ADR-0030) and opens a Perfex staff session, so unmigrated screens load without a second login.
Version: 0.1.0
Requires at least: 2.3.*
*/

// The vendored php-jwt 5.x (namespace App\Firebase\JWT), loaded exactly as
// application/libraries/Api_token.php does. The library is NOT replaced or
// upgraded: Api_token.php and the timesheets module depend on its 5.x API.
require_once APPPATH . 'third_party/php-jwt/JWT.php';
require_once APPPATH . 'third_party/php-jwt/BeforeValidException.php';
require_once APPPATH . 'third_party/php-jwt/ExpiredException.php';
require_once APPPATH . 'third_party/php-jwt/SignatureInvalidException.php';

require_once __DIR__ . '/config/erp_sso.php';

define('ERP_SSO_MODULE_NAME', 'erp_sso');
define('ERP_SSO_HANDOFF_URI', 'erp_sso/handoff');

// App_Controller.php fires `app_init` after the session, db and input are
// loaded and BEFORE AdminController's is_staff_logged_in() check, for every
// controller that extends App_Controller. That is the middleware slot.
hooks()->add_action('app_init', 'erp_sso_authenticate');

/**
 * Reads the bearer token from the request, or null when there is none.
 *
 * Order mirrors Api_token::getBearerToken(): CI's request headers, then the
 * HTTP_AUTHORIZATION variable the .htaccess rewrite exports on cPanel
 * (CGI/FastCGI drops the Authorization header otherwise), then the
 * REDIRECT_ prefixed copy some hosts produce.
 *
 * @return string|null
 */
function erp_sso_bearer()
{
    $ci = &get_instance();

    $candidates = [
        $ci->input->get_request_header('Authorization'),
        $_SERVER['HTTP_AUTHORIZATION'] ?? null,
        $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null,
    ];

    foreach ($candidates as $value) {
        if (is_string($value) && preg_match('/^Bearer\s+(\S+)$/i', trim($value), $m)) {
            return $m[1];
        }
    }

    return null;
}

/**
 * app_init listener: a valid erp-api access token becomes a Perfex staff session.
 *
 * Every failure path returns silently: Perfex's own redirect / 401 follows, and
 * the module never answers 401 itself from here (the handoff controller does).
 * The listener never touches an existing staff session (no elevation, no
 * replacement) and never logs the token.
 */
function erp_sso_authenticate()
{
    $ci = &get_instance();

    // Liveness marker for the handoff route only: proves the init file was
    // required by Perfex's module loader (a bind-mounted module without a
    // tblmodules row is silently ignored). Other pages are left untouched.
    if ($ci->uri->uri_string() === ERP_SSO_HANDOFF_URI) {
        $ci->output->set_header('X-Erp-Sso: active');
    }

    if (is_staff_logged_in()) {
        return;
    }

    $bearer = erp_sso_bearer();
    if ($bearer === null) {
        return;
    }

    $ci->load->library('erp_sso/erp_sso_jwks');

    \App\Firebase\JWT\JWT::$leeway = ERP_SSO_LEEWAY;

    // RS256 only: the algorithm list is ours, never the token's header (T-1.3-32).
    // The key map is [kid => PEM]; an unknown kid triggers exactly one forced
    // JWKS refetch (key rotation on the api side), then fails closed.
    try {
        $payload = \App\Firebase\JWT\JWT::decode($bearer, $ci->erp_sso_jwks->keys(), ['RS256']);
    } catch (\UnexpectedValueException $e) {
        if (str_contains($e->getMessage(), '"kid" invalid')) {
            try {
                $payload = \App\Firebase\JWT\JWT::decode($bearer, $ci->erp_sso_jwks->keys(true), ['RS256']);
            } catch (\Throwable $e2) {
                return;
            }
        } else {
            return;
        }
    } catch (\Throwable $e) {
        return;
    }

    // php-jwt 5 checks nbf/iat/exp only; issuer and audience are ours to check (T-1.3-34).
    if (($payload->iss ?? '') !== ERP_SSO_ISSUER) {
        return;
    }
    if (($payload->aud ?? '') !== ERP_SSO_AUDIENCE) {
        return;
    }

    $staffid = (int) ($payload->sub ?? 0);
    if ($staffid <= 0) {
        return;
    }

    // The row must exist AND be active before any session write (T-1.3-35).
    $staff = $ci->db->select('staffid')
        ->where('staffid', $staffid)
        ->where('active', 1)
        ->get(db_prefix() . 'staff')
        ->row();
    if (!$staff) {
        return;
    }

    // New session id before the identity is written (ASVS 3.2.1, T-1.3-36), then
    // exactly the two keys Perfex's own login sets (Authentication_model.php).
    $ci->session->sess_regenerate(true);
    $ci->session->set_userdata([
        'staff_user_id'   => (int) $staff->staffid,
        'staff_logged_in' => true,
    ]);

    // The api's session id, never the token (T-1.3-38).
    $sid = isset($payload->sid) && is_scalar($payload->sid) ? (string) $payload->sid : '?';
    log_activity('SSO: staff session opened from Node JWT (sid ' . $sid . ')', $staffid);
}
