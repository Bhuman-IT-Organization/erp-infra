<?php

defined('BASEPATH') or exit('No direct script access allowed');

/**
 * POST /erp_sso/handoff — the one-time handoff of the Node access token into a
 * Perfex staff session.
 *
 * The work is done by the app_init listener (erp_sso.php), which runs in
 * App_Controller's constructor before this method: a valid `Authorization:
 * Bearer` has already opened the session by the time handoff() executes, and
 * CodeIgniter's database session driver emits `Set-Cookie: sp_session` at the
 * end of the request. This method only reports the outcome.
 *
 * Extends App_Controller (not AdminController) on purpose: AdminController
 * would redirect an anonymous caller to the login page instead of answering
 * 401 JSON. The URI is CSRF-excluded by config/csrf_exclude_uris.php; the
 * bearer itself is the anti-CSRF factor (T-1.3-37).
 */
class Erp_sso extends App_Controller
{
    public function handoff()
    {
        if ($this->input->method(true) !== 'POST') {
            // The readiness signal for erp-api's `legacy` probe: 405 means the
            // module is mounted and active; Perfex's 404 means it is not.
            $this->output->set_status_header(405);
            $this->output->set_header('Allow: POST');
            return;
        }

        if (is_staff_logged_in()) {
            $this->output->set_status_header(204);
            return;
        }

        $this->output
            ->set_status_header(401)
            ->set_content_type('application/json')
            ->set_output(json_encode([
                'code'  => 'ERP-SSO-0001',
                'title' => 'No valid bearer token',
            ]));
    }
}
