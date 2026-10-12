<?php

defined('BASEPATH') or exit('No direct script access allowed');

// CI's CSRF check is bypassed for exactly this URI (matched anchored ^...$ against
// uri_string() by App_Security). The handoff is POST-only and requires the bearer,
// which a cross-site page cannot obtain (T-1.3-37).
return ['erp_sso/handoff'];
