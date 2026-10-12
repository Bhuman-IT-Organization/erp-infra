<?php

defined('BASEPATH') or exit('No direct script access allowed');

/**
 * JWKS fetch + cache and the JWK -> PEM helper for the erp_sso module.
 *
 * No CodeIgniter dependency beyond the BASEPATH guard: only the ERP_SSO_*
 * constants (config/erp_sso.php) and PHP's openssl/json, so the proof script
 * (erp-infra/scripts/verify-erp-sso.mjs) runs it in the container standalone.
 *
 * Transport: ext-curl (Perfex requires it), because the cPanel-generated php.ini in
 * the web root sets allow_url_fopen = Off for the web SAPI; the stream wrapper is
 * only the fallback when curl is absent.
 *
 * Failure policy (T-1.3-33, T-1.3-40): the JWKS URL is a constant, never taken
 * from the request; a fetch has a 3 s timeout; a fetch failure with a cached
 * copy uses the stale copy; with no cached copy keys() returns [] and
 * JWT::decode fails closed ("Key may not be empty"). The module never fails
 * open.
 */
class Erp_sso_jwks
{
    const FETCH_TIMEOUT_SECONDS = 3;

    /**
     * Public keys as [kid => SubjectPublicKeyInfo PEM].
     *
     * @param bool $forceRefresh bypass the fresh-cache check (unknown kid path);
     *                           rate-limited by ERP_SSO_REFETCH_MIN_INTERVAL
     * @return array<string,string>
     */
    public function keys($forceRefresh = false)
    {
        $cached = $this->readCache();

        if ($cached !== null) {
            $age = time() - $cached['mtime'];
            if (!$forceRefresh && $age < ERP_SSO_JWKS_TTL) {
                return $this->toPemMap($cached['jwks']);
            }
            if ($forceRefresh && $age < ERP_SSO_REFETCH_MIN_INTERVAL) {
                return $this->toPemMap($cached['jwks']);
            }
        }

        $fresh = $this->fetch();
        if ($fresh !== null) {
            $this->writeCache($fresh);
            return $this->toPemMap($fresh);
        }

        // Fetch failed: stale copy if there is one, otherwise nothing (fail closed).
        return $cached !== null ? $this->toPemMap($cached['jwks']) : [];
    }

    /**
     * RSA public JWK (base64url n, e) -> PEM SubjectPublicKeyInfo, byte-identical
     * to Node's `exportSPKI` / `publicKey.export({ type: 'spki', format: 'pem' })`.
     *
     *   SubjectPublicKeyInfo ::= SEQUENCE {
     *     algorithm  SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL },
     *     subjectPublicKey BIT STRING { RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER } } }
     *
     * @param string $n
     * @param string $e
     * @return string
     */
    public static function jwkToPem($n, $e)
    {
        $n = self::base64UrlDecode($n);
        $e = self::base64UrlDecode($e);

        // DER INTEGER is signed: a leading 1 bit needs a 0x00 pad to stay positive.
        if (ord($n[0]) & 0x80) {
            $n = "\x00" . $n;
        }
        if (ord($e[0]) & 0x80) {
            $e = "\x00" . $e;
        }

        // DER length: short form below 128, else 0x81 / 0x82 long form (an RSA-4096
        // SPKI is ~550 bytes, so two length bytes are enough).
        $len = static function ($l) {
            if ($l < 0x80) {
                return chr($l);
            }
            if ($l < 0x100) {
                return "\x81" . chr($l);
            }
            return "\x82" . chr($l >> 8) . chr($l & 0xff);
        };

        $modulus  = "\x02" . $len(strlen($n)) . $n;
        $exponent = "\x02" . $len(strlen($e)) . $e;
        $rsaPublicKey = "\x30" . $len(strlen($modulus . $exponent)) . $modulus . $exponent;

        // BIT STRING with zero unused bits.
        $bitString = "\x03" . $len(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;

        // SEQUENCE { OID 1.2.840.113549.1.1.1 rsaEncryption, NULL }
        $algorithmIdentifier = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

        $spki = "\x30" . $len(strlen($algorithmIdentifier . $bitString)) . $algorithmIdentifier . $bitString;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * @param string $s
     * @return string
     * @throws InvalidArgumentException on malformed input
     */
    public static function base64UrlDecode($s)
    {
        $padded  = strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4);
        $decoded = base64_decode($padded, true);
        if ($decoded === false || $decoded === '') {
            throw new InvalidArgumentException('Malformed base64url value');
        }
        return $decoded;
    }

    /**
     * @param array $jwks decoded JWKS document
     * @return array<string,string> kid => PEM; keys that are not RSA, have no kid,
     *                              or fail to convert are skipped
     */
    private function toPemMap(array $jwks)
    {
        $map = [];
        foreach ($jwks['keys'] ?? [] as $jwk) {
            if (!is_array($jwk) || ($jwk['kty'] ?? '') !== 'RSA') {
                continue;
            }
            if (!isset($jwk['kid'], $jwk['n'], $jwk['e']) || !is_string($jwk['kid']) || $jwk['kid'] === '') {
                continue;
            }
            try {
                $map[$jwk['kid']] = self::jwkToPem($jwk['n'], $jwk['e']);
            } catch (\Throwable $e) {
                continue;
            }
        }
        return $map;
    }

    /**
     * @return array|null decoded JWKS on HTTP 200 with a `keys` array, else null
     */
    private function fetch()
    {
        // ext-curl first: the customer's cPanel-generated php.ini in the web root sets
        // allow_url_fopen = Off for the web SAPI (the CLI does not read that file, which is
        // why a CLI proof passes while the request path fails silently). Perfex itself
        // requires curl, so it is always present; the stream wrapper stays as a fallback.
        $result = function_exists('curl_init') ? $this->fetchWithCurl() : $this->fetchWithStream();
        if ($result === null) {
            return null;
        }
        list($status, $body) = $result;
        if ($status !== 200 || !is_string($body)) {
            return null;
        }

        $jwks = json_decode($body, true);
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
            return null;
        }

        return $jwks;
    }

    /**
     * @return array{0: int, 1: string}|null [status, body], or null on a transport failure
     */
    private function fetchWithCurl()
    {
        $ch = curl_init(ERP_SSO_JWKS_URL);
        if ($ch === false) {
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_HTTPGET        => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => self::FETCH_TIMEOUT_SECONDS,
            CURLOPT_TIMEOUT        => self::FETCH_TIMEOUT_SECONDS,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);
        $body   = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return is_string($body) ? [$status, $body] : null;
    }

    /**
     * @return array{0: int, 1: string}|null [status, body], or null on a transport failure
     */
    private function fetchWithStream()
    {
        $context = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'timeout'       => self::FETCH_TIMEOUT_SECONDS,
                'ignore_errors' => true,
                'header'        => "Accept: application/json\r\n",
            ],
        ]);

        $body = @file_get_contents(ERP_SSO_JWKS_URL, false, $context);
        if ($body === false) {
            return null;
        }

        $status = 0;
        if (isset($http_response_header[0]) && preg_match('#^HTTP/\S+\s+(\d{3})#', $http_response_header[0], $m)) {
            $status = (int) $m[1];
        }

        return [$status, $body];
    }

    /**
     * @return array{jwks: array, mtime: int}|null
     */
    private function readCache()
    {
        if (!is_file(ERP_SSO_JWKS_CACHE)) {
            return null;
        }
        $body = @file_get_contents(ERP_SSO_JWKS_CACHE);
        $jwks = is_string($body) ? json_decode($body, true) : null;
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
            return null;
        }
        return ['jwks' => $jwks, 'mtime' => (int) @filemtime(ERP_SSO_JWKS_CACHE)];
    }

    /**
     * Atomic write (temp file + rename) so a concurrent request never reads a
     * half-written document. A failure to cache is not an error: the fresh
     * document is still used for this request.
     *
     * @param array $jwks
     */
    private function writeCache(array $jwks)
    {
        $tmp = ERP_SSO_JWKS_CACHE . '.' . getmypid() . '.tmp';
        if (@file_put_contents($tmp, json_encode($jwks), LOCK_EX) === false) {
            return;
        }
        if (!@rename($tmp, ERP_SSO_JWKS_CACHE)) {
            @unlink($tmp);
        }
    }
}
