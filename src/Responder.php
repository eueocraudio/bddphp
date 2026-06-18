<?php

declare(strict_types=1);

namespace Bdd;

/**
 * Emits an HTTP response while stripping gratuitous metadata, preserving the
 * server's blindness.
 *
 * PHP/php-fpm would otherwise advertise `X-Powered-By` (PHP version) — we
 * remove it and disable expose_php at the front controller. Headers added by
 * the fronting web server (Server, Date) are outside PHP's control, so a blind
 * deployment must also quiet those there (e.g. nginx `server_tokens off` and
 * stripping Date). Only Content-Type and Content-Length are sent here.
 *
 * Captured (test) mode records the response instead of writing it, so the
 * Server can be exercised without a live HTTP context.
 */
class Responder
{
    public int $status = 0;
    public string $body = '';
    public string $contentType = '';

    public function __construct(private readonly bool $capture = false)
    {
    }

    public function send(int $code, string $body = '', string $contentType = 'application/octet-stream'): int
    {
        $this->status = $code;
        $this->body = $body;
        $this->contentType = $contentType;

        if ($this->capture) {
            return $code;
        }

        header_remove('X-Powered-By');
        http_response_code($code);
        header('Content-Type: ' . $contentType);
        header('Content-Length: ' . strlen($body));
        if ($body !== '') {
            echo $body;
        }
        return $code;
    }
}
