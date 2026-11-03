<?php

namespace App\Crawl;

// Audit de sécurité passif d'une page individuelle.
final class PageAudit
{
    // Durée minimale recommandée pour le HSTS : 6 mois (en secondes)
    public const HSTS_MIN_SECONDS = 15_552_000;

    /**
     * @return list<Issue>
     */
    public static function issues(PageReport $page): array
    {
        if ('robots' === $page->error) {
            return [Issue::Blocked];
        }
        if (0 === $page->status || $page->status >= 400) {
            return [Issue::HttpError];
        }
        if (null !== $page->redirect) {
            return [Issue::Redirect];
        }

        $issues = [];
        $add = static function (Issue $issue) use (&$issues): void {
            $issues[$issue->value] = $issue;
        };

        $headers = array_change_key_case($page->headers, \CASE_LOWER);
        $isHttps = str_starts_with($page->url, 'https://');

        // Content-Security-Policy (CSP)
        $csp = $headers['content-security-policy'][0] ?? null;
        if (null === $csp) {
            $add(Issue::CspMissing);
        } else {
            $lowerCsp = strtolower($csp);
            if (str_contains($lowerCsp, "'unsafe-inline'")) {
                $add(Issue::CspUnsafeInline);
            }
            if (str_contains($lowerCsp, "'unsafe-eval'")) {
                $add(Issue::CspUnsafeEval);
            }
            if (preg_match('/(?:default|script|style)-src[^;]*\s\*\s/', $lowerCsp)) {
                $add(Issue::CspWildcard);
            }
        }

        // Strict-Transport-Security (HSTS)
        if ($isHttps) {
            $hsts = $headers['strict-transport-security'][0] ?? null;
            if (null === $hsts) {
                $add(Issue::HstsMissing);
            } elseif (preg_match('/max-age=(\d+)/i', $hsts, $matches)) {
                if ((int) $matches[1] < self::HSTS_MIN_SECONDS) {
                    $add(Issue::HstsShortMaxAge);
                }
            }
        }

        // Clickjacking (X-Frame-Options ou CSP frame-ancestors)
        $xfo = $headers['x-frame-options'][0] ?? null;
        $hasFrameAncestors = null !== $csp && str_contains(strtolower($csp), 'frame-ancestors');
        if (null === $xfo && !$hasFrameAncestors) {
            $add(Issue::XFrameMissing);
        }

        // MIME sniffing (X-Content-Type-Options: nosniff)
        $xcto = $headers['x-content-type-options'][0] ?? null;
        if (null === $xcto || !str_contains(strtolower($xcto), 'nosniff')) {
            $add(Issue::NosniffMissing);
        }

        // Referrer-Policy
        $rp = $headers['referrer-policy'][0] ?? null;
        if (null === $rp || 'unsafe-url' === strtolower(trim($rp))) {
            $add(Issue::ReferrerPolicyMissing);
        }

        // Permissions-Policy
        $pp = $headers['permissions-policy'][0] ?? $headers['feature-policy'][0] ?? null;
        if (null === $pp) {
            $add(Issue::PermissionsPolicyMissing);
        }

        // Fuite de version de serveur
        $server = $headers['server'][0] ?? null;
        $xPoweredBy = $headers['x-powered-by'][0] ?? null;
        $hasServerVersion = null !== $server && preg_match('#[/\d]#', $server);
        if (null !== $xPoweredBy || $hasServerVersion) {
            $add(Issue::ServerHeaderLeak);
        }

        // CORS
        $acao = $headers['access-control-allow-origin'][0] ?? null;
        $acac = $headers['access-control-allow-credentials'][0] ?? null;
        if ('*' === $acao && 'true' === strtolower((string) $acac)) {
            $add(Issue::CorsWildcard);
        }

        // Analyse des cookies
        $hasCookieNoSecure = false;
        $hasCookieNoHttpOnly = false;
        $hasCookieSameSiteMissing = false;

        foreach ($page->cookies as $cookie) {
            if ($isHttps && !$cookie['secure']) {
                $hasCookieNoSecure = true;
            }
            if (!$cookie['httponly']) {
                $hasCookieNoHttpOnly = true;
            }
            if (null === $cookie['samesite'] || ('none' === strtolower($cookie['samesite']) && !$cookie['secure'])) {
                $hasCookieSameSiteMissing = true;
            }
        }

        if ($hasCookieNoSecure) {
            $add(Issue::CookieNoSecure);
        }
        if ($hasCookieNoHttpOnly) {
            $add(Issue::CookieNoHttpOnly);
        }
        if ($hasCookieSameSiteMissing) {
            $add(Issue::CookieSameSiteMissing);
        }

        // Analyse du DOM
        $content = $page->content;
        if (null !== $content) {
            if (\count($content->mixedContent) > 0) {
                $add(Issue::MixedContent);
            }
            if (\count($content->tabnabbingLinks) > 0) {
                $add(Issue::Tabnabbing);
            }
            if (\count($content->secretsFound) > 0) {
                $add(Issue::SecretTokenExposed);
            }
            if (\count($content->sourcemaps) > 0) {
                $add(Issue::SourcemapExposed);
            }
            if (\count($content->suspiciousComments) > 0) {
                $add(Issue::CommentLeak);
            }

            foreach ($content->insecureForms as $form) {
                if (($isHttps && str_starts_with($form['action'], 'http://')) || (!$isHttps && $form['hasPassword'])) {
                    $add(Issue::InsecureFormAction);
                    break;
                }
            }
            foreach ($content->insecureForms as $form) {
                if ('POST' === $form['method'] && !$form['hasCsrf']) {
                    $add(Issue::FormNoCsrf);
                    break;
                }
            }
        }

        return array_values($issues);
    }
}
