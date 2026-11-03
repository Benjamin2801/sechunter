<?php

namespace App\Crawl;

// Vulnérabilités relevées par PageAudit, de la plus grave à la simple information.
enum Issue: string
{
    // Critiques
    case SecretTokenExposed = 'secret_token_exposed';
    case InsecureFormAction = 'insecure_form_action';

    // Élevées
    case MixedContent = 'mixed_content';
    case CspMissing = 'csp_missing';
    case HstsMissing = 'hsts_missing';
    case XFrameMissing = 'x_frame_missing';
    case CookieNoSecure = 'cookie_no_secure';
    case CookieNoHttpOnly = 'cookie_no_httponly';
    case CookieSameSiteMissing = 'cookie_samesite_missing';

    // Moyennes
    case CspUnsafeInline = 'csp_unsafe_inline';
    case CspUnsafeEval = 'csp_unsafe_eval';
    case CspWildcard = 'csp_wildcard';
    case NosniffMissing = 'nosniff_missing';
    case Tabnabbing = 'tabnabbing';
    case SourcemapExposed = 'sourcemap_exposed';
    case HstsShortMaxAge = 'hsts_short_max_age';
    case CorsWildcard = 'cors_wildcard';

    // Faibles
    case ReferrerPolicyMissing = 'referrer_policy_missing';
    case PermissionsPolicyMissing = 'permissions_policy_missing';
    case ServerHeaderLeak = 'server_header_leak';
    case FormNoCsrf = 'form_no_csrf';
    case CommentLeak = 'comment_leak';

    // Informations
    case HttpError = 'http_error';
    case Redirect = 'redirect';
    case Blocked = 'blocked';

    public function severity(): string
    {
        return match ($this) {
            self::SecretTokenExposed, self::InsecureFormAction => 'critical',
            self::MixedContent, self::CspMissing, self::HstsMissing, self::XFrameMissing,
            self::CookieNoSecure, self::CookieNoHttpOnly, self::CookieSameSiteMissing => 'high',
            self::CspUnsafeInline, self::CspUnsafeEval, self::CspWildcard, self::NosniffMissing,
            self::Tabnabbing, self::SourcemapExposed, self::HstsShortMaxAge, self::CorsWildcard => 'medium',
            self::ReferrerPolicyMissing, self::PermissionsPolicyMissing, self::ServerHeaderLeak,
            self::FormNoCsrf, self::CommentLeak => 'low',
            self::HttpError, self::Redirect, self::Blocked => 'info',
        };
    }

    public function category(): string
    {
        return match ($this) {
            self::CspMissing, self::CspUnsafeInline, self::CspUnsafeEval, self::CspWildcard,
            self::HstsMissing, self::HstsShortMaxAge, self::XFrameMissing, self::NosniffMissing,
            self::ReferrerPolicyMissing, self::PermissionsPolicyMissing, self::ServerHeaderLeak,
            self::CorsWildcard => 'headers',
            self::CookieNoSecure, self::CookieNoHttpOnly, self::CookieSameSiteMissing => 'cookies',
            self::MixedContent, self::InsecureFormAction, self::Tabnabbing,
            self::FormNoCsrf, self::CommentLeak => 'dom',
            self::SecretTokenExposed, self::SourcemapExposed => 'secrets',
            self::HttpError, self::Redirect, self::Blocked => 'general',
        };
    }
}
