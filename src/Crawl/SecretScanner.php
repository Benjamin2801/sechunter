<?php

namespace App\Crawl;

// Recherche passive de secrets, clés d'API et tokens dans le code HTML et JavaScript.
final class SecretScanner
{
    /** @var array<string, string> */
    private const PATTERNS = [
        'AWS Access Key' => '/\b(AKIA[0-9A-Z]{16})\b/',
        'Stripe Secret / Live Key' => '/\b(sk_live_[0-9a-zA-Z]{24,})\b/',
        'Stripe Publishable Key' => '/\b(pk_live_[0-9a-zA-Z]{24,})\b/',
        'Google Cloud / Maps API Key' => '/\b(AIza[0-9A-Za-z_-]{30,40})\b/',
        'GitHub Personal Access Token' => '/\b(gh[pousr]_[0-9a-zA-Z]{36})\b/',
        'JSON Web Token (JWT)' => '/\b(eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,})\b/',
        'Slack Bot / User Token' => '/\b(xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})\b/',
        'Slack Webhook' => '#(https://hooks\.slack\.com/services/T[0-9a-zA-Z_]{8,}/B[0-9a-zA-Z_]{8,}/[0-9a-zA-Z_]{20,})#',
        'Private Key' => '/(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/',
        'Generic API Secret' => '/(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\']([0-9a-zA-Z_-]{24,})["\']/',
    ];

    /**
     * @param ?string $source fichier .js d'où vient le code, null pour la page elle-même
     *
     * @return list<array{type: string, sample: string, source?: string}>
     */
    public static function scan(string $content, ?string $source = null): array
    {
        $findings = [];

        foreach (self::PATTERNS as $type => $pattern) {
            if (preg_match_all($pattern, $content, $matches)) {
                foreach ($matches[1] as $match) {
                    $findings[] = [
                        'type' => $type,
                        'sample' => self::mask((string) $match),
                    ] + (null === $source ? [] : ['source' => $source]);
                    if (\count($findings) >= 15) {
                        break 2;
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Sourcemaps annoncées par un commentaire sourceMappingURL, résolues depuis l'adresse du code.
     *
     * @return list<string>
     */
    public static function sourcemaps(string $content, string $base): array
    {
        $sourcemaps = [];
        if (preg_match_all('~sourceMappingURL=([^\s\'"\*]+)~', $content, $matches)) {
            foreach ($matches[1] as $map) {
                $resolved = str_starts_with($map, 'data:') ? null : Url::resolve($base, trim($map));
                if (null !== $resolved) {
                    $sourcemaps[] = $resolved;
                }
            }
        }

        return array_values(array_unique($sourcemaps));
    }

    // Masque le milieu du secret pour ne pas exposer le token complet dans les rapports.
    private static function mask(string $secret): string
    {
        $length = \strlen($secret);
        if ($length <= 8) {
            return str_repeat('*', $length);
        }

        $visibleStart = min(4, (int) floor($length / 4));
        $visibleEnd = min(4, (int) floor($length / 4));

        return substr($secret, 0, $visibleStart)
            .str_repeat('*', max(4, $length - $visibleStart - $visibleEnd))
            .substr($secret, -$visibleEnd);
    }
}
