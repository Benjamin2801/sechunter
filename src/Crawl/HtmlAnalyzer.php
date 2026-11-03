<?php

namespace App\Crawl;

// Analyse le DOM et le HTML d'une page sous l'angle de la sécurité.
final class HtmlAnalyzer
{
    private const SENSITIVE_COMMENT_PATTERN = '/(?i)(TODO|FIXME|password|mdp|passwd|secret|token|api[_-]?key|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/';

    public function analyze(string $html, string $url, SiteScope $scope, ?string $contentType = null): PageContent
    {
        $doc = self::load($html, $contentType);
        $xpath = new \DOMXPath($doc);
        $base = Url::resolve($url, self::attribute($xpath, '//base[@href]', 'href') ?? '') ?? $url;

        [$links, $externalCount] = self::links($xpath, $base, $scope);
        $scripts = self::scripts($xpath, $base);
        $insecureForms = self::forms($xpath, $base, $url);
        $tabnabbing = self::tabnabbing($xpath, $base, $scope);
        $mixedContent = self::mixedContent($xpath, $base, $url);
        $suspiciousComments = self::comments($xpath);

        // Le HTML et ses scripts intégrés ; les fichiers .js du site sont lus ensuite par PageCrawler.
        $secrets = SecretScanner::scan($html);
        $sourcemaps = SecretScanner::sourcemaps($html, $base);

        return new PageContent(
            title: self::text($xpath, '//title'),
            links: $links,
            externalLinks: $externalCount,
            scripts: $scripts,
            insecureForms: $insecureForms,
            tabnabbingLinks: $tabnabbing,
            mixedContent: $mixedContent,
            secretsFound: $secrets,
            sourcemaps: $sourcemaps,
            suspiciousComments: $suspiciousComments,
        );
    }

    private static function load(string $html, ?string $contentType): \DOMDocument
    {
        $charset = preg_match('/charset=["\']?([\w-]+)/i', (string) $contentType, $match) ? strtolower($match[1]) : 'utf-8';
        if ('utf-8' !== $charset && \in_array($charset, array_map('strtolower', mb_list_encodings()), true)) {
            $html = mb_convert_encoding($html, 'UTF-8', $charset) ?: $html;
        } elseif (!mb_check_encoding($html, 'UTF-8')) {
            $html = mb_convert_encoding($html, 'UTF-8', 'Windows-1252') ?: $html;
        }

        $document = new \DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML('<?xml encoding="UTF-8">'.$html, \LIBXML_NONET | \LIBXML_COMPACT);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        return $document;
    }

    /** @return array{list<string>, int} */
    private static function links(\DOMXPath $xpath, string $base, SiteScope $scope): array
    {
        $internal = [];
        $external = 0;
        foreach ($xpath->query('//a[@href]') ?: [] as $link) {
            \assert($link instanceof \DOMElement);
            $href = trim($link->getAttribute('href'));
            if ('' === $href || str_starts_with($href, '#') || str_starts_with($href, 'javascript:') || str_starts_with($href, 'mailto:') || str_starts_with($href, 'tel:')) {
                continue;
            }
            $url = Url::resolve($base, $href);
            if (null === $url) {
                continue;
            }
            if ($scope->contains($url)) {
                $internal[$url] = true;
            } else {
                ++$external;
            }
        }

        return [array_keys($internal), $external];
    }

    /** @return list<string> */
    private static function scripts(\DOMXPath $xpath, string $base): array
    {
        $scripts = [];
        foreach ($xpath->query('//script[@src]') ?: [] as $element) {
            \assert($element instanceof \DOMElement);
            $src = trim($element->getAttribute('src'));
            $url = Url::resolve($base, $src);
            if (null !== $url) {
                $scripts[] = $url;
            }
        }

        return array_values(array_unique($scripts));
    }

    /** @return list<array{action: string, method: string, hasPassword: bool, hasCsrf: bool}> */
    private static function forms(\DOMXPath $xpath, string $base, string $pageUrl): array
    {
        $forms = [];
        $isHttps = str_starts_with($pageUrl, 'https://');

        foreach ($xpath->query('//form') ?: [] as $form) {
            \assert($form instanceof \DOMElement);
            $actionAttr = trim($form->getAttribute('action'));
            $action = '' === $actionAttr ? $pageUrl : (Url::resolve($base, $actionAttr) ?? $actionAttr);
            $method = strtoupper(trim($form->getAttribute('method')) ?: 'GET');

            // Présence d'un champ mot de passe
            $hasPassword = ($xpath->query('.//input[@type="password"]', $form) ?: new \DOMNodeList())->count() > 0;

            // Détection de jeton CSRF (hidden input avec token, csrf, nonce...)
            $hasCsrf = false;
            foreach ($xpath->query('.//input[@type="hidden"]', $form) ?: [] as $hidden) {
                \assert($hidden instanceof \DOMElement);
                $name = strtolower($hidden->getAttribute('name'));
                if (str_contains($name, 'csrf') || str_contains($name, 'token') || str_contains($name, 'nonce') || '_token' === $name) {
                    $hasCsrf = true;
                    break;
                }
            }

            // Un formulaire est notable pour la sécurité s'il soumet vers HTTP depuis HTTPS, ou s'il s'agit d'un POST
            if (($isHttps && str_starts_with($action, 'http://')) || 'POST' === $method || $hasPassword) {
                $forms[] = [
                    'action' => $action,
                    'method' => $method,
                    'hasPassword' => $hasPassword,
                    'hasCsrf' => $hasCsrf,
                ];
            }
        }

        return $forms;
    }

    /** @return list<string> */
    private static function tabnabbing(\DOMXPath $xpath, string $base, SiteScope $scope): array
    {
        $unsafe = [];
        foreach ($xpath->query('//a[@target="_blank"][@href]') ?: [] as $link) {
            \assert($link instanceof \DOMElement);
            $href = trim($link->getAttribute('href'));
            $url = Url::resolve($base, $href);
            if (null === $url || $scope->contains($url)) {
                continue;
            }
            $rel = strtolower(trim($link->getAttribute('rel')));
            $hasNoopener = str_contains($rel, 'noopener');
            $hasNoreferrer = str_contains($rel, 'noreferrer');

            if (!$hasNoopener && !$hasNoreferrer) {
                $unsafe[] = $url;
            }
        }

        return array_values(array_unique($unsafe));
    }

    /** @return list<string> */
    private static function mixedContent(\DOMXPath $xpath, string $base, string $pageUrl): array
    {
        if (!str_starts_with($pageUrl, 'https://')) {
            return [];
        }

        $queries = [
            '//script[@src]' => 'src',
            '//link[@rel="stylesheet"][@href]' => 'href',
            '//img[@src]' => 'src',
            '//iframe[@src]' => 'src',
            '//video[@src]' => 'src',
            '//audio[@src]' => 'src',
        ];

        $mixed = [];
        foreach ($queries as $query => $attribute) {
            foreach ($xpath->query($query) ?: [] as $element) {
                \assert($element instanceof \DOMElement);
                $raw = trim($element->getAttribute($attribute));
                $url = Url::resolve($base, $raw);
                if (null !== $url && str_starts_with($url, 'http://')) {
                    $mixed[] = $url;
                }
            }
        }

        return array_values(array_unique($mixed));
    }

    /** @return list<string> */
    private static function comments(\DOMXPath $xpath): array
    {
        $findings = [];
        foreach ($xpath->query('//comment()') ?: [] as $comment) {
            \assert($comment instanceof \DOMComment);
            $value = trim($comment->data);
            if (preg_match(self::SENSITIVE_COMMENT_PATTERN, $value, $matches)) {
                $snippet = mb_substr($value, 0, 80);
                $findings[] = $snippet;
                if (\count($findings) >= 5) {
                    break;
                }
            }
        }

        return $findings;
    }

    private static function text(\DOMXPath $xpath, string $query): ?string
    {
        $nodes = $xpath->query($query);
        if (false === $nodes || 0 === $nodes->count()) {
            return null;
        }

        $text = trim((string) $nodes->item(0)?->nodeValue);

        return '' === $text ? null : $text;
    }

    private static function attribute(\DOMXPath $xpath, string $query, string $name): ?string
    {
        $nodes = $xpath->query($query);
        if (false === $nodes || 0 === $nodes->count()) {
            return null;
        }
        $node = $nodes->item(0);

        return $node instanceof \DOMElement && $node->hasAttribute($name) ? $node->getAttribute($name) : null;
    }
}
