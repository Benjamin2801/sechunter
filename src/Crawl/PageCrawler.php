<?php

namespace App\Crawl;

use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

// Analyse un lot de pages en parallèle : en-têtes HTTP, cookies, DOM et fichiers .js du site.
final class PageCrawler
{
    private const MAX_HTML_BYTES = 5_000_000;

    // Fichiers .js lus par lot, leur taille maximale, et le temps qu'il doit rester au lot pour les lire.
    private const MAX_SCRIPTS = 12;
    private const MAX_SCRIPT_BYTES = 3_000_000;
    private const SCRIPT_MIN_SECONDS = 4;

    public function __construct(
        private readonly HttpClientInterface $siteClient,
        private readonly HtmlAnalyzer $analyzer,
    ) {
    }

    /**
     * @param list<string> $urls
     *
     * @return list<PageReport>
     */
    public function crawl(array $urls, SiteScope $scope, RobotsTxt $robots, float $deadline): array
    {
        $reports = [];
        $responses = [];
        $contents = [];

        foreach ($urls as $url) {
            if (!$robots->allows($url)) {
                $reports[$url] = new PageReport($url, 0, error: 'robots');
                continue;
            }
            try {
                $responses[] = $this->siteClient->request('GET', $url, [
                    'headers' => ['Accept' => 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'],
                    'max_redirects' => 0,
                    'user_data' => $url,
                ]);
            } catch (TransportExceptionInterface) {
                $reports[$url] = new PageReport($url, 0, error: 'network');
            }
        }

        foreach ($this->fetch($responses) as $url => [$response, $html, $error]) {
            if (null === $html) {
                $reports[$url] = $this->buildReport($url, $response, $error);
                continue;
            }

            try {
                $headers = $response->getHeaders(false);
                $contentType = $headers['content-type'][0] ?? null;
            } catch (TransportExceptionInterface) {
                $contentType = null;
            }

            $contents[$url] = [$response, $this->analyzer->analyze($html, $url, $scope, $contentType)];
        }

        $scripts = $this->scanScripts(array_map(static fn (array $page): PageContent => $page[1], $contents), $scope, $robots, $deadline);
        foreach ($contents as $url => [$response, $content]) {
            $secrets = $sourcemaps = [];
            foreach ($content->scripts as $script) {
                $secrets = [...$secrets, ...($scripts[$script][0] ?? [])];
                $sourcemaps = [...$sourcemaps, ...($scripts[$script][1] ?? [])];
            }
            $reports[$url] = $this->buildReport($url, $response, null, $content->withScriptFindings($secrets, $sourcemaps));
        }

        return array_values(array_filter(array_map(static fn (string $url): ?PageReport => $reports[$url] ?? null, $urls)));
    }

    /**
     * @param list<ResponseInterface> $responses
     *
     * @return array<string, array{ResponseInterface, ?string, ?string}>
     */
    private function fetch(array $responses): array
    {
        $results = [];
        foreach ($this->siteClient->stream($responses) as $response => $chunk) {
            $url = $response->getInfo('user_data');
            if (isset($results[$url])) {
                continue;
            }
            try {
                if ($chunk->isFirst() && !self::isHtml($response)) {
                    $response->cancel();
                    $results[$url] = [$response, null, null];
                } elseif ($response->getInfo('size_download') > self::MAX_HTML_BYTES) {
                    $response->cancel();
                    $results[$url] = [$response, null, 'too_large'];
                } elseif ($chunk->isLast()) {
                    $results[$url] = [$response, $response->getContent(false), null];
                }
            } catch (TransportExceptionInterface) {
                $results[$url] = [$response, null, 'network'];
            }
        }

        return $results;
    }

    /**
     * Lit les fichiers .js du site chargés par les pages du lot : un script partagé n'est lu qu'une fois,
     * les scripts d'autres domaines ne sont pas téléchargés, et rien n'est tenté si le lot manque de temps.
     *
     * @param array<string, PageContent> $contents
     *
     * @return array<string, array{list<array{type: string, sample: string, source?: string}>, list<string>}>
     */
    private function scanScripts(array $contents, SiteScope $scope, RobotsTxt $robots, float $deadline): array
    {
        $remaining = $deadline - microtime(true) - 2;
        if ($remaining < self::SCRIPT_MIN_SECONDS) {
            return [];
        }

        $urls = [];
        foreach ($contents as $content) {
            foreach ($content->scripts as $script) {
                if ($scope->contains($script) && $robots->allows($script)) {
                    $urls[$script] = true;
                }
            }
        }

        $responses = [];
        foreach (\array_slice(array_keys($urls), 0, self::MAX_SCRIPTS) as $url) {
            try {
                $responses[] = $this->siteClient->request('GET', $url, [
                    'headers' => ['Accept' => 'application/javascript,text/javascript,*/*;q=0.1'],
                    'max_redirects' => 0,
                    'max_duration' => min(10, $remaining),
                    'user_data' => $url,
                ]);
            } catch (TransportExceptionInterface) {
            }
        }

        $found = [];
        foreach ($this->siteClient->stream($responses) as $response => $chunk) {
            $url = $response->getInfo('user_data');
            if (isset($found[$url])) {
                continue;
            }
            try {
                if ($chunk->isFirst() && (200 !== $response->getStatusCode() || self::isHtml($response))) {
                    $response->cancel();
                    $found[$url] = [[], []];
                } elseif ($response->getInfo('size_download') > self::MAX_SCRIPT_BYTES) {
                    $response->cancel();
                    $found[$url] = [[], []];
                } elseif ($chunk->isLast()) {
                    $headers = $response->getHeaders(false);
                    $map = $headers['sourcemap'][0] ?? $headers['x-sourcemap'][0] ?? null;
                    $code = $response->getContent(false).(null === $map ? '' : "\n//# sourceMappingURL=".$map);
                    $found[$url] = [SecretScanner::scan($code, $url), SecretScanner::sourcemaps($code, $url)];
                }
            } catch (TransportExceptionInterface) {
                $found[$url] = [[], []];
            }
        }

        return $found;
    }

    private static function isHtml(ResponseInterface $response): bool
    {
        $status = $response->getStatusCode();
        if ($status >= 300 && $status < 400) {
            return false;
        }
        $type = $response->getHeaders(false)['content-type'][0] ?? '';

        return '' === $type || str_contains($type, 'text/html') || str_contains($type, 'application/xhtml+xml');
    }

    public static function retryAfter(?string $value): ?int
    {
        if (null === $value || '' === trim($value)) {
            return null;
        }
        if (ctype_digit(trim($value))) {
            return (int) trim($value);
        }
        $date = strtotime($value);

        return false === $date ? null : max(0, $date - time());
    }

    private function buildReport(string $url, ResponseInterface $response, ?string $error, ?PageContent $content = null): PageReport
    {
        try {
            $status = $response->getStatusCode();
            $headers = $response->getHeaders(false);
        } catch (TransportExceptionInterface) {
            return new PageReport($url, 0, error: $error ?? 'network');
        }

        $info = $response->getInfo();
        $location = $headers['location'][0] ?? null;
        $htmlMs = (int) round((float) ($info['total_time'] ?? 0) * 1000);
        $ttfb = (int) round((float) ($info['starttransfer_time'] ?? 0) * 1000);

        // Analyse structurée des cookies
        $cookies = [];
        foreach ($headers['set-cookie'] ?? [] as $rawCookie) {
            $parts = array_map('trim', explode(';', $rawCookie));
            $nameVal = explode('=', array_shift($parts), 2);
            $name = trim($nameVal[0]);
            $flags = array_map('strtolower', $parts);
            $secure = \in_array('secure', $flags, true);
            $httponly = \in_array('httponly', $flags, true);
            $samesite = null;
            foreach ($flags as $flag) {
                if (str_starts_with($flag, 'samesite=')) {
                    $samesite = substr($flag, 9);
                }
            }
            $cookies[] = [
                'name' => $name,
                'secure' => $secure,
                'httponly' => $httponly,
                'samesite' => $samesite,
            ];
        }

        return new PageReport(
            url: $url,
            status: $status,
            error: $error,
            contentType: $headers['content-type'][0] ?? null,
            redirect: $status >= 300 && $status < 400 && null !== $location ? Url::resolve($url, $location) : null,
            ttfb: $ttfb,
            htmlMs: $htmlMs,
            headers: $headers,
            cookies: $cookies,
            retryAfter: self::retryAfter($headers['retry-after'][0] ?? null),
            content: $content,
        );
    }
}
