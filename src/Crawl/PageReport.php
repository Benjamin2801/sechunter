<?php

namespace App\Crawl;

// Rapport d'analyse de sécurité d'une page individuelle.
final class PageReport implements \JsonSerializable
{
    /**
     * @param array<string, list<string>>                                                $headers
     * @param list<array{name: string, secure: bool, httponly: bool, samesite: ?string}> $cookies
     * @param list<string>                                                               $blockedLinks
     */
    public function __construct(
        public readonly string $url,
        public readonly int $status,
        public readonly ?string $error = null,
        public readonly ?string $contentType = null,
        public readonly ?string $redirect = null,
        public readonly ?int $ttfb = null,
        public readonly ?int $htmlMs = null,
        public readonly array $headers = [],
        public readonly array $cookies = [],
        public readonly ?int $retryAfter = null,
        public readonly ?PageContent $content = null,
        public readonly array $blockedLinks = [],
    ) {
    }

    public function isHtml(): bool
    {
        return null !== $this->content;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $content = $this->content;
        $issues = PageAudit::issues($this);

        return [
            'url' => $this->url,
            'status' => $this->status,
            'error' => $this->error,
            'contentType' => $this->contentType,
            'redirect' => $this->redirect,
            'retryAfter' => $this->retryAfter,
            'ttfb' => $this->ttfb,
            'htmlMs' => $this->htmlMs,
            'headers' => $this->headers,
            'cookies' => $this->cookies,
            'html' => $this->isHtml(),
            'title' => $content?->title,
            'links' => $content ? $content->links : [],
            'blockedLinks' => $this->blockedLinks,
            'externalLinks' => $content ? $content->externalLinks : 0,
            'scripts' => $content ? $content->scripts : [],
            'insecureForms' => $content ? $content->insecureForms : [],
            'tabnabbingLinks' => $content ? $content->tabnabbingLinks : [],
            'mixedContent' => $content ? $content->mixedContent : [],
            'secretsFound' => $content ? $content->secretsFound : [],
            'sourcemaps' => $content ? $content->sourcemaps : [],
            'suspiciousComments' => $content ? $content->suspiciousComments : [],
            'issues' => array_map(static fn (Issue $issue): string => $issue->value, $issues),
        ];
    }
}
