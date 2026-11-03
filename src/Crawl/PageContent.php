<?php

namespace App\Crawl;

// Ce que l'analyse du DOM et du code d'une page révèle pour la sécurité.
final class PageContent
{
    /**
     * @param list<string>                                                                  $links              liens internes pour le crawl
     * @param list<string>                                                                  $scripts            fichiers .js référencés sur la page
     * @param list<array{action: string, method: string, hasPassword: bool, hasCsrf: bool}> $insecureForms
     * @param list<string>                                                                  $tabnabbingLinks    liens target=_blank sans noopener
     * @param list<string>                                                                  $mixedContent       ressources http:// sur page https://
     * @param list<array{type: string, sample: string, source?: string}>                    $secretsFound       clés API ou tokens trouvés dans le code
     * @param list<string>                                                                  $sourcemaps         références de sourcemaps (.js.map)
     * @param list<string>                                                                  $suspiciousComments commentaires avec IP, TODO, identifiants
     */
    public function __construct(
        public readonly ?string $title,
        public readonly array $links = [],
        public readonly int $externalLinks = 0,
        public readonly array $scripts = [],
        public readonly array $insecureForms = [],
        public readonly array $tabnabbingLinks = [],
        public readonly array $mixedContent = [],
        public readonly array $secretsFound = [],
        public readonly array $sourcemaps = [],
        public readonly array $suspiciousComments = [],
    ) {
    }

    /**
     * Ajoute ce que révèlent les fichiers .js chargés par la page.
     *
     * @param list<array{type: string, sample: string, source?: string}> $secrets
     * @param list<string>                                               $sourcemaps
     */
    public function withScriptFindings(array $secrets, array $sourcemaps): self
    {
        return new self(
            title: $this->title,
            links: $this->links,
            externalLinks: $this->externalLinks,
            scripts: $this->scripts,
            insecureForms: $this->insecureForms,
            tabnabbingLinks: $this->tabnabbingLinks,
            mixedContent: $this->mixedContent,
            secretsFound: [...$this->secretsFound, ...$secrets],
            sourcemaps: array_values(array_unique([...$this->sourcemaps, ...$sourcemaps])),
            suspiciousComments: $this->suspiciousComments,
        );
    }
}
