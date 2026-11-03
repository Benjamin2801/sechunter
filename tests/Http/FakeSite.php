<?php

namespace App\Tests\Http;

use Symfony\Component\HttpClient\Response\MockResponse;

// Faux site de test sans réseau pour les tests unitaires et d'intégration SecHunter.
final class FakeSite
{
    public const ROOT = 'https://www.site.test/';

    public const HOME = <<<'HTML'
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="utf-8">
            <title>Accueil du site de test SecHunter</title>
            <link rel="stylesheet" href="/style.css">
            <script src="/app.js" defer></script>
        </head>
        <body>
            <h1>Bienvenue sur SecHunter Test</h1>
            <a href="/a">Page A</a>
            <a href="/b">Page 404</a>
            <a href="/vuln">Page Vulnérable</a>
            <a href="/secure">Page Sécurisée</a>
            <a href="/private/x">Privé</a>
            <a href="https://ailleurs.test/" target="_blank">Ailleurs sans noopener</a>
        </body>
        </html>
        HTML;

    public const VULN = <<<'HTML'
        <!DOCTYPE html>
        <html>
        <head><title>Page Vulnérable</title></head>
        <body>
            <script>const apiKey = "AKIA1111222233334444";</script>
            <img src="http://insecure.test/image.png">
            <form action="http://insecure.test/login" method="POST">
                <input type="password" name="pwd">
                <button type="submit">Connexion</button>
            </form>
            <!-- TODO: changer le mot de passe admin admin123 sur 192.168.1.50 -->
            //# sourceMappingURL=bundle.js.map
        </body>
        </html>
        HTML;

    public const SECURE = <<<'HTML'
        <!DOCTYPE html>
        <html>
        <head><title>Page Sécurisée</title></head>
        <body>
            <h1>Page Propre</h1>
            <form action="https://www.site.test/contact" method="POST">
                <input type="hidden" name="_csrf_token" value="abc123token">
                <input type="text" name="name">
                <button type="submit">Envoyer</button>
            </form>
        </body>
        </html>
        HTML;

    /** @var list<string> */
    public array $requestedUrls = [];

    /** @var list<array<string, mixed>> */
    public array $requestedOptions = [];

    /** @param array<string, mixed> $options */
    public function __invoke(string $method, string $url, array $options = []): MockResponse
    {
        $this->requestedUrls[] = $url;
        $this->requestedOptions[] = $options;
        $html = ['content-type: text/html; charset=utf-8'];

        return match ($url) {
            'https://site.test/' => self::redirect(self::ROOT),
            'https://www.site.test/robots.txt' => new MockResponse("User-agent: *\nDisallow: /private/\n\nSitemap: https://www.site.test/sitemap.xml\n"),
            'https://www.site.test/sitemap.xml' => self::ok(<<<'XML'
                <?xml version="1.0" encoding="UTF-8"?>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                    <url><loc>https://www.site.test/</loc></url>
                    <url><loc>https://www.site.test/a</loc></url>
                    <url><loc>https://www.site.test/vuln</loc></url>
                </urlset>
                XML, ['content-type: application/xml']),
            self::ROOT => self::ok(self::HOME, [
                ...$html,
                'server: nginx/1.18.0',
                'set-cookie: session_id=abc; path=/',
            ]),
            'https://www.site.test/a' => self::ok('<html><body><h1>Page A</h1><a href="/vuln">Lien</a></body></html>', $html),
            'https://www.site.test/vuln' => self::ok(self::VULN, [
                ...$html,
                'x-powered-by: PHP/8.2.0',
            ]),
            'https://www.site.test/secure' => self::ok(self::SECURE, [
                ...$html,
                'content-security-policy: default-src \'self\'',
                'strict-transport-security: max-age=31536000; includeSubDomains',
                'x-frame-options: DENY',
                'x-content-type-options: nosniff',
                'referrer-policy: strict-origin-when-cross-origin',
                'permissions-policy: geolocation=()',
                'set-cookie: auth=xyz; Secure; HttpOnly; SameSite=Lax',
            ]),
            'https://www.site.test/app.js' => self::ok('const stripe = "sk_live_'.str_repeat('a1', 12).'";', ['content-type: application/javascript', 'sourcemap: /app.js.map']),
            'https://www.site.test/b' => new MockResponse('Introuvable', ['http_code' => 404, 'response_headers' => $html]),
            'https://down.test/' => new MockResponse('', ['http_code' => 503]),
            default => new MockResponse('Introuvable', ['http_code' => 404]),
        };
    }

    /** @param list<string> $headers */
    private static function ok(string $body, array $headers): MockResponse
    {
        return new MockResponse($body, ['response_headers' => $headers, 'size_download' => \strlen($body)]);
    }

    private static function redirect(string $location): MockResponse
    {
        return new MockResponse('', ['http_code' => 301, 'response_headers' => ['location' => $location]]);
    }
}
