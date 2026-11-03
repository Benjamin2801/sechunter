<?php

namespace App\Tests\Crawl;

use App\Crawl\HtmlAnalyzer;
use App\Crawl\SecretScanner;
use App\Crawl\SiteScope;
use App\Tests\Http\FakeSite;
use PHPUnit\Framework\TestCase;

final class HtmlAnalyzerTest extends TestCase
{
    public function testExtractsLinksAndDetectsTabnabbing(): void
    {
        $analyzer = new HtmlAnalyzer();
        $page = $analyzer->analyze(FakeSite::HOME, FakeSite::ROOT, new SiteScope(FakeSite::ROOT));

        self::assertSame('Accueil du site de test SecHunter', $page->title);
        self::assertContains('https://www.site.test/a', $page->links);
        self::assertContains('https://www.site.test/b', $page->links);
        self::assertContains('https://www.site.test/vuln', $page->links);
        self::assertContains('https://www.site.test/secure', $page->links);
        self::assertContains('https://www.site.test/private/x', $page->links);
        self::assertSame(1, $page->externalLinks);
        self::assertSame(['https://ailleurs.test/'], $page->tabnabbingLinks);
    }

    public function testDetectsVulnerabilitiesInHtmlAndDom(): void
    {
        $analyzer = new HtmlAnalyzer();
        $page = $analyzer->analyze(FakeSite::VULN, 'https://www.site.test/vuln', new SiteScope(FakeSite::ROOT));

        // Mixed Content
        self::assertSame(['http://insecure.test/image.png'], $page->mixedContent);

        // Insecure form with password and HTTP action
        self::assertCount(1, $page->insecureForms);
        $form = $page->insecureForms[0];
        self::assertSame('http://insecure.test/login', $form['action']);
        self::assertSame('POST', $form['method']);
        self::assertTrue($form['hasPassword']);
        self::assertFalse($form['hasCsrf']);

        // Secrets in JS
        self::assertCount(1, $page->secretsFound);
        self::assertSame('AWS Access Key', $page->secretsFound[0]['type']);
        self::assertStringContainsString('AKIA', $page->secretsFound[0]['sample']);

        // Sourcemap
        self::assertCount(1, $page->sourcemaps);
        self::assertSame('https://www.site.test/bundle.js.map', $page->sourcemaps[0]);

        // Suspicious comment
        self::assertCount(1, $page->suspiciousComments);
        self::assertStringContainsString('192.168.1.50', $page->suspiciousComments[0]);
    }

    public function testSecretScannerPatterns(): void
    {
        // Préfixes coupés : les scanners de secrets (push protection GitHub) ne doivent pas y voir de vraies clés.
        [$stripe, $github] = ['sk_live_', 'ghp_'];
        $payload = <<<TXT
            stripe_live: "{$stripe}1234567890abcdef1234567890abcdef"
            google_key = "AIzaSyD-1234567890abcdef1234567890abcdef"
            github_token = "{$github}1234567890abcdef1234567890abcdef1234"
            jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        TXT;

        $findings = SecretScanner::scan($payload);
        $types = array_column($findings, 'type');

        self::assertContains('Stripe Secret / Live Key', $types);
        self::assertContains('Google Cloud / Maps API Key', $types);
        self::assertContains('GitHub Personal Access Token', $types);
        self::assertContains('JSON Web Token (JWT)', $types);
    }
}
