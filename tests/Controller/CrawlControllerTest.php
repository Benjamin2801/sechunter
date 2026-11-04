<?php

namespace App\Tests\Controller;

use App\Tests\Http\FakeSite;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class CrawlControllerTest extends WebTestCase
{
    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        $cache = static::getContainer()->get('cache.app');
        self::assertInstanceOf(CacheItemPoolInterface::class, $cache);
        $cache->clear();
    }

    public function testHomeShowsTheForm(): void
    {
        $this->client->request('GET', '/', server: ['HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9,en;q=0.8']);
        self::assertResponseRedirects('/fr');

        $this->client->request('GET', '/fr');
        self::assertResponseIsSuccessful();
        self::assertSelectorTextContains('.hero-facts', '50 pages');
        self::assertSelectorTextContains('.thresholds', 'Content-Security-Policy');
        self::assertSelectorTextContains('section[aria-labelledby="foundations-title"]', 'OWASP Top 10');
        self::assertSelectorTextContains('section[aria-labelledby="technologies-title"]', 'Symfony');
        self::assertSelectorExists('.foundation-card[href="https://www.w3.org/TR/CSP3/"]');
        self::assertSame(8, $this->client->getCrawler()->filter('.home-sources.is-tech .sources-list li')->count());
        self::assertSame(2, $this->client->getCrawler()->filter('.home-sources.is-tech svg.source-logo')->count());
        self::assertSame(6, $this->client->getCrawler()->filter('.home-sources.is-tech .source-mark')->count());
        self::assertSelectorExists('.home-discord-button[href="https://discord.gg/cdD8C6hjWu"]');
        self::assertSelectorTextContains('.home-discord', 'Rejoignez Net Labs sur Discord');
        self::assertSelectorExists('form.crawl-form input[name="url"]');
        self::assertSelectorExists('form.crawl-form input[name="consent"]');
        self::assertSelectorNotExists('.form-error');
    }

    public function testHomeLocalizesTheReferencesInEnglish(): void
    {
        $this->client->request('GET', '/en');

        self::assertResponseIsSuccessful();
        self::assertSelectorTextContains('section[aria-labelledby="foundations-title"]', 'Foundational security references');
        self::assertSelectorTextContains('section[aria-labelledby="technologies-title"]', 'Project technologies');
        self::assertSelectorTextContains('.home-sources.is-tech', 'Symfony');
        self::assertSelectorTextContains('.home-discord', 'Join Net Labs on Discord');
    }

    public function testStartsTheCrawlInTheBrowser(): void
    {
        $crawler = $this->client->request('GET', '/fr/crawl', ['url' => 'site.test']);

        self::assertResponseIsSuccessful();
        self::assertSelectorTextContains('h1', 'Audit de sécurité : www.site.test');
        self::assertSelectorTextContains('.crawl-meta', '3 pages dans le sitemap');
        self::assertSelectorExists('meta[name="robots"][content="noindex"]');
        self::assertInputValueSame('url', 'www.site.test');

        $config = json_decode($crawler->filter('#crawl-config')->text(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertSame(FakeSite::ROOT, $config['root']);
        self::assertSame('/fr/crawl/pages', $config['endpoint']);
        self::assertSame(50, $config['maxPages']);
        self::assertSame('critical', $config['issues']['secret_token_exposed']['severity']);
        self::assertSame('high', $config['issues']['csp_missing']['severity']);

        $fakeSite = static::getContainer()->get(FakeSite::class);
        self::assertInstanceOf(FakeSite::class, $fakeSite);
        self::assertSame(10.0, $fakeSite->requestedOptions[0]['timeout']);

        foreach ($config['issues'] as $code => $issue) {
            self::assertNotSame('', $issue['why'], $code.' : explication manquante.');
            self::assertNotSame('', $issue['fix'], $code.' : correction manquante.');
        }
    }

    public function testUnreachableSiteGoesBackToTheForm(): void
    {
        $this->client->request('GET', '/en/crawl', ['url' => 'https://down.test/']);

        self::assertResponseStatusCodeSame(422);
        self::assertSelectorTextContains('.form-error', 'HTTP error 503');
        self::assertInputValueSame('url', 'https://down.test/');
    }

    public function testEmptyAddressRedirectsHome(): void
    {
        $this->client->request('GET', '/fr/crawl', ['url' => '  ']);

        self::assertResponseRedirects('/fr');
    }

    public function testAnalysesABatchOfPages(): void
    {
        $this->client->jsonRequest('POST', '/fr/crawl/pages', ['root' => FakeSite::ROOT, 'urls' => [FakeSite::ROOT, 'https://www.site.test/b']]);

        self::assertResponseIsSuccessful();
        $pages = json_decode((string) $this->client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR)['pages'];
        self::assertCount(2, $pages);

        [$home, $missing] = $pages;
        self::assertSame(FakeSite::ROOT, $home['url']);
        self::assertTrue($home['html']);
        self::assertContains('csp_missing', $home['issues']);
        self::assertContains('https://www.site.test/a', $home['links']);

        self::assertSame(404, $missing['status']);
        self::assertSame(['http_error'], $missing['issues']);
    }

    public function testRefusesPagesOutsideTheSite(): void
    {
        $this->client->jsonRequest('POST', '/fr/crawl/pages', ['root' => FakeSite::ROOT, 'urls' => ['https://ailleurs.test/']]);
        self::assertResponseStatusCodeSame(400);
    }
}
