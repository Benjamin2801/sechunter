<?php

namespace App\Tests\Crawl;

use App\Crawl\Issue;
use App\Crawl\PageAudit;
use App\Crawl\PageCrawler;
use App\Crawl\PageReport;
use App\Crawl\SiteDiscovery;
use App\Crawl\SiteScope;
use App\Tests\Http\FakeSite;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

final class PageCrawlerTest extends KernelTestCase
{
    protected function setUp(): void
    {
        $cache = static::getContainer()->get('cache.app');
        self::assertInstanceOf(CacheItemPoolInterface::class, $cache);
        $cache->clear();
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private static function service(string $class): object
    {
        $service = static::getContainer()->get($class);
        self::assertInstanceOf($class, $service);

        return $service;
    }

    /** @return array<string, PageReport> */
    private static function crawl(string ...$paths): array
    {
        $discovery = self::service(SiteDiscovery::class);

        $reports = self::service(PageCrawler::class)->crawl(
            array_values(array_map(static fn (string $path): string => FakeSite::ROOT.$path, $paths)),
            new SiteScope(FakeSite::ROOT),
            $discovery->robots(FakeSite::ROOT),
            microtime(true) + 30,
        );

        return array_combine(array_map(static fn (PageReport $r): string => $r->url, $reports), $reports);
    }

    public function testAuditsSecurityOfHome(): void
    {
        $home = self::crawl('')[FakeSite::ROOT];

        self::assertSame(200, $home->status);
        self::assertTrue($home->isHtml());
        self::assertSame('Accueil du site de test SecHunter', $home->content?->title);

        $issues = PageAudit::issues($home);
        self::assertContains(Issue::CspMissing, $issues);
        self::assertContains(Issue::HstsMissing, $issues);
        self::assertContains(Issue::XFrameMissing, $issues);
        self::assertContains(Issue::NosniffMissing, $issues);
        self::assertContains(Issue::ServerHeaderLeak, $issues);
        self::assertContains(Issue::CookieNoSecure, $issues);
        self::assertContains(Issue::Tabnabbing, $issues);
    }

    public function testAuditsSecurityOfVulnerablePage(): void
    {
        $vuln = self::crawl('vuln')[FakeSite::ROOT.'vuln'];

        self::assertSame(200, $vuln->status);
        $issues = PageAudit::issues($vuln);

        self::assertContains(Issue::SecretTokenExposed, $issues);
        self::assertContains(Issue::MixedContent, $issues);
        self::assertContains(Issue::InsecureFormAction, $issues);
        self::assertContains(Issue::SourcemapExposed, $issues);
        self::assertContains(Issue::CommentLeak, $issues);
        self::assertContains(Issue::ServerHeaderLeak, $issues);
    }

    public function testAuditsSecurityOfProperlySecuredPage(): void
    {
        $secure = self::crawl('secure')[FakeSite::ROOT.'secure'];

        self::assertSame(200, $secure->status);
        $issues = PageAudit::issues($secure);

        self::assertNotContains(Issue::CspMissing, $issues);
        self::assertNotContains(Issue::HstsMissing, $issues);
        self::assertNotContains(Issue::XFrameMissing, $issues);
        self::assertNotContains(Issue::NosniffMissing, $issues);
        self::assertNotContains(Issue::CookieNoSecure, $issues);
        self::assertNotContains(Issue::CookieNoHttpOnly, $issues);
        self::assertNotContains(Issue::SecretTokenExposed, $issues);
        self::assertNotContains(Issue::MixedContent, $issues);
    }

    public function testScansSameSiteScriptsOncePerBatch(): void
    {
        $site = static::getContainer()->get(FakeSite::class);
        self::assertInstanceOf(FakeSite::class, $site);

        $reports = self::crawl('', 'secure');
        $home = $reports[FakeSite::ROOT];

        self::assertSame([['type' => 'Stripe Secret / Live Key', 'sample' => 'sk_l'.str_repeat('*', 24).'a1a1', 'source' => FakeSite::ROOT.'app.js']], $home->content?->secretsFound);
        self::assertSame([FakeSite::ROOT.'app.js.map'], $home->content->sourcemaps);
        self::assertContains(Issue::SecretTokenExposed, PageAudit::issues($home));
        self::assertNotContains(Issue::SecretTokenExposed, PageAudit::issues($reports[FakeSite::ROOT.'secure']));
        self::assertCount(1, array_keys($site->requestedUrls, FakeSite::ROOT.'app.js', true));
    }

    public function testHandles404AndRobots(): void
    {
        $reports = self::crawl('b', 'private/x');

        $missing = $reports[FakeSite::ROOT.'b'];
        self::assertSame(404, $missing->status);
        self::assertSame([Issue::HttpError], PageAudit::issues($missing));

        $blocked = $reports[FakeSite::ROOT.'private/x'];
        self::assertSame('robots', $blocked->error);
        self::assertSame([Issue::Blocked], PageAudit::issues($blocked));
    }
}
