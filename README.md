# SecHunter

[![CI](https://github.com/Benjamin2801/sechunter/actions/workflows/ci.yml/badge.svg)](https://github.com/Benjamin2801/sechunter/actions/workflows/ci.yml)

Passive web security audit for your own website. Type an address: SecHunter follows the internal links (and the
sitemap) up to 50 pages and fills a table with the security headers, cookies, exposed secrets and form flaws of every
page.

Companion of [SemSeeker](https://github.com/Benjamin2801/semseeker) and
[SemSpider](https://github.com/Benjamin2801/semspider), same stack and same constraints: shared hosting, no database,
no front-end build.

## What it checks

- **Security headers**: Content-Security-Policy (missing, `unsafe-inline`, `unsafe-eval`, `*` sources),
  Strict-Transport-Security (missing, max-age under 6 months), clickjacking protection (X-Frame-Options or
  `frame-ancestors`), `X-Content-Type-Options: nosniff`, Referrer-Policy, Permissions-Policy, CORS open to everyone with
  credentials, server versions leaked by `Server` or `X-Powered-By`.
- **Cookies**: `Secure`, `HttpOnly` and `SameSite` on every cookie set by a page.
- **Secrets**: API keys and tokens (AWS, Stripe, Google, GitHub, Slack, JWT, private keys) in the HTML, inline scripts
  and the site's own JavaScript files; sourcemaps announced by a page or its scripts.
- **Page content**: mixed content, password forms sent over HTTP, POST forms without a CSRF token, `target="_blank"`
  links without `noopener`, HTML comments revealing internal addresses or credentials.
- **Priorities**: a security score out of 100, a "fix first" list (severity × pages affected), and for every flaw why
  it matters and the configuration to add.

Results can be sorted, filtered by severity or category, opened page by page and exported as CSV.

## How a crawl runs

```
CrawlController::start      the home page (after redirects), robots.txt, sitemaps
public/js/app.js            the queue: batches of 4 pages, depth, score
└── CrawlController::pages  one batch, under 30 s (the host stops PHP after 165 s)
    └── PageCrawler             HTML of the 4 pages in parallel, then the site's scripts they load
        ├── HtmlAnalyzer        DOM: links, scripts, forms, mixed content, tabnabbing, comments
        ├── SecretScanner       API keys and sourcemaps in HTML and JavaScript
        └── PageAudit           headers, cookies and DOM against public recommendations (OWASP, ANSSI, RFCs)
```

The audit is passive: SecHunter only reads what any visitor receives, it never sends a payload or tries a password.
The browser drives the crawl, so no request comes near the hosting time limit and nothing has to be stored on the
server. Every request goes through Symfony's `NoPrivateNetworkHttpClient`: an address typed by a visitor can never
reach the server itself or its private network. robots.txt is followed, and scripts from other domains are not
downloaded.

## Stack

- Symfony 7.4 LTS, PHP 8.4 — no database, no front-end build (hand-written CSS and JavaScript)
- Symfony HttpClient (curl, parallel requests) and PHP's DOM

## Quality

PHPStan level 8, PHP-CS-Fixer (Symfony rules) and PHPUnit against a fake website (`tests/Http/FakeSite.php`), with no
network, run by GitHub Actions on every push. Code comments are in French.

## Getting started

```bash
composer install
php -S 127.0.0.1:8000 -t public
```

Or `docker compose up`, then open http://127.0.0.1:8000.

```bash
composer check    # style, static analysis, tests
```

The page limit and batch size are set in `config/services.yaml` (`app.crawl.*`).

## Deployment

`deploy/build.ps1` builds a production copy in `build/`. Each build gets its own Symfony cache directory
(`APP_BUILD_ID`), so a new version never reads the previous one's cache.

## License

[MIT](LICENSE)
