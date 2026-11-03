document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
    button.hidden = false;
    button.addEventListener('click', () => {
        const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
        document.documentElement.dataset.theme = theme;
        try {
            localStorage.setItem('theme', theme);
        } catch {
        }
    });
});

document.querySelectorAll('[data-to-form]').forEach((link) => {
    link.addEventListener('click', (event) => {
        event.preventDefault();
        window.scrollTo({ top: 0, behavior: 'smooth' });
        document.getElementById('url')?.focus({ preventScroll: true });
    });
});

const crawlSection = document.querySelector('[data-crawl]');
if (crawlSection) {
    startCrawl(crawlSection);
}

// Le navigateur pilote l'audit : il maintient la file d'attente (queue),
// envoie des requêtes par lots au serveur Symfony et met à jour l'interface en direct.
function startCrawl(section) {
    const config = JSON.parse(section.querySelector('#crawl-config').textContent);
    const t = (key, params = {}) => (config.i18n[key] ?? key).replace(/%(\w+)%/g, (_, name) => params[name] ?? '');
    const $ = (selector) => section.querySelector(selector);

    const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const SEVERITY_WEIGHT = { critical: 25, high: 10, medium: 3, low: 1, info: 0 };
    const SCORE_PENALTY = { critical: 30, high: 15, medium: 5, low: 2, info: 0 };

    const pages = new Map();
    const depths = new Map([[config.root, 0]]);
    const incoming = new Map();
    const sitemap = new Set(config.sitemap ?? []);
    const queue = [config.root];
    let sitemapQueued = false;
    let state = 'running';
    let sort = { key: 'order', direction: 1 };
    const opened = new Set();
    const openDrawers = new Set();

    const bareHost = (url) => new URL(url).host.replace(/^www\./, '');
    const rootHost = bareHost(config.root);
    const isInternal = (url) => {
        try {
            return bareHost(url) === rootHost;
        } catch {
            return false;
        }
    };

    let blockedCount = 0;
    const counted = () => depths.size - blockedCount;
    const discover = (url, depth, blocked = false) => {
        if (!depths.has(url)) {
            if (!blocked && counted() >= config.maxPages) {
                return;
            }
            depths.set(url, depth);
            if (blocked) {
                ++blockedCount;
                record({ ...failed(url), error: 'robots', issues: ['blocked'] });
            } else {
                queue.push(url);
            }
        } else if (depth !== null && (depths.get(url) === null || depth < depths.get(url))) {
            depths.set(url, depth);
        }
    };

    const number = new Intl.NumberFormat(document.documentElement.lang);
    const percent = (part, total) => (total ? Math.round((part / total) * 100) : 0);

    const el = (tag, attributes = {}, ...children) => {
        const node = document.createElement(tag);
        Object.entries(attributes).forEach(([name, value]) => {
            if (value !== null && value !== undefined && value !== false) {
                node.setAttribute(name, value === true ? '' : value);
            }
        });
        node.append(...children.flat().filter((child) => child !== null && child !== undefined && child !== false));

        return node;
    };

    const rootHostname = new URL(config.root).host;
    const path = (url) => {
        try {
            const parsed = new URL(url);
            let local = parsed.pathname + parsed.search;
            try {
                local = decodeURI(local);
            } catch {}
            return parsed.host === rootHostname ? local : `${parsed.host}${local}`;
        } catch {
            return url;
        }
    };

    const issuesOf = (page) => (page.issues ?? [])
        .filter((code) => config.issues[code])
        .sort((a, b) => (SEVERITY_ORDER[config.issues[a].severity] ?? 9) - (SEVERITY_ORDER[config.issues[b].severity] ?? 9));

    const pageScore = (page) => Math.max(0, 100 - issuesOf(page).reduce((sum, code) => sum + (SCORE_PENALTY[config.issues[code].severity] ?? 0), 0));
    const hasSeverity = (page, severity) => issuesOf(page).some((code) => config.issues[code].severity === severity);

    const severityCounts = (page) => {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        issuesOf(page).forEach((code) => {
            const sev = config.issues[code].severity;
            if (counts[sev] !== undefined) counts[sev]++;
        });
        return counts;
    };

    const metric = (value, className = null, title = null) => el('span', { class: `metric ${className ?? ''}`, title }, String(value));

    // Colonnes du tableau
    const columns = [
        { key: 'url', sort: (p) => p.url, cell: pageCell, className: 'is-page' },
        { key: 'status', sort: (p) => p.status, cell: statusCell },
        { key: 'depth', sort: (p) => depths.get(p.url) ?? 99, cell: (p) => metric(depths.get(p.url) ?? '—'), className: 'is-number' },
        { key: 'headers', sort: (p) => headersScore(p), cell: headersCell },
        { key: 'cookies', sort: (p) => (p.cookies?.length ?? 0), cell: cookiesCell },
        { key: 'secrets', sort: (p) => (p.secretsFound?.length ?? 0), cell: secretsCell },
        { key: 'score', sort: (p) => pageScore(p), cell: scoreCell, className: 'is-number' },
        { key: 'issues', sort: (p) => {
            const c = severityCounts(p);
            return c.critical * 1e6 + c.high * 1e4 + c.medium * 100 + c.low;
        }, cell: issuesCell },
    ];

    function headersScore(page) {
        const h = page.headers ?? {};
        let count = 0;
        if (h['content-security-policy']) count++;
        if (h['strict-transport-security']) count++;
        if (h['x-frame-options']) count++;
        if (h['x-content-type-options']) count++;
        return count;
    }

    function pageCell(page) {
        const sub = page.html ? (page.title || '—')
            : page.redirect ? `→ ${isInternal(page.redirect) ? path(page.redirect) : page.redirect}`
                : page.contentType ?? (page.error ? t(`error.${page.error}`) : '—');

        return el('button', { type: 'button', class: 'page-toggle', 'aria-expanded': String(opened.has(page.url)) },
            el('span', { class: 'chevron', 'aria-hidden': 'true' }),
            el('span', { class: 'page-text' },
                el('span', { class: 'page-path', title: page.url }, path(page.url)),
                el('span', { class: 'page-sub', title: sub }, sub)));
    }

    function statusCell(page) {
        const label = page.status || (page.error ? t(`error.${page.error}`) : '0');
        const kind = page.status >= 400 || page.status === 0 ? (page.error === 'robots' ? 'is-file' : 'is-error')
            : page.redirect ? 'is-redirect' : page.html ? 'is-ok' : 'is-file';

        return el('span', { class: `status ${kind}`, title: page.redirect ?? page.contentType ?? '' }, String(label));
    }

    function headersCell(page) {
        if (!page.html && page.status !== 200) return el('span', { class: 'muted' }, '—');
        const count = headersScore(page);
        const className = count >= 3 ? 'is-good' : count >= 1 ? 'is-warn' : 'is-bad';
        return el('span', { class: `metric ${className}`, title: t('cell.headers', { count }) }, `${count}/4`);
    }

    function cookiesCell(page) {
        const count = page.cookies?.length ?? 0;
        if (!count) return el('span', { class: 'muted' }, '0');
        const insecure = page.cookies.filter((c) => !c.secure || !c.httponly).length;
        const className = insecure ? 'is-warn' : 'is-good';
        return el('span', { class: `metric ${className}`, title: t('cell.cookies', { insecure, count }) },
            insecure ? t('cell.cookies_alert', { count: insecure }) : `${count} OK`);
    }

    function secretsCell(page) {
        const count = page.secretsFound?.length ?? 0;
        if (!count) return el('span', { class: 'muted' }, '—');
        return el('span', { class: 'metric is-bad', title: t('cell.secrets', { count }) }, String(count));
    }

    function scoreCell(page) {
        if (page.status === 0 || page.error === 'robots') return el('span', { class: 'muted' }, '—');
        const score = pageScore(page);
        const kind = score >= 80 ? 'is-good' : score >= 50 ? 'is-warn' : 'is-bad';
        return el('span', { class: `metric ${kind}` }, String(score));
    }

    function issuesCell(page) {
        const counts = severityCounts(page);
        const pills = ['critical', 'high', 'medium', 'low'].filter((severity) => counts[severity])
            .map((severity) => el('span', { class: `pill is-${severity}`, title: `${counts[severity]} × ${t(`severity.${severity}`)}` }, String(counts[severity])));
        if (!pills.length) pills.push(el('span', { class: 'pill is-info' }, '0'));

        return el('span', { class: 'issue-counts' }, pills);
    }

    // Synthèse au-dessus du tableau
    function renderSynthesis() {
        const all = [...pages.values()].filter((p) => p.error !== 'robots');
        const withCritical = all.filter((p) => hasSeverity(p, 'critical')).length;
        const withHigh = all.filter((p) => hasSeverity(p, 'high')).length;
        const score = all.length ? Math.round(all.reduce((sum, p) => sum + pageScore(p), 0) / all.length) : null;

        const counts = new Map();
        all.forEach((p) => issuesOf(p).forEach((code) => counts.set(code, (counts.get(code) ?? 0) + 1)));
        const impact = ([code, n]) => (SEVERITY_WEIGHT[config.issues[code]?.severity] ?? 0) * n;
        const top = [...counts.entries()].filter((entry) => impact(entry) > 0).sort((a, b) => impact(b) - impact(a)).slice(0, 8);

        const stat = (label, value, className = null, title = null) => el('div', { class: `stat ${className ?? ''}`, title },
            el('dt', {}, label), el('dd', {}, value));

        const scoreClass = score === null ? null : `is-score ${score >= 80 ? 'is-good' : score >= 50 ? 'is-warn' : 'is-bad'}`;
        const grade = score === null ? null : t(`score.grade_${score >= 90 ? 'a' : score >= 80 ? 'b' : score >= 60 ? 'c' : score >= 40 ? 'd' : 'f'}`);

        $('[data-synthesis]').replaceChildren(
            el('dl', { class: 'stats' },
                stat(t('synth.score'), score === null ? '—' : [String(score), el('small', {}, '/100')], scoreClass, grade),
                stat(t('synth.pages'), number.format(all.length)),
                stat(t('synth.critical'), number.format(withCritical), withCritical ? 'is-error' : null),
                stat(t('synth.high'), number.format(withHigh), withHigh ? 'is-warn' : null)),
            el('div', { class: 'synthesis-card' },
                el('div', { class: 'synthesis-head' },
                    el('h2', {}, t('synth.top')),
                    filter.value ? el('button', { type: 'button', class: 'link-button', 'data-reset': true }, t('synth.show_all')) : null),
                top.length ? el('ol', { class: 'top-issues' }, top.map(([code, n]) => el('li', {},
                    el('button', {
                        type: 'button',
                        'data-issue': code,
                        'aria-pressed': String(filter.value === code),
                        title: `${config.issues[code]?.why ?? ''}\n→ ${config.issues[code]?.fix ?? ''}`,
                    },
                        el('span', { class: `dot is-${config.issues[code]?.severity ?? 'notice'}` }),
                        el('span', { class: 'top-issue-label' }, config.issues[code]?.label ?? code),
                        el('b', {}, t('synth.share', { count: number.format(n), percent: percent(n, all.length) }))))))
                    : el('p', { class: 'muted' }, t('synth.none'))),
        );
    }

    // Gestion de la table, du filtre et de la recherche
    const head = $('[data-head]');
    const body = $('[data-body]');
    const search = $('[data-search]');
    const filter = $('[data-filter]');

    head.append(el('tr', {}, columns.map((column) => el('th', {
        scope: 'col',
        class: column.className ?? null,
        'data-key': column.key,
    }, el('button', { type: 'button', 'data-sort': column.key }, t(`columns.${column.key}`))))));

    head.addEventListener('click', (event) => {
        const key = event.target.closest('[data-sort]')?.dataset.sort;
        if (!key) return;
        sort = { key, direction: sort.key === key ? -sort.direction : (key === 'url' || key === 'depth' ? 1 : -1) };
        head.querySelectorAll('[data-sort]').forEach((button) => {
            button.removeAttribute('aria-sort');
            if (button.dataset.sort === sort.key) {
                button.setAttribute('aria-sort', sort.direction === 1 ? 'ascending' : 'descending');
            }
        });
        renderTable();
    });

    function renderFilter() {
        const counts = { all: pages.size, critical: 0, high: 0, medium: 0, low: 0, headers: 0, cookies: 0, secrets: 0, dom: 0, clean: 0 };
        pages.forEach((page) => {
            const issues = issuesOf(page);
            if (!issues.length) counts.clean++;
            if (hasSeverity(page, 'critical')) counts.critical++;
            if (hasSeverity(page, 'high')) counts.high++;
            if (hasSeverity(page, 'medium')) counts.medium++;
            if (hasSeverity(page, 'low')) counts.low++;
            if (issues.some((c) => config.issues[c]?.category === 'headers')) counts.headers++;
            if (issues.some((c) => config.issues[c]?.category === 'cookies')) counts.cookies++;
            if (issues.some((c) => config.issues[c]?.category === 'secrets')) counts.secrets++;
            if (issues.some((c) => config.issues[c]?.category === 'dom')) counts.dom++;
        });

        const previous = filter.value;
        filter.replaceChildren(
            el('option', { value: '' }, `${t('filter.all')} (${counts.all})`),
            el('option', { value: 'critical' }, `${t('filter.critical')} (${counts.critical})`),
            el('option', { value: 'high' }, `${t('filter.high')} (${counts.high})`),
            el('option', { value: 'medium' }, `${t('filter.medium')} (${counts.medium})`),
            el('option', { value: 'low' }, `${t('filter.low')} (${counts.low})`),
            el('option', { value: 'cat:headers' }, `${t('filter.headers')} (${counts.headers})`),
            el('option', { value: 'cat:cookies' }, `${t('filter.cookies')} (${counts.cookies})`),
            el('option', { value: 'cat:secrets' }, `${t('filter.secrets')} (${counts.secrets})`),
            el('option', { value: 'cat:dom' }, `${t('filter.dom')} (${counts.dom})`),
            el('option', { value: 'clean' }, `${t('filter.clean')} (${counts.clean})`),
        );
        filter.value = previous;
    }

    const matchesFilter = (page) => {
        const val = filter.value;
        if (!val) return true;
        if (val === 'critical' || val === 'high' || val === 'medium' || val === 'low') return hasSeverity(page, val);
        if (val === 'clean') return issuesOf(page).length === 0;
        if (val.startsWith('cat:')) {
            const cat = val.slice(4);
            return issuesOf(page).some((code) => config.issues[code]?.category === cat);
        }
        return issuesOf(page).includes(val);
    };

    const matchesSearch = (page, query) => {
        if (!query) return true;
        const q = query.toLowerCase();
        if (page.url.toLowerCase().includes(q)) return true;
        if (page.title?.toLowerCase().includes(q)) return true;
        return issuesOf(page).some((code) => config.issues[code]?.label.toLowerCase().includes(q));
    };

    function renderTable() {
        const query = search.value.trim();
        const sorted = [...pages.values()]
            .filter((p) => matchesFilter(p) && matchesSearch(p, query))
            .sort((a, b) => {
                const col = columns.find((c) => c.key === sort.key);
                if (!col?.sort) return (a.order - b.order) * sort.direction;
                const va = col.sort(a);
                const vb = col.sort(b);
                if (va === vb) return a.order - b.order;
                if (va === null || va === undefined) return 1;
                if (vb === null || vb === undefined) return -1;
                return (va < vb ? -1 : 1) * sort.direction;
            });

        const rows = [];
        sorted.forEach((page) => {
            rows.push(el('tr', { 'data-url': page.url, class: opened.has(page.url) ? 'is-open' : null },
                columns.map((col) => el('td', { class: col.className ?? null, 'data-key': col.key }, col.cell(page)))));

            if (opened.has(page.url)) {
                rows.push(el('tr', { class: 'detail-row', 'data-url': page.url }, el('td', { colspan: columns.length }, detail(page))));
            }
        });

        body.replaceChildren(...rows);
    }

    body.addEventListener('click', (event) => {
        const button = event.target.closest('.page-toggle');
        if (!button) return;
        const row = button.closest('tr');
        const url = row.dataset.url;
        if (opened.has(url)) {
            opened.delete(url);
        } else {
            opened.add(url);
        }
        renderTable();
    });

    body.addEventListener('toggle', (event) => {
        const d = event.target.closest('[data-drawer]');
        if (!d) return;
        if (d.open) {
            openDrawers.add(d.dataset.drawer);
        } else {
            openDrawers.delete(d.dataset.drawer);
        }
    }, true);

    search.addEventListener('input', () => renderTable());
    filter.addEventListener('change', () => renderTable());

    $('[data-synthesis]').addEventListener('click', (event) => {
        const reset = event.target.closest('[data-reset]');
        if (reset) {
            filter.value = '';
            renderTable();
            return;
        }
        const btn = event.target.closest('[data-issue]');
        if (btn) {
            filter.value = btn.dataset.issue;
            renderTable();
        }
    });

    // Tiroir d'inspection détaillée d'une page
    function detail(page) {
        const link = (url, label = url) => el('a', { href: url, target: '_blank', rel: 'noopener nofollow' }, label);
        const sectionEl = (title, ...children) => el('section', { class: 'detail-section' }, el('h3', {}, title), ...children);
        const facts = (rows) => el('dl', { class: 'facts' }, rows.filter(Boolean).map(([label, value, className]) => el('div', { class: className ?? null },
            el('dt', {}, label), el('dd', {}, value ?? '—'))));

        const codes = issuesOf(page);
        const issuesList = codes.length
            ? el('ul', { class: 'issue-list' }, codes.map((code) => {
                const info = config.issues[code] ?? {};
                return el('li', {},
                    el('details', { class: 'issue-help', 'data-drawer': `${page.url}|help|${code}`, open: openDrawers.has(`${page.url}|help|${code}`) },
                        el('summary', {}, el('span', { class: `dot is-${info.severity ?? 'notice'}` }), info.label ?? code),
                        el('p', {}, el('b', {}, t('drawer.why_title')), ' ', info.why ?? ''),
                        el('p', {}, el('b', {}, t('drawer.fix_title'))),
                        el('pre', { class: 'fix-code' }, el('code', {}, info.fix ?? ''))));
            }))
            : el('p', { class: 'muted' }, t('drawer.no_issues'));

        const drawer = (key, title, items) => (items && items.length ? el('details', {
            class: 'drawer',
            'data-drawer': `${page.url}|${key}`,
            open: openDrawers.has(`${page.url}|${key}`),
        },
            el('summary', {}, title, el('b', {}, number.format(items.length))),
            el('ul', {}, items.slice(0, 50).map((item) => el('li', {}, item)))) : null);

        const yesNo = (value) => t(value ? 'drawer.yes' : 'drawer.no');
        const headersList = Object.entries(page.headers ?? {}).map(([name, values]) =>
            el('div', { class: 'header-row' }, el('b', {}, `${name}: `), el('span', {}, values.join(', '))));
        const cookiesList = (page.cookies ?? []).map((c) => el('span', {}, t('drawer.cookie', {
            name: c.name, secure: yesNo(c.secure), httponly: yesNo(c.httponly), samesite: c.samesite ?? t('drawer.no'),
        })));
        const secretsList = (page.secretsFound ?? []).map((s) => el('span', {}, `${s.type} : ${s.sample}`, s.source ? [' · ', link(s.source, path(s.source))] : null));
        const sourcemapList = (page.sourcemaps ?? []).map((url) => link(url, path(url)));
        const formsList = (page.insecureForms ?? []).map((f) => el('span', {}, t('drawer.form', {
            method: f.method, action: f.action, password: yesNo(f.hasPassword), csrf: yesNo(f.hasCsrf),
        })));
        const mixedList = (page.mixedContent ?? []).map((url) => link(url));
        const tabList = (page.tabnabbingLinks ?? []).map((url) => link(url));
        const headerFact = (label, name, present = t('drawer.present')) =>
            [label, page.headers?.[name] ? present : t('drawer.absent'), page.headers?.[name] ? 'is-good' : 'is-warn'];

        const drawers = el('div', { class: 'drawers' },
            drawer('secrets', t('drawer.secrets_title', { count: secretsList.length }), secretsList),
            drawer('sourcemaps', t('drawer.sourcemaps_title', { count: sourcemapList.length }), sourcemapList),
            drawer('forms', t('drawer.forms_title', { count: formsList.length }), formsList),
            drawer('mixed', t('drawer.mixed_title', { count: mixedList.length }), mixedList),
            drawer('tabnabbing', t('drawer.tabnabbing_title', { count: tabList.length }), tabList),
            drawer('cookies', t('drawer.cookies_received', { count: cookiesList.length }), cookiesList),
            drawer('headers', t('drawer.headers_received', { count: headersList.length }), headersList),
        );

        return el('div', { class: 'detail' },
            el('div', { class: 'detail-grid' },
                sectionEl(t('drawer.issues_title', { count: codes.length }),
                    facts([
                        [t('drawer.score'), `${pageScore(page)} / 100`, pageScore(page) >= 80 ? 'is-good' : pageScore(page) >= 50 ? 'is-warn' : 'is-error'],
                        [t('drawer.status'), String(page.status || t(`error.${page.error}`))],
                        [t('drawer.depth'), String(depths.get(page.url) ?? 0)],
                    ]),
                    issuesList),
                sectionEl(t('drawer.headers_title'),
                    facts([
                        headerFact('CSP', 'content-security-policy'),
                        headerFact('HSTS', 'strict-transport-security'),
                        headerFact('X-Frame-Options', 'x-frame-options'),
                        headerFact('X-Content-Type-Options', 'x-content-type-options', 'nosniff'),
                        [t('drawer.server'), page.headers?.['server']?.[0] ?? page.headers?.['x-powered-by']?.[0] ?? t('drawer.hidden')],
                    ])),
                sectionEl(t('drawer.dom_title'),
                    facts([
                        [t('drawer.cookies'), String(page.cookies?.length ?? 0)],
                        [t('drawer.secrets'), String(page.secretsFound?.length ?? 0), page.secretsFound?.length ? 'is-error' : null],
                        [t('drawer.mixed'), String(page.mixedContent?.length ?? 0), page.mixedContent?.length ? 'is-error' : null],
                        [t('drawer.tabnabbing'), String(page.tabnabbingLinks?.length ?? 0), page.tabnabbingLinks?.length ? 'is-warn' : null],
                    ]))),
            drawers);
    }

    // Export CSV
    $('[data-csv]').addEventListener('click', () => {
        const severities = ['critical', 'high', 'medium', 'low'];
        const rows = [[...['url', 'status', 'depth', 'score'].map((key) => t(`columns.${key}`)), ...severities.map((s) => t(`severity.${s}`)), t('columns.issues')]];
        pages.forEach((page) => {
            const counts = severityCounts(page);
            rows.push([
                page.url,
                page.status,
                depths.get(page.url) ?? 0,
                pageScore(page),
                ...severities.map((s) => counts[s]),
                issuesOf(page).map((code) => config.issues[code]?.label ?? code).join(' ; '),
            ]);
        });
        const csv = rows.map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\r\n');
        const a = el('a', {
            href: URL.createObjectURL(new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' })),
            download: section.dataset.filename || 'sechunter.csv',
        });
        a.click();
        URL.revokeObjectURL(a.href);
    });

    // Boucle de crawl
    const pauseButton = $('[data-pause]');
    const stopButton = $('[data-stop]');

    function renderStatus() {
        const analysed = pages.size;
        let status = t(`status.${state}`, { analysed, total: counted() });
        if (counted() >= config.maxPages && state !== 'running') {
            status += ` (${t('status.limit')})`;
        }
        $('[data-status]').textContent = status;
        $('[data-progress]').style.width = `${percent(analysed, counted())}%`;
        section.classList.toggle('is-running', state === 'running');
        pauseButton.querySelector('span').textContent = t(state === 'paused' ? 'resume' : 'pause');
        pauseButton.classList.toggle('is-paused', state === 'paused');
        pauseButton.hidden = stopButton.hidden = state === 'done' || state === 'stopped';
    }

    function render() {
        renderStatus();
        renderSynthesis();
        renderFilter();
        renderTable();
    }

    async function fetchBatch(urls) {
        const response = await fetch(config.endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ root: config.root, urls }),
        });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        return (await response.json()).pages;
    }

    const failed = (url) => ({
        url, status: 0, error: 'network', html: false,
        links: [], issues: ['http_error'], headers: {}, cookies: [],
    });

    function record(page) {
        page.order = pages.size;
        pages.set(page.url, page);
        const depth = depths.get(page.url);
        if (page.redirect && isInternal(page.redirect)) {
            discover(page.redirect, depth);
        }
        const blocked = new Set(page.blockedLinks ?? []);
        (page.links ?? []).forEach((link) => {
            if (!incoming.has(link)) {
                incoming.set(link, new Set());
            }
            incoming.get(link).add(page.url);
            discover(link, depth === null ? null : depth + 1, blocked.has(link));
        });
    }

    let looping = false;
    const THROTTLED = [429, 503];
    const MAX_RETRIES = 2;
    const RETRY_PAUSE_S = 5;
    const MAX_PAUSE_S = 30;
    const retries = new Map();
    let batchSize = config.batchSize;

    async function run() {
        if (looping) return;
        looping = true;
        while (state === 'running') {
            if (!queue.length) {
                if (sitemapQueued) {
                    state = 'done';
                    break;
                }
                sitemapQueued = true;
                (config.sitemap ?? []).forEach((url) => discover(url, null));
                continue;
            }
            const batch = queue.splice(0, batchSize);
            let reports;
            try {
                reports = await fetchBatch(batch);
            } catch {
                try {
                    reports = await fetchBatch(batch);
                } catch {
                    reports = batch.map(failed);
                }
            }
            let pause = 0;
            reports.forEach((report) => {
                const attempts = retries.get(report.url) ?? 0;
                if (!THROTTLED.includes(report.status) || attempts >= MAX_RETRIES) {
                    record(report);
                    return;
                }
                retries.set(report.url, attempts + 1);
                queue.push(report.url);
                batchSize = 1;
                pause = Math.max(pause, Math.min(MAX_PAUSE_S, report.retryAfter ?? RETRY_PAUSE_S * (attempts + 1)));
            });
            render();
            if (pause && state === 'running') {
                $('[data-status]').textContent = t('status.throttled', { s: pause });
                await new Promise((resolve) => setTimeout(resolve, pause * 1000));
            }
        }
        looping = false;
        render();
    }

    pauseButton.addEventListener('click', () => {
        if (state === 'paused') {
            state = 'running';
            run();
        } else if (state === 'running') {
            state = 'paused';
            renderStatus();
        }
    });

    stopButton.addEventListener('click', () => {
        state = 'stopped';
        queue.length = 0;
        render();
    });

    render();
    run();
}
