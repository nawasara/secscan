<?php

namespace Nawasara\Secscan\Jobs;

use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Cloudflare\Models\CloudflareDnsRecord;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Models\SecscanFindingHistory;
use Nawasara\Secscan\Services\FindingTriage;
use Nawasara\Secscan\Services\HtmlSignalDetector;
use Nawasara\Secscan\Services\SiteHttpFetcher;
use Nawasara\Secscan\Services\SitemapProbe;
use Nawasara\Sync\Jobs\AbstractSyncJob;

/**
 * F2 HTTP probe scanner.
 *
 * Iterates all A/CNAME records from nawasara/cloudflare that resolve to
 * *.ponorogo.go.id, reads each site as Googlebot and as a phone arriving from
 * Google (cloaking), plus WordPress high-risk paths and a few sitemap URLs —
 * see probeHost(). Runs HtmlSignalDetector and upserts findings into
 * nawasara_secscan_findings with scan_source='http'.
 *
 * Read-only against target sites — the only writes are to local secscan tables.
 */
class ScanHttpJob extends AbstractSyncJob
{
    public int $timeout = 900;

    protected function service(): string  { return 'secscan'; }
    protected function action(): string   { return 'scan_http'; }
    protected function targetType(): ?string { return null; }
    protected function targetId(): ?string   { return null; }

    protected function execute(): array
    {
        $fetcher  = app(SiteHttpFetcher::class);
        $detector = app(HtmlSignalDetector::class);
        $suffix   = config('nawasara-secscan.expected_host_suffix', 'ponorogo.go.id');
        $alertMin = (int) config('nawasara-secscan.thresholds.alert_min_score', 70);

        $hostnames = $this->resolveHostnames($suffix);

        // Time-box the scan so it always finishes cleanly before the worker
        // timeout kills it (which corrupts failed_jobs + leaves the sync tracker
        // stuck). With many hosts × throttle, one pass can exceed the limit; we
        // stop early and the next scheduled run (every 6h) resumes from where a
        // rotating offset left off, so all hosts get covered over time.
        $started    = microtime(true);
        $budgetSecs = max(60, $this->timeout - 120); // leave a safety margin
        $timedOut   = false;

        // Rotate the starting point each run so we don't always scan the same
        // prefix of hosts and starve the tail of the list.
        $hostnames = $this->rotateHostList($hostnames);

        $scanned = 0;
        $findings = 0;
        $created  = 0;
        $updated  = 0;
        $alerted  = 0;
        $skipped  = 0;
        $hostsDone = 0;

        // Pages fetched and read this run. Only these may have findings closed
        // for "no longer detected": a page that errored, hit a challenge, or
        // was not reached before the time box says nothing about whether it
        // is clean.
        $scannedPaths = [];

        foreach ($hostnames as $hostname) {
            if (microtime(true) - $started > $budgetSecs) {
                $timedOut = true;
                break; // resume remaining hosts next scheduled run
            }

            foreach ($this->probeHost($fetcher, $detector, $hostname) as $page) {
                if ($page['skipped']) {
                    $skipped++;
                    continue;
                }
                if (! $page['scanned']) {
                    continue;
                }

                $scanned++;
                $path = $page['path'];
                $url  = $page['url'];
                $scannedPaths[$hostname.'|'.$path] = true;

                foreach ($page['signals'] as $signal) {
                    $findings++;
                    try {
                        ['created' => $c, 'updated' => $u, 'alerted' => $a] = $this->upsertFinding(
                            $hostname, $path, $url, $signal, $alertMin
                        );
                        $created += $c;
                        $updated += $u;
                        $alerted += $a;
                    } catch (\Throwable $e) {
                        // One malformed row must not abort the whole fleet scan.
                        \Illuminate\Support\Facades\Log::warning('secscan: upsertFinding failed', [
                            'hostname' => $hostname, 'path' => $path,
                            'threat' => $signal['threat_type'] ?? '?', 'error' => $e->getMessage(),
                        ]);
                    }
                }
            }

            $hostsDone++;
            // Remember how far we got so the next run resumes after this host.
            \Illuminate\Support\Facades\Cache::put('secscan:http:scan_offset', $this->scanOffset + $hostsDone, now()->addDay());
        }

        $hours = (int) config('nawasara-secscan.auto_resolve_after_hours', 24);
        $stale = SecscanFinding::active()
            ->where('scan_source', 'http')
            ->where('last_detected_at', '<', now()->subHours($hours))
            ->get()
            ->filter(fn (SecscanFinding $f) => isset($scannedPaths[$f->db_name.'|'.$f->scan_path]));
        $autoResolved = app(FindingTriage::class)->autoResolve($stale);

        return [
            'auto_resolved'     => $autoResolved,
            'hosts_total'       => count($hostnames),
            'hosts_scanned'     => $hostsDone,
            'paths_scanned'     => $scanned,
            'paths_skipped'     => $skipped,
            'findings_detected' => $findings,
            'created'           => $created,
            'updated'           => $updated,
            'alerted'           => $alerted,
            'timed_out'         => $timedOut, // true = stopped early, resumes next run
        ];
    }

    /** Offset into the host list used this run (persisted for rotation). */
    private int $scanOffset = 0;

    /**
     * Rotate the host list so each run starts after where the previous run
     * stopped — over successive runs every host gets covered even when a single
     * pass is time-boxed. The offset wraps around the list length.
     *
     * @param  list<string>  $hostnames
     * @return list<string>
     */
    private function rotateHostList(array $hostnames): array
    {
        $count = count($hostnames);
        if ($count === 0) {
            return $hostnames;
        }
        $offset = (int) \Illuminate\Support\Facades\Cache::get('secscan:http:scan_offset', 0) % $count;
        $this->scanOffset = $offset;

        // Start from $offset, wrapping around.
        return array_merge(
            array_slice($hostnames, $offset),
            array_slice($hostnames, 0, $offset),
        );
    }

    /**
     * Get unique hostnames from Cloudflare DNS records scoped to the expected suffix.
     *
     * @return list<string>
     */
    private function resolveHostnames(string $suffix): array
    {
        return CloudflareDnsRecord::query()
            ->whereIn('type', ['A', 'CNAME'])
            ->where('name', 'like', "%{$suffix}")
            ->where('proxied', true)   // only proxied = behind CF = our sites
            ->pluck('name')
            ->unique()
            ->values()
            ->all();
    }

    /**
     * Probe one host and return one entry per page read.
     *
     * What is fetched, and why:
     *  - "/" as Googlebot — what the search index sees.
     *  - "/" as a phone arriving from Google — the visitor cloakers target.
     *    The usual judol cloak serves the normal page to anyone typing the URL
     *    and swaps content (or redirects) only for search traffic. Staff open
     *    these links from a phone, which is how SLOT777 on umum was spotted.
     *  - WordPress high-risk paths — only when the homepage is WordPress;
     *    probing /wp-login.php on a Laravel site just burns the host's quota.
     *  - A few sitemap URLs — spam-looking slugs first, then the newest.
     *
     * @return list<array{path:string, url:string, scanned:bool, skipped:bool, signals:list<array>}>
     */
    private function probeHost(SiteHttpFetcher $fetcher, HtmlSignalDetector $detector, string $hostname): array
    {
        $pages = [];

        $home = $this->readPage($fetcher, $detector, $hostname, '/');

        if (config('nawasara-secscan.http_probe.cloak_check', true)) {
            $mobile = $this->readPage(
                $fetcher, $detector, $hostname, '/',
                SiteHttpFetcher::UA_MOBILE, SiteHttpFetcher::REFERER_GOOGLE,
            );
            $home['signals'] = self::mergeVariants($home, $mobile);
            $home['scanned'] = $home['scanned'] || $mobile['scanned'];
            $home['skipped'] = $home['skipped'] && $mobile['skipped'];
        }
        $pages[] = $home;

        if (str_contains($home['body'], '/wp-content/') || str_contains($home['body'], '/wp-includes/')) {
            foreach ((array) config('nawasara-secscan.http_probe.wp_paths', ['/wp-login.php', '/wp-content/uploads/']) as $path) {
                $pages[] = $this->readPage($fetcher, $detector, $hostname, $path);
            }
        }

        $limit = (int) config('nawasara-secscan.http_probe.sitemap_urls', 3);
        if ($limit > 0) {
            $sitemap = app(SitemapProbe::class)->discover($hostname, $limit);

            // Recorded as read even when clean, so a sitemap finding closes
            // itself once the spam slugs are gone (see auto-resolve below).
            if (($sitemap['sitemap'] ?? null) !== null) {
                $pages[] = [
                    'path' => '/sitemap.xml',
                    'url' => $sitemap['sitemap'],
                    'scanned' => true,
                    'skipped' => false,
                    'body' => '',
                    'signals' => ($sitemap['spam_count'] ?? 0) > 0 ? [self::sitemapSignal($sitemap)] : [],
                ];
            }

            foreach ($sitemap['paths'] ?? [] as $path) {
                $pages[] = $this->readPage($fetcher, $detector, $hostname, $path);
            }
        }

        return $pages;
    }

    /**
     * Fetch one page as one visitor type and run the detectors on it.
     *
     * @return array{path:string, url:string, scanned:bool, skipped:bool, body:string, signals:list<array>}
     */
    private function readPage(
        SiteHttpFetcher $fetcher,
        HtmlSignalDetector $detector,
        string $hostname,
        string $path,
        string $ua = SiteHttpFetcher::UA_GOOGLEBOT,
        ?string $referer = null,
    ): array {
        $page = ['path' => $path, 'url' => 'https://'.$hostname.$path, 'scanned' => false, 'skipped' => false, 'body' => '', 'signals' => []];

        $result = $fetcher->fetch($hostname, $path, $ua, true, $referer);

        if ($result === null || ! empty($result['error']) || ($result['is_challenge'] ?? false)) {
            $page['skipped'] = true;

            return $page;
        }

        $statusCode = $result['status_code'] ?? 0;
        if ($statusCode < 200 || $statusCode >= 400) {
            // Off-domain redirects still matter even though nothing was read.
            if ($signal = $this->detectRedirectHijack($result, $hostname)) {
                $page['scanned'] = true;
                $page['signals'][] = $signal;
            }

            return $page;
        }

        $page['scanned'] = true;
        $page['body'] = (string) ($result['body'] ?? '');
        $page['url'] = $result['final_url'] ?? $result['url'];
        $page['signals'] = $detector->detect($page['body'], $page['url'], $hostname);

        if ($signal = $this->detectRedirectHijack($result, $hostname)) {
            $page['signals'][] = $signal;
        }

        return $page;
    }

    /**
     * Merge the Googlebot and Google-referred-phone readings of one page.
     *
     * One signal per threat type (the finding key is host + path + threat), at
     * the higher score. A signal seen by only ONE visitor type is the cloaking
     * itself — the page shows a different face depending on who asks — and is
     * tagged so staff know why a URL that "looks clean" was flagged.
     *
     * @param  array{scanned:bool, signals:list<array>}  $bot
     * @param  array{scanned:bool, signals:list<array>}  $mobile
     * @return list<array>
     */
    public static function mergeVariants(array $bot, array $mobile): array
    {
        $byType = [];
        $seenBy = [];

        foreach (['googlebot' => $bot, 'mobile_google' => $mobile] as $variant => $page) {
            foreach ($page['signals'] as $signal) {
                $type = $signal['threat_type'];
                $seenBy[$type][] = $variant;

                if (! isset($byType[$type]) || $signal['score'] > $byType[$type]['score']) {
                    $byType[$type] = $signal;
                }
            }
        }

        foreach ($byType as $type => &$signal) {
            $variants = array_values(array_unique($seenBy[$type]));
            $signal['evidence']['variants'] = $variants;

            // Only meaningful when both readings succeeded; a failed fetch is
            // not "the page looked clean to that visitor".
            if (count($variants) === 1 && $bot['scanned'] && $mobile['scanned']) {
                $signal['evidence']['cloaking'] = $variants[0];
            }
        }
        unset($signal);

        return array_values($byType);
    }

    /** Spam slugs listed in the site's own sitemap. */
    public static function sitemapSignal(array $sitemap): array
    {
        $count = (int) $sitemap['spam_count'];

        // Pharma slugs ("jual-obat-aborsi") are a different threat with a
        // different cleanup audience; anything else here is gambling.
        $pharma = array_map('strtolower', (array) config('nawasara-secscan.pharma_keywords_strong', []));
        $isPharma = $sitemap['spam_urls'] !== [] && collect($sitemap['spam_urls'])
            ->every(fn ($u) => array_intersect($u['keywords'], $pharma) !== []);

        return [
            'threat_type' => $isPharma ? 'illegal_pharma' : 'judol',
            // The site itself advertises these URLs to Google — no ambiguity
            // left about whether the content is there.
            'score' => min(100, 70 + $count * 5),
            'evidence' => [
                'source' => 'http',
                'url' => $sitemap['sitemap'],
                'sitemap_spam_count' => $count,
                'sitemap_total' => (int) $sitemap['total'],
                'sitemap_spam_urls' => $sitemap['spam_urls'],
            ],
        ];
    }

    /**
     * Detect if the final URL after redirect resolves off the expected domain.
     */
    private function detectRedirectHijack(array $result, string $hostname): ?array
    {
        $finalUrl = $result['final_url'] ?? '';
        $suffix   = config('nawasara-secscan.expected_host_suffix', 'ponorogo.go.id');

        if ($finalUrl === '' || $finalUrl === ($result['url'] ?? '')) {
            return null;
        }

        $parsed = parse_url($finalUrl);
        $finalHost = $parsed['host'] ?? '';

        if ($finalHost === '' || str_ends_with($finalHost, $suffix)) {
            return null;
        }

        return [
            'threat_type' => 'defaced',
            'score'       => 85,
            'evidence'    => [
                'source'          => 'http',
                'url'             => $result['url'],
                'redirect_target' => $finalUrl,
                'redirect_chain'  => $result['redirect_chain'] ?? [],
                'note'            => 'Homepage redirects off-domain',
            ],
        ];
    }

    /**
     * Upsert a finding from HTTP probe. Mirrors ScanWordpressJob upsert logic
     * but keys on (db_name=hostname, scan_path=path, threat_type).
     *
     * @return array{created:int, updated:int, alerted:int}
     */
    private function upsertFinding(
        string $hostname,
        string $path,
        string $url,
        array $signal,
        int $alertMin,
    ): array {
        $now = now();
        $created = $updated = $alerted = 0;

        // Off-domain redirect targets (e.g. Cloudflare Access login URLs with a
        // JWT) can be very long; scan_url is TEXT but cap defensively so an
        // extreme URL never bloats the row or the evidence JSON.
        $url = mb_substr($url, 0, 2000);

        $existing = SecscanFinding::where('db_name', $hostname)
            ->where('scan_path', $path)
            ->where('threat_type', $signal['threat_type'])
            ->first();

        if (! $existing) {
            $finding = SecscanFinding::create([
                'scan_source'      => 'http',
                'db_name'          => $hostname,
                'site_url'         => 'https://' . $hostname,
                'site_name'        => $hostname,
                'scan_path'        => $path,
                'scan_url'         => $url,
                'threat_type'      => $signal['threat_type'],
                'severity'         => $this->severityFor($signal['score']),
                'score'            => $signal['score'],
                'status'           => SecscanFinding::STATUS_OPEN,
                'evidence'         => $signal['evidence'],
                'first_detected_at' => $now,
                'last_detected_at'  => $now,
            ]);

            SecscanFindingHistory::create([
                'finding_id'  => $finding->id,
                'status_from' => null,
                'status_to'   => SecscanFinding::STATUS_OPEN,
                'changed_by'  => null,
                'reason'      => 'Terdeteksi oleh HTTP probe otomatis.',
                'created_at'  => $now,
            ]);

            $created++;
        } else {
            // False positive stays dismissed: staff said the detector is wrong
            // about this page. Selesai detected again is reopened, because the
            // page is still serving what was detected; see FindingTriage.
            if ($existing->status === SecscanFinding::STATUS_FALSE_POSITIVE) {
                return compact('created', 'updated', 'alerted');
            }

            app(FindingTriage::class)->reopenIfResolved($existing);

            $existing->forceFill([
                'scan_url'        => $url,
                'severity'        => $this->severityFor($signal['score']),
                'score'           => $signal['score'],
                'evidence'        => $signal['evidence'],
                'last_detected_at' => $now,
            ])->save();

            $updated++;
            $finding = $existing;
        }

        // Fire alert for active high-confidence findings
        if ($finding->isActive() && $signal['score'] >= $alertMin) {
            Alerter::fire(
                $this->ruleFor($signal['threat_type']),
                'SecscanFinding',
                (string) $finding->id,
                [
                    'site_name'   => $hostname,
                    'db_name'     => $hostname,
                    'threat_type' => $finding->threatLabel(),
                    'score'       => $signal['score'],
                    'site_url'    => 'https://' . $hostname . $path,
                    'source'      => 'http',
                ]
            );
            $alerted++;
        }

        return compact('created', 'updated', 'alerted');
    }

    private function severityFor(int $score): string
    {
        $critical = (int) config('nawasara-secscan.thresholds.critical', 70);
        $warning  = (int) config('nawasara-secscan.thresholds.warning', 40);

        if ($score >= $critical) return SecscanFinding::SEVERITY_CRITICAL;
        if ($score >= $warning)  return SecscanFinding::SEVERITY_WARNING;
        return SecscanFinding::SEVERITY_INFO;
    }

    private function ruleFor(string $threatType): string
    {
        return match ($threatType) {
            'judol', 'illegal_pharma', 'defaced', 'malware', 'phishing' => 'secscan.site.compromised',
            default => 'secscan.site.suspicious',
        };
    }
}
