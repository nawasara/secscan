<?php

namespace Nawasara\Secscan\Jobs;

use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Cloudflare\Models\CloudflareDnsRecord;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Models\SecscanFindingHistory;
use Nawasara\Secscan\Services\HtmlSignalDetector;
use Nawasara\Secscan\Services\SiteHttpFetcher;
use Nawasara\Sync\Jobs\AbstractSyncJob;

/**
 * F2 HTTP probe scanner.
 *
 * Iterates all A/CNAME records from nawasara/cloudflare that resolve to
 * *.ponorogo.go.id, fetches the homepage (and a small set of high-risk paths)
 * with a Googlebot UA, runs HtmlSignalDetector, and upserts findings into
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

        foreach ($hostnames as $hostname) {
            if (microtime(true) - $started > $budgetSecs) {
                $timedOut = true;
                break; // resume remaining hosts next scheduled run
            }

            $pathsToScan = $this->pathsForHostname($hostname);

            foreach ($pathsToScan as $path) {
                $result = $fetcher->fetch($hostname, $path);

                if ($result === null || ! empty($result['error'])) {
                    $skipped++;
                    continue;
                }

                if ($result['is_challenge'] ?? false) {
                    $skipped++;
                    continue;
                }

                $statusCode = $result['status_code'] ?? 0;
                if ($statusCode < 200 || $statusCode >= 400) {
                    continue;
                }

                $scanned++;
                $html     = $result['body'] ?? '';
                $url      = $result['final_url'] ?? $result['url'];
                $signals  = $detector->detect($html, $url, $hostname);

                // Check for redirect hijack — final URL pointing off-domain
                $redirectSignal = $this->detectRedirectHijack($result, $hostname);
                if ($redirectSignal) {
                    $signals[] = $redirectSignal;
                }

                foreach ($signals as $signal) {
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

        return [
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
     * Paths to probe per hostname. Homepage always included; high-risk WP
     * paths added because SQL scanner may miss injected upload-dir pages.
     *
     * @return list<string>
     */
    private function pathsForHostname(string $hostname): array
    {
        $paths = ['/'];

        // WordPress-specific high-risk paths (common injection landing pages)
        $wpPaths = config('nawasara-secscan.http_probe.wp_paths', [
            '/wp-login.php',
            '/wp-content/uploads/',
            '/wp-admin/',
        ]);

        return array_merge($paths, $wpPaths);
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
            // Don't resurrect dismissed findings
            if (in_array($existing->status, [
                SecscanFinding::STATUS_RESOLVED,
                SecscanFinding::STATUS_FALSE_POSITIVE,
            ], true)) {
                return compact('created', 'updated', 'alerted');
            }

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
