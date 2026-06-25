<?php

namespace Nawasara\Secscan\Services;

use Nawasara\DatabaseMonitor\Services\MysqlConnection;

/**
 * SQL-only WordPress threat detector. Iterates the monitored databases,
 * detects WordPress installs, gathers signals via WpInspector, and scores
 * them via FindingScorer. Read-only end to end (connection is READ ONLY).
 *
 * Returns a flat list of finding rows ready to upsert into
 * nawasara_secscan_findings — each carrying the originating db + site identity.
 */
class SqlSignalDetector
{
    public function __construct(
        protected MysqlConnection $connection,
        protected FindingScorer $scorer,
    ) {}

    /**
     * Scan every WordPress database and return all findings.
     *
     * @return array{
     *   scanned_total:int,
     *   wordpress_total:int,
     *   findings: list<array{db_name:string, site_url:?string, site_name:?string, threat_type:string, score:int, severity:string, evidence:array}>
     * }
     */
    public function scanAll(): array
    {
        $conn = $this->connection->connection();
        $inspector = new WpInspector($conn);

        $databases = $inspector->databases();
        $wpCount = 0;
        $errors = 0;
        $findings = [];

        try {
            foreach ($databases as $db) {
                // One malformed database must never abort the whole sweep —
                // some schemas have WP-lookalike tables (e.g. a literal
                // `options` table that isn't WordPress) that error on a real
                // WP query. Isolate per database.
                try {
                    $prefix = $inspector->wordpressPrefix($db);
                    if ($prefix === null) {
                        continue;
                    }
                    $wpCount++;

                    $site = $this->scanWordpress($inspector, $db, $prefix);
                    foreach ($site['findings'] as $f) {
                        $findings[] = array_merge([
                            'db_name' => $db,
                            'site_url' => $site['site_url'],
                            'site_name' => $site['site_name'],
                        ], $f);
                    }
                } catch (\Throwable $e) {
                    $errors++;
                    report($e);
                }
            }
        } finally {
            // Always release the LAN socket + scrub the plaintext password from
            // config() (purge() does both).
            $this->connection->purge();
        }

        return [
            'scanned_total' => count($databases),
            'wordpress_total' => $wpCount,
            'errors' => $errors,
            'findings' => $findings,
        ];
    }

    /**
     * Gather signals for one WP database and score them.
     *
     * @return array{site_url:?string, site_name:?string, findings:list<array>}
     */
    protected function scanWordpress(WpInspector $inspector, string $db, string $prefix): array
    {
        $keywords = (array) config('nawasara-secscan.judol_keywords', []);
        $expectedSuffix = (string) config('nawasara-secscan.expected_host_suffix', 'ponorogo.go.id');

        $opts = $inspector->options($db, $prefix, ['siteurl', 'home', 'blogname']);
        $siteUrl = $opts['siteurl'] ?? ($opts['home'] ?? null);
        $blogname = $opts['blogname'] ?? null;

        $signals = [];

        // blogname carrying gambling keywords = defacement-ish title.
        $signals['blogname'] = $blogname;
        $signals['blogname_judol'] = $this->matchesAny((string) $blogname, $keywords);

        // siteurl/home not on the expected gov domain → redirect hijack.
        $offsite = [];
        foreach (['siteurl', 'home'] as $k) {
            $v = $opts[$k] ?? '';
            if ($v !== '' && stripos($v, $expectedSuffix) === false) {
                $offsite[$k] = $v;
            }
        }
        $signals['redirect_hijack'] = ! empty($offsite);
        $signals['offsite_urls'] = $offsite;

        // judol posts, injected content, suspicious options, admin stats.
        $signals['judol_posts'] = $inspector->publishedJudolPosts($db, $prefix, $keywords);
        $signals['injected_content'] = $inspector->injectedContentCount($db, $prefix);
        $signals['suspicious_options'] = $inspector->suspiciousOptionCount($db, $prefix);
        $signals['admin_stats'] = $inspector->adminStats($db, $prefix, $expectedSuffix);

        return [
            'site_url' => $siteUrl,
            'site_name' => $blogname,
            'findings' => $this->scorer->score($signals),
        ];
    }

    /**
     * Case-insensitive substring match. 'rtp' is space-padded to avoid hits
     * inside ordinary words (e.g. "konsorsium").
     *
     * @param  list<string>  $keywords
     */
    protected function matchesAny(string $haystack, array $keywords): bool
    {
        if ($haystack === '') {
            return false;
        }
        $h = mb_strtolower($haystack);
        foreach ($keywords as $kw) {
            $needle = mb_strtolower(trim($kw));
            if (mb_strlen($needle) <= 3) {
                $needle = ' '.$needle.' ';
                $h2 = ' '.$h.' ';
                if (str_contains($h2, $needle)) {
                    return true;
                }
            } elseif (str_contains($h, $needle)) {
                return true;
            }
        }

        return false;
    }
}
