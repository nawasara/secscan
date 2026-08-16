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
        $cmsInspector = new GenericCmsInspector($conn);

        // One pathological table must not hang the hourly sweep. Bound every
        // statement server-side; a timed-out query is caught per-schema below.
        try {
            $conn->statement('SET SESSION max_execution_time = 15000');
        } catch (\Throwable) {
            // Not fatal — older MySQL/MariaDB may not support the variable.
        }

        $databases = $inspector->databases();
        $wpCount = 0;
        $cmsCount = 0;
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
                        // Not WordPress — but that is not the same as "not a
                        // website". Most OPD sites here run bespoke PHP CMSes,
                        // and skipping them outright is how puskesmaspudak
                        // served 1,784 rows of pharma spam unnoticed. Fall back
                        // to a structure-agnostic content sweep.
                        $cms = $this->scanGenericCms($cmsInspector, $db);
                        if ($cms !== null) {
                            $cmsCount++;
                            foreach ($cms['findings'] as $f) {
                                $findings[] = array_merge([
                                    'db_name' => $db,
                                    'site_url' => $cms['site_url'],
                                    'site_name' => $cms['site_name'],
                                ], $f);
                            }
                        }
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
            'cms_total' => $cmsCount,
            'errors' => $errors,
            'findings' => $findings,
        ];
    }

    /**
     * Content sweep for a non-WordPress schema.
     *
     * Deliberately narrower than the WordPress path: it only reports keyword
     * injection, because that is all it can establish without knowing the
     * schema. There is no options table to read siteurl from, no post_status
     * to tell published from draft, and no way to tell a CMS apart from an
     * internal app — so a schema with no content columns simply returns null.
     *
     * Only STRONG keywords count here. The weak tiers ("slot", "aborsi",
     * "misoprostol") rely on WordPress corroboration signals that do not exist
     * in this path, and these columns include free-text bodies where an
     * ordinary health article would trip them. Strong terms — "jual obat
     * aborsi", "gacor" — do not appear in legitimate government content.
     *
     * @return array{site_url:?string, site_name:?string, findings:list<array>}|null
     */
    protected function scanGenericCms(GenericCmsInspector $inspector, string $db): ?array
    {
        $columns = $inspector->contentColumns($db);
        if (empty($columns)) {
            return null;   // no content-shaped columns — an app DB, not a site
        }

        $findings = [];

        $checks = [
            'judol' => (array) config('nawasara-secscan.judol_keywords_strong', []),
            'illegal_pharma' => (array) config('nawasara-secscan.pharma_keywords_strong', []),
        ];

        foreach ($checks as $threatType => $keywords) {
            $hit = $inspector->matchedContent($db, $keywords);
            if ($hit['count'] <= 0) {
                continue;
            }

            $findings[] = [
                'threat_type' => $threatType,
                'score' => $this->cmsScore($hit['count'], count($hit['columns'])),
                'severity' => '',   // filled in by severityFrom() below
                'evidence' => [
                    'source' => 'sql-cms',
                    'note' => 'Non-WordPress CMS — content columns matched by name.',
                    'matched_rows' => $hit['count'],
                    'matched_columns' => $hit['columns'],
                    'samples' => $hit['samples'],
                ],
            ];
        }

        // Severity mirrors the HTTP/WP paths so one threshold governs all three.
        $critical = (int) config('nawasara-secscan.thresholds.critical', 70);
        $warning = (int) config('nawasara-secscan.thresholds.warning', 40);
        foreach ($findings as &$f) {
            $f['severity'] = $f['score'] >= $critical ? 'critical'
                : ($f['score'] >= $warning ? 'warning' : 'info');
        }

        return [
            'site_url' => null,     // no reliable way to read the site URL here
            'site_name' => $db,
            'findings' => $findings,
        ];
    }

    /**
     * Score a generic-CMS content hit.
     *
     * Strong keywords carry the confidence, so even one match is meaningful —
     * but a single row could be a news article quoting a spam headline, so it
     * starts as a warning and only mass injection reaches critical. Spread
     * across several columns means the CMS was written to broadly (title, body
     * and slug all rewritten), which is injection rather than editorial.
     */
    protected function cmsScore(int $rows, int $columnCount): int
    {
        $score = 45 + min(30, $rows * 3);

        if ($rows >= 20 && $columnCount >= 3) {
            $score = max($score, 85);
        }

        return min(100, $score);
    }

    /**
     * Gather signals for one WP database and score them.
     *
     * @return array{site_url:?string, site_name:?string, findings:list<array>}
     */
    protected function scanWordpress(WpInspector $inspector, string $db, string $prefix): array
    {
        $strong = (array) config('nawasara-secscan.judol_keywords_strong', []);
        $weak = (array) config('nawasara-secscan.judol_keywords_weak', []);
        $expectedSuffix = (string) config('nawasara-secscan.expected_host_suffix', 'ponorogo.go.id');

        $opts = $inspector->options($db, $prefix, ['siteurl', 'home', 'blogname']);
        $siteUrl = $opts['siteurl'] ?? ($opts['home'] ?? null);
        $blogname = $opts['blogname'] ?? null;
        // Prefer home for public post links (siteurl can point at /wp).
        $homeUrl = $opts['home'] ?? ($opts['siteurl'] ?? '');

        $signals = [];

        // blogname carrying STRONG gambling keywords = defacement-ish title.
        $signals['blogname'] = $blogname;
        $signals['blogname_judol'] = $this->matchesAny((string) $blogname, $strong);

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

        // --- Judol detection, two-tier ---
        // Strong keywords (gacor/casino/scatter/…) flag on their own. Weak ones
        // (judi online/slot online/…) also appear in legit Indonesian news, so
        // they only count when corroborated by foreign script or a strong hit.
        $strongHits = $inspector->matchedTitlePosts($db, $prefix, $strong, $homeUrl, 5);
        $weakHits = $inspector->matchedTitlePosts($db, $prefix, $weak, $homeUrl, 5);

        // Foreign script in any sample title = near-certain injection.
        $foreign = false;
        foreach (array_merge($strongHits['samples'], $weakHits['samples']) as $s) {
            if ($this->hasForeignScript((string) ($s['title'] ?? ''))) {
                $foreign = true;
                break;
            }
        }
        if (! config('nawasara-secscan.foreign_script_boost', true)) {
            $foreign = false;
        }

        // Build the effective judol signal. Weak hits only contribute when
        // corroborated (strong present OR foreign script) — otherwise an
        // anti-gambling article ("Bahaya Judi Online") would false-positive.
        $corroborated = $strongHits['count'] > 0 || $foreign;
        $count = $strongHits['count'] + ($corroborated ? $weakHits['count'] : 0);
        $samples = $strongHits['samples'];
        if ($corroborated && count($samples) < 5) {
            $samples = array_slice(array_merge($samples, $weakHits['samples']), 0, 5);
        }

        $signals['judol_posts'] = ['count' => $count, 'samples' => $samples];
        $signals['judol_foreign'] = $foreign;
        $signals['judol_strong_count'] = $strongHits['count'];

        // --- Illegal pharma detection, two-tier ---
        // Strong terms ("penggugur kandungan", "jual obat aborsi", "cytotec 400")
        // flag on their own. Weak clinical terms (misoprostol/aborsi) also appear
        // in legit health articles, so in the DB-title path they only count when
        // corroborated by a strong hit on the same site — conservative by design.
        $pharmaStrong = (array) config('nawasara-secscan.pharma_keywords_strong', []);
        $pharmaWeak = (array) config('nawasara-secscan.pharma_keywords_weak', []);
        $pStrongHits = $inspector->matchedTitlePosts($db, $prefix, $pharmaStrong, $homeUrl, 5);
        $pWeakHits = $inspector->matchedTitlePosts($db, $prefix, $pharmaWeak, $homeUrl, 5);

        $pCorroborated = $pStrongHits['count'] > 0;
        $pCount = $pStrongHits['count'] + ($pCorroborated ? $pWeakHits['count'] : 0);
        $pSamples = $pStrongHits['samples'];
        if ($pCorroborated && count($pSamples) < 5) {
            $pSamples = array_slice(array_merge($pSamples, $pWeakHits['samples']), 0, 5);
        }

        $signals['pharma_posts'] = ['count' => $pCount, 'samples' => $pSamples];
        $signals['pharma_strong_count'] = $pStrongHits['count'];

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
     * True if the text contains script outside the Latin + common-Indonesian
     * range — Cyrillic, Greek, Arabic, CJK, or Turkish-specific letters
     * (İ ı ş ğ). Legitimate OPD titles are Latin/Indonesian; foreign script in
     * a gambling-keyword title is a strong "this is injected spam" signal.
     */
    protected function hasForeignScript(string $text): bool
    {
        if ($text === '') {
            return false;
        }

        // Unicode blocks that should never appear in an Indonesian gov title.
        if (preg_match('/[\x{0400}-\x{04FF}\x{0370}-\x{03FF}\x{0600}-\x{06FF}\x{4E00}-\x{9FFF}\x{0E00}-\x{0E7F}]/u', $text)) {
            return true;
        }

        // Turkish dotted/dotless I + ş ğ (common in TR gambling spam here).
        return (bool) preg_match('/[İıŞşĞğ]/u', $text);
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
