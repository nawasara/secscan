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
