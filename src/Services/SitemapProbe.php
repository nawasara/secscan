<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Support\Facades\Cache;

/**
 * Discovers extra pages to probe from a site's sitemap.
 *
 * The homepage alone misses the usual judol injection: pages planted at deep,
 * unlinked URLs that Google finds through a sitemap or backlinks. That is how
 * "SLOT777 LOGIN" on umum.ponorogo.go.id (October 2026) reached search results
 * while every probe of "/" came back clean.
 *
 * Two outputs:
 *  - spam_urls: sitemap entries whose SLUG already reads as gambling/pharma.
 *    A government sitemap listing /slot-gacor-maxwin/ is conclusive on its own,
 *    before any page is fetched.
 *  - paths: a few URLs worth fetching — spam-looking slugs first, then the
 *    most recently modified entries (fresh injections land there).
 *
 * The sitemap is cached per host so a 6-hourly scan does not re-download it.
 */
class SitemapProbe
{
    private const CANDIDATES = ['/sitemap.xml', '/sitemap_index.xml', '/wp-sitemap.xml'];

    public function __construct(private SiteHttpFetcher $fetcher) {}

    /**
     * @return array{sitemap: ?string, total: int, spam_urls: list<array{url:string, keywords:list<string>}>, paths: list<string>}
     */
    public function discover(string $hostname, int $limit): array
    {
        $ttl = (int) config('nawasara-secscan.http_probe.sitemap_cache_minutes', 720);

        return Cache::remember("secscan:sitemap:{$hostname}", now()->addMinutes(max(1, $ttl)), function () use ($hostname, $limit) {
            [$sitemapUrl, $locs] = $this->collect($hostname);

            return $this->analyse($hostname, $sitemapUrl, $locs, $limit);
        });
    }

    /**
     * Pure part of discover(), separated for testing.
     *
     * @param  list<array{loc:string, lastmod:?string}>  $locs
     */
    public function analyse(string $hostname, ?string $sitemapUrl, array $locs, int $limit): array
    {
        $keywords = array_merge(
            (array) config('nawasara-secscan.judol_keywords_strong', []),
            (array) config('nawasara-secscan.pharma_keywords_strong', []),
        );

        $spam = [];
        $sameHost = [];

        foreach ($locs as $entry) {
            $parts = parse_url($entry['loc']);
            $host = strtolower($parts['host'] ?? '');
            if ($host !== strtolower($hostname)) {
                continue;
            }

            $path = ($parts['path'] ?? '/').(isset($parts['query']) ? '?'.$parts['query'] : '');
            $sameHost[] = ['path' => $path, 'lastmod' => $entry['lastmod']];

            $hits = self::slugKeywords($path, $keywords);
            if ($hits) {
                $spam[] = ['url' => $entry['loc'], 'path' => $path, 'keywords' => $hits];
            }
        }

        // Spam-looking slugs first, then newest by lastmod.
        usort($sameHost, fn ($a, $b) => strcmp((string) $b['lastmod'], (string) $a['lastmod']));

        $paths = array_column($spam, 'path');
        foreach ($sameHost as $entry) {
            if (count($paths) >= $limit) {
                break;
            }
            if ($entry['path'] !== '/' && ! in_array($entry['path'], $paths, true)) {
                $paths[] = $entry['path'];
            }
        }

        return [
            'sitemap' => $sitemapUrl,
            'total' => count($sameHost),
            'spam_urls' => array_slice(array_map(fn ($s) => ['url' => $s['url'], 'keywords' => $s['keywords']], $spam), 0, 20),
            'spam_count' => count($spam),
            'paths' => array_slice($paths, 0, $limit),
        ];
    }

    /**
     * Strong keywords found in a URL slug, with -, _, / and . read as spaces.
     *
     * @param  list<string>  $keywords
     * @return list<string>
     */
    public static function slugKeywords(string $path, array $keywords): array
    {
        $text = ' '.strtolower(preg_replace('/[\/\-_.+%?=&]+/', ' ', rawurldecode($path)) ?? '').' ';

        $hits = [];
        foreach ($keywords as $kw) {
            $kw = strtolower((string) $kw);
            if ($kw !== '' && preg_match('/\b'.preg_quote($kw, '/').'\b/u', $text)) {
                $hits[] = $kw;
            }
        }

        // "slot" + a number is the brand pattern (slot777, slot88) and never a
        // government slug; plain "slot" stays out — "slot-anggaran" is real.
        if (preg_match('/\bslot\s?\d{2,4}\b/', $text, $m)) {
            $hits[] = trim($m[0]);
        }

        return array_values(array_unique($hits));
    }

    /** @return array{0: ?string, 1: list<array{loc:string, lastmod:?string}>} */
    private function collect(string $hostname): array
    {
        foreach ($this->sitemapCandidates($hostname) as $path) {
            $xml = $this->fetchXml($hostname, $path);
            if ($xml === null) {
                continue;
            }

            $locs = self::parseLocs($xml);

            // Sitemap index: follow a few children. Post sitemaps first — that
            // is where injected posts land.
            if (str_contains($xml, '<sitemapindex')) {
                $children = array_column($locs, 'loc');
                usort($children, fn ($a, $b) => (int) str_contains($b, 'post') <=> (int) str_contains($a, 'post'));

                $locs = [];
                foreach (array_slice($children, 0, 2) as $child) {
                    $p = parse_url($child);
                    if (strtolower($p['host'] ?? '') !== strtolower($hostname)) {
                        continue;
                    }
                    $childXml = $this->fetchXml($hostname, ($p['path'] ?? '/').(isset($p['query']) ? '?'.$p['query'] : ''));
                    if ($childXml !== null) {
                        $locs = array_merge($locs, self::parseLocs($childXml));
                    }
                }
            }

            return ['https://'.$hostname.$path, $locs];
        }

        return [null, []];
    }

    /** @return list<string> */
    private function sitemapCandidates(string $hostname): array
    {
        $paths = [];

        $robots = $this->fetcher->fetch($hostname, '/robots.txt');
        if ($robots && empty($robots['error']) && ($robots['status_code'] ?? 0) === 200
            && preg_match_all('/^\s*sitemap:\s*(\S+)/mi', (string) $robots['body'], $m)) {
            foreach ($m[1] as $url) {
                $p = parse_url($url);
                if (strtolower($p['host'] ?? '') === strtolower($hostname)) {
                    $paths[] = ($p['path'] ?? '/').(isset($p['query']) ? '?'.$p['query'] : '');
                }
            }
        }

        return array_values(array_unique(array_merge($paths, self::CANDIDATES)));
    }

    private function fetchXml(string $hostname, string $path): ?string
    {
        $result = $this->fetcher->fetch($hostname, $path, SiteHttpFetcher::UA_GOOGLEBOT, false);
        if (! $result || ! empty($result['error']) || ($result['status_code'] ?? 0) !== 200) {
            return null;
        }

        $body = (string) ($result['body'] ?? '');

        // A Laravel/CMS 404 page served with 200 is not a sitemap.
        return str_contains($body, '<loc>') ? $body : null;
    }

    /** @return list<array{loc:string, lastmod:?string}> */
    public static function parseLocs(string $xml): array
    {
        $out = [];
        if (preg_match_all('#<(?:url|sitemap)>(.*?)</(?:url|sitemap)>#is', $xml, $blocks)) {
            foreach ($blocks[1] as $block) {
                if (preg_match('#<loc>\s*(.*?)\s*</loc>#is', $block, $loc)) {
                    preg_match('#<lastmod>\s*(.*?)\s*</lastmod>#is', $block, $mod);
                    $out[] = [
                        'loc' => html_entity_decode(trim($loc[1]), ENT_QUOTES | ENT_XML1),
                        'lastmod' => $mod[1] ?? null,
                    ];
                }
            }
        }

        return $out;
    }
}
