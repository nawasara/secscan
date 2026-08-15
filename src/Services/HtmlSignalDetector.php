<?php

namespace Nawasara\Secscan\Services;

/**
 * HTML-based threat detector for the F2 HTTP probe scanner.
 *
 * Analyses raw HTML from a fetched page and returns a list of signals,
 * each with a threat_type, score contribution, and evidence snippets.
 *
 * Design principles (same as FindingScorer / WpInspector):
 * - Strong signals can standalone and push score to critical on their own.
 * - Weak signals only accumulate — they never alert in isolation.
 * - Every match is evidence-tagged so operators can verify in one click.
 * - No external dependencies — pure PHP regex + string ops, fast on any host.
 */
class HtmlSignalDetector
{
    /**
     * Run all detectors against a raw HTML string.
     *
     * @param  string  $html      Raw HTML body from SiteHttpFetcher
     * @param  string  $url       The probed URL (for evidence context)
     * @param  string  $hostname  Hostname being scanned
     * @return list<array{threat_type:string, score:int, evidence:array}>
     */
    public function detect(string $html, string $url, string $hostname): array
    {
        $findings = [];

        // Text extraction happens ONCE here and is passed down, so every
        // detector sees the same body and a malformed page cannot blind one
        // detector while sparing another.
        $bodyText = $this->extractText($html);

        $judol = $this->detectJudol($html, $url, $bodyText);
        if ($judol) $findings[] = $judol;

        $pharma = $this->detectPharma($html, $url, $bodyText);
        if ($pharma) $findings[] = $pharma;

        $defacement = $this->detectDefacement($html, $url, $hostname, $bodyText);
        if ($defacement) $findings[] = $defacement;

        $hidden = $this->detectHiddenInjection($html, $url);
        if ($hidden) $findings[] = $hidden;

        $links = $this->detectSuspiciousLinks($html, $url, $hostname);
        if ($links) $findings[] = $links;

        return $findings;
    }

    // -------------------------------------------------------------------------
    // 1. Judol — gambling keyword injection
    // -------------------------------------------------------------------------

    private function detectJudol(string $html, string $url, string $bodyText): ?array
    {
        $score    = 0;
        $evidence = [];

        $title = $this->extractTitle($html);
        $strong = config('nawasara-secscan.judol_keywords_strong', []);
        $weak   = config('nawasara-secscan.judol_keywords_weak', []);

        // --- Title check (highest weight — very deliberate injection) ---
        if ($title !== '') {
            $titleLower = mb_strtolower($title);
            $strongHits = $this->matchKeywords($titleLower, $strong);
            $weakHits   = $this->matchKeywords($titleLower, $weak);

            if ($strongHits) {
                $score += min(90, 60 + count($strongHits) * 10);
                $evidence['title_strong_keywords'] = $strongHits;
                $evidence['title'] = mb_substr($title, 0, 120);
            } elseif ($weakHits) {
                $score += min(50, 30 + count($weakHits) * 8);
                $evidence['title_weak_keywords'] = $weakHits;
                $evidence['title'] = mb_substr($title, 0, 120);
            }
        }

        // --- Meta description check ---
        $meta = $this->extractMeta($html, 'description');
        if ($meta !== '') {
            $metaLower = mb_strtolower($meta);
            $hits = $this->matchKeywords($metaLower, $strong);
            if ($hits) {
                $score += min(30, count($hits) * 10);
                $evidence['meta_description_keywords'] = $hits;
                $evidence['meta_description'] = mb_substr($meta, 0, 120);
            }
        }

        // --- Body text scan (lower weight — can be anti-gambling article) ---
        $bodyLower = mb_strtolower($bodyText);
        $bodyStrong = $this->matchKeywordsWithCount($bodyLower, $strong);
        if ($bodyStrong) {
            // Only score strong-keyword density in body; weak body hits ignored
            $totalHits = array_sum($bodyStrong);
            if ($totalHits >= 3) {
                $score += min(40, 10 + $totalHits * 3);
                $evidence['body_strong_keyword_density'] = $bodyStrong;
            }
        }

        // --- Foreign script boost (non-Latin titles on .go.id = near-certain injection) ---
        if ($title && $this->hasForeignScript($title) && $score > 0) {
            $score = max($score, 85);
            $evidence['foreign_script_title'] = true;
        }

        if ($score <= 0) return null;

        return [
            'threat_type' => 'judol',
            'score'       => min(100, $score),
            'evidence'    => array_merge(['url' => $url, 'source' => 'http'], $evidence),
        ];
    }

    // -------------------------------------------------------------------------
    // 1b. Illegal pharma — abortion-drug SEO spam
    // -------------------------------------------------------------------------

    /**
     * Same shape as detectJudol, but weak clinical terms (misoprostol, aborsi)
     * only score when corroborated by a strong keyword OR a sales-intent term
     * on the same page — so a legitimate obstetric article that mentions
     * "misoprostol" for postpartum haemorrhage is not flagged.
     */
    private function detectPharma(string $html, string $url, string $bodyText): ?array
    {
        $score    = 0;
        $evidence = [];

        $strong = config('nawasara-secscan.pharma_keywords_strong', []);
        $weak   = config('nawasara-secscan.pharma_keywords_weak', []);
        $sales  = config('nawasara-secscan.pharma_sales_terms', []);

        $title    = $this->extractTitle($html);
        $meta     = $this->extractMeta($html, 'description');

        // Sales-intent present anywhere on the page corroborates weak keywords.
        $pageLower  = mb_strtolower($title . ' ' . $meta . ' ' . $bodyText);
        $hasSales   = (bool) $this->matchKeywords($pageLower, $sales);

        // --- Title ---
        if ($title !== '') {
            $titleLower = mb_strtolower($title);
            $strongHits = $this->matchKeywords($titleLower, $strong);
            $weakHits   = $this->matchKeywords($titleLower, $weak);

            if ($strongHits) {
                $score += min(90, 60 + count($strongHits) * 10);
                $evidence['title_strong_keywords'] = $strongHits;
                $evidence['title'] = mb_substr($title, 0, 120);
            } elseif ($weakHits && $hasSales) {
                // weak clinical term + sales intent = for-sale spam, not an article
                $score += min(60, 35 + count($weakHits) * 8);
                $evidence['title_weak_keywords'] = $weakHits;
                $evidence['title'] = mb_substr($title, 0, 120);
                $evidence['corroborated_by_sales'] = true;
            }
        }

        // --- Meta description (strong only) ---
        if ($meta !== '') {
            $hits = $this->matchKeywords(mb_strtolower($meta), $strong);
            if ($hits) {
                $score += min(30, count($hits) * 10);
                $evidence['meta_description_keywords'] = $hits;
                $evidence['meta_description'] = mb_substr($meta, 0, 120);
            }
        }

        // --- Body density: strong always; weak only when corroborated by sales ---
        $bodyLower  = mb_strtolower($bodyText);
        $bodyStrong = $this->matchKeywordsWithCount($bodyLower, $strong);
        if ($bodyStrong) {
            $totalHits = array_sum($bodyStrong);
            if ($totalHits >= 2) {
                $score += min(40, 10 + $totalHits * 3);
                $evidence['body_strong_keyword_density'] = $bodyStrong;

                // Mass injection stands on its own. A clean title keeps the
                // title/meta branches at zero, so a page can carry dozens of
                // "jual obat aborsi" blocks and still cap at 40 — recorded as a
                // warning, below alert_min_score (70), and silently never
                // alerted. That is exactly how the puskesmas site read while
                // serving 57 such blocks. Volume this far past incidental
                // mention is not ambiguous, so let it reach critical alone.
                $distinct = count($bodyStrong);
                if ($totalHits >= 20 && $distinct >= 3) {
                    $score = max($score, 85);
                    $evidence['mass_injection'] = [
                        'total_hits'       => $totalHits,
                        'distinct_keywords' => $distinct,
                    ];
                }
            }
        } elseif ($hasSales) {
            $bodyWeak = $this->matchKeywordsWithCount($bodyLower, $weak);
            $totalWeak = array_sum($bodyWeak);
            if ($totalWeak >= 3) {
                $score += min(30, 10 + $totalWeak * 3);
                $evidence['body_weak_keyword_density'] = $bodyWeak;
                $evidence['corroborated_by_sales'] = true;
            }
        }

        if ($score <= 0) return null;

        return [
            'threat_type' => 'illegal_pharma',
            'score'       => min(100, $score),
            'evidence'    => array_merge(['url' => $url, 'source' => 'http'], $evidence),
        ];
    }

    // -------------------------------------------------------------------------
    // 2. Defacement — page takeover / redirect hijack
    // -------------------------------------------------------------------------

    private function detectDefacement(string $html, string $url, string $hostname, string $bodyText): ?array
    {
        $score    = 0;
        $evidence = [];

        $title = $this->extractTitle($html);
        $titleLower = mb_strtolower($title);

        // Classic defacement signatures in title
        $defacePatterns = [
            '/hacked\s+by/i',
            '/defaced\s+by/i',
            '/owned\s+by/i',
            '/was\s+here/i',
            '/r00ted/i',
            '/0wned/i',
            '/pwned\s+by/i',
        ];
        foreach ($defacePatterns as $pattern) {
            if (preg_match($pattern, $titleLower)) {
                $score += 80;
                $evidence['deface_title_pattern'] = $title;
                break;
            }
        }

        // Body deface signatures
        $bodyPatterns = [
            '/hacked\s+by\s+\w+/i',
            '/defaced\s+by\s+\w+/i',
            '/greetz\s+to\s+\w+/i',
            '/\bShell\s+by\s+\w+/i',
        ];
        foreach ($bodyPatterns as $pattern) {
            if (preg_match($pattern, $bodyText, $m)) {
                $score += 70;
                $evidence['deface_body_pattern'] = mb_substr($m[0], 0, 100);
                break;
            }
        }

        // Suspicious redirect in meta refresh to an off-domain URL
        if (preg_match('/<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\'>\s]+)/i', $html, $m)) {
            $redirectTarget = $m[1];
            if (! str_contains($redirectTarget, $hostname) && ! str_starts_with($redirectTarget, '/')) {
                $score += 60;
                $evidence['meta_redirect'] = $redirectTarget;
            }
        }

        // JS redirect to off-domain (window.location = "https://badsite.com")
        if (preg_match('/window\.location(?:\.href)?\s*=\s*["\']https?:\/\/([^"\'\/]+)/i', $html, $m)) {
            $target = $m[1];
            if (! str_contains($target, $hostname)) {
                $score += 50;
                $evidence['js_redirect'] = $target;
            }
        }

        if ($score <= 0) return null;

        return [
            'threat_type' => 'defaced',
            'score'       => min(100, $score),
            'evidence'    => array_merge(['url' => $url, 'source' => 'http'], $evidence),
        ];
    }

    // -------------------------------------------------------------------------
    // 3. Hidden injection — content not visible to users but seen by crawlers
    // -------------------------------------------------------------------------

    private function detectHiddenInjection(string $html, string $url): ?array
    {
        $score    = 0;
        $evidence = [];

        // display:none blocks containing gambling/spam content
        $hiddenPattern = '/<(?:div|span|p|a)[^>]*style=["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>(.*?)<\/(?:div|span|p|a)>/is';
        if (preg_match_all($hiddenPattern, $html, $matches)) {
            $strong = config('nawasara-secscan.judol_keywords_strong', []);
            foreach ($matches[1] as $hiddenContent) {
                $lower = mb_strtolower(strip_tags($hiddenContent));
                $hits  = $this->matchKeywords($lower, $strong);
                if ($hits) {
                    $score += min(70, 40 + count($hits) * 10);
                    $evidence['hidden_div_keywords'] = $hits;
                    $evidence['hidden_snippet']      = mb_substr(strip_tags($hiddenContent), 0, 200);
                    break;
                }
            }
        }

        // visibility:hidden with suspicious content
        $visHiddenPattern = '/<[^>]+style=["\'][^"\']*visibility\s*:\s*hidden[^"\']*["\'][^>]*>(.*?)<\/[^>]+>/is';
        if (preg_match_all($visHiddenPattern, $html, $matches)) {
            $strong = config('nawasara-secscan.judol_keywords_strong', []);
            foreach ($matches[1] as $content) {
                $lower = mb_strtolower(strip_tags($content));
                if ($this->matchKeywords($lower, $strong)) {
                    $score += 30;
                    $evidence['visibility_hidden_injection'] = true;
                    break;
                }
            }
        }

        // Obfuscated PHP output in HTML (eval/base64 echoed to page)
        $obfuscatedPatterns = [
            '/eval\s*\(\s*base64_decode\s*\(/i',
            '/eval\s*\(\s*gzinflate\s*\(/i',
            '/document\.write\s*\(\s*atob\s*\(/i',
            '/String\.fromCharCode\s*\(\s*\d{2,3}\s*,/i',
        ];
        foreach ($obfuscatedPatterns as $pattern) {
            if (preg_match($pattern, $html)) {
                $score += 60;
                $evidence['obfuscated_js_payload'] = true;
                break;
            }
        }

        // Iframe to external domain hidden in page
        if (preg_match_all('/<iframe[^>]+src=["\']https?:\/\/([^"\'\/]+)/i', $html, $m)) {
            $externalIframes = array_filter(
                $m[1],
                fn ($d) => ! $this->isTrustedIframeDomain($d)
            );
            if ($externalIframes) {
                $score += 40;
                $evidence['external_iframes'] = array_values(array_unique($externalIframes));
            }
        }

        if ($score <= 0) return null;

        return [
            'threat_type' => 'malware',
            'score'       => min(100, $score),
            'evidence'    => array_merge(['url' => $url, 'source' => 'http'], $evidence),
        ];
    }

    // -------------------------------------------------------------------------
    // 4. Suspicious outbound links — SEO juice theft
    // -------------------------------------------------------------------------

    private function detectSuspiciousLinks(string $html, string $url, string $hostname): ?array
    {
        $score    = 0;
        $evidence = [];

        // Extract all outbound href links
        preg_match_all('/<a[^>]+href=["\']https?:\/\/([^"\'\/]+)/i', $html, $m);
        if (empty($m[1])) return null;

        $domains = array_filter(
            array_unique($m[1]),
            fn ($d) => ! str_contains($d, $hostname) && ! str_contains($d, '.go.id')
        );

        if (empty($domains)) return null;

        // Known gambling TLD / domain patterns
        $gamblingPatterns = [
            '/slot/i', '/gacor/i', '/togel/i', '/casino/i', '/sbobet/i',
            '/poker/i', '/judi/i', '/bet\d*/i', '/88\./i', '/\d+slot/i',
        ];

        $gamblingDomains = [];
        foreach ($domains as $domain) {
            foreach ($gamblingPatterns as $pattern) {
                if (preg_match($pattern, $domain)) {
                    $gamblingDomains[] = $domain;
                    break;
                }
            }
        }

        if ($gamblingDomains) {
            $count  = count($gamblingDomains);
            $score += min(80, 30 + $count * 15);
            $evidence['gambling_outbound_domains'] = array_slice(array_unique($gamblingDomains), 0, 10);
            $evidence['gambling_link_count']       = $count;
        }

        // Many unique external domains (link farm signal — normal pages have few external links)
        if (count($domains) > 20) {
            $score += min(30, (count($domains) - 20) * 2);
            $evidence['total_external_domains'] = count($domains);
        }

        if ($score <= 0) return null;

        return [
            'threat_type' => 'spam',
            'score'       => min(100, $score),
            'evidence'    => array_merge(['url' => $url, 'source' => 'http'], $evidence),
        ];
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Domains that are universally trusted as iframe sources on government sites.
     * YouTube embeds, Google Maps, analytics widgets — all normal, never malware.
     * Extend via config nawasara-secscan.trusted_iframe_domains.
     */
    private const TRUSTED_IFRAME_DOMAINS = [
        // Google / YouTube
        'www.youtube.com',
        'youtube.com',
        'www.youtube-nocookie.com',
        'youtube-nocookie.com',
        'www.google.com',
        'google.com',
        'maps.google.com',
        'www.google.co.id',
        'maps.google.co.id',
        'www.googletagmanager.com',
        'googletagmanager.com',
        'www.google-analytics.com',
        'google-analytics.com',
        // Social media embeds — common on OPD sites
        'www.facebook.com',
        'facebook.com',
        'www.instagram.com',
        'instagram.com',
        'platform.twitter.com',
        'twitter.com',
        // Mapping providers
        'maps.googleapis.com',
        'embed.waze.com',
        'www.openstreetmap.org',
        'openstreetmap.org',
        // Indonesian gov infrastructure
        'sso.ponorogo.go.id',
    ];

    private function isTrustedIframeDomain(string $domain): bool
    {
        // Always trust any .go.id subdomain
        if (str_ends_with($domain, '.go.id') || $domain === 'go.id') {
            return true;
        }

        $extra = config('nawasara-secscan.trusted_iframe_domains', []);
        $all   = array_merge(self::TRUSTED_IFRAME_DOMAINS, $extra);

        foreach ($all as $trusted) {
            // Exact match or subdomain match (e.g. "youtube.com" also covers "www.youtube.com")
            if ($domain === $trusted || str_ends_with($domain, '.'.$trusted)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract visible text from HTML — WITHOUT strip_tags().
     *
     * strip_tags() runs a stateful parser: an unbalanced quote inside an
     * attribute leaves it "inside a tag" and it silently discards the ENTIRE
     * remainder of the document. That is not a hypothetical. A puskesmas site
     * carried a stray quote in its search box:
     *
     *     <input type='text' placeholder='Search something..'' name='kata' />
     *
     * and strip_tags() reduced 79,676 bytes to 632 — dropping every one of the
     * 187 "aborsi" occurrences injected below it. The page was fetched fine and
     * scored clean for weeks, and illegal_pharma sat at zero findings fleet-wide
     * because the detector was never handed any text to judge.
     *
     * A plain regex tag-strip has no such state: each <...> is removed on its
     * own, so one broken tag costs one tag, not the rest of the page.
     */
    private function extractText(string $html): string
    {
        // Script/style contents are code, not visible copy — drop them whole so
        // JS string literals can't be read as page text.
        $text = preg_replace('#<(script|style)\b[^>]*>.*?</\1\s*>#is', ' ', $html) ?? $html;

        // Unterminated script/style (truncated body, or another broken tag):
        // cut from the opening tag to the end rather than leaving raw JS in.
        $text = preg_replace('#<(script|style)\b.*$#is', ' ', $text) ?? $text;

        // Comments — injected spam is sometimes parked in them, but so is
        // boilerplate; drop them to stay consistent with "visible text".
        $text = preg_replace('/<!--.*?-->/s', ' ', $text) ?? $text;

        // Stateless tag removal.
        $text = preg_replace('/<[^>]*>/', ' ', $text) ?? $text;

        // Entities to their characters, so &nbsp; and &#111; don't split words.
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        $text = preg_replace('/\s+/', ' ', $text) ?? $text;

        return trim($text);
    }

    private function extractTitle(string $html): string
    {
        if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $html, $m)) {
            return trim(html_entity_decode(strip_tags($m[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        }
        return '';
    }

    private function extractMeta(string $html, string $name): string
    {
        if (preg_match('/<meta[^>]+name=["\']' . preg_quote($name, '/') . '["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) {
            return trim($m[1]);
        }
        return '';
    }

    /** Return matched keywords (deduplicated). */
    private function matchKeywords(string $haystack, array $keywords): array
    {
        $hits = [];
        foreach ($keywords as $kw) {
            $pattern = '/\b' . preg_quote(mb_strtolower($kw), '/') . '\b/u';
            if (preg_match($pattern, $haystack)) {
                $hits[] = $kw;
            }
        }
        return $hits;
    }

    /** Return [keyword => count] for density analysis. */
    private function matchKeywordsWithCount(string $haystack, array $keywords): array
    {
        $result = [];
        foreach ($keywords as $kw) {
            $pattern = '/\b' . preg_quote(mb_strtolower($kw), '/') . '\b/u';
            $count   = preg_match_all($pattern, $haystack);
            if ($count > 0) {
                $result[$kw] = $count;
            }
        }
        return $result;
    }

    /** Detect non-Latin/non-Indonesian script in string (Turkish, Greek, Cyrillic, Arabic, etc.) */
    private function hasForeignScript(string $text): bool
    {
        // Matches characters outside Latin Extended + Indonesian common range
        return (bool) preg_match('/[\x{0400}-\x{04FF}\x{0370}-\x{03FF}\x{0600}-\x{06FF}\x{4E00}-\x{9FFF}]/u', $text);
    }
}
