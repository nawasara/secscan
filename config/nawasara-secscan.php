<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Scheduler
    |--------------------------------------------------------------------------
    | Hourly WordPress scan by default. Scanning hits the monitored MySQL
    | server read-only, so keep the cadence modest to avoid load on the
    | shared OPD database server.
    */
    'scheduler' => [
        'enabled' => env('SECSCAN_SCHEDULER_ENABLED', true),
    ],

    // Minutes between scheduled scans (cron is */{interval} so keep ≤ 60).
    'scan_interval' => env('SECSCAN_SCAN_INTERVAL', 60),

    /*
    |--------------------------------------------------------------------------
    | Judol / gambling keywords
    |--------------------------------------------------------------------------
    | Matched as WHOLE WORDS (MySQL 8 ICU \b boundary) against post titles.
    | Substring matching false-positived on legit gov content (recon 2026-06-25):
    | 'dewa'→"Dewan", 'judi'→"Iswahjudi"/anti-gambling articles, 'toto'→"Totokan".
    |
    | TWO TIERS:
    |   strong — gambling vocabulary legit gov articles never use. A single
    |            whole-word match flags the site.
    |   weak   — phrases that DO appear in normal Indonesian news/education
    |            ("Bahaya Judi Online", "waspada slot online"). Counted ONLY when
    |            corroborated: foreign-script title OR a strong keyword also on
    |            the same site. Alone they are ignored, so anti-gambling articles
    |            don't false-positive.
    */
    'judol_keywords_strong' => [
        'gacor', 'maxwin', 'togel', 'casino', 'kasino', 'sbobet', 'pragmatic',
        'scatter', 'olympus', 'mahjong', 'pgsoft', 'sweet bonanza',
        'gates of olympus', 'situs gacor', 'slot gacor', 'rtp slot',
        'zeus olympus', 'starlight princess',
    ],
    'judol_keywords_weak' => [
        'slot', 'judi online', 'judi slot', 'slot online', 'bonus new member',
        'deposit pulsa', 'link alternatif',
    ],

    /*
    |--------------------------------------------------------------------------
    | Foreign-language booster
    |--------------------------------------------------------------------------
    | A judol keyword in a title that ALSO contains non-Indonesian/English
    | script (Turkish, Greek, Cyrillic, etc.) is a very strong compromise
    | signal — legit OPD posts are in Indonesian. Used by the scorer.
    */
    'foreign_script_boost' => env('SECSCAN_FOREIGN_BOOST', true),

    /*
    |--------------------------------------------------------------------------
    | Scoring & severity thresholds
    |--------------------------------------------------------------------------
    | A finding's score (0-100) maps to severity. Tuned conservatively:
    | better to under-flag than drown operators in false positives (lesson
    | from hibah DuplicateDetector). Tune after first-week calibration.
    */
    'thresholds' => [
        'critical' => env('SECSCAN_THRESHOLD_CRITICAL', 70),
        'warning' => env('SECSCAN_THRESHOLD_WARNING', 40),
        // Below 'warning' → 'info' (recorded but not alerted).
        'alert_min_score' => env('SECSCAN_ALERT_MIN_SCORE', 70),
    ],

    /*
    |--------------------------------------------------------------------------
    | Expected host suffix
    |--------------------------------------------------------------------------
    | siteurl/home options that do NOT contain this are flagged as a possible
    | redirect hijack.
    */
    'expected_host_suffix' => env('SECSCAN_EXPECTED_HOST', 'ponorogo.go.id'),

    /*
    |--------------------------------------------------------------------------
    | F2 HTTP Probe — SiteHttpFetcher configuration
    |--------------------------------------------------------------------------
    | Probes *.ponorogo.go.id hostnames from CF DNS records with Googlebot UA.
    | Rate-limiting protects OPD sites from being overloaded by the scanner.
    */
    'http_probe' => [
        'enabled'             => env('SECSCAN_HTTP_PROBE_ENABLED', true),
        'scan_interval'       => env('SECSCAN_HTTP_SCAN_INTERVAL', 360),  // minutes; default 6 hours
        'timeout_seconds'     => env('SECSCAN_HTTP_TIMEOUT', 15),
        'delay_ms_per_host'   => env('SECSCAN_HTTP_DELAY_MS', 2000),    // delay between requests to same host
        'daily_quota_per_host' => env('SECSCAN_HTTP_DAILY_QUOTA', 100), // max fetches per host per day
        'backoff_after_failures' => 3,
        'backoff_minutes'     => 30,
        'max_body_kb'         => 2048,
        // WP-specific paths probed in addition to homepage
        'wp_paths' => [
            '/wp-login.php',
            '/wp-content/uploads/',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Alerting cooldown (minutes) — re-notify suppression per finding.
    |--------------------------------------------------------------------------
    */
    'alerts' => [
        'cooldown_minutes' => env('SECSCAN_ALERT_COOLDOWN', 60),
    ],

    /*
    |--------------------------------------------------------------------------
    | Agent binary distribution
    |--------------------------------------------------------------------------
    | The /agent/download/{version}/{os}/{arch}/nawasara-agent endpoint
    | redirects to GitHub Releases. Set the repo slug here.
    */
    'agent' => [
        'github_repo' => env('SECSCAN_AGENT_GITHUB_REPO', 'nawasara/agent'),

        // Incoming incidents with the same agent + type + source_ip whose
        // last_seen_at falls within this window are folded into the existing
        // row (occurrences++, last_seen_at bumped) instead of a new row.
        'incident_aggregation_hours' => env('SECSCAN_INCIDENT_AGG_HOURS', 24),

        // Max evidence entries kept per incident when aggregating (newest win).
        'incident_evidence_cap' => env('SECSCAN_INCIDENT_EVIDENCE_CAP', 20),
    ],

    /*
    |--------------------------------------------------------------------------
    | Trusted iframe domains (HTTP probe)
    |--------------------------------------------------------------------------
    | Domains listed here are NEVER flagged as suspicious iframes. YouTube,
    | Google Maps, social media embeds, etc. are universally trusted and
    | common on government sites. Add site-specific trusted domains here.
    | The built-in list is in HtmlSignalDetector::TRUSTED_IFRAME_DOMAINS.
    */
    'trusted_iframe_domains' => [
        // Add extra trusted domains per deployment if needed, e.g.:
        // 'embed.example.go.id',
    ],
];
