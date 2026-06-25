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
    | Matched against post titles, blognames, and (later) crawled page text.
    | Lowercased substring match. Foreign-language gambling terms are strong
    | signals on a *.go.id site. Keep this list maintainable — it is the core
    | of the SQL detector. Word-boundary-ish terms (rtp) are space-padded by
    | the detector to avoid matching inside ordinary words.
    */
    'judol_keywords' => [
        'slot', 'gacor', 'maxwin', 'toto', 'togel', 'judi', 'casino', 'kasino',
        'poker', 'rtp', 'pragmatic', 'sbobet', 'jackpot', 'scatter', 'dewa',
        'zeus', 'olympus', 'mahjong', 'pulsa', 'depo', 'bonus new member',
        'situs gacor', 'link alternatif', 'bandar', 'bet88', 'pgsoft',
        'fortune', 'koi gate', 'sweet bonanza',
    ],

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
    | Sidecar (Fase 2 — Python HTTP probe). Unused until F2 lands.
    |--------------------------------------------------------------------------
    */
    'sidecar' => [
        'enabled' => env('SECSCAN_SIDECAR_ENABLED', false),
        'url' => env('SECSCAN_SIDECAR_URL', 'http://secscan-sidecar:8300'),
        'timeout' => env('SECSCAN_SIDECAR_TIMEOUT', 30),
    ],

    /*
    |--------------------------------------------------------------------------
    | Alerting cooldown (minutes) — re-notify suppression per finding.
    |--------------------------------------------------------------------------
    */
    'alerts' => [
        'cooldown_minutes' => env('SECSCAN_ALERT_COOLDOWN', 60),
    ],
];
