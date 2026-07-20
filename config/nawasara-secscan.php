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
    | Illegal pharma / abortion-drug SEO spam
    |--------------------------------------------------------------------------
    | Same two-tier logic as judol. Government (esp. puskesmas) sites are mass
    | injected with pages selling Cytotec/misoprostol abortion pills.
    |
    | strong — commercial abortion-drug vocabulary a legit health article never
    |          uses ("penggugur kandungan", "jual obat aborsi", "cytotec 400").
    |          A single whole-word match flags the site.
    | weak   — clinical terms that CAN appear in legitimate obstetric content
    |          (misoprostol is legally used for postpartum haemorrhage). Counted
    |          ONLY when corroborated by a strong hit OR a sales term below, so
    |          real medical articles don't false-positive.
    */
    'pharma_keywords_strong' => [
        'penggugur kandungan', 'obat penggugur', 'jual obat aborsi', 'obat aborsi',
        'menggugurkan kandungan', 'cytotec 400', 'cytotec 200', 'apotek cytotec',
        'gastrul', 'obat cytotec', 'pil aborsi', 'jual cytotec', 'cara menggugurkan',
    ],
    'pharma_keywords_weak' => [
        'cytotec', 'misoprostol', 'mifepristone', 'aborsi', 'telat datang bulan',
        'telat bulan',
    ],
    // Sales-intent terms that corroborate a weak pharma keyword (turn a clinical
    // mention into a "for sale" signal). Presence of any alongside a weak keyword
    // lets weak hits count even without a strong keyword.
    'pharma_sales_terms' => [
        'jual', 'harga', 'ready', 'cod', 'wa ', 'whatsapp', 'pesan', 'order',
        'terpercaya', 'tanpa resep', 'dijamin', 'kirim',
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
        'timeout_seconds'     => env('SECSCAN_HTTP_TIMEOUT', 12),
        'delay_ms_per_host'   => env('SECSCAN_HTTP_DELAY_MS', 800),     // delay between requests to same host
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
    | Auto-block (Decision Engine)
    |--------------------------------------------------------------------------
    | Decides which attacker IPs to block at the Cloudflare edge (account-wide
    | IP Access Rule). SAFETY FIRST — this action denies access, so the engine
    | is conservative and heavily whitelisted.
    |
    |   enabled  — master kill switch. false = never block (engine won't run).
    |   dry_run  — engine runs + records decisions but does NOT call Cloudflare.
    |              Start here on a new deploy; watch the decisions, then flip off.
    */
    'autoblock' => [
        'enabled' => env('SECSCAN_AUTOBLOCK_ENABLED', false),
        'dry_run' => env('SECSCAN_AUTOBLOCK_DRYRUN', true),

        // --- Threshold (conservative): ALL must hold to block ---
        // Incident types that are ever blockable. Override per-deployment with a
        // comma-separated SECSCAN_AUTOBLOCK_TYPES env. The default now also
        // blocks brute_force, ssh_root_login, xss, and 4xx_storm — for 4xx_storm
        // the min_occurrences gate is what keeps light recon out (only sustained
        // storms, hundreds of 4xx from one IP, cross the threshold). Whitelist
        // (office CIDR + Cloudflare + search bots) is still checked first.
        'blockable_types' => array_filter(explode(',', (string) env(
            'SECSCAN_AUTOBLOCK_TYPES',
            'sql_injection,directory_traversal,webshell_upload,exploit_chain,'
            .'vulnerability_scan,file_scan_webshell,file_scan_backdoor,file_scan_exploit,'
            .'brute_force,ssh_root_login,xss,4xx_storm'
        ))),
        'min_score'       => env('SECSCAN_AUTOBLOCK_MIN_SCORE', 70),
        'min_occurrences' => env('SECSCAN_AUTOBLOCK_MIN_OCCURRENCES', 3),

        // --- Whitelist (checked FIRST, fail-safe) ---
        // Cloudflare edge ranges — a safety net so a stray CF-attributed
        // incident can never blackhole Cloudflare (which would down every site).
        'whitelist_cloudflare' => true,
        // Extra CIDRs never to block: office/OPD public IPs, internal servers,
        // monitoring. Fill these in per deployment (comma-separated env or here).
        'whitelist_cidrs' => array_filter(explode(',', (string) env('SECSCAN_AUTOBLOCK_WHITELIST', ''))),
        // Known good crawler ranges (Googlebot/Bingbot) — kept out of blocks so
        // SEO isn't harmed. Verified by CIDR (coarse but safe).
        'whitelist_search_bots' => true,

        // CF IP Access Rule notes tag prefix (for audit + bulk cleanup).
        'notes_prefix' => 'nawasara-autoblock',
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

    /*
    |--------------------------------------------------------------------------
    | Laporan harian (daily digest)
    |--------------------------------------------------------------------------
    | One e-mail each morning summarising the last 24 hours: incidents by
    | severity/type, top attacker IPs, which sites were targeted, and what the
    | Decision Engine blocked. Complements the real-time per-incident alerts.
    |
    |   SECSCAN_DIGEST_ENABLED=true
    |   SECSCAN_DIGEST_AT=07:00                 # jam kirim (waktu server)
    |   SECSCAN_DIGEST_RECIPIENTS=csirt@ponorogo.go.id,kominfo@ponorogo.go.id
    |   SECSCAN_DIGEST_SEND_WHEN_EMPTY=true     # tetap kirim walau 0 insiden
    |
    | Recipients kosong => fallback ke audience alerting severity "critical",
    | jadi laporan tetap sampai ke seseorang.
    */
    'digest' => [
        'enabled' => env('SECSCAN_DIGEST_ENABLED', true),
        'at' => env('SECSCAN_DIGEST_AT', '07:00'),
        'recipients' => array_filter(array_map('trim', explode(',', (string) env('SECSCAN_DIGEST_RECIPIENTS', '')))),
        'send_when_empty' => env('SECSCAN_DIGEST_SEND_WHEN_EMPTY', true),
    ],
];
