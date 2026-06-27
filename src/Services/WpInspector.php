<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Database\Connection;

/**
 * Safe, read-only helpers for inspecting a WordPress database on the monitored
 * MySQL server. The connection comes from nawasara/database-monitor's
 * MysqlConnection (session forced READ ONLY), so nothing here can write.
 *
 * SECURITY: database and table names come from the server (information_schema)
 * but are still treated as untrusted. Every identifier is validated against a
 * strict whitelist and wrapped in backticks before interpolation — never pass
 * a raw name into SQL. Values always go through bound parameters.
 */
class WpInspector
{
    public function __construct(protected Connection $conn) {}

    /**
     * Validate + backtick-quote a MySQL identifier (db, table, column). WP
     * table prefixes can be arbitrary (e.g. "sLg7vSDZW_"), so we allow
     * [A-Za-z0-9_$] only and reject anything else outright.
     */
    public function quoteIdent(string $name): string
    {
        if (! preg_match('/^[A-Za-z0-9_$]+$/', $name)) {
            throw new \InvalidArgumentException("Unsafe identifier: {$name}");
        }

        return '`'.$name.'`';
    }

    /**
     * List all non-system schemas on the server.
     *
     * @return list<string>
     */
    public function databases(): array
    {
        $system = ['information_schema', 'performance_schema', 'mysql', 'sys'];
        $rows = $this->conn->select('SHOW DATABASES');
        $out = [];
        foreach ($rows as $r) {
            $name = array_values((array) $r)[0];
            if (! in_array($name, $system, true)) {
                $out[] = $name;
            }
        }

        return $out;
    }

    /**
     * Detect a WordPress install in a schema and return its table prefix, or
     * null if it isn't WordPress. WP is identified by a {prefix}options table
     * that has matching {prefix}posts + {prefix}users siblings.
     */
    public function wordpressPrefix(string $db): ?string
    {
        $tables = array_map(
            fn ($r) => array_values((array) $r)[0],
            $this->conn->select(
                'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?',
                [$db]
            )
        );
        $set = array_flip($tables);

        foreach ($tables as $t) {
            if (preg_match('/^(.*)options$/', $t, $m)) {
                $p = $m[1];
                if (isset($set[$p.'posts'], $set[$p.'users'])
                    && $this->hasOptionColumns($db, $p.'options')) {
                    return $p;
                }
            }
        }

        return null;
    }

    /**
     * Confirm a candidate options table is really a WordPress options table —
     * it must have option_name + option_value columns. Some other CMSes ship a
     * plain `options` table (with `posts`/`users` siblings) that would
     * otherwise be mistaken for WP and crash the option queries.
     */
    protected function hasOptionColumns(string $db, string $table): bool
    {
        $cols = array_map(
            fn ($r) => array_values((array) $r)[0],
            $this->conn->select(
                'SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?',
                [$db, $table]
            )
        );
        $cols = array_flip($cols);

        return isset($cols['option_name'], $cols['option_value']);
    }

    /**
     * Read selected wp_options values.
     *
     * @param  list<string>  $names
     * @return array<string,string>
     */
    public function options(string $db, string $prefix, array $names): array
    {
        $table = $this->quoteIdent($db).'.'.$this->quoteIdent($prefix.'options');
        $place = implode(',', array_fill(0, count($names), '?'));
        $rows = $this->conn->select(
            "SELECT option_name, option_value FROM {$table} WHERE option_name IN ({$place})",
            $names
        );
        $out = [];
        foreach ($rows as $r) {
            $out[$r->option_name] = $r->option_value;
        }

        return $out;
    }

    /**
     * Count published posts/pages whose title matches a keyword set, returning
     * the count + up to `$limit` sample {title, url} pairs (clickable ?p=ID
     * links that resolve regardless of permalink structure).
     *
     * One word-boundary REGEXP instead of N×LIKE — accurate ('dewa' no longer
     * matches "Dewan") AND fast (single pass, no filesort). MySQL 8 ICU \b.
     *
     * @param  list<string>  $keywords
     * @param  string  $home  the site's home/siteurl (for building ?p=ID links)
     * @return array{count:int, samples:list<array{title:string, url:?string}>}
     */
    public function matchedTitlePosts(string $db, string $prefix, array $keywords, string $home = '', int $limit = 5): array
    {
        if (empty($keywords)) {
            return ['count' => 0, 'samples' => []];
        }
        $table = $this->quoteIdent($db).'.'.$this->quoteIdent($prefix.'posts');
        $regex = $this->judolRegex($keywords);
        $limit = max(1, $limit);

        $count = (int) $this->conn->scalar(
            "SELECT COUNT(*) FROM {$table} WHERE post_status = 'publish' AND post_type IN ('post','page') AND post_title REGEXP ?",
            [$regex]
        );

        $samples = [];
        if ($count > 0) {
            // No ORDER BY — any matching rows are fine as evidence; avoiding the
            // sort keeps this fast on huge post tables (tppkk: tens of thousands).
            $rows = $this->conn->select(
                "SELECT ID, post_title FROM {$table} WHERE post_status = 'publish' AND post_type IN ('post','page') AND post_title REGEXP ? LIMIT {$limit}",
                [$regex]
            );
            $base = rtrim($home, '/');
            foreach ($rows as $r) {
                $samples[] = [
                    'title' => mb_substr((string) $r->post_title, 0, 120),
                    'url' => $base !== '' ? $base.'/?p='.(int) $r->ID : null,
                ];
            }
        }

        return ['count' => $count, 'samples' => $samples];
    }

    /**
     * Build a single MySQL word-boundary REGEXP alternation from the keyword
     * list, e.g. "[[:<:]](slot|casino|gates of olympus)[[:>:]]". Keywords are
     * regex-escaped; spaces are kept literal (multi-word phrases work).
     *
     * @param  list<string>  $keywords
     */
    protected function judolRegex(array $keywords): string
    {
        $parts = [];
        foreach ($keywords as $kw) {
            $kw = trim((string) $kw);
            if ($kw === '') {
                continue;
            }
            // Escape regex metacharacters. MySQL 8 REGEXP is ICU (PCRE-like).
            $parts[] = preg_quote($kw, null);
        }

        // MySQL 8 uses the ICU regex engine: \b is the word boundary. (The old
        // POSIX [[:<:]]/[[:>:]] anchors were REMOVED in MySQL 8.0.4 and raise
        // "Illegal argument to a regular expression".) \b before/after the
        // alternation keeps "dewa" from matching inside "dewan".
        return '\\b('.implode('|', $parts).')\\b';
    }

    /**
     * Count published posts whose content carries injection markers. The
     * patterns are tight on purpose: a loose '%.php%' matched ordinary PDF
     * links during recon, so we require .php to be followed by a quote, query
     * string, or whitespace (i.e. an actual script reference), and require the
     * hidden-script pattern to combine <script with display:none.
     *
     * @return array{count:int}
     */
    public function injectedContentCount(string $db, string $prefix): array
    {
        $table = $this->quoteIdent($db).'.'.$this->quoteIdent($prefix.'posts');

        // MySQL 8 ICU regex: \s (not POSIX [[:space:]]). Patterns kept tight so
        // a plain PDF/page link doesn't trip the .php rule (recon false positive).
        $count = (int) $this->conn->scalar(
            "SELECT COUNT(*) FROM {$table} WHERE post_status = 'publish' AND ("
            ."post_content REGEXP '<script[^>]*display:\\\\s*none' "
            ."OR post_content LIKE '%eval(base64_decode%' "
            ."OR post_content LIKE '%gzinflate(base64_decode%' "
            ."OR post_content REGEXP '/wp-content/uploads/[^\"'']+\\\\.php([?\"'' ]|$)'"
            .')'
        );

        return ['count' => $count];
    }

    /**
     * Count suspicious autoloaded options (common malware persistence). Names
     * like eval/base64 functions or absurdly long transient keys.
     */
    public function suspiciousOptionCount(string $db, string $prefix): int
    {
        $table = $this->quoteIdent($db).'.'.$this->quoteIdent($prefix.'options');

        return (int) $this->conn->scalar(
            "SELECT COUNT(*) FROM {$table} WHERE autoload = 'yes' AND option_name REGEXP "
            ."'(eval|base64_decode|gzinflate|str_rot13|_transient_[A-Za-z0-9]{24,})'"
        );
    }

    /**
     * Count *real* administrators by JOINing users × usermeta (not COUNT on
     * usermeta alone — recon showed duplicate capability rows + orphaned meta
     * from deleted users inflated the count and produced false positives).
     * Also returns admins whose email is outside the expected gov domain and
     * those registered in the last 14 days (hack indicator).
     *
     * @return array{admins:int, foreign_email_admins:int, recent_admins:int, total_users:int}
     */
    public function adminStats(string $db, string $prefix, string $expectedSuffix): array
    {
        $users = $this->quoteIdent($db).'.'.$this->quoteIdent($prefix.'users');
        $meta = $this->quoteIdent($db).'.'.$this->quoteIdent($prefix.'usermeta');
        $capKey = $prefix.'capabilities';

        $totalUsers = (int) $this->conn->scalar("SELECT COUNT(*) FROM {$users}");

        // Distinct real users that currently have the administrator capability.
        $rows = $this->conn->select(
            "SELECT u.ID, u.user_email, u.user_registered "
            ."FROM {$users} u "
            ."JOIN {$meta} m ON m.user_id = u.ID AND m.meta_key = ? "
            ."WHERE m.meta_value LIKE '%administrator%' "
            ."GROUP BY u.ID, u.user_email, u.user_registered",
            [$capKey]
        );

        $admins = count($rows);
        $foreign = 0;
        $recent = 0;
        $recentList = [];
        $regDays = [];          // distinct YYYY-MM-DD on which admins registered recently
        $cutoff = now()->subDays(30);
        foreach ($rows as $r) {
            $email = (string) ($r->user_email ?? '');
            $isGov = $email !== ''
                && (stripos($email, $expectedSuffix) !== false);
            if ($email !== '' && ! $isGov) {
                $foreign++;
            }
            if (! empty($r->user_registered) && $r->user_registered > $cutoff->toDateTimeString()) {
                $recent++;
                $recentList[] = [
                    'email' => $email,
                    'registered' => (string) $r->user_registered,
                    'gov_email' => $isGov,
                ];
                $regDays[substr((string) $r->user_registered, 0, 10)] = true;
            }
        }

        // Burst = several admins created within a tight window. A backdoor
        // attacker mass-creates accounts; legit gov sites add admins one at a
        // time over months. ≥3 new admins spanning ≤3 distinct days is a strong
        // backdoor signal — especially when the emails are non-gov.
        $recentNonGov = count(array_filter($recentList, fn ($a) => ! $a['gov_email']));
        $burst = $recent >= 3 && count($regDays) <= 3;

        return [
            'admins' => $admins,
            'foreign_email_admins' => $foreign,
            'recent_admins' => $recent,
            'recent_nongov_admins' => $recentNonGov,
            'recent_admin_list' => array_slice($recentList, 0, 8),
            'registration_burst' => $burst,
            'total_users' => $totalUsers,
        ];
    }
}
