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
                if (isset($set[$p.'posts'], $set[$p.'users'])) {
                    return $p;
                }
            }
        }

        return null;
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
     * Count published posts/pages whose title matches any keyword. Returns the
     * count plus a few sample titles for the evidence trail. Keywords are
     * matched as bound LIKE params (no interpolation).
     *
     * @param  list<string>  $keywords
     * @return array{count:int, samples:list<string>}
     */
    public function publishedJudolPosts(string $db, string $prefix, array $keywords): array
    {
        if (empty($keywords)) {
            return ['count' => 0, 'samples' => []];
        }
        $table = $this->quoteIdent($db).'.'.$this->quoteIdent($prefix.'posts');

        $likes = [];
        $bind = [];
        foreach ($keywords as $kw) {
            $likes[] = 'post_title LIKE ?';
            $bind[] = '%'.trim($kw).'%';
        }
        $where = implode(' OR ', $likes);

        $count = (int) $this->conn->scalar(
            "SELECT COUNT(*) FROM {$table} WHERE post_status = 'publish' AND post_type IN ('post','page') AND ({$where})",
            $bind
        );

        $samples = [];
        if ($count > 0) {
            $rows = $this->conn->select(
                "SELECT post_title FROM {$table} WHERE post_status = 'publish' AND post_type IN ('post','page') AND ({$where}) ORDER BY post_date DESC LIMIT 5",
                $bind
            );
            $samples = array_map(fn ($r) => mb_substr((string) $r->post_title, 0, 120), $rows);
        }

        return ['count' => $count, 'samples' => $samples];
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

        $count = (int) $this->conn->scalar(
            "SELECT COUNT(*) FROM {$table} WHERE post_status = 'publish' AND ("
            ."post_content REGEXP '<script[^>]*display:[[:space:]]*none' "
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
        $cutoff = now()->subDays(14);
        foreach ($rows as $r) {
            $email = (string) ($r->user_email ?? '');
            if ($email !== '' && stripos($email, $expectedSuffix) === false
                && stripos($email, '@'.$expectedSuffix) === false) {
                // Only count clearly-external if it isn't a gov address. Many
                // legit admins use gmail though, so this stays a weak signal.
                $foreign++;
            }
            if (! empty($r->user_registered) && $r->user_registered > $cutoff->toDateTimeString()) {
                $recent++;
            }
        }

        return [
            'admins' => $admins,
            'foreign_email_admins' => $foreign,
            'recent_admins' => $recent,
            'total_users' => $totalUsers,
        ];
    }
}
