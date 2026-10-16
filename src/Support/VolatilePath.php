<?php

namespace Nawasara\Secscan\Support;

/**
 * Paths whose files rewrite themselves — page caches, logs, sessions,
 * compiled templates. Integrity changes there are noise.
 *
 * Mirrors internal/scanner/volatile.go in nawasara/agent; keep the two lists
 * in step. Measured on alpine (16 Oct 2026): of 29,263 open integrity findings
 * only 1,818 were caches/logs. The bulk (27,445) are WordPress core and plugin
 * files changed by updates — deliberately NOT skipped here, since that is
 * where backdoors go; telling them apart needs WP checksums (README roadmap).
 */
class VolatilePath
{
    public const DEFAULTS = [
        '/wp-content/cache/',
        '/wp-content/litespeed/',
        '/wp-content/et-cache/',
        '/wp-content/uploads/cache/',
        '/wp-content/w3tc-config/',
        '/storage/framework/',
        '/storage/logs/',
        '/bootstrap/cache/',
        '/application/logs/',
        '/application/cache/',
        '/application/user/logs/',
        '/writable/cache/',
        '/writable/logs/',
        '/writable/session/',
        '/tmp/',
        '/cache/',
        '/logs/',
    ];

    public static function matches(string $path): bool
    {
        $lower = strtolower(str_replace('\\', '/', $path));

        // Guarded: also runs in container-less unit tests.
        $extra = function_exists('app') && app()->bound('config')
            ? (array) config('nawasara-secscan.agent_scan.integrity_ignore', [])
            : [];

        foreach (array_merge(self::DEFAULTS, $extra) as $needle) {
            if ($needle !== '' && str_contains($lower, strtolower((string) $needle))) {
                return true;
            }
        }

        // Per-day logs written as PHP so they are not served raw
        // (CodeIgniter: log-2026-10-16.php).
        $base = basename($lower);

        return str_starts_with($base, 'log-') && str_ends_with($base, '.php');
    }
}
