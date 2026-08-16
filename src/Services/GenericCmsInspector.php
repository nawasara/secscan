<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Database\Connection;

/**
 * Read-only content inspector for NON-WordPress databases.
 *
 * WpInspector only understands WordPress: it looks for a {prefix}posts table
 * and gives up when there isn't one. On the production server that blind spot
 * is the majority — 99 of 155 schemas are custom PHP CMSes written for a single
 * OPD, with Indonesian table names (berita, album, halamanstatis) and no shared
 * convention between them.
 *
 * That gap is not theoretical. puskesmaspudak.ponorogo.go.id runs one of these
 * CMSes and was serving 1,784 rows of abortion-pill spam out of its `berita`
 * table. The SQL scanner walked straight past it every hour for weeks, because
 * wordpressPrefix() returned null and the schema was skipped.
 *
 * Rather than teach the scanner every CMS, this finds content columns by NAME
 * (judul/isi/title/content/…) from information_schema and matches keywords
 * against them. Structure-agnostic: it works on a CMS nobody has seen before.
 *
 * SECURITY: identifiers come from the server but are still untrusted — every
 * one is whitelist-validated and backtick-quoted before interpolation, and all
 * values are bound. Same contract as WpInspector.
 */
class GenericCmsInspector
{
    /**
     * Column names that hold human-readable content across the CMSes on this
     * server. Matched as a substring of the column name, case-insensitively:
     * "judul" also catches "judul_seo" and "sub_judul".
     */
    private const CONTENT_COLUMN_PATTERNS = [
        'judul', 'title', 'isi', 'content', 'konten',
        'deskripsi', 'description', 'keterangan', 'nama', 'name',
        'artikel', 'berita', 'text', 'body', 'seo',
    ];

    /** Tables that never hold public page content — skip to keep the sweep cheap. */
    private const SKIP_TABLE_PATTERNS = [
        'migration', 'job_batches', 'failed_jobs', 'sessions', 'cache',
        'password_reset', 'personal_access_token', 'telescope', 'permission',
        'role', 'oauth_', 'log', 'audit',
    ];

    public function __construct(protected Connection $conn) {}

    /**
     * Validate + backtick-quote a MySQL identifier. Mirrors WpInspector.
     */
    public function quoteIdent(string $name): string
    {
        if (! preg_match('/^[A-Za-z0-9_$]+$/', $name)) {
            throw new \InvalidArgumentException("Unsafe identifier: {$name}");
        }

        return '`'.$name.'`';
    }

    /**
     * Discover candidate content columns in a schema.
     *
     * @return list<array{table:string, column:string}>
     */
    public function contentColumns(string $db, int $limit = 60): array
    {
        $rows = $this->conn->select(
            'SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = ?
               AND DATA_TYPE IN (?, ?, ?, ?)
             ORDER BY TABLE_NAME, COLUMN_NAME',
            [$db, 'varchar', 'text', 'mediumtext', 'longtext']
        );

        $out = [];
        foreach ($rows as $r) {
            $table  = (string) $r->TABLE_NAME;
            $column = (string) $r->COLUMN_NAME;

            if (! preg_match('/^[A-Za-z0-9_$]+$/', $table)
                || ! preg_match('/^[A-Za-z0-9_$]+$/', $column)) {
                continue;
            }
            if ($this->matchesAny($table, self::SKIP_TABLE_PATTERNS)) {
                continue;
            }
            if (! $this->matchesAny($column, self::CONTENT_COLUMN_PATTERNS)) {
                continue;
            }

            $out[] = ['table' => $table, 'column' => $column];
            if (count($out) >= $limit) {
                break;
            }
        }

        return $out;
    }

    /**
     * Count rows whose content matches any keyword, with a few sample values.
     *
     * Matching uses ONE REGEXP alternation per column, not a chain of ORed
     * LIKEs. These columns are unindexed free text, so every predicate is a
     * full scan: with 13 pharma keywords an OR-chain scans each column 13
     * times. Measured on the production server, that turned a sub-second
     * schema (bantaranginapp_antrian, 34 columns) into minutes — unusable in
     * an hourly job that already sweeps 155 schemas. A single REGEXP visits
     * each row once regardless of keyword count.
     *
     * @param  list<string>  $keywords
     * @return array{count:int, samples:list<array{table:string, column:string, value:string}>, columns:array<string,int>}
     */
    public function matchedContent(string $db, array $keywords, int $sampleLimit = 5): array
    {
        if (empty($keywords)) {
            return ['count' => 0, 'samples' => [], 'columns' => []];
        }

        $total   = 0;
        $samples = [];
        $columns = [];
        $regex   = $this->keywordRegex($keywords);

        foreach ($this->contentColumns($db) as $cc) {
            $table  = $this->quoteIdent($db).'.'.$this->quoteIdent($cc['table']);
            $column = $this->quoteIdent($cc['column']);

            $where    = "{$column} REGEXP ?";
            $bindings = [$regex];

            try {
                $count = (int) $this->conn->scalar(
                    "SELECT COUNT(*) FROM {$table} WHERE {$where}",
                    $bindings
                );
            } catch (\Throwable) {
                // A single unreadable table must never abort the schema sweep.
                continue;
            }

            if ($count <= 0) {
                continue;
            }

            $total += $count;
            $columns[$cc['table'].'.'.$cc['column']] = $count;

            if (count($samples) < $sampleLimit) {
                try {
                    $rows = $this->conn->select(
                        "SELECT {$column} AS v FROM {$table} WHERE {$where} LIMIT 2",
                        $bindings
                    );
                    foreach ($rows as $r) {
                        if (count($samples) >= $sampleLimit) {
                            break;
                        }
                        $samples[] = [
                            'table'  => $cc['table'],
                            'column' => $cc['column'],
                            'value'  => mb_substr(trim(preg_replace('/\s+/', ' ', (string) $r->v) ?? ''), 0, 120),
                        ];
                    }
                } catch (\Throwable) {
                    // Evidence is optional; the count already stands.
                }
            }
        }

        return ['count' => $total, 'samples' => $samples, 'columns' => $columns];
    }

    /**
     * Build one REGEXP alternation from the keyword list.
     *
     * No word boundaries here, unlike WpInspector's judolRegex(). This path
     * matches HTML bodies where a keyword is routinely glued to markup
     * ("<p>Jual Obat Aborsi" or a hyphenated slug), and a boundary assertion
     * would miss those. Only STRONG keywords reach this method — multi-word
     * commercial phrases that do not occur inside ordinary Indonesian words —
     * so substring matching does not reintroduce the "judi"→"Iswahjudi" class
     * of false positive that boundaries were added to prevent.
     *
     * @param  list<string>  $keywords
     */
    private function keywordRegex(array $keywords): string
    {
        $parts = [];
        foreach ($keywords as $kw) {
            $kw = trim((string) $kw);
            if ($kw === '') {
                continue;
            }
            // Escape regex metacharacters; spaces stay literal so multi-word
            // phrases keep working.
            $parts[] = preg_replace('/([.\\\\+*?\[\]^$(){}|\/-])/', '\\\\$1', $kw);
        }

        if (empty($parts)) {
            return '$^';   // matches nothing
        }

        return '('.implode('|', $parts).')';
    }

    /** Case-insensitive substring match against a pattern list. */
    private function matchesAny(string $haystack, array $patterns): bool
    {
        $lower = mb_strtolower($haystack);
        foreach ($patterns as $p) {
            if (str_contains($lower, $p)) {
                return true;
            }
        }

        return false;
    }
}