<?php

namespace Nawasara\Secscan\Support;

/**
 * Menggolongkan sebuah versi PHP terhadap daftar versi yang sudah ditambal.
 *
 * Daftarnya berisi versi PERTAMA yang aman per cabang (config
 * `php_monitor.patched`, mis. `8.2.35`). Aturannya:
 *
 * - cabang tercantum, versi >= tambalan    → aman
 * - cabang tercantum, versi < tambalan     → rentan (ada tambalan, belum dipasang)
 * - cabang lebih lama dari semua yang tercantum → eol (tidak akan pernah ditambal)
 * - cabang lebih baru dari semua yang tercantum → aman (rilis sesudah advisory)
 *
 * ⚠️ cPanel kadang menambal cabang EOL sendiri tanpa mengubah nomor versi
 * PHP (ea-php81 8.1.34 bisa saja sudah ditambal). Golongan "eol" tetap
 * benar sebagai peringatan: tambalan resmi dari PHP untuk cabang itu tidak
 * ada, dan mengandalkan tambalan vendor yang tak terlihat bukan rencana.
 */
class PhpPatchLevels
{
    public const SAFE = 'safe';

    public const VULNERABLE = 'vulnerable';

    public const EOL = 'eol';

    public const HIDDEN = 'hidden';

    /** @var array<string,string> cabang "8.2" => versi aman pertama "8.2.35" */
    protected array $patched = [];

    /** @param  list<string>  $patched */
    public function __construct(array $patched)
    {
        foreach ($patched as $version) {
            if (preg_match('/^(\d+)\.(\d+)\.(\d+)$/', trim($version), $m)) {
                $this->patched["$m[1].$m[2]"] = "$m[1].$m[2].$m[3]";
            }
        }
        uksort($this->patched, 'version_compare');
    }

    public static function fromConfig(): self
    {
        return new self((array) config('nawasara-secscan.php_monitor.patched', []));
    }

    /** Versi kosong atau tak lengkap (mis. hanya "8.2") = PHP terdeteksi, versi tersembunyi. */
    public function classify(?string $version): string
    {
        if ($version === null || ! preg_match('/^(\d+)\.(\d+)\.(\d+)/', $version, $m)) {
            return self::HIDDEN;
        }

        $full = "$m[1].$m[2].$m[3]";
        $branch = "$m[1].$m[2]";

        if (isset($this->patched[$branch])) {
            return version_compare($full, $this->patched[$branch], '>=') ? self::SAFE : self::VULNERABLE;
        }

        if ($this->patched === []) {
            return self::SAFE;
        }

        $oldest = array_key_first($this->patched);

        return version_compare($branch, $oldest, '<') ? self::EOL : self::SAFE;
    }

    /** Versi aman yang dituju untuk sebuah versi, atau null bila tak ada tambalan di cabangnya. */
    public function targetFor(?string $version): ?string
    {
        if ($version === null || ! preg_match('/^(\d+)\.(\d+)/', $version, $m)) {
            return null;
        }

        return $this->patched["$m[1].$m[2]"] ?? null;
    }

    public static function label(string $status): string
    {
        return match ($status) {
            self::SAFE => 'Aman',
            self::VULNERABLE => 'Rentan',
            self::EOL => 'Tidak didukung',
            self::HIDDEN => 'Versi tersembunyi',
            default => $status,
        };
    }

    public static function color(string $status): string
    {
        return match ($status) {
            self::SAFE => 'success',
            self::VULNERABLE => 'danger',
            self::EOL => 'warning',
            default => 'neutral',
        };
    }
}
