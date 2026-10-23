<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Nawasara\Secscan\Support\PhpPatchLevels;

/**
 * Satu versi PHP yang terlihat di ekosistem. Lihat migrasi
 * create_nawasara_secscan_php_runtimes_table.
 */
class PhpRuntime extends Model
{
    public const SOURCE_EXTERNAL = 'external';

    public const SOURCE_WHM = 'whm';

    public const SOURCE_AGENT = 'agent';

    protected $table = 'nawasara_secscan_php_runtimes';

    protected $guarded = ['id'];

    protected $casts = [
        'exposes_version' => 'boolean',
        'first_seen_at' => 'datetime',
        'last_seen_at' => 'datetime',
    ];

    /**
     * Simpan satu pengamatan. Status dihitung ulang dari versinya di sini,
     * supaya mengganti daftar tambalan cukup dengan memindai ulang.
     *
     * ⚠️ origin null disimpan sebagai string kosong: indeks unik MySQL
     * menganggap dua NULL berbeda, sehingga updateOrCreate dengan origin
     * null akan menambah baris ganda tiap pemindaian.
     */
    public static function record(string $source, string $target, ?string $origin, array $attrs, PhpPatchLevels $levels): self
    {
        $version = $attrs['php_version'] ?? null;
        $now = now();

        $row = static::firstOrNew([
            'source' => $source,
            'target' => mb_substr(strtolower($target), 0, 191),
            'origin' => (string) $origin,
        ]);

        $row->fill([
            'handler' => $attrs['handler'] ?? null,
            'php_version' => $version,
            'status' => $levels->classify($version),
            'detected_via' => $attrs['detected_via'] ?? null,
            'exposes_version' => (bool) ($attrs['exposes_version'] ?? false),
            'last_seen_at' => $now,
        ]);
        $row->first_seen_at ??= $now;
        $row->save();

        return $row;
    }

    public static function sourceLabel(?string $source): string
    {
        return match ($source) {
            self::SOURCE_EXTERNAL => 'Dari luar',
            self::SOURCE_WHM => 'Server WHM',
            self::SOURCE_AGENT => 'Agen',
            default => (string) $source,
        };
    }
}
