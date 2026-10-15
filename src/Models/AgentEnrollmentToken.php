<?php

namespace Nawasara\Secscan\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * Token pendaftaran agen sekali pakai (audit keamanan 15 Oktober 2026, T1).
 *
 * Admin membuatnya di halaman Agen, lalu menempelkannya ke perintah pasang.
 * Token mentah hanya ada di respons pembuatan; basis data hanya menyimpan
 * SHA-256-nya.
 */
class AgentEnrollmentToken extends Model
{
    protected $table = 'nawasara_agent_enrollment_tokens';

    public const PREFIX = 'nwe_';

    protected $fillable = [
        'token_hash', 'label', 'created_by', 'expires_at',
        'used_at', 'used_by_agent_id', 'used_from_ip', 'revoked_at', 'revoked_by',
    ];

    protected $hidden = ['token_hash'];

    protected $casts = [
        'expires_at' => 'datetime',
        'used_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    public static function generateRaw(): string
    {
        return self::PREFIX.bin2hex(random_bytes(24));
    }

    public static function hashToken(string $raw): string
    {
        return hash('sha256', trim($raw));
    }

    /**
     * Buat token baru. Mengembalikan [model, token mentah]; token mentah
     * tidak dapat diambil lagi setelah ini.
     *
     * @return array{0: self, 1: string}
     */
    public static function issue(?string $label, int $ttlHours, ?int $userId): array
    {
        $raw = self::generateRaw();

        $token = self::create([
            'token_hash' => self::hashToken($raw),
            'label' => $label !== null && trim($label) !== '' ? trim($label) : null,
            'created_by' => $userId,
            'expires_at' => Carbon::now()->addHours(max(1, $ttlHours)),
        ]);

        return [$token, $raw];
    }

    /**
     * Klaim token secara atomik untuk satu pendaftaran.
     *
     * Pencarian lewat indeks hash, lalu hash_equals sebagai pembanding yang
     * waktu-konstan. UPDATE bersyarat `used_at IS NULL` memastikan dua
     * pendaftaran serentak dengan token yang sama hanya satu yang menang.
     */
    public static function claim(string $raw, ?string $fromIp): ?self
    {
        $raw = trim($raw);
        if (! str_starts_with($raw, self::PREFIX) || strlen($raw) > 128) {
            return null;
        }

        $hash = self::hashToken($raw);
        $token = self::where('token_hash', $hash)->first();

        if (! $token || ! hash_equals((string) $token->token_hash, $hash)) {
            return null;
        }

        if (! $token->isUsableAt(Carbon::now())) {
            return null;
        }

        $won = self::whereKey($token->id)
            ->whereNull('used_at')
            ->whereNull('revoked_at')
            ->update(['used_at' => Carbon::now(), 'used_from_ip' => $fromIp]);

        return $won === 1 ? $token->refresh() : null;
    }

    /**
     * Logika murni (tanpa basis data) supaya dapat diuji: belum dipakai,
     * belum dicabut, dan belum kedaluwarsa pada saat $now.
     */
    public function isUsableAt(CarbonInterface $now): bool
    {
        return $this->used_at === null
            && $this->revoked_at === null
            && $this->expires_at !== null
            && $this->expires_at->greaterThan($now);
    }

    public function statusLabel(): string
    {
        return match (true) {
            $this->revoked_at !== null => 'Dicabut',
            $this->used_at !== null => 'Terpakai',
            $this->expires_at !== null && $this->expires_at->isPast() => 'Kedaluwarsa',
            default => 'Aktif',
        };
    }

    public function statusColor(): string
    {
        return match ($this->statusLabel()) {
            'Aktif' => 'success',
            'Terpakai' => 'info',
            default => 'neutral',
        };
    }

    public function creator(): BelongsTo
    {
        return $this->belongsTo(\App\Models\User::class, 'created_by');
    }

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class, 'used_by_agent_id')->withTrashed();
    }
}
