<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

class Agent extends Model
{
    use SoftDeletes;

    protected $table = 'nawasara_agents';

    protected $fillable = [
        'agent_id', 'name', 'hostname', 'os', 'arch', 'agent_version',
        'web_server', 'ip_local', 'opd_id', 'api_key_hash', 'status',
        'health_score', 'plugins_active', 'last_seen_at', 'registered_at',
        'approval_status', 'approved_by', 'approved_at', 'enrollment_token_id',
    ];

    protected $hidden = ['api_key_hash'];

    protected $casts = [
        'plugins_active' => 'array',
        'last_seen_at'   => 'datetime',
        'registered_at'  => 'datetime',
        'approved_at'    => 'datetime',
        'health_score'   => 'float',
    ];

    const STATUS_NEVER   = 'never_connected';
    const STATUS_ONLINE  = 'online';
    const STATUS_OFFLINE = 'offline';

    // Persetujuan agen (audit keamanan 15 Oktober 2026, T1). Hanya agen
    // `approved` yang insidennya masuk Decision Engine dan yang menerima
    // perintah. Agen lama ditandai approved oleh migrasinya.
    const APPROVAL_PENDING  = 'pending';
    const APPROVAL_APPROVED = 'approved';

    // Offline if no heartbeat in last 3 minutes
    const OFFLINE_THRESHOLD_SECONDS = 180;

    public function incidents(): HasMany
    {
        return $this->hasMany(SecurityIncident::class, 'agent_id');
    }

    public function commands(): HasMany
    {
        return $this->hasMany(AgentCommand::class, 'agent_id');
    }

    public function heartbeats(): HasMany
    {
        return $this->hasMany(AgentHeartbeat::class, 'agent_id');
    }

    public function isOnline(): bool
    {
        if (! $this->last_seen_at) {
            return false;
        }
        return $this->last_seen_at->diffInSeconds(now()) < self::OFFLINE_THRESHOLD_SECONDS;
    }

    /**
     * Online/offline by last heartbeat, the same rule as isOnline().
     *
     * The `status` column is NOT used for this: it is written on each
     * heartbeat and only flipped back later, so filtering on it disagreed
     * with the badge on the same row. One definition for the filter, the
     * stat cards and the dashboard.
     */
    public function scopeOnline($query)
    {
        return $query->where('last_seen_at', '>=', now()->subSeconds(self::OFFLINE_THRESHOLD_SECONDS));
    }

    public function scopeOffline($query)
    {
        return $query->where('status', '!=', self::STATUS_NEVER)
            ->where(fn ($q) => $q->whereNull('last_seen_at')
                ->orWhere('last_seen_at', '<', now()->subSeconds(self::OFFLINE_THRESHOLD_SECONDS)));
    }

    /** The agent already reports "v0.11.2"; prefixing another v showed "vv0.11.2". */
    public function versionLabel(): ?string
    {
        if (! $this->agent_version) {
            return null;
        }

        return str_starts_with($this->agent_version, 'v') ? $this->agent_version : 'v'.$this->agent_version;
    }

    /**
     * Retire an agent: its key stops working, its queued commands are
     * cancelled, its offline alert is resolved.
     *
     * Soft delete keeps its incidents and history readable. The key hash is
     * replaced as well, so restoring the row by hand never revives a key that
     * may still sit on a decommissioned server.
     *
     * The queued commands matter: a dead agent never pulls them, and they
     * piled up as "approved" for months (170 in production on 8 October
     * 2026) while the panel showed those IPs as blocked on the host.
     *
     * @return int commands cancelled
     */
    public function revoke(?int $userId): int
    {
        $cancelled = AgentCommand::where('agent_id', $this->id)
            ->whereIn('status', [AgentCommand::STATUS_PENDING, AgentCommand::STATUS_APPROVED])
            ->update([
                'status' => AgentCommand::STATUS_REJECTED,
                'rejected_by' => $userId,
                'rejected_at' => now(),
                'rejection_reason' => 'Dibatalkan: agen dicabut.',
            ]);

        $this->forceFill(['api_key_hash' => password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT)])->save();
        $this->delete();

        if (class_exists(\Nawasara\Alerting\Facades\Alerter::class)) {
            try {
                \Nawasara\Alerting\Facades\Alerter::resolve('secscan.agent.offline', 'Agent', (string) $this->id);
            } catch (\Throwable) {
                // The rule is registered by the health job's worker; a web
                // process that never registered it must not fail the revoke.
            }
        }

        return $cancelled;
    }

    public function statusLabel(): string
    {
        if ($this->status === self::STATUS_NEVER) return 'Belum terhubung';
        return $this->isOnline() ? 'Online' : 'Offline';
    }

    public function statusColor(): string
    {
        if ($this->status === self::STATUS_NEVER) return 'neutral';
        return $this->isOnline() ? 'success' : 'danger';
    }

    public function healthColor(): string
    {
        return match (true) {
            $this->health_score >= 80 => 'success',
            $this->health_score >= 60 => 'warning',
            $this->health_score >= 40 => 'orange',
            default                   => 'danger',
        };
    }

    public function isApproved(): bool
    {
        return $this->approval_status === self::APPROVAL_APPROVED && ! $this->trashed();
    }

    public function scopeApproved($query)
    {
        return $query->where('approval_status', self::APPROVAL_APPROVED);
    }

    /**
     * Cari agen untuk satu permintaan API: WAJIB lewat agent_id, lalu satu
     * password_verify terhadap baris itu saja.
     *
     * Audit keamanan 15 Oktober 2026 (T1): versi lama (findByApiKey) mencoba
     * password_verify ke SETIAP agen bila X-Agent-Id tidak dikirim. Dengan
     * ratusan agen palsu, satu permintaan memakan ratusan operasi bcrypt (DoS).
     * Jalur itu tidak dibutuhkan: semua agen Go mengirim X-Agent-Id sejak
     * reporter.go ed96e75 (1 Juli 2026), sehari setelah tabel ini dibuat,
     * begitu pula executor dan scanner.
     */
    public static function authenticate(string $agentId, string $rawKey): ?self
    {
        if ($agentId === '' || $rawKey === '' || strlen($agentId) > 64 || strlen($rawKey) > 128) {
            return null;
        }

        $agent = static::where('agent_id', $agentId)->first();

        if (! $agent || ! password_verify($rawKey, (string) $agent->api_key_hash)) {
            return null;
        }

        return $agent;
    }

    public static function generateApiKey(): string
    {
        return 'nwa_'.bin2hex(random_bytes(16));
    }
}
