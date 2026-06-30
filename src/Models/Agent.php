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
    ];

    protected $casts = [
        'plugins_active' => 'array',
        'last_seen_at'   => 'datetime',
        'registered_at'  => 'datetime',
        'health_score'   => 'float',
    ];

    const STATUS_NEVER   = 'never_connected';
    const STATUS_ONLINE  = 'online';
    const STATUS_OFFLINE = 'offline';

    // Offline if no heartbeat in last 3 minutes
    const OFFLINE_THRESHOLD_SECONDS = 180;

    public function incidents(): HasMany
    {
        return $this->hasMany(SecurityIncident::class, 'agent_id');
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

    public function statusLabel(): string
    {
        if ($this->status === self::STATUS_NEVER) return 'Belum Connect';
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

    public static function findByApiKey(string $rawKey): ?self
    {
        // Api key format: nwa_{32chars} — hash stored as bcrypt
        return static::where('status', '!=', self::STATUS_NEVER)
            ->get()
            ->first(fn ($agent) => password_verify($rawKey, $agent->api_key_hash));
    }

    public static function generateApiKey(): string
    {
        return 'nwa_'.bin2hex(random_bytes(16));
    }
}
