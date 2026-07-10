<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A record of one IP block action (automatic via the Decision Engine, or
 * manual via an operator). The source of truth for what is currently blocked
 * and the handle (cf_rule_id) needed to unblock it later.
 */
class IpBlock extends Model
{
    protected $table = 'nawasara_ip_blocks';

    protected $fillable = [
        'ip', 'status', 'reason', 'cf_rule_id', 'incident_id', 'dry_run',
        'notes', 'blocked_by', 'unblocked_by', 'blocked_at', 'unblocked_at',
    ];

    protected $casts = [
        'dry_run'      => 'boolean',
        'blocked_at'   => 'datetime',
        'unblocked_at' => 'datetime',
    ];

    public const STATUS_ACTIVE  = 'active';
    public const STATUS_REMOVED = 'removed';

    public function incident(): BelongsTo
    {
        return $this->belongsTo(SecurityIncident::class, 'incident_id');
    }

    public function blockedBy(): BelongsTo
    {
        return $this->belongsTo(\App\Models\User::class, 'blocked_by');
    }

    public function scopeActive($query)
    {
        return $query->where('status', self::STATUS_ACTIVE);
    }

    public function isActive(): bool
    {
        return $this->status === self::STATUS_ACTIVE;
    }

    /** True for a decided-but-not-actually-enforced block (dry-run mode). */
    public function isDryRun(): bool
    {
        return (bool) $this->dry_run;
    }
}
