<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AgentHeartbeat extends Model
{
    protected $table = 'nawasara_agent_heartbeats';

    protected $fillable = [
        'agent_id', 'agent_version', 'health_score', 'pending_incidents',
        'plugins_active', 'metrics', 'uptime_seconds',
    ];

    protected $casts = [
        'plugins_active' => 'array',
        'metrics'        => 'array',
        'health_score'   => 'float',
    ];

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class, 'agent_id');
    }
}
