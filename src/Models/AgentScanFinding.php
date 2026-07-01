<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AgentScanFinding extends Model
{
    protected $table = 'nawasara_agent_scan_findings';

    protected $fillable = [
        'finding_id', 'agent_id',
        'path', 'signature_id', 'sig_name', 'category', 'severity', 'score',
        'description', 'matched_line',
        'file_size', 'file_mtime',
        'status', 'triaged_by', 'triaged_at', 'triage_note',
        'detected_at',
    ];

    protected $casts = [
        'file_mtime'  => 'datetime',
        'triaged_at'  => 'datetime',
        'detected_at' => 'datetime',
    ];

    const STATUS_OPEN           = 'open';
    const STATUS_ACKNOWLEDGED   = 'acknowledged';
    const STATUS_RESOLVED       = 'resolved';
    const STATUS_FALSE_POSITIVE = 'false_positive';

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class);
    }

    public function triagedBy(): BelongsTo
    {
        return $this->belongsTo(\App\Models\User::class, 'triaged_by');
    }

    public function statusColor(): string
    {
        return match ($this->status) {
            self::STATUS_OPEN           => 'danger',
            self::STATUS_ACKNOWLEDGED   => 'warning',
            self::STATUS_RESOLVED       => 'success',
            self::STATUS_FALSE_POSITIVE => 'neutral',
            default                     => 'neutral',
        };
    }

    public function severityColor(): string
    {
        return match ($this->severity) {
            'critical' => 'danger',
            'high'     => 'warning',
            'medium'   => 'info',
            default    => 'neutral',
        };
    }

    public function categoryLabel(): string
    {
        return match ($this->category) {
            'webshell'  => 'Webshell',
            'backdoor'  => 'Backdoor',
            'exploit'   => 'Exploit Artifact',
            'integrity' => 'File Integrity',
            default     => ucfirst($this->category),
        };
    }

    public function isOpen(): bool
    {
        return $this->status === self::STATUS_OPEN;
    }
}
