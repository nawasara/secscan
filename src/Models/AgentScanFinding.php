<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Nawasara\Secscan\Support\MitreAttack;

class AgentScanFinding extends Model
{
    protected $table = 'nawasara_agent_scan_findings';

    protected $fillable = [
        'finding_id', 'agent_id',
        'path', 'signature_id', 'mitre_technique', 'sig_name', 'category', 'severity', 'score',
        'description', 'matched_line', 'matched_context', 'context_start_line', 'match_line',
        'file_size', 'file_mtime',
        'status', 'triaged_by', 'triaged_at', 'triage_note',
        'detected_at', 'last_seen_at',
    ];

    protected $casts = [
        'file_mtime'   => 'datetime',
        'triaged_at'   => 'datetime',
        'detected_at'  => 'datetime',
        'last_seen_at' => 'datetime',
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

    /**
     * Code context as numbered lines for the "Lihat kode" modal.
     *
     * @return list<array{no:int, text:string, match:bool}>
     */
    public function codeLines(): array
    {
        if ($this->matched_context === null || $this->matched_context === '') {
            return [];
        }

        $start = max(1, (int) $this->context_start_line);
        $lines = [];
        foreach (explode("\n", $this->matched_context) as $i => $text) {
            $no = $start + $i;
            $lines[] = ['no' => $no, 'text' => $text, 'match' => $no === (int) $this->match_line];
        }

        return $lines;
    }

    public function mitreName(): ?string
    {
        return MitreAttack::name($this->mitre_technique);
    }

    public function mitreUrl(): ?string
    {
        return MitreAttack::url($this->mitre_technique);
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
            'seo_spam'  => 'SEO Spam',
            default     => ucfirst($this->category),
        };
    }

    public function isOpen(): bool
    {
        return $this->status === self::STATUS_OPEN;
    }
}
