<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A detected security issue on a monitored site/database. One row per
 * (db_name, threat_type) — the scanner upserts, so a recurring problem
 * refreshes score/last_detected_at rather than duplicating.
 */
class SecscanFinding extends Model
{
    protected $table = 'nawasara_secscan_findings';

    public const THREAT_JUDOL = 'judol';
    public const THREAT_DEFACED = 'defaced';
    public const THREAT_PHISHING = 'phishing';
    public const THREAT_SPAM = 'spam';
    public const THREAT_MALWARE = 'malware';
    public const THREAT_BACKDOOR = 'backdoor';

    public const STATUS_OPEN = 'open';
    public const STATUS_ACKNOWLEDGED = 'acknowledged';
    public const STATUS_FALSE_POSITIVE = 'false_positive';
    public const STATUS_RESOLVED = 'resolved';

    public const SEVERITY_CRITICAL = 'critical';
    public const SEVERITY_WARNING = 'warning';
    public const SEVERITY_INFO = 'info';

    protected $guarded = [];

    protected $casts = [
        'evidence' => 'array',
        'score' => 'integer',
        'first_detected_at' => 'datetime',
        'last_detected_at' => 'datetime',
        'acknowledged_at' => 'datetime',
        'resolved_at' => 'datetime',
    ];

    public function histories(): HasMany
    {
        return $this->hasMany(SecscanFindingHistory::class, 'finding_id');
    }

    /** Findings that still need attention (not dismissed/resolved). */
    public function scopeActive($query)
    {
        return $query->whereIn('status', [self::STATUS_OPEN, self::STATUS_ACKNOWLEDGED]);
    }

    public function isActive(): bool
    {
        return in_array($this->status, [self::STATUS_OPEN, self::STATUS_ACKNOWLEDGED], true);
    }

    public static function threatLabels(): array
    {
        return [
            self::THREAT_JUDOL => 'Judi Online',
            self::THREAT_DEFACED => 'Defacement',
            self::THREAT_PHISHING => 'Phishing',
            self::THREAT_SPAM => 'SEO Spam',
            self::THREAT_MALWARE => 'Malware',
            self::THREAT_BACKDOOR => 'Akun Backdoor',
        ];
    }

    public function threatLabel(): string
    {
        return self::threatLabels()[$this->threat_type] ?? ucfirst($this->threat_type);
    }

    public static function statusLabels(): array
    {
        return [
            self::STATUS_OPEN => 'Terbuka',
            self::STATUS_ACKNOWLEDGED => 'Diakui',
            self::STATUS_FALSE_POSITIVE => 'False Positive',
            self::STATUS_RESOLVED => 'Selesai',
        ];
    }

    public function statusLabel(): string
    {
        return self::statusLabels()[$this->status] ?? ucfirst($this->status);
    }

    /** nawasara-ui badge color token for severity. */
    public function severityColor(): string
    {
        return match ($this->severity) {
            self::SEVERITY_CRITICAL => 'danger',
            self::SEVERITY_WARNING => 'warning',
            default => 'neutral',
        };
    }

    /** nawasara-ui badge color token for status. */
    public function statusColor(): string
    {
        return match ($this->status) {
            self::STATUS_OPEN => 'danger',
            self::STATUS_ACKNOWLEDGED => 'warning',
            self::STATUS_RESOLVED => 'success',
            self::STATUS_FALSE_POSITIVE => 'neutral',
            default => 'neutral',
        };
    }
}
