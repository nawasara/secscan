<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Nawasara\Secscan\Support\MitreAttack;

class SecurityIncident extends Model
{
    protected $table = 'nawasara_security_incidents';

    protected $fillable = [
        'incident_id', 'agent_id', 'type', 'severity', 'source_ip',
        'score', 'occurrences', 'correlated', 'correlated_group_id',
        'mitre_technique', 'evidence',
        'metadata', 'detected_at', 'last_seen_at', 'notified', 'notified_at',
        'blocked_at', 'block_id',
    ];

    protected $casts = [
        'evidence'      => 'array',
        'metadata'      => 'array',
        'detected_at'   => 'datetime',
        'last_seen_at'  => 'datetime',
        'notified_at'   => 'datetime',
        'blocked_at'    => 'datetime',
        'correlated'    => 'boolean',
        'notified'      => 'boolean',
    ];

    const SEVERITY_INFO     = 'info';
    const SEVERITY_MEDIUM   = 'medium';
    const SEVERITY_HIGH     = 'high';
    const SEVERITY_CRITICAL = 'critical';

    public function agent(): BelongsTo
    {
        // withTrashed: a revoked agent's incidents still name the host they
        // came from, instead of turning into anonymous rows.
        return $this->belongsTo(Agent::class, 'agent_id')->withTrashed();
    }

    public function block(): BelongsTo
    {
        return $this->belongsTo(IpBlock::class, 'block_id');
    }

    public function isBlocked(): bool
    {
        return $this->blocked_at !== null;
    }

    /**
     * Returns whichever of the two severities ranks higher
     * (info < medium < high < critical). Used when aggregating
     * a re-detected incident into an existing row.
     */
    public static function maxSeverity(string $a, string $b): string
    {
        $rank = [
            self::SEVERITY_INFO     => 0,
            self::SEVERITY_MEDIUM   => 1,
            self::SEVERITY_HIGH     => 2,
            self::SEVERITY_CRITICAL => 3,
        ];

        return ($rank[$a] ?? 0) >= ($rank[$b] ?? 0) ? $a : $b;
    }

    public function mitreName(): ?string
    {
        return MitreAttack::name($this->mitre_technique);
    }

    public function mitreUrl(): ?string
    {
        return MitreAttack::url($this->mitre_technique);
    }

    public function severityColor(): string
    {
        return match ($this->severity) {
            self::SEVERITY_CRITICAL => 'danger',
            self::SEVERITY_HIGH     => 'warning',
            self::SEVERITY_MEDIUM   => 'info',
            default                 => 'neutral',
        };
    }

    public function typeLabel(): string
    {
        return self::labelForType($this->type);
    }

    /**
     * One label per attack type, shared by incidents and IP blocks (a block's
     * `reason` is the type of the incident that triggered it).
     *
     * Established attack names stay as they are (Brute Force, SQL Injection,
     * XSS, Webshell): staff search for and report them by those names. Only
     * the descriptive ones are Indonesian.
     */
    public static function labelForType(?string $type): string
    {
        return match ($type) {
            'brute_force', 'brute_force_http' => 'Brute Force HTTP',
            'brute_force_ssh' => 'Brute Force SSH',
            'ssh_root_login' => 'Login Root SSH',
            'vuln_scan', 'vulnerability_scan' => 'Pemindaian Celah',
            'dir_traversal', 'directory_traversal' => 'Directory Traversal',
            'sqli_attempt', 'sql_injection' => 'SQL Injection',
            'xss_probe' => 'Percobaan XSS',
            'exploit_chain' => 'Rantai Eksploit',
            '4xx_storm' => 'Banjir Galat 4xx',
            'scanner_bot' => 'Bot Pemindai',
            'webshell_upload' => 'Unggah Webshell',
            null, '' => '-',
            default => ucfirst(str_replace('_', ' ', $type)),
        };
    }

    /**
     * "Hari ini" as staff in Ponorogo mean it: since midnight WIB.
     *
     * whereDate(..., today()) used the app timezone, which is UTC, so the
     * "today" cards rolled over at 07:00 WIB and counted the small hours in
     * the previous day.
     */
    public function scopeToday($query, string $column = 'detected_at')
    {
        return $query->where($column, '>=', now('Asia/Jakarta')->startOfDay()->utc());
    }

    /** @return array<string,string> */
    public static function severityLabels(): array
    {
        return [
            self::SEVERITY_CRITICAL => 'Kritis',
            self::SEVERITY_HIGH => 'Tinggi',
            self::SEVERITY_MEDIUM => 'Sedang',
            self::SEVERITY_INFO => 'Info',
        ];
    }

    public function severityLabel(): string
    {
        return self::severityLabels()[$this->severity] ?? ucfirst((string) $this->severity);
    }
}
