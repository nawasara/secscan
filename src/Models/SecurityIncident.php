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
    ];

    protected $casts = [
        'evidence'      => 'array',
        'metadata'      => 'array',
        'detected_at'   => 'datetime',
        'last_seen_at'  => 'datetime',
        'notified_at'   => 'datetime',
        'correlated'    => 'boolean',
        'notified'      => 'boolean',
    ];

    const SEVERITY_INFO     = 'info';
    const SEVERITY_MEDIUM   = 'medium';
    const SEVERITY_HIGH     = 'high';
    const SEVERITY_CRITICAL = 'critical';

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class, 'agent_id');
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
        return match ($this->type) {
            'brute_force_http'  => 'Brute Force HTTP',
            'brute_force_ssh'   => 'Brute Force SSH',
            'ssh_root_login'    => 'SSH Root Login',
            'vuln_scan'         => 'Vulnerability Scan',
            'dir_traversal'     => 'Directory Traversal',
            'sqli_attempt'      => 'SQL Injection',
            'xss_probe'         => 'XSS Probe',
            'exploit_chain'     => 'Exploit Chain',
            '4xx_storm'         => '4xx Storm',
            default             => ucwords(str_replace('_', ' ', $this->type)),
        };
    }
}
