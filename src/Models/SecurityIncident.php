<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityIncident extends Model
{
    protected $table = 'nawasara_security_incidents';

    protected $fillable = [
        'incident_id', 'agent_id', 'type', 'severity', 'source_ip',
        'score', 'correlated', 'correlated_group_id', 'evidence',
        'metadata', 'detected_at', 'notified', 'notified_at',
    ];

    protected $casts = [
        'evidence'      => 'array',
        'metadata'      => 'array',
        'detected_at'   => 'datetime',
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
