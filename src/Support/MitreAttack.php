<?php

namespace Nawasara\Secscan\Support;

/**
 * Minimal MITRE ATT&CK helper — maps the technique IDs the agent emits to
 * human-readable names and canonical attack.mitre.org URLs. Only the techniques
 * used by nawasara-agent rules/signatures are listed; unknown IDs still render
 * with a working link (MITRE URL is derivable from the ID).
 */
class MitreAttack
{
    /** Technique ID => short name. */
    public const TECHNIQUES = [
        'T1027'     => 'Obfuscated Files or Information',
        'T1059.004' => 'Command & Scripting: Unix Shell',
        'T1078'     => 'Valid Accounts',
        'T1083'     => 'File & Directory Discovery',
        'T1105'     => 'Ingress Tool Transfer',
        'T1110.001' => 'Brute Force: Password Guessing',
        'T1190'     => 'Exploit Public-Facing Application',
        'T1505.003' => 'Server Software Component: Web Shell',
        'T1565.001' => 'Stored Data Manipulation',
        'T1566'     => 'Phishing',
        'T1595'     => 'Active Scanning',
        'T1595.002' => 'Active Scanning: Vulnerability Scanning',
        'T1595.003' => 'Active Scanning: Wordlist Scanning',
    ];

    public static function name(?string $id): ?string
    {
        if (! $id) {
            return null;
        }

        return self::TECHNIQUES[$id] ?? $id;
    }

    /**
     * Canonical MITRE URL. Sub-technique T1595.002 →
     * https://attack.mitre.org/techniques/T1595/002/
     */
    public static function url(?string $id): ?string
    {
        if (! $id || ! preg_match('/^T\d{4}(\.\d{3})?$/', $id)) {
            return null;
        }

        $path = str_replace('.', '/', $id);

        return "https://attack.mitre.org/techniques/{$path}/";
    }
}
