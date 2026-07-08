<?php

namespace Nawasara\Secscan\Jobs;

use Illuminate\Support\Facades\DB;
use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Models\SecscanFindingHistory;
use Nawasara\Secscan\Services\SqlSignalDetector;
use Nawasara\Sync\Jobs\AbstractSyncJob;

/**
 * Hourly WordPress security scan. Runs SqlSignalDetector against every
 * monitored WP database, upserts findings, records triage history on new/
 * recurring issues, and fires alerts for critical findings.
 *
 * Read-only against OPD databases — the only writes are to local
 * nawasara_secscan_* tables.
 */
class ScanWordpressJob extends AbstractSyncJob
{
    public int $timeout = 300;

    protected function service(): string
    {
        return 'secscan';
    }

    protected function action(): string
    {
        return 'scan_wordpress';
    }

    protected function targetType(): ?string
    {
        return null;
    }

    protected function targetId(): ?string
    {
        return null;
    }

    protected function execute(): array
    {
        $detector = app(SqlSignalDetector::class);
        $result = $detector->scanAll();

        $now = now();
        $seenKeys = [];
        $created = 0;
        $updated = 0;
        $alerted = 0;
        $alertMin = (int) config('nawasara-secscan.thresholds.alert_min_score', 70);

        foreach ($result['findings'] as $f) {
            $seenKeys[] = $f['db_name'].'|'.$f['threat_type'];

            $existing = SecscanFinding::where('db_name', $f['db_name'])
                ->where('threat_type', $f['threat_type'])
                ->first();

            if (! $existing) {
                $finding = SecscanFinding::create([
                    'db_name' => $f['db_name'],
                    'site_url' => $f['site_url'],
                    'site_name' => $f['site_name'],
                    'threat_type' => $f['threat_type'],
                    'severity' => $f['severity'],
                    'score' => $f['score'],
                    'status' => SecscanFinding::STATUS_OPEN,
                    'evidence' => $f['evidence'],
                    'first_detected_at' => $now,
                    'last_detected_at' => $now,
                ]);
                $this->recordHistory($finding, null, SecscanFinding::STATUS_OPEN, 'Terdeteksi oleh scan otomatis.', $now);
                $created++;
            } else {
                // Refresh score/evidence/last_detected. Do NOT resurrect a
                // finding an operator already dismissed (false_positive/
                // resolved) — that would re-spam. Only refresh active rows.
                $existing->forceFill([
                    'site_url' => $f['site_url'] ?: $existing->site_url,
                    'site_name' => $f['site_name'] ?: $existing->site_name,
                    'severity' => $f['severity'],
                    'score' => $f['score'],
                    'evidence' => $f['evidence'],
                    'last_detected_at' => $now,
                ])->save();
                $updated++;
                $finding = $existing;
            }

            // Alert only for active, high-score findings.
            if ($finding->isActive() && $f['score'] >= $alertMin) {
                Alerter::fire(
                    $this->ruleFor($f['threat_type']),
                    'SecscanFinding',
                    (string) $finding->id,
                    [
                        'site_name' => $f['site_name'] ?: $f['db_name'],
                        'db_name' => $f['db_name'],
                        'threat_type' => $finding->threatLabel(),
                        'score' => $f['score'],
                        'site_url' => $f['site_url'],
                    ]
                );
                $alerted++;
            }
        }

        return [
            'scanned' => $result['scanned_total'],
            'wordpress' => $result['wordpress_total'],
            'findings' => count($result['findings']),
            'created' => $created,
            'updated' => $updated,
            'alerted' => $alerted,
        ];
    }

    protected function recordHistory(SecscanFinding $finding, ?string $from, string $to, string $reason, $at): void
    {
        SecscanFindingHistory::create([
            'finding_id' => $finding->id,
            'status_from' => $from,
            'status_to' => $to,
            'changed_by' => null,
            'reason' => $reason,
            'created_at' => $at,
        ]);
    }

    /** Map threat type → alert rule key (registered in the ServiceProvider). */
    protected function ruleFor(string $threatType): string
    {
        return match ($threatType) {
            SecscanFinding::THREAT_JUDOL,
            SecscanFinding::THREAT_ILLEGAL_PHARMA,
            SecscanFinding::THREAT_DEFACED,
            SecscanFinding::THREAT_MALWARE,
            SecscanFinding::THREAT_PHISHING => 'secscan.site.compromised',
            default => 'secscan.site.suspicious',
        };
    }
}
