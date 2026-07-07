<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Support\Facades\DB;
use Nawasara\Secscan\Models\AgentScanFinding;
use Nawasara\Secscan\Models\SecurityIncident;

/**
 * One-off cleanup for duplicate rows accumulated before the aggregation fix
 * (agent < 0.2 sent a fresh random ID per re-detection, so the same ongoing
 * attack / webshell stacked hundreds of rows).
 *
 * Merges duplicates into one canonical row per logical identity:
 *   - incidents (with source_ip): agent_id + type + source_ip
 *   - incidents (filesystem):     agent_id + type + first evidence raw line
 *   - scan findings:              agent_id + path + signature_id
 *
 * Canonical row keeps the EARLIEST detected_at (tanggal deteksi), gets
 * last_seen_at = latest detection (tanggal update) and occurrences = row count.
 *
 * Run via tinker (package console commands don't reliably register):
 *
 *   $dedup = new \Nawasara\Secscan\Services\IncidentDeduplicator;
 *   $dedup->run();                 // dry run — reports what would be merged
 *   $dedup->run(dryRun: false);    // actually merge + delete duplicates
 */
class IncidentDeduplicator
{
    public function run(bool $dryRun = true): array
    {
        $report = [
            'dry_run'                => $dryRun,
            'incident_groups'        => 0,
            'incident_rows_merged'   => 0,
            'filesystem_groups'      => 0,
            'filesystem_rows_merged' => 0,
            'finding_groups'         => 0,
            'finding_rows_merged'    => 0,
        ];

        $this->dedupeNetworkIncidents($dryRun, $report);
        $this->dedupeFilesystemIncidents($dryRun, $report);
        $this->dedupeScanFindings($dryRun, $report);

        return $report;
    }

    /** Incidents with a source IP: identity = agent + type + source_ip. */
    protected function dedupeNetworkIncidents(bool $dryRun, array &$report): void
    {
        $groups = SecurityIncident::query()
            ->whereNotNull('source_ip')
            ->selectRaw('agent_id, type, source_ip, COUNT(*) as cnt')
            ->groupBy('agent_id', 'type', 'source_ip')
            ->havingRaw('COUNT(*) > 1')
            ->get();

        foreach ($groups as $g) {
            $rows = SecurityIncident::where('agent_id', $g->agent_id)
                ->where('type', $g->type)
                ->where('source_ip', $g->source_ip)
                ->orderBy('detected_at')
                ->get();

            $report['incident_groups']++;
            $report['incident_rows_merged'] += $rows->count() - 1;

            if (! $dryRun) {
                $this->mergeIncidentRows($rows);
            }
        }
    }

    /**
     * Filesystem incidents (source_ip null, from the file scanner): the random
     * ID differs per re-scan but the first evidence raw line is stable
     * ("[sig] /path: matched line"), so it works as the logical identity.
     */
    protected function dedupeFilesystemIncidents(bool $dryRun, array &$report): void
    {
        $buckets = [];

        SecurityIncident::query()
            ->whereNull('source_ip')
            ->orderBy('detected_at')
            ->chunkById(500, function ($incidents) use (&$buckets) {
                foreach ($incidents as $inc) {
                    $raw = $inc->evidence[0]['raw'] ?? null;
                    if ($raw === null) {
                        continue;
                    }
                    $key = $inc->agent_id.'|'.$inc->type.'|'.md5($raw);
                    $buckets[$key][] = $inc->id;
                }
            });

        foreach ($buckets as $ids) {
            if (count($ids) < 2) {
                continue;
            }

            $report['filesystem_groups']++;
            $report['filesystem_rows_merged'] += count($ids) - 1;

            if (! $dryRun) {
                $rows = SecurityIncident::whereIn('id', $ids)->orderBy('detected_at')->get();
                $this->mergeIncidentRows($rows);
            }
        }
    }

    /** Keeps the earliest row, folds the rest in, deletes them. */
    protected function mergeIncidentRows($rows): void
    {
        $canonical = $rows->first();
        $rest      = $rows->slice(1);

        DB::transaction(function () use ($canonical, $rest, $rows) {
            $lastSeen = $rows->max(fn ($r) => $r->last_seen_at ?? $r->detected_at);

            $canonical->update([
                'occurrences'  => $rows->sum(fn ($r) => max(1, (int) $r->occurrences)),
                'last_seen_at' => $lastSeen,
                'score'        => $rows->max('score'),
                'severity'     => $rows->reduce(
                    fn ($carry, $r) => SecurityIncident::maxSeverity($carry, $r->severity),
                    SecurityIncident::SEVERITY_INFO
                ),
                'correlated'   => $rows->contains(fn ($r) => $r->correlated),
                'evidence'     => $rest->last()?->evidence ?? $canonical->evidence,
            ]);

            SecurityIncident::whereIn('id', $rest->pluck('id'))->delete();
        });
    }

    /** Scan findings: identity = agent + path + signature_id. */
    protected function dedupeScanFindings(bool $dryRun, array &$report): void
    {
        $groups = AgentScanFinding::query()
            ->selectRaw('agent_id, path, signature_id, COUNT(*) as cnt')
            ->groupBy('agent_id', 'path', 'signature_id')
            ->havingRaw('COUNT(*) > 1')
            ->get();

        foreach ($groups as $g) {
            $rows = AgentScanFinding::where('agent_id', $g->agent_id)
                ->where('path', $g->path)
                ->where('signature_id', $g->signature_id)
                ->orderBy('detected_at')
                ->get();

            $report['finding_groups']++;
            $report['finding_rows_merged'] += $rows->count() - 1;

            if ($dryRun) {
                continue;
            }

            $canonical = $rows->first();
            $rest      = $rows->slice(1);

            DB::transaction(function () use ($canonical, $rest, $rows) {
                $updates = [
                    'last_seen_at' => $rows->max(fn ($r) => $r->last_seen_at ?? $r->detected_at),
                    'score'        => $rows->max('score'),
                ];

                // Preserve triage done on a duplicate row instead of losing it.
                $triaged = $rows->whereNotNull('triaged_at')->sortByDesc('triaged_at')->first();
                if ($triaged && $canonical->status === AgentScanFinding::STATUS_OPEN) {
                    $updates['status']      = $triaged->status;
                    $updates['triaged_by']  = $triaged->triaged_by;
                    $updates['triaged_at']  = $triaged->triaged_at;
                    $updates['triage_note'] = $triaged->triage_note;
                }

                $canonical->update($updates);

                AgentScanFinding::whereIn('id', $rest->pluck('id'))->delete();
            });
        }
    }
}
