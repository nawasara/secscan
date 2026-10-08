<?php

namespace Nawasara\Secscan\Services;

use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Models\SecscanFindingHistory;

/**
 * Every status change of a finding goes through here: staff triage from the
 * panel, and the scanners closing or reopening on their own.
 *
 * One place, so each change leaves the same trail (history row, alert
 * resolved) whoever made it. A scanner that flipped the column directly would
 * leave findings that changed status with nobody able to say why.
 */
class FindingTriage
{
    /**
     * @param  int|null  $userId  null = changed by the scanner itself
     * @return bool false when the finding already had that status
     */
    public function transition(SecscanFinding $finding, string $to, string $reason, ?int $userId): bool
    {
        $from = $finding->status;

        if ($from === $to) {
            return false;
        }

        $finding->status = $to;

        if ($to === SecscanFinding::STATUS_ACKNOWLEDGED) {
            $finding->acknowledged_by = $userId;
            $finding->acknowledged_at = now();
            $finding->acknowledged_reason = $reason;
        }

        if (self::isDismissal($to)) {
            $finding->resolved_by = $userId;
            $finding->resolved_at = now();
            $finding->resolved_reason = $reason;
        }

        if ($to === SecscanFinding::STATUS_OPEN) {
            // Reopened: the earlier "Selesai oleh X" no longer describes this
            // finding, and leaving it would read as if X closed a site that is
            // still compromised. The history row keeps what happened.
            $finding->forceFill([
                'acknowledged_by' => null, 'acknowledged_at' => null, 'acknowledged_reason' => null,
                'resolved_by' => null, 'resolved_at' => null, 'resolved_reason' => null,
            ]);
        }

        $finding->save();

        SecscanFindingHistory::create([
            'finding_id' => $finding->id,
            'status_from' => $from,
            'status_to' => $to,
            'changed_by' => $userId,
            'reason' => $reason,
            'created_at' => now(),
        ]);

        // A dismissed finding clears its alert so notifications stop.
        if (self::isDismissal($to)) {
            Alerter::resolve('secscan.site.compromised', 'SecscanFinding', (string) $finding->id);
            Alerter::resolve('secscan.site.suspicious', 'SecscanFinding', (string) $finding->id);
        }

        return true;
    }

    /**
     * Close active findings the scanner no longer sees.
     *
     * @param  iterable<SecscanFinding>  $findings  already narrowed by the caller to
     *                                             sites that were scanned cleanly
     */
    public function autoResolve(iterable $findings): int
    {
        $hours = (int) config('nawasara-secscan.auto_resolve_after_hours', 24);
        $closed = 0;

        foreach ($findings as $finding) {
            $closed += (int) $this->transition(
                $finding,
                SecscanFinding::STATUS_RESOLVED,
                "Ditutup otomatis: tidak terdeteksi lagi selama {$hours} jam pada pemindaian.",
                null,
            );
        }

        return $closed;
    }

    /**
     * Reopen a finding marked Selesai that the scanner detects again.
     *
     * False positive is NOT reopened: that is staff saying the detector is
     * wrong about this site, and the detector repeating itself does not
     * change that. Selesai is a claim about the site, and a fresh detection
     * contradicts it.
     */
    public function reopenIfResolved(SecscanFinding $finding): bool
    {
        if ($finding->status !== SecscanFinding::STATUS_RESOLVED) {
            return false;
        }

        return $this->transition(
            $finding,
            SecscanFinding::STATUS_OPEN,
            'Terdeteksi lagi setelah ditandai selesai.',
            null,
        );
    }

    public static function isDismissal(string $status): bool
    {
        return in_array($status, [SecscanFinding::STATUS_RESOLVED, SecscanFinding::STATUS_FALSE_POSITIVE], true);
    }
}
