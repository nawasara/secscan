<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Support\Facades\Log;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Secscan\Support\IpWhitelist;

/**
 * Decides whether an incident's source IP should be blocked at the Cloudflare
 * edge, and records the decision. SAFETY-FIRST ordering:
 *
 *   Gate 0 — master enabled? (kill switch)
 *   Gate 1 — WHITELIST (checked before anything else; fail-safe)
 *   Gate 2 — already blocked? (dedup, no double-block / API spam)
 *   Gate 3 — conservative threshold (blockable type AND score AND occurrences)
 *
 * Only when all gates pass is the IP blocked. In dry_run the full pipeline
 * runs and a decision is recorded, but Cloudflare is NOT called — so operators
 * can watch what *would* be blocked before arming it.
 *
 * The engine never throws into the ingestion path: any failure is logged and
 * the incident is simply left un-actioned.
 */
class DecisionEngine
{
    public function __construct(protected CloudflareBlockService $blocker)
    {
    }

    /**
     * Evaluate one incident. Returns a short verdict array for logging/tests.
     *
     * @return array{action:string, reason:string, ip:?string, block_id:?int}
     */
    public function evaluate(SecurityIncident $incident): array
    {
        $ip = (string) $incident->source_ip;

        // Gate 0 — master switch.
        if (! config('nawasara-secscan.autoblock.enabled', false)) {
            return $this->verdict('disabled', 'autoblock disabled', $ip);
        }

        // Filesystem findings and correlated-only rows may have no IP.
        if ($ip === '' || $incident->source_ip === null) {
            return $this->verdict('skip', 'no source ip', null);
        }

        // Gate 1 — WHITELIST first (fail-safe).
        $wl = IpWhitelist::check($ip);
        if ($wl['whitelisted']) {
            return $this->verdict('whitelisted', 'whitelist:'.$wl['reason'], $ip);
        }

        // Gate 2 — already blocked? (either this incident, or an active block
        // for the same IP from an earlier incident).
        if ($incident->blocked_at !== null) {
            return $this->verdict('already', 'incident already blocked', $ip);
        }
        if (IpBlock::active()->where('ip', $ip)->exists()) {
            return $this->verdict('already', 'ip already blocked', $ip);
        }

        // Gate 3 — conservative threshold.
        if (! $this->meetsThreshold($incident)) {
            return $this->verdict('alert', 'below block threshold', $ip);
        }

        // Decision: BLOCK.
        return $this->doBlock($incident, $ip);
    }

    /** All three conditions must hold. */
    protected function meetsThreshold(SecurityIncident $incident): bool
    {
        $types   = (array) config('nawasara-secscan.autoblock.blockable_types', []);
        $minScore = (int) config('nawasara-secscan.autoblock.min_score', 70);
        $minOcc   = (int) config('nawasara-secscan.autoblock.min_occurrences', 3);

        return in_array($incident->type, $types, true)
            && (int) $incident->score >= $minScore
            && (int) $incident->occurrences >= $minOcc;
    }

    protected function doBlock(SecurityIncident $incident, string $ip): array
    {
        $dryRun = (bool) config('nawasara-secscan.autoblock.dry_run', true);
        $prefix = (string) config('nawasara-secscan.autoblock.notes_prefix', 'nawasara-autoblock');
        $notes  = sprintf('%s:inc_%d ip=%s type=%s score=%d occ=%d',
            $prefix, $incident->id, $ip, $incident->type, $incident->score, $incident->occurrences);

        $cfRuleId = null;
        if (! $dryRun) {
            $cfRuleId = $this->blocker->block($ip, $notes);
            if (! $cfRuleId) {
                // CF call failed — record nothing as blocked; leave for retry/alert.
                Log::warning('[secscan] DecisionEngine: block skipped, CF failed', ['ip' => $ip, 'incident' => $incident->id]);
                return $this->verdict('block_failed', 'cloudflare error', $ip);
            }
        }

        $block = IpBlock::create([
            'ip'          => $ip,
            'status'      => IpBlock::STATUS_ACTIVE,
            'reason'      => $incident->type,
            'cf_rule_id'  => $cfRuleId,
            'incident_id' => $incident->id,
            'dry_run'     => $dryRun,
            'notes'       => $notes,
            'blocked_by'  => null, // automatic
            'blocked_at'  => now(),
        ]);

        $incident->forceFill(['blocked_at' => now(), 'block_id' => $block->id])->save();

        Log::info('[secscan] DecisionEngine: '.($dryRun ? 'WOULD block (dry-run)' : 'BLOCKED').' '.$ip, [
            'incident' => $incident->id, 'type' => $incident->type,
            'score' => $incident->score, 'occ' => $incident->occurrences, 'cf_rule' => $cfRuleId,
        ]);

        // Notify operators. Alerter is optional at runtime — never let a missing
        // alerting package break the block path.
        try {
            \Nawasara\Alerting\Facades\Alerter::fire(
                'secscan.ip.autoblocked',
                'IpBlock',
                (string) $block->id,
                [
                    'ip' => $ip, 'reason' => $incident->type, 'score' => $incident->score,
                    'occurrences' => $incident->occurrences, 'dry_run' => $dryRun,
                    'agent' => $incident->agent?->name,
                ],
            );
        } catch (\Throwable $e) {
            Log::warning('[secscan] autoblock alert failed: '.$e->getMessage());
        }

        return [
            'action'   => $dryRun ? 'would_block' : 'blocked',
            'reason'   => $incident->type,
            'ip'       => $ip,
            'block_id' => $block->id,
        ];
    }

    /**
     * @return array{action:string, reason:string, ip:?string, block_id:?int}
     */
    protected function verdict(string $action, string $reason, ?string $ip): array
    {
        return ['action' => $action, 'reason' => $reason, 'ip' => $ip, 'block_id' => null];
    }
}
