<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Nawasara\Secscan\Models\AgentCommand;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Secscan\Support\IpWhitelist;

/**
 * Decides whether an incident's source IP should be blocked, and records the
 * decision. Blocks land at the Cloudflare edge and — when autoblock.host_block
 * is on — also as an iptables/nftables rule on the agent that saw the attack,
 * which is what covers an origin reachable directly on 80/443.
 *
 * SAFETY-FIRST ordering:
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

        if ($incident->blocked_at !== null) {
            return $this->verdict('already', 'incident already blocked', $ip);
        }

        // Gate 3 — conservative threshold.
        if (! $this->meetsThreshold($incident)) {
            return $this->verdict('alert', 'below block threshold', $ip);
        }

        // Serialize the "already-blocked?" check + create for this IP. Without a
        // lock, two incidents for the same IP evaluated on parallel workers both
        // pass Gate 2 before either inserts, producing two active IpBlock rows
        // for one IP (real bug seen during backfill). A short per-IP lock makes
        // check-then-create atomic; the loser sees the row and skips.
        $lock = Cache::lock('secscan:autoblock:'.$ip, 10);

        try {
            $lock->block(5); // wait up to 5s for the lock

            // Gate 2 — already blocked? (this IP, from this or an earlier incident)
            if (IpBlock::active()->where('ip', $ip)->exists()) {
                return $this->verdict('already', 'ip already blocked', $ip);
            }

            // Decision: BLOCK.
            return $this->doBlock($incident, $ip);
        } catch (LockTimeoutException $e) {
            // Another evaluation for this IP is in flight — treat as already
            // handled rather than risk a duplicate.
            return $this->verdict('already', 'ip block in progress', $ip);
        } finally {
            optional($lock)->release();
        }
    }

    /**
     * Type must be blockable and the score must clear min_score. The
     * occurrence requirement then scales with how confident the score is.
     *
     * A flat min_occurrences of 3 let a large class of attacks through: an IP
     * that probes once with an unmistakable payload and moves on never
     * reaches three hits. Over 30 days in production that was 201 incidents
     * across 190 unique IPs — and 147 of them scored 100, the maximum. The
     * repeat requirement exists to keep *ambiguous* signals from blocking
     * real users, so it should not apply to signals that are already
     * unambiguous.
     *
     * Above high_confidence_score a single occurrence is enough; below it the
     * original min_occurrences still applies. Set high_confidence_score to 0
     * to disable the exemption and go back to a flat gate.
     */
    protected function meetsThreshold(SecurityIncident $incident): bool
    {
        $types    = (array) config('nawasara-secscan.autoblock.blockable_types', []);
        $minScore = (int) config('nawasara-secscan.autoblock.min_score', 70);
        $minOcc   = (int) config('nawasara-secscan.autoblock.min_occurrences', 3);
        $highScore = (int) config('nawasara-secscan.autoblock.high_confidence_score', 90);

        if (! in_array($incident->type, $types, true)) {
            return false;
        }

        $score = (int) $incident->score;
        if ($score < $minScore) {
            return false;
        }

        $required = ($highScore > 0 && $score >= $highScore)
            ? (int) config('nawasara-secscan.autoblock.high_confidence_occurrences', 1)
            : $minOcc;

        return (int) $incident->occurrences >= $required;
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

        $this->queueHostBlock($incident, $ip, $block, $dryRun);

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
    /**
     * Queue a host-level block on the agent that saw the attack, alongside the
     * Cloudflare rule.
     *
     * A Cloudflare block only helps for traffic that actually reaches
     * Cloudflare. Where an origin is reachable directly on 80/443 — which is
     * the case for the WHM host, and true of any server whose public IP is
     * known — an attacker simply skips the edge and the CF rule never applies.
     * Observed in production: an IP blocked at the edge since 14 July was still
     * hitting the origin two weeks later, 17k requests in a month.
     *
     * Blocking at the host with iptables/nftables closes that path. The two
     * layers are complementary rather than redundant: Cloudflare absorbs the
     * traffic before it costs the origin anything, and the host rule catches
     * whatever bypasses the edge.
     *
     * Deliberately conservative:
     *  - Opt-in via autoblock.host_block. Off means behaviour is unchanged.
     *  - Commands are created as PENDING. The agent only ever fetches APPROVED
     *    commands, so an admin still confirms before any firewall on a
     *    production host is touched. Set host_block_auto_approve to skip that
     *    step once the flow has been trusted in practice.
     *  - Only the agent that reported the incident is targeted, not every
     *    agent — the others never saw this attacker.
     *  - Nothing is queued in dry-run.
     */
    protected function queueHostBlock(SecurityIncident $incident, string $ip, IpBlock $block, bool $dryRun): void
    {
        if ($dryRun || ! config('nawasara-secscan.autoblock.host_block', false)) {
            return;
        }

        $agent = $incident->agent;
        if (! $agent) {
            return; // e.g. a filesystem finding with no reporting agent
        }

        try {
            $autoApprove = (bool) config('nawasara-secscan.autoblock.host_block_auto_approve', false);

            AgentCommand::create([
                'command_id'  => (string) Str::uuid()->getHex(),
                'agent_id'    => $agent->id,
                'action'      => 'block_ip',
                'params'      => ['ip' => $ip, 'reason' => $incident->type, 'block_id' => $block->id],
                'status'      => $autoApprove ? AgentCommand::STATUS_APPROVED : AgentCommand::STATUS_PENDING,
                'approved_at' => $autoApprove ? now() : null,
            ]);

            Log::info('[secscan] host block queued', [
                'ip' => $ip, 'agent' => $agent->name,
                'status' => $autoApprove ? 'approved' : 'pending approval',
            ]);
        } catch (\Throwable $e) {
            // Never let this break the Cloudflare block that already succeeded.
            Log::warning('[secscan] host block queue failed: '.$e->getMessage(), ['ip' => $ip]);
        }
    }

    /**
     * Queue the host-level counterpart of an unblock.
     *
     * Public because both unblock paths (the API controller and the Livewire
     * page) must call it — lifting a block only at the edge while the host
     * firewall still drops the IP would leave it blocked with no visible
     * reason, which is worse than not blocking at all.
     *
     * Safe to call unconditionally: it returns early when host blocking is off
     * or when no host block was ever queued for this IP.
     */
    public function queueHostUnblock(IpBlock $block, ?int $userId = null): void
    {
        if (! config('nawasara-secscan.autoblock.host_block', false)) {
            return;
        }

        // Only undo on agents we actually sent a block to, so we never touch a
        // host that was never involved.
        $agentIds = AgentCommand::where('action', 'block_ip')
            ->whereJsonContains('params->ip', $block->ip)
            ->pluck('agent_id')
            ->unique();

        if ($agentIds->isEmpty()) {
            return;
        }

        $autoApprove = (bool) config('nawasara-secscan.autoblock.host_block_auto_approve', false);

        foreach ($agentIds as $agentId) {
            try {
                AgentCommand::create([
                    'command_id'  => (string) Str::uuid()->getHex(),
                    'agent_id'    => $agentId,
                    'action'      => 'unblock_ip',
                    'params'      => ['ip' => $block->ip, 'block_id' => $block->id],
                    'status'      => $autoApprove ? AgentCommand::STATUS_APPROVED : AgentCommand::STATUS_PENDING,
                    'approved_at' => $autoApprove ? now() : null,
                    'approved_by' => $autoApprove ? $userId : null,
                ]);
            } catch (\Throwable $e) {
                Log::warning('[secscan] host unblock queue failed: '.$e->getMessage(), [
                    'ip' => $block->ip, 'agent_id' => $agentId,
                ]);
            }
        }

        Log::info('[secscan] host unblock queued', [
            'ip' => $block->ip, 'agents' => $agentIds->count(),
            'status' => $autoApprove ? 'approved' : 'pending approval',
        ]);
    }

    protected function verdict(string $action, string $reason, ?string $ip): array
    {
        return ['action' => $action, 'reason' => $reason, 'ip' => $ip, 'block_id' => null];
    }
}
