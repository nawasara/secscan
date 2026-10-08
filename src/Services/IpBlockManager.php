<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Support\Facades\Log;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Support\IpWhitelist;

/**
 * Manual block and every unblock, for the panel, the API and bulk cleanup.
 *
 * The automatic path stays in DecisionEngine (thresholds, locking, alerts);
 * this is the one place a PERSON blocks or lifts a block. It exists because
 * the panel and the API had drifted: the panel marked a block removed even
 * when deleting the Cloudflare rule failed, so the page said "dicabut" while
 * Cloudflare kept dropping the IP. The API already refused in that case.
 */
class IpBlockManager
{
    public const ERROR_WHITELISTED = 'whitelisted';

    public const ERROR_CLOUDFLARE = 'cloudflare_error';

    public function __construct(
        protected CloudflareBlockService $blocker,
        protected DecisionEngine $engine,
    ) {}

    /**
     * Block an IP by hand. Idempotent: an IP already blocked returns its
     * existing record.
     *
     * Same gates as the Decision Engine: the whitelist (office range,
     * Cloudflare, search bots) always wins, and the global dry-run switch
     * cannot be bypassed from here.
     *
     * @return array{block: ?IpBlock, error: ?string, existing: bool}
     */
    public function block(string $ip, string $reason, string $source, ?int $userId): array
    {
        $wl = IpWhitelist::check($ip);
        if ($wl['whitelisted']) {
            return ['block' => null, 'error' => self::ERROR_WHITELISTED.':'.$wl['reason'], 'existing' => false];
        }

        if ($existing = IpBlock::active()->where('ip', $ip)->first()) {
            return ['block' => $existing, 'error' => null, 'existing' => true];
        }

        $dryRun = (bool) config('nawasara-secscan.autoblock.dry_run', true);
        $prefix = (string) config('nawasara-secscan.autoblock.notes_prefix', 'nawasara-autoblock');
        $notes = sprintf('%s:%s ip=%s reason=%s by=%s', $prefix, $source, $ip, $reason, $userId ?? '?');

        $cfRuleId = null;
        if (! $dryRun) {
            $cfRuleId = $this->blocker->block($ip, $notes);
            if (! $cfRuleId) {
                Log::warning('[secscan] manual block failed at Cloudflare', ['ip' => $ip, 'source' => $source]);

                return ['block' => null, 'error' => self::ERROR_CLOUDFLARE, 'existing' => false];
            }
        }

        $block = IpBlock::create([
            'ip' => $ip,
            'status' => IpBlock::STATUS_ACTIVE,
            'reason' => $reason,
            'cf_rule_id' => $cfRuleId,
            'incident_id' => null,
            'dry_run' => $dryRun,
            'notes' => $notes,
            'blocked_by' => $userId,
            'blocked_at' => now(),
        ]);

        Log::info('[secscan] '.($dryRun ? 'WOULD block (dry-run)' : 'BLOCKED').' '.$ip, ['source' => $source, 'user' => $userId]);

        return ['block' => $block, 'error' => null, 'existing' => false];
    }

    /**
     * Lift a block: Cloudflare first, then the record.
     *
     * Returns false, and changes NOTHING, when Cloudflare refuses. Marking it
     * removed anyway is how the panel used to show an IP as unblocked while
     * Cloudflare kept blocking it.
     */
    public function unblock(IpBlock $block, ?int $userId): bool
    {
        if (! $block->isActive()) {
            return true;
        }

        if (! $block->dry_run && $block->cf_rule_id) {
            if (! $this->blocker->unblock($block->cf_rule_id)) {
                Log::warning('[secscan] unblock: Cloudflare delete failed', ['ip' => $block->ip, 'rule' => $block->cf_rule_id]);

                return false;
            }
        }

        $block->update([
            'status' => IpBlock::STATUS_REMOVED,
            'unblocked_by' => $userId,
            'unblocked_at' => now(),
        ]);

        // Clear the flag on the incident that pointed at this block.
        $block->incident?->forceFill(['blocked_at' => null, 'block_id' => null])->save();

        // Lift the host-level firewall rule too, otherwise the IP stays dropped
        // at the origin with nothing in the UI explaining why.
        $this->engine->queueHostUnblock($block, $userId);

        return true;
    }
}
