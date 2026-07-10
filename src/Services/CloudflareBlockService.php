<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Support\Facades\Log;
use Nawasara\Cloudflare\Services\CloudflareClient;

/**
 * Blocks / unblocks attacker IPs at the Cloudflare edge via account-wide IP
 * Access Rules. Wraps CloudflareClient with:
 *   - a naive retry on transient failure (the CF client has no 429 handling),
 *   - a consistent notes tag for audit + bulk cleanup,
 *   - dry-run awareness (caller decides; this class just reports what it did).
 *
 * Returns the Cloudflare rule id on success so the caller can persist it for a
 * later unblock. Never throws for an API failure — returns null and logs, so a
 * block failure never breaks incident ingestion.
 */
class CloudflareBlockService
{
    public function __construct(protected CloudflareClient $cf)
    {
    }

    /**
     * Create a 'block' IP Access Rule. Returns the CF rule id, or null on
     * failure (logged). Idempotent-ish: if a matching block already exists,
     * returns its id instead of creating a duplicate.
     */
    public function block(string $ip, string $notes): ?string
    {
        // Reuse an existing block for this IP if one is already on Cloudflare.
        if ($existing = $this->findRuleId($ip)) {
            return $existing;
        }

        $result = $this->withRetry(fn () => $this->cf->createIpAccessRule('block', 'ip', $ip, $notes));

        $id = $result['id'] ?? null;
        if (! $id) {
            Log::warning('[secscan] Cloudflare block failed', ['ip' => $ip]);
            return null;
        }

        return $id;
    }

    /** Remove a block rule by its Cloudflare rule id. */
    public function unblock(string $cfRuleId): bool
    {
        return (bool) $this->withRetry(fn () => $this->cf->deleteIpAccessRule($cfRuleId));
    }

    /**
     * Find an existing CF block rule id for an IP (matches our notes prefix so
     * we don't touch rules created outside Nawasara).
     */
    public function findRuleId(string $ip): ?string
    {
        $prefix = (string) config('nawasara-secscan.autoblock.notes_prefix', 'nawasara-autoblock');
        $rules = $this->withRetry(fn () => $this->cf->listIpAccessRules($prefix, 100)) ?: [];

        foreach ($rules as $rule) {
            $value = $rule['configuration']['value'] ?? null;
            $mode  = $rule['mode'] ?? null;
            if ($value === $ip && $mode === 'block') {
                return $rule['id'] ?? null;
            }
        }
        return null;
    }

    /**
     * Retry a CF call a couple of times with linear backoff. The CF client
     * returns null/false on failure (no exceptions), so we retry on a falsy
     * result. Kept small — this runs inside a queued job.
     *
     * @template T
     * @param callable():T $fn
     * @return T
     */
    private function withRetry(callable $fn, int $attempts = 3)
    {
        $result = null;
        for ($i = 1; $i <= $attempts; $i++) {
            $result = $fn();
            if ($result !== null && $result !== false && $result !== []) {
                return $result;
            }
            if ($i < $attempts) {
                usleep(300_000 * $i); // 0.3s, 0.6s — brief, for transient 429/5xx
            }
        }
        return $result;
    }
}
