<?php

namespace Nawasara\Secscan\Services;

use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\AgentScanFinding;

/**
 * Alerts for agent file-scanner findings.
 *
 * Until October 2026 these findings were only STORED: scanFinding() wrote the
 * row and returned, with no notification at all. 124 judol pages under the
 * jambonponorogogo account sat open from 14 July and nobody knew — the agent
 * did its job, but nothing told a human.
 *
 * One alert per SITE, not per file. Judol pages arrive in batches (dozens of
 * files per injection); one alert per file means 124 messages for a single
 * incident, and a flooded topic stops being read. The target key is
 * agent + site root, which is stable across scans — a requirement for
 * acknowledge and resolve to work (see reference_alert_target_id_stability).
 */
class FileFindingAlerts
{
    public const RULE_SPAM = 'secscan.file.spam';

    public const RULE_MALICIOUS = 'secscan.file.malicious';

    /** Categories closed automatically once the agent stops reporting them. */
    private const SIGNATURE_CATEGORIES = ['seo_spam', 'webshell', 'backdoor', 'exploit', 'suspicious'];

    /**
     * Category → rule. `integrity` deliberately fires nothing: thousands of
     * cache files changing every hour are not a security event, and letting
     * them alert would bury the ones that matter.
     */
    public static function ruleFor(string $category): ?string
    {
        return match ($category) {
            'seo_spam' => self::RULE_SPAM,
            'webshell', 'backdoor', 'exploit' => self::RULE_MALICIOUS,
            default => null,
        };
    }

    /** @return list<string> */
    public static function categoriesFor(string $rule): array
    {
        return match ($rule) {
            self::RULE_SPAM => ['seo_spam'],
            self::RULE_MALICIOUS => ['webshell', 'backdoor', 'exploit'],
            default => [],
        };
    }

    /**
     * Site root of a file path — the unit one person cleans up.
     *
     *   /home/jambonponorogogo/public_html/x/y.html → /home/jambonponorogogo
     *   /var/www/umum/public/a.php                  → /var/www/umum
     *
     * Other layouts fall back to their first two segments so files of one
     * application still group together on an unfamiliar server.
     */
    public static function siteRoot(string $path): string
    {
        $parts = array_values(array_filter(explode('/', $path), fn ($p) => $p !== ''));

        if (count($parts) >= 2 && in_array($parts[0], ['home', 'home2', 'home3'], true)) {
            return '/'.$parts[0].'/'.$parts[1];
        }

        if (count($parts) >= 3 && $parts[0] === 'var' && $parts[1] === 'www') {
            return '/var/www/'.$parts[2];
        }

        return '/'.implode('/', array_slice($parts, 0, min(2, max(1, count($parts) - 1))));
    }

    public static function targetId(int $agentId, string $siteRoot): string
    {
        return $agentId.':'.$siteRoot;
    }

    /**
     * Call on every finding the agent reports, new or repeated.
     *
     * Firing an already-firing state is safe: the evaluator only refreshes the
     * context and renotifies once the cooldown has passed. That is the point —
     * a judol page still there a day later deserves another reminder.
     */
    public function notify(Agent $agent, AgentScanFinding $finding): void
    {
        $rule = self::ruleFor((string) $finding->category);
        if ($rule === null || $finding->status !== AgentScanFinding::STATUS_OPEN) {
            return;
        }

        if (! Alerter::hasRule($rule)) {
            return;
        }

        $root = self::siteRoot((string) $finding->path);
        $account = $this->whmAccount($root);

        // A suspended account is already handled — the site is offline, only
        // the files remain. jambonponorogogo was suspended for "Indikasi judol"
        // while its 124 pages stayed on disk; alerting about it every day would
        // be noise. The rows stay open, so cleanup is not forgotten.
        if ($account && (int) $account->suspended === 1) {
            Alerter::resolve($rule, 'AgentSite', self::targetId($agent->id, $root));

            return;
        }

        Alerter::fire($rule, 'AgentSite', self::targetId($agent->id, $root), [
            'site' => $account->domain ?? $root,
            'account' => $account ? $root : null,
            'agent' => $agent->name,
            'signature' => (string) $finding->sig_name,
            'file_count' => $this->openQuery($agent->id, $root, $rule)->count(),
            'sample_file' => mb_substr((string) $finding->path, 0, 200),
            'score' => (int) $finding->score,
        ]);
    }

    /**
     * Call after a finding's status changes (triage, auto-resolve). The site's
     * alert resolves once no open file remains on that site.
     */
    public function reconcile(AgentScanFinding $finding): void
    {
        $rule = self::ruleFor((string) $finding->category);
        if ($rule === null || ! Alerter::hasRule($rule)) {
            return;
        }

        $root = self::siteRoot((string) $finding->path);

        if (! $this->openQuery((int) $finding->agent_id, $root, $rule)->exists()) {
            Alerter::resolve($rule, 'AgentSite', self::targetId((int) $finding->agent_id, $root));
        }
    }

    /**
     * Close signature findings that a LIVE agent no longer reports — the file
     * has been deleted. Without this, a cleaned site keeps being reminded every
     * day just because nobody clicked "resolved" on hundreds of rows one by one.
     *
     * Live agents only: a dead agent also stops reporting, and its silence
     * proves nothing about the files. `integrity` findings are left alone — a
     * file change is an event, not a state, so "not seen again" means nothing.
     */
    public function resolveStale(int $hours): int
    {
        // From last_seen_at, not the status column: status is only written when
        // the agent reports, so an agent that just died still reads "online".
        $liveMinutes = (int) config('nawasara-secscan.agent_health.offline_minutes', 30);
        $agentIds = Agent::where('last_seen_at', '>=', now()->subMinutes(max(1, $liveMinutes)))->pluck('id');
        if ($agentIds->isEmpty()) {
            return 0;
        }

        $stale = AgentScanFinding::whereIn('agent_id', $agentIds)
            ->where('status', AgentScanFinding::STATUS_OPEN)
            ->whereIn('category', self::SIGNATURE_CATEGORIES)
            ->where('last_seen_at', '<', now()->subHours(max(1, $hours)))
            ->get();

        foreach ($stale as $finding) {
            $finding->update([
                'status' => AgentScanFinding::STATUS_RESOLVED,
                'triaged_at' => now(),
                // Shown to staff in the findings table, hence Indonesian.
                'triage_note' => "Ditutup otomatis: tidak dilaporkan agen lebih dari {$hours} jam (berkas kemungkinan sudah dihapus).",
            ]);
            $this->reconcile($finding);
        }

        return $stale->count();
    }

    /**
     * cPanel account behind /home/<user>, from nawasara/whm's synced table.
     * Null when whm is not installed or the account is unknown.
     */
    private function whmAccount(string $root): ?object
    {
        if (! preg_match('#^/home\d*/([^/]+)$#', $root, $m)) {
            return null;
        }

        try {
            return \Illuminate\Support\Facades\Cache::remember(
                'secscan:whm-account:'.$m[1],
                now()->addMinutes(10),
                fn () => \Illuminate\Support\Facades\DB::table('nawasara_whm_accounts')
                    ->where('username', $m[1])
                    ->first(['domain', 'suspended']),
            );
        } catch (\Throwable) {
            return null; // table absent: whm package not installed
        }
    }

    private function openQuery(int $agentId, string $root, string $rule)
    {
        return AgentScanFinding::where('agent_id', $agentId)
            ->where('status', AgentScanFinding::STATUS_OPEN)
            ->whereIn('category', self::categoriesFor($rule))
            ->where('path', 'like', str_replace(['%', '_'], ['\%', '\_'], $root).'/%');
    }
}
