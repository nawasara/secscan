<?php

namespace Nawasara\Secscan\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Nawasara\Notification\Facades\Notify;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Models\SecurityIncident;

/**
 * Daily security digest: one e-mail summarising the last 24 hours — how many
 * incidents by severity and type, which IPs attacked most, which sites were
 * targeted, and what the Decision Engine blocked.
 *
 * Complements the per-incident alerts (nawasara/alerting), which fire in real
 * time: the digest is the "what happened overnight" recap an operator reads
 * once each morning, and evidence for reporting.
 */
class SendDailyDigestJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 2;
    public int $timeout = 120;

    /** @param string|null $forDate Y-m-d to report on; defaults to the last 24h. */
    public function __construct(protected ?string $forDate = null)
    {
    }

    public function handle(): void
    {
        $tz = config('app.display_timezone', 'Asia/Jakarta');

        // Window: a named date reports that whole day (local), otherwise last 24h.
        if ($this->forDate) {
            $start = \Carbon\Carbon::parse($this->forDate, $tz)->startOfDay()->utc();
            $end = $start->copy()->addDay();
            $label = \Carbon\Carbon::parse($this->forDate, $tz)->translatedFormat('l, d F Y');
        } else {
            $end = now();
            $start = $end->copy()->subDay();
            $label = '24 jam terakhir';
        }

        $recipients = $this->recipients();
        if (empty($recipients)) {
            Log::warning('[secscan] daily digest: no recipients configured', [
                'hint' => 'set SECSCAN_DIGEST_RECIPIENTS or ALERTING_RECIPIENTS, or assign the role',
            ]);

            return;
        }

        $data = $this->collect($start, $end, $tz);

        // Nothing happened and the operator opted out of empty reports — skip.
        if ($data['total'] === 0 && ! config('nawasara-secscan.digest.send_when_empty', true)) {
            Log::info('[secscan] daily digest: no incidents, skipping (send_when_empty=false)');

            return;
        }

        $body = view('nawasara-secscan::emails.daily-digest', $data + [
            'label' => $label,
            'tz' => $tz,
            'dashboardUrl' => rtrim((string) config('app.url'), '/'),
        ])->render();

        $subject = sprintf(
            '[Nawasara] Laporan Keamanan Harian — %d insiden (%s)',
            $data['total'],
            $label
        );

        try {
            Notify::to(...$recipients)
                ->channel('email')
                ->subject($subject)
                ->body($body)
                ->context(['kind' => 'secscan.daily_digest', 'window_start' => $start->toIso8601String()])
                ->send();

            Log::info('[secscan] daily digest sent', [
                'recipients' => count($recipients),
                'incidents' => $data['total'],
            ]);
        } catch (\Throwable $e) {
            Log::error('[secscan] daily digest failed: '.$e->getMessage());
            throw $e;
        }
    }

    /**
     * Who gets the digest: explicitly configured addresses, else fall back to
     * the alerting audience for critical (so it always reaches someone).
     *
     * @return list<string>
     */
    protected function recipients(): array
    {
        $configured = collect((array) config('nawasara-secscan.digest.recipients', []))
            ->map(fn ($e) => trim((string) $e))
            ->filter(fn ($e) => $e !== '' && filter_var($e, FILTER_VALIDATE_EMAIL));

        if ($configured->isNotEmpty()) {
            return $configured->unique()->values()->all();
        }

        // Fallback: reuse the alerting audience for critical severity.
        if (class_exists(\Nawasara\Alerting\Services\RecipientResolver::class)) {
            $resolver = app(\Nawasara\Alerting\Services\RecipientResolver::class);
            $emails = collect($resolver->resolveBySeverity('critical')->pluck('email')->filter()->all());
            if (method_exists($resolver, 'extraEmailsBySeverity')) {
                $emails = $emails->merge($resolver->extraEmailsBySeverity('critical'));
            }

            return $emails->unique()->values()->all();
        }

        return [];
    }

    /**
     * Gather the numbers for the window. Kept to a handful of grouped queries
     * so this stays cheap even on a busy incident table.
     *
     * @return array<string, mixed>
     */
    protected function collect(\Carbon\Carbon $start, \Carbon\Carbon $end, string $tz): array
    {
        $base = fn () => SecurityIncident::query()->whereBetween('last_seen_at', [$start, $end]);

        $total = $base()->count();

        $bySeverity = $base()
            ->selectRaw('severity, COUNT(*) as n')
            ->groupBy('severity')
            ->pluck('n', 'severity')
            ->all();

        $byType = $base()
            ->selectRaw('type, COUNT(*) as n')
            ->groupBy('type')
            ->orderByDesc('n')
            ->limit(8)
            ->pluck('n', 'type')
            ->all();

        $topIps = $base()
            ->whereNotNull('source_ip')
            ->selectRaw('source_ip, COUNT(*) as n, MAX(score) as max_score')
            ->groupBy('source_ip')
            ->orderByDesc('n')
            ->limit(10)
            ->get()
            ->map(fn ($r) => [
                'ip' => $r->source_ip,
                'count' => (int) $r->n,
                'score' => (int) $r->max_score,
            ])->all();

        // Targeted hosts come from evidence JSON, so aggregate in PHP over the
        // window's incidents that actually carry a host.
        $hostCounts = [];
        foreach ($base()->get(['evidence']) as $inc) {
            foreach ((array) ($inc->evidence ?? []) as $ev) {
                $h = $ev['host'] ?? null;
                if ($h) {
                    $hostCounts[$h] = ($hostCounts[$h] ?? 0) + 1;
                }
            }
        }
        arsort($hostCounts);
        $topHosts = array_slice($hostCounts, 0, 10, true);

        $blocked = IpBlock::whereBetween('blocked_at', [$start, $end])->count();
        $blockedActive = IpBlock::where('status', IpBlock::STATUS_ACTIVE)->count();

        $agentsOnline = Agent::where('status', Agent::STATUS_ONLINE)->count();
        $agentsTotal = Agent::count();

        return [
            'total' => $total,
            'bySeverity' => $bySeverity,
            'byType' => $byType,
            'topIps' => $topIps,
            'topHosts' => $topHosts,
            'blocked' => $blocked,
            'blockedActive' => $blockedActive,
            'agentsOnline' => $agentsOnline,
            'agentsTotal' => $agentsTotal,
            'start' => $start->copy()->timezone($tz),
            'end' => $end->copy()->timezone($tz),
        ];
    }
}
