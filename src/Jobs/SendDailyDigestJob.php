<?php

namespace Nawasara\Secscan\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Nawasara\Notification\Facades\Notify;
use Nawasara\Secscan\Services\IncidentStatsCollector;

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
        $sendWhenEmpty = class_exists(\Nawasara\Core\Models\Setting::class)
            ? (bool) \Nawasara\Core\Models\Setting::get('secscan.digest.send_when_empty', config('nawasara-secscan.digest.send_when_empty', true))
            : (bool) config('nawasara-secscan.digest.send_when_empty', true);

        if ($data['total'] === 0 && ! $sendWhenEmpty) {
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
        // UI-managed setting wins; env/config is the untouched-deployment default.
        $fromSetting = class_exists(\Nawasara\Core\Models\Setting::class)
            ? \Nawasara\Core\Models\Setting::get('secscan.digest.recipients', null)
            : null;

        $raw = $fromSetting !== null && $fromSetting !== ''
            ? $fromSetting
            : config('nawasara-secscan.digest.recipients', []);

        if (is_string($raw)) {
            $raw = preg_split('/[\s,;]+/', $raw) ?: [];
        }

        $configured = collect((array) $raw)
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
     * Gather the numbers for the window.
     *
     * Delegates to IncidentStatsCollector so the digest email and the public
     * stats API can never drift apart. Keys are remapped to the camelCase shape
     * the email template already expects, and topHosts back to a host => count
     * map, so the template is untouched by this refactor.
     *
     * @return array<string, mixed>
     */
    protected function collect(\Carbon\Carbon $start, \Carbon\Carbon $end, string $tz): array
    {
        $stats = app(IncidentStatsCollector::class)->collect($start, $end);

        $topHosts = [];
        foreach ($stats['top_hosts'] as $row) {
            $topHosts[$row['host']] = $row['count'];
        }

        return [
            'total' => $stats['total'],
            'bySeverity' => $stats['by_severity'],
            'byType' => $stats['by_type'],
            'topIps' => $stats['top_ips'],
            'topHosts' => $topHosts,
            'blocked' => $stats['blocked'],
            'blockedActive' => $stats['blocked_active'],
            'agentsOnline' => $stats['agents_online'],
            'agentsTotal' => $stats['agents_total'],
            'start' => $start->copy()->timezone($tz),
            'end' => $end->copy()->timezone($tz),
        ];
    }
}
