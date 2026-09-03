<?php

namespace Nawasara\Secscan\Jobs;

use Carbon\Carbon;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Nawasara\Alerting\Services\RecipientResolver;
use Nawasara\Core\Models\Setting;
use Nawasara\Notification\Facades\Notify;
use Nawasara\Secscan\Services\IncidentStatsCollector;
use Nawasara\Vault\Facades\Vault;

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
    public function __construct(protected ?string $forDate = null) {}

    public function handle(): void
    {
        $tz = config('app.display_timezone', 'Asia/Jakarta');

        // Window: a named date reports that whole day (local), otherwise last 24h.
        if ($this->forDate) {
            $start = Carbon::parse($this->forDate, $tz)->startOfDay()->utc();
            $end = $start->copy()->addDay();
            $label = Carbon::parse($this->forDate, $tz)->translatedFormat('l, d F Y');
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
        $sendWhenEmpty = class_exists(Setting::class)
            ? (bool) Setting::get('secscan.digest.send_when_empty', config('nawasara-secscan.digest.send_when_empty', true))
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

        $context = [
            'kind' => 'secscan.daily_digest',
            'window_start' => $start->toIso8601String(),
        ];

        try {
            Notify::to(...$recipients)
                ->channel('email')
                ->subject($subject)
                ->body($body)
                ->context($context)
                ->send();

            $this->sendToGroupChannels($subject, $data, $label, $context);

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
        $fromSetting = class_exists(Setting::class)
            ? Setting::get('secscan.digest.recipients', null)
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
        if (class_exists(RecipientResolver::class)) {
            $resolver = app(RecipientResolver::class);
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
    /**
     * Kirim juga ke kanal yang menuju SATU TEMPAT bersama, mis. Telegram.
     *
     * Ringkasannya disusun ulang dari DATA, bukan dari badan surel. Badan itu
     * berupa tabel HTML; membuang tag-nya hanya menyisakan kerangka berupa
     * baris kosong berlapis dengan angka tercecer di antaranya — dan yang
     * paling dicari, angka beserta artinya, justru paling sulit ditemukan.
     *
     * Gagal mengirim ke sini TIDAK boleh menggagalkan digest: surelnya sudah
     * terkirim, dan job yang dilempar ulang akan mengirim surel kedua.
     *
     * @param  array<string,mixed>  $data
     * @param  array<string,mixed>  $context
     */
    protected function sendToGroupChannels(string $subject, array $data, string $label, array $context): void
    {
        $channels = (array) config('nawasara-secscan.digest.group_channels', []);

        foreach ($channels as $channel) {
            $tujuan = $this->groupRecipientFor($channel);

            if ($tujuan === null) {
                Log::warning("[secscan] digest: kanal '{$channel}' aktif tetapi tujuannya belum dikonfigurasi");

                continue;
            }

            try {
                Notify::to($tujuan)
                    ->channel([$channel])
                    ->subject($subject)
                    ->body($this->summaryText($data, $label))
                    ->context($context + ['telegram_topic' => 'pengumuman'])
                    ->send();
            } catch (\Throwable $e) {
                Log::warning("[secscan] digest ke '{$channel}' gagal: ".$e->getMessage());
            }
        }
    }

    /**
     * Tujuan untuk kanal yang mengirim ke satu tempat bersama.
     */
    protected function groupRecipientFor(string $channel): ?string
    {
        $tujuan = config("nawasara-secscan.digest.group_recipients.{$channel}");

        if (! $tujuan && class_exists(Vault::class)) {
            try {
                $tujuan = Vault::get($channel, 'chat_id');
            } catch (\Throwable) {
                $tujuan = null;
            }
        }

        return ($tujuan !== null && $tujuan !== '') ? (string) $tujuan : null;
    }

    /**
     * Ringkasan sependek mungkin yang masih menjawab "perlu saya lihat?".
     *
     * Rinciannya tetap di dasbor dan di surel. Yang di ponsel cukup bentuknya:
     * berapa banyak, seberapa gawat, dan apakah ada yang diblokir.
     *
     * @param  array<string,mixed>  $data
     */
    protected function summaryText(array $data, string $label): string
    {
        $b = [];
        $b[] = 'Ringkasan '.$label;
        $b[] = '';
        $b[] = 'Insiden: '.$data['total'];

        foreach (['critical' => 'Kritis', 'high' => 'Tinggi', 'medium' => 'Sedang', 'low' => 'Rendah'] as $k => $nama) {
            if (! empty($data['bySeverity'][$k])) {
                $b[] = '  '.$nama.': '.$data['bySeverity'][$k];
            }
        }

        $b[] = '';
        $b[] = 'IP diblokir hari ini: '.($data['blocked'] ?? 0);
        $b[] = 'Blokir aktif: '.($data['blockedActive'] ?? 0);
        $b[] = 'Agen daring: '.($data['agentsOnline'] ?? 0).'/'.($data['agentsTotal'] ?? 0);

        // Tiga jenis terbanyak — cukup untuk mengenali polanya tanpa
        // memindahkan seluruh tabel ke ponsel.
        $byType = $data['byType'] ?? [];
        arsort($byType);
        $tiga = array_slice($byType, 0, 3, true);

        if ($tiga !== []) {
            $b[] = '';
            $b[] = 'Terbanyak:';
            foreach ($tiga as $jenis => $n) {
                $b[] = '  '.$jenis.': '.$n;
            }
        }

        $b[] = '';
        $b[] = rtrim((string) config('app.url'), '/').'/nawasara-secscan/dashboard';

        return implode("\n", $b);
    }

    protected function collect(Carbon $start, Carbon $end, string $tz): array
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
