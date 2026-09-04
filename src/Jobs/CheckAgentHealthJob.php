<?php

namespace Nawasara\Secscan\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Alerting\Models\AlertRule;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\AgentCommand;

/**
 * Memperingatkan saat agen berhenti melapor.
 *
 * ## Kenapa ini yang paling penting
 *
 * Agen adalah MATA sistem keamanan. Saat ia diam, dasbor tidak menunjukkan
 * bahaya — ia menunjukkan ketenangan. Nol insiden dari sebuah host terbaca
 * persis sama, entah host itu aman atau tidak ada yang mengawasinya.
 *
 * Diperiksa 4 September 2026: dua agen sudah lama diam — `sadap` **45 hari**,
 * `ponorogo` **21 jam** — dan tidak ada satu pun peringatan tentang keduanya.
 *
 * ## Yang membuatnya lebih merugikan daripada kelihatannya
 *
 * Agen yang diam juga **tidak menarik perintah blokir**. Saat ini 168 perintah
 * blokir menumpuk berstatus `approved` tanpa pernah terkirim — 87 di antaranya
 * untuk `ponorogo` sendirian. Jadi bukan hanya pengawasannya yang berhenti;
 * pemblokirannya ikut berhenti, sementara dasbor tetap menampilkan IP-nya
 * sebagai "diblokir".
 *
 * Karena itu jumlah perintah yang macet ikut dibawa dalam peringatannya: ia
 * yang mengubah "sebuah agen mati" menjadi "sekian serangan tidak diblokir".
 *
 * ## Ambangnya
 *
 * Detak jantung agen tiap **60 detik** (terukur: rata-rata 60s, terlama 120s
 * pada enam agen sehat). Ambang bawaan **30 menit** memberi kelonggaran tiga
 * puluh kali lipat — cukup untuk mulai ulang, pembaruan, atau jaringan yang
 * tersendat, tanpa membiarkan agen mati semalaman tanpa ketahuan.
 *
 * Agen berstatus `never_connected` DILEWATI: ia belum pernah hidup, jadi
 * "berhenti melapor" tidak berlaku — dan memberitakannya tiap hari hanya
 * melatih orang mengabaikan peringatan ini.
 */
class CheckAgentHealthJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 60;

    public function handle(): void
    {
        if (! class_exists(Alerter::class)) {
            return;
        }

        $this->registerRules();

        $ambang = (int) config('nawasara-secscan.agent_health.offline_minutes', 30);
        $alerter = Alerter::class;

        // SoftDeletes menyaring agen yang sudah diganti — `Docker-Master` lama
        // masih ada di tabel sebagai baris terhapus, dan memberitakannya berarti
        // memberitakan mesin yang memang sengaja dipensiunkan.
        $agents = Agent::query()
            ->where('status', '!=', Agent::STATUS_NEVER)
            ->get();

        $mati = 0;

        foreach ($agents as $agent) {
            $menit = $agent->last_seen_at
                ? (int) $agent->last_seen_at->diffInMinutes(now())
                : null;

            $key = 'secscan.agent.offline';
            $target = (string) $agent->id;

            if ($menit === null || $menit < $ambang) {
                $alerter::resolve($key, 'Agent', $target);

                continue;
            }

            $mati++;

            // Perintah yang tertahan — inilah yang mengubah "agen mati" menjadi
            // akibat yang dapat diukur.
            $macet = AgentCommand::query()
                ->where('agent_id', $agent->id)
                ->where('status', AgentCommand::STATUS_APPROVED)
                ->whereNull('sent_at')
                ->count();

            $alerter::fire($key, 'Agent', $target, [
                'label' => $agent->name ?: "Agent {$agent->id}",
                'hostname' => $agent->hostname,
                'versi' => $agent->agent_version,
                'diam_selama' => $this->lamaTerbaca($menit),
                'terakhir_lapor' => $agent->last_seen_at?->toDateTimeString(),
                'perintah_tertahan' => $macet,
            ]);
        }

        if ($mati > 0) {
            Log::warning("[secscan] {$mati} agen berhenti melapor lebih dari {$ambang} menit");
        }
    }

    /**
     * "45 hari" terbaca; "64.631 menit" tidak.
     *
     * Peringatan ini dibaca di ponsel, sering oleh orang yang harus memutuskan
     * cepat apakah perlu bangun. Satuan yang harus dihitung sendiri menunda
     * keputusan itu.
     */
    protected function lamaTerbaca(int $menit): string
    {
        if ($menit < 60) {
            return $menit.' menit';
        }

        if ($menit < 1440) {
            return intdiv($menit, 60).' jam';
        }

        return intdiv($menit, 1440).' hari';
    }

    /**
     * Didaftarkan di sini, bukan di ServiceProvider.
     *
     * Job berjalan di pekerja antrean, dan daftar aturan hanya hidup di memori
     * proses. Pekerja yang tidak pernah mendaftarkannya akan melempar
     * UnknownAlertRule saat memulihkan.
     */
    protected function registerRules(): void
    {
        $alerter = Alerter::class;

        if ($alerter::hasRule('secscan.agent.offline')) {
            return;
        }

        $alerter::registerRule(AlertRule::make([
            'key' => 'secscan.agent.offline',
            'severity' => 'critical',
            'category' => 'keamanan',

            // Sekali sehari. Agen yang mati tidak berubah keadaannya tiap jam,
            // dan mengingatkan tiap jam hanya membuat peringatan ini diabaikan
            // justru saat ada agen yang BARU mati.
            'cooldown_minutes' => 1440,
            'description' => 'Agen keamanan berhenti melapor',
            'subject_template' => 'Agen {context.label} diam {context.diam_selama} — {context.perintah_tertahan} perintah blokir tertahan',
        ]));
    }
}
