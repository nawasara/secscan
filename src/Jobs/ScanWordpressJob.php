<?php

namespace Nawasara\Secscan\Jobs;

use Illuminate\Support\Facades\DB;
use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Models\SecscanFindingHistory;
use Nawasara\Secscan\Services\FindingTriage;
use Nawasara\Secscan\Services\SqlSignalDetector;
use Nawasara\Sync\Jobs\AbstractSyncJob;

/**
 * Hourly WordPress security scan. Runs SqlSignalDetector against every
 * monitored WP database, upserts findings, records triage history on new/
 * recurring issues, and fires alerts for critical findings.
 *
 * Read-only against OPD databases — the only writes are to local
 * nawasara_secscan_* tables.
 */
class ScanWordpressJob extends AbstractSyncJob
{
    /**
     * Satu putaran memindai SETIAP database WordPress yang dipantau — ratusan
     * di produksi — jadi durasinya diukur dalam puluhan menit, bukan detik.
     * Pengukuran di prod: ~1.930 detik (32 menit) untuk sekali jalan penuh.
     *
     * Nilai lama 300 detik membunuh scan di menit ke-5, mengembalikannya ke
     * antrian, dan mengulangnya sampai `$tries` habis — muncul sebagai
     * "attempted too many times" tanpa exception asli, karena memang tidak ada
     * yang dilempar; job dihentikan paksa. Yang tercatat sukses pun menyesatkan:
     * durasinya mencakup percobaan-percobaan yang gagal, bukan satu jalan bersih.
     *
     * 50 menit memberi ruang untuk pertumbuhan jumlah database sambil tetap
     * selesai dalam satu jam, dan tetap di bawah --timeout=960 worker-sync…
     * (lihat catatan di bawah).
     */
    public int $timeout = 3000;

    /**
     * Scan penuh tidak layak diulang otomatis. Kalau gagal, mengulang seluruh
     * pemindaian ratusan database jarang memperbaiki keadaan — penyebabnya
     * biasanya satu database yang tidak bisa dijangkau, dan percobaan ulang
     * hanya menghabiskan slot worker selama setengah jam lagi. Scheduler akan
     * menjalankannya lagi pada jam berikutnya.
     */
    public int $tries = 1;

    protected function service(): string
    {
        return 'secscan';
    }

    protected function action(): string
    {
        return 'scan_wordpress';
    }

    protected function targetType(): ?string
    {
        return null;
    }

    protected function targetId(): ?string
    {
        return null;
    }

    protected function execute(): array
    {
        $detector = app(SqlSignalDetector::class);
        $result = $detector->scanAll();

        $now = now();
        $created = 0;
        $updated = 0;
        $alerted = 0;
        $alertMin = (int) config('nawasara-secscan.thresholds.alert_min_score', 70);
        $triage = app(FindingTriage::class);

        foreach ($result['findings'] as $f) {

            $existing = SecscanFinding::where('db_name', $f['db_name'])
                ->where('threat_type', $f['threat_type'])
                ->first();

            if (! $existing) {
                $finding = SecscanFinding::create([
                    'db_name' => $f['db_name'],
                    'site_url' => $f['site_url'],
                    'site_name' => $f['site_name'],
                    'threat_type' => $f['threat_type'],
                    'severity' => $f['severity'],
                    'score' => $f['score'],
                    'status' => SecscanFinding::STATUS_OPEN,
                    'evidence' => $f['evidence'],
                    'first_detected_at' => $now,
                    'last_detected_at' => $now,
                ]);
                $this->recordHistory($finding, null, SecscanFinding::STATUS_OPEN, 'Terdeteksi oleh scan otomatis.', $now);
                $created++;
            } else {
                // Selesai stays Selesai here, unlike the HTTP probe. This scan
                // reads the DATABASE, and the usual fix is suspending the
                // cPanel account: the site stops serving, the injected rows
                // stay. In production 16 of 19 "Selesai but still detected"
                // were exactly that, and reopening them would alert "site
                // compromised" about sites that are offline.
                //
                // last_detected_at still moves, which is the point: the panel
                // shows "masih ada di database" when it is newer than
                // resolved_at (SecscanFinding::stillInDatabase()), so the dirty
                // database is not forgotten when the account is reactivated.

                $existing->forceFill([
                    'site_url' => $f['site_url'] ?: $existing->site_url,
                    'site_name' => $f['site_name'] ?: $existing->site_name,
                    'severity' => $f['severity'],
                    'score' => $f['score'],
                    'evidence' => $f['evidence'],
                    'last_detected_at' => $now,
                ])->save();
                $updated++;
                $finding = $existing;
            }

            // Alert only for active, high-score findings.
            if ($finding->isActive() && $f['score'] >= $alertMin) {
                Alerter::fire(
                    $this->ruleFor($f['threat_type']),
                    'SecscanFinding',
                    (string) $finding->id,
                    [
                        'site_name' => $f['site_name'] ?: $f['db_name'],
                        'db_name' => $f['db_name'],
                        'threat_type' => $finding->threatLabel(),
                        'score' => $f['score'],
                        'site_url' => $f['site_url'],
                    ]
                );
                $alerted++;
            }
        }

        // Active findings on databases swept cleanly this run whose signal has
        // been absent long enough: the site was cleaned. Detected-this-run rows
        // were just stamped with $now, so the age check already excludes them.
        $stale = SecscanFinding::active()
            ->where(fn ($q) => $q->whereNull('scan_source')->orWhere('scan_source', 'sql'))
            ->whereIn('db_name', $result['inspected'] ?? [])
            ->where('last_detected_at', '<', $now->copy()->subHours((int) config('nawasara-secscan.auto_resolve_after_hours', 24)))
            ->get();
        $autoResolved = $triage->autoResolve($stale);

        return [
            'auto_resolved' => $autoResolved,
            'scanned' => $result['scanned_total'],
            'wordpress' => $result['wordpress_total'],
            'cms' => $result['cms_total'] ?? 0,
            'findings' => count($result['findings']),
            'created' => $created,
            'updated' => $updated,
            'alerted' => $alerted,
        ];
    }

    protected function recordHistory(SecscanFinding $finding, ?string $from, string $to, string $reason, $at): void
    {
        SecscanFindingHistory::create([
            'finding_id' => $finding->id,
            'status_from' => $from,
            'status_to' => $to,
            'changed_by' => null,
            'reason' => $reason,
            'created_at' => $at,
        ]);
    }

    /** Map threat type → alert rule key (registered in the ServiceProvider). */
    protected function ruleFor(string $threatType): string
    {
        return match ($threatType) {
            SecscanFinding::THREAT_JUDOL,
            SecscanFinding::THREAT_ILLEGAL_PHARMA,
            SecscanFinding::THREAT_DEFACED,
            SecscanFinding::THREAT_MALWARE,
            SecscanFinding::THREAT_PHISHING => 'secscan.site.compromised',
            default => 'secscan.site.suspicious',
        };
    }
}
