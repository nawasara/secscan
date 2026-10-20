<?php

namespace Nawasara\Secscan\Console;

use Illuminate\Console\Command;
use Nawasara\Secscan\Models\AgentScanFinding;
use Nawasara\Sync\Support\ChunkedPruner;

/**
 * Pembersihan data agen yang tumbuh tanpa batas.
 *
 *   heartbeats      satu baris per agen per menit (730 ribu per Oktober 2026).
 *                   Status online dibaca dari heartbeat TERAKHIR dan halaman
 *                   detail paling jauh membaca 1.000 baris (~16 jam), jadi
 *                   14 hari sudah longgar.
 *   incidents       bukti serangan. Disimpan setahun: dipakai menelusuri pola
 *                   penyerang dan menjawab "IP ini diblokir karena apa".
 *                   ip_blocks.incident_id bernilai null saat insidennya hilang
 *                   (nullOnDelete), blokirnya sendiri tetap.
 *   scan findings   hanya yang sudah DITUTUP (resolved / false_positive).
 *                   Temuan yang masih terbuka tidak pernah dihapus, setua apa
 *                   pun: menghapusnya sama dengan menyembunyikan webshell.
 */
class PruneCommand extends Command
{
    protected $signature = 'nawasara-secscan:prune
        {--dry-run : Hitung saja, tidak menghapus apa pun}';

    protected $description = 'Prune old agent heartbeats, security incidents and closed scan findings';

    public function handle(): int
    {
        $dry = (bool) $this->option('dry-run');
        $prefix = $dry ? '[dry-run] ' : '';
        $cfg = config('nawasara-secscan.prune', []);

        $hb = (int) ($cfg['heartbeats_days'] ?? 14);
        if ($hb > 0) {
            $n = ChunkedPruner::deleteOlderThan('nawasara_agent_heartbeats', 'created_at', now()->subDays($hb), dryRun: $dry);
            $this->line($prefix."Heartbeat > {$hb} hari: ".number_format($n));
        }

        $inc = (int) ($cfg['incidents_days'] ?? 365);
        if ($inc > 0) {
            $n = ChunkedPruner::deleteOlderThan('nawasara_security_incidents', 'detected_at', now()->subDays($inc), dryRun: $dry);
            $this->line($prefix."Insiden > {$inc} hari: ".number_format($n));
        }

        $fnd = (int) ($cfg['closed_findings_days'] ?? 365);
        if ($fnd > 0) {
            $n = ChunkedPruner::deleteOlderThan('nawasara_agent_scan_findings', 'detected_at', now()->subDays($fnd),
                scope: fn ($q) => $q->whereIn('status', [AgentScanFinding::STATUS_RESOLVED, AgentScanFinding::STATUS_FALSE_POSITIVE]),
                dryRun: $dry);
            $this->line($prefix."Temuan tertutup > {$fnd} hari: ".number_format($n));
        }

        return self::SUCCESS;
    }
}
