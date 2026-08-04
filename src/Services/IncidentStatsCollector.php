<?php

namespace Nawasara\Secscan\Services;

use Carbon\CarbonInterface;
use Illuminate\Support\Facades\DB;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Models\SecurityIncident;

/**
 * Agregat insiden untuk sebuah rentang waktu.
 *
 * Diekstrak dari SendDailyDigestJob supaya angka yang sama bisa dipakai email
 * digest dan API tanpa dua implementasi yang bisa berbeda diam-diam.
 *
 * Semua hitungan dilakukan sebagai query grouped — termasuk host, yang di versi
 * digest sebelumnya diagregasi di PHP dengan memuat SELURUH insiden dalam window
 * ke memori. Itu aman untuk window 24 jam, tapi API menerima rentang dari
 * pemanggil; window sebulan akan menjadi jalur kehabisan memori.
 */
class IncidentStatsCollector
{
    /**
     * @return array{
     *   total:int,
     *   by_severity:array<string,int>,
     *   by_type:array<string,int>,
     *   top_ips:array<int,array{ip:string,count:int,score:int}>,
     *   top_hosts:array<int,array{host:string,count:int}>,
     *   blocked:int,
     *   blocked_active:int,
     *   agents_online:int,
     *   agents_total:int
     * }
     */
    public function collect(CarbonInterface $start, CarbonInterface $end): array
    {
        $base = fn () => SecurityIncident::query()->whereBetween('last_seen_at', [$start, $end]);

        return [
            'total' => $base()->count(),

            'by_severity' => $base()
                ->selectRaw('severity, COUNT(*) as n')
                ->groupBy('severity')
                ->pluck('n', 'severity')
                ->map(fn ($n) => (int) $n)
                ->all(),

            'by_type' => $base()
                ->selectRaw('type, COUNT(*) as n')
                ->groupBy('type')
                ->orderByDesc('n')
                ->limit(8)
                ->pluck('n', 'type')
                ->map(fn ($n) => (int) $n)
                ->all(),

            'top_ips' => $base()
                ->whereNotNull('source_ip')
                ->selectRaw('source_ip, COUNT(*) as n, MAX(score) as max_score')
                ->groupBy('source_ip')
                ->orderByDesc('n')
                ->limit(10)
                ->get()
                ->map(fn ($r) => [
                    'ip' => (string) $r->source_ip,
                    'count' => (int) $r->n,
                    'score' => (int) $r->max_score,
                ])
                ->all(),

            'top_hosts' => $this->topHosts($start, $end),

            'blocked' => IpBlock::whereBetween('blocked_at', [$start, $end])->count(),
            'blocked_active' => IpBlock::where('status', IpBlock::STATUS_ACTIVE)->count(),

            'agents_online' => Agent::where('status', Agent::STATUS_ONLINE)->count(),
            'agents_total' => Agent::count(),
        ];
    }

    /**
     * Host (vhost kita sendiri) yang paling sering jadi sasaran.
     *
     * Host tersimpan di dalam blob `evidence`, satu entry per bukti, sehingga
     * tidak bisa di-GROUP BY langsung. Alih-alih memuat semua baris, kita ambil
     * hanya kolom evidence secara chunk — memori tetap datar berapa pun
     * panjang window yang diminta.
     *
     * Yang diambil HANYA nama host; sisa isi evidence (baris log mentah, aturan
     * yang cocok, payload serangan) tidak pernah keluar dari method ini.
     *
     * @return array<int, array{host:string, count:int}>
     */
    protected function topHosts(CarbonInterface $start, CarbonInterface $end, int $limit = 10): array
    {
        $counts = [];

        SecurityIncident::query()
            ->whereBetween('last_seen_at', [$start, $end])
            ->whereNotNull('evidence')
            ->select(['id', 'evidence'])
            ->chunkById(500, function ($chunk) use (&$counts) {
                foreach ($chunk as $incident) {
                    foreach ((array) ($incident->evidence ?? []) as $entry) {
                        $host = is_array($entry) ? ($entry['host'] ?? null) : null;

                        if (is_string($host) && $host !== '') {
                            $counts[$host] = ($counts[$host] ?? 0) + 1;
                        }
                    }
                }
            });

        arsort($counts);

        $out = [];
        foreach (array_slice($counts, 0, $limit, true) as $host => $count) {
            $out[] = ['host' => (string) $host, 'count' => (int) $count];
        }

        return $out;
    }
}
