<?php

namespace Nawasara\Secscan\Http\Api;

use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Nawasara\Secscan\Services\IncidentStatsCollector;

/**
 * Public API statistik keamanan — angka ringkas untuk dashboard atau monitoring
 * di luar Nawasara.
 *
 * Memakai IncidentStatsCollector yang sama dengan email digest harian, supaya
 * angka di API dan di email tidak bisa berbeda diam-diam.
 *
 * Auth + scope dicek di middleware:
 *   - api.auth → token valid
 *   - scope:secscan.stats.read
 */
class StatsController extends Controller
{
    /**
     * Batas panjang window. Bukan soal beban query — agregat host memindai
     * evidence secara chunk — tapi supaya pemanggil tidak sengaja meminta
     * rentang bertahun-tahun dan menunggu lama tanpa tahu kenapa.
     */
    protected const MAX_WINDOW_DAYS = 90;

    /**
     * GET /api/v1/secscan/stats
     * Scope: secscan.stats.read
     *
     * Query params:
     *   days  — panjang window ke belakang dari sekarang, 1..90, default 1
     *   from  — ISO8601 (dipakai bersama `to`; menimpa `days`)
     *   to    — ISO8601
     */
    public function index(Request $request): JsonResponse
    {
        try {
            [$start, $end] = $this->resolveWindow($request);
        } catch (\InvalidArgumentException $e) {
            return response()->json([
                'error'   => 'invalid_parameter',
                'message' => $e->getMessage(),
            ], 422);
        }

        $stats = app(IncidentStatsCollector::class)->collect($start, $end);

        return response()->json([
            'data' => $stats,
            'meta' => [
                'from' => $start->toIso8601String(),
                'to'   => $end->toIso8601String(),
            ],
        ]);
    }

    /**
     * Tentukan rentang waktu dari query params.
     *
     * @return array{0: Carbon, 1: Carbon}
     *
     * @throws \InvalidArgumentException
     */
    protected function resolveWindow(Request $request): array
    {
        $from = trim((string) $request->query('from', ''));
        $to = trim((string) $request->query('to', ''));

        if ($from !== '' || $to !== '') {
            if ($from === '' || $to === '') {
                throw new \InvalidArgumentException('Parameter `from` dan `to` harus diisi bersamaan.');
            }

            try {
                $start = Carbon::parse($from);
                $end = Carbon::parse($to);
            } catch (\Throwable $e) {
                throw new \InvalidArgumentException('Parameter `from`/`to` bukan tanggal yang valid (pakai ISO8601).');
            }

            if ($start->greaterThan($end)) {
                throw new \InvalidArgumentException('Parameter `from` harus lebih awal dari `to`.');
            }

            if ($start->diffInDays($end) > self::MAX_WINDOW_DAYS) {
                throw new \InvalidArgumentException('Rentang maksimum '.self::MAX_WINDOW_DAYS.' hari.');
            }

            return [$start, $end];
        }

        $days = (int) $request->query('days', 1);

        if ($days < 1 || $days > self::MAX_WINDOW_DAYS) {
            throw new \InvalidArgumentException('Parameter `days` harus antara 1 dan '.self::MAX_WINDOW_DAYS.'.');
        }

        return [now()->subDays($days), now()];
    }
}
