<?php

namespace Nawasara\Secscan\Http\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Nawasara\Secscan\Http\Resources\IncidentResource;
use Nawasara\Secscan\Models\SecurityIncident;

/**
 * Public API insiden keamanan — serangan yang dideteksi agent di server OPD.
 *
 * Read-only. Insiden dibuat oleh agent lewat jalur ingestion terpisah
 * (/api/agent/*, autentikasi X-Agent-Key); endpoint ini hanya membacanya.
 *
 * Auth + scope dicek di middleware:
 *   - api.auth → token valid
 *   - scope:secscan.incident.read
 */
class IncidentController extends Controller
{
    /**
     * GET /api/v1/secscan/incidents
     * Scope: secscan.incident.read
     *
     * Query params:
     *   severity  — info | medium | high | critical (boleh koma: high,critical)
     *   type      — tipe insiden (brute_force_ssh, sqli_attempt, …)
     *   ip        — filter tepat pada IP penyerang
     *   blocked   — 1 hanya yang sudah di-block, 0 hanya yang belum
     *   since     — ISO8601; insiden dengan last_seen_at >= nilai ini
     *   per_page  — 1..100, default 50
     */
    public function index(Request $request): JsonResponse
    {
        $query = SecurityIncident::query()->with('agent');

        if ($severity = trim((string) $request->query('severity', ''))) {
            $query->whereIn('severity', $this->csv($severity));
        }

        if ($type = trim((string) $request->query('type', ''))) {
            $query->whereIn('type', $this->csv($type));
        }

        if ($ip = trim((string) $request->query('ip', ''))) {
            $query->where('source_ip', $ip);
        }

        if ($request->has('blocked')) {
            $request->boolean('blocked')
                ? $query->whereNotNull('blocked_at')
                : $query->whereNull('blocked_at');
        }

        if ($since = trim((string) $request->query('since', ''))) {
            try {
                $query->where('last_seen_at', '>=', \Carbon\Carbon::parse($since));
            } catch (\Throwable $e) {
                return response()->json([
                    'error' => 'invalid_parameter',
                    'message' => 'Parameter `since` bukan tanggal yang valid (pakai ISO8601).',
                ], 422);
            }
        }

        $perPage = min(100, max(1, (int) $request->query('per_page', 50)));

        // Urut pakai id sebagai tie-breaker: agent terus meng-update
        // last_seen_at pada insiden lama (agregasi), jadi mengurutkan hanya
        // dengan kolom itu membuat baris berpindah halaman di tengah paginasi.
        $incidents = $query
            ->orderByDesc('last_seen_at')
            ->orderByDesc('id')
            ->paginate($perPage);

        return response()->json([
            'data' => IncidentResource::collection($incidents->items())->resolve(),
            'meta' => [
                'total'        => $incidents->total(),
                'per_page'     => $incidents->perPage(),
                'current_page' => $incidents->currentPage(),
                'last_page'    => $incidents->lastPage(),
            ],
        ]);
    }

    /**
     * GET /api/v1/secscan/incidents/{incidentId}
     * Scope: secscan.incident.read
     */
    public function show(string $incidentId): JsonResponse
    {
        $incident = SecurityIncident::with('agent')
            ->where('incident_id', $incidentId)
            ->first();

        if (! $incident) {
            return response()->json([
                'error'   => 'not_found',
                'message' => 'Insiden tidak ditemukan.',
            ], 404);
        }

        return response()->json([
            'data' => (new IncidentResource($incident))->resolve(request()),
        ]);
    }

    /**
     * Pecah nilai query berkoma jadi list bersih.
     *
     * @return array<int, string>
     */
    protected function csv(string $value): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $value))));
    }
}
