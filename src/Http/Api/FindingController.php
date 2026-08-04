<?php

namespace Nawasara\Secscan\Http\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Nawasara\Secscan\Http\Resources\FindingResource;
use Nawasara\Secscan\Models\SecscanFinding;

/**
 * Public API temuan situs — situs pemerintah yang terindikasi judi online,
 * deface, phishing, dan sejenisnya.
 *
 * Read-only. Triase (acknowledge / resolve / false-positive) tetap lewat UI,
 * yang mencatat siapa mengubah apa ke tabel histori.
 *
 * Auth + scope dicek di middleware:
 *   - api.auth → token valid
 *   - scope:secscan.finding.read
 */
class FindingController extends Controller
{
    /**
     * GET /api/v1/secscan/findings
     * Scope: secscan.finding.read
     *
     * Query params:
     *   status      — open | acknowledged | resolved | false_positive (boleh koma).
     *                 Default: hanya yang aktif (open + acknowledged).
     *   threat      — judol | phishing | defaced | … (boleh koma)
     *   severity    — critical | warning | info (boleh koma)
     *   q           — cari di nama situs / URL
     *   per_page    — 1..100, default 50
     */
    public function index(Request $request): JsonResponse
    {
        $query = SecscanFinding::query();

        // Default ke temuan aktif: konsumen hampir selalu memaksudkan "yang
        // masih perlu ditindak", dan menyertakan temuan lama yang sudah
        // diselesaikan diam-diam membuat angka mereka salah.
        $status = trim((string) $request->query('status', ''));
        if ($status === '') {
            $query->active();
        } elseif ($status !== 'all') {
            $query->whereIn('status', $this->csv($status));
        }

        if ($threat = trim((string) $request->query('threat', ''))) {
            $query->whereIn('threat_type', $this->csv($threat));
        }

        if ($severity = trim((string) $request->query('severity', ''))) {
            $query->whereIn('severity', $this->csv($severity));
        }

        if ($q = trim((string) $request->query('q', ''))) {
            $query->where(function ($sub) use ($q) {
                $sub->where('site_name', 'like', '%'.$q.'%')
                    ->orWhere('site_url', 'like', '%'.$q.'%');
            });
        }

        $perPage = min(100, max(1, (int) $request->query('per_page', 50)));

        $findings = $query
            ->orderByDesc('score')
            ->orderByDesc('last_detected_at')
            ->orderByDesc('id')
            ->paginate($perPage);

        return response()->json([
            'data' => FindingResource::collection($findings->items())->resolve(),
            'meta' => [
                'total'        => $findings->total(),
                'per_page'     => $findings->perPage(),
                'current_page' => $findings->currentPage(),
                'last_page'    => $findings->lastPage(),
            ],
        ]);
    }

    /**
     * GET /api/v1/secscan/findings/{id}
     * Scope: secscan.finding.read
     */
    public function show(int $id): JsonResponse
    {
        $finding = SecscanFinding::find($id);

        if (! $finding) {
            return response()->json([
                'error'   => 'not_found',
                'message' => 'Temuan tidak ditemukan.',
            ], 404);
        }

        return response()->json([
            'data' => (new FindingResource($finding))->resolve(request()),
        ]);
    }

    /** @return array<int, string> */
    protected function csv(string $value): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $value))));
    }
}
