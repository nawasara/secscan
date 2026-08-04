<?php

namespace Nawasara\Secscan\Http\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Nawasara\Secscan\Http\Resources\AgentResource;
use Nawasara\Secscan\Models\Agent;

/**
 * Public API status agent — untuk monitoring eksternal yang perlu tahu agent
 * mana yang berhenti melapor.
 *
 * Namanya AgentStatusController, bukan AgentController, supaya tidak tertukar
 * dengan Http\Controllers\Api\AgentController yang menangani ingestion dari
 * agent (arah sebaliknya, autentikasi X-Agent-Key, tanpa scope).
 *
 * Read-only. Perintah ke agent (restart, scan, block host) sengaja tidak
 * diekspos: itu bidang kendali, dan mengeksposnya lewat token API berarti
 * memberi jalur eksekusi jarak jauh di server OPD.
 *
 * Auth + scope dicek di middleware:
 *   - api.auth → token valid
 *   - scope:secscan.agent.read
 */
class AgentStatusController extends Controller
{
    /**
     * GET /api/v1/secscan/agents
     * Scope: secscan.agent.read
     *
     * Query params:
     *   status   — online | offline | never_connected (boleh koma)
     *   per_page — 1..100, default 50
     */
    public function index(Request $request): JsonResponse
    {
        $query = Agent::query()->withCount('incidents');

        if ($status = trim((string) $request->query('status', ''))) {
            $query->whereIn('status', array_values(array_filter(
                array_map('trim', explode(',', $status)),
            )));
        }

        $perPage = min(100, max(1, (int) $request->query('per_page', 50)));

        $agents = $query
            ->orderBy('name')
            ->orderBy('id')
            ->paginate($perPage);

        return response()->json([
            'data' => AgentResource::collection($agents->items())->resolve(),
            'meta' => [
                'total'        => $agents->total(),
                'per_page'     => $agents->perPage(),
                'current_page' => $agents->currentPage(),
                'last_page'    => $agents->lastPage(),
                // Ringkasan fleet — pemanggil monitoring biasanya hanya butuh
                // ini dan tidak perlu menelusuri seluruh halaman.
                'online'       => Agent::where('status', Agent::STATUS_ONLINE)->count(),
                'offline'      => Agent::where('status', Agent::STATUS_OFFLINE)->count(),
            ],
        ]);
    }

    /**
     * GET /api/v1/secscan/agents/{agentId}
     * Scope: secscan.agent.read
     */
    public function show(string $agentId): JsonResponse
    {
        $agent = Agent::withCount('incidents')->where('agent_id', $agentId)->first();

        if (! $agent) {
            return response()->json([
                'error'   => 'not_found',
                'message' => 'Agent tidak ditemukan.',
            ], 404);
        }

        return response()->json([
            'data' => (new AgentResource($agent))->resolve(request()),
        ]);
    }
}
