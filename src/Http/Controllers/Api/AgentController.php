<?php

namespace Nawasara\Secscan\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Str;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\AgentHeartbeat;
use Nawasara\Secscan\Models\SecurityIncident;

class AgentController extends Controller
{
    /**
     * POST /api/agent/register
     * Called once during agent install. Returns the api_key (only time it's shown).
     */
    public function register(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name'          => 'required|string|max:100',
            'hostname'      => 'required|string|max:255',
            'os'            => 'nullable|string|max:64',
            'arch'          => 'nullable|string|max:16',
            'agent_version' => 'nullable|string|max:32',
            'web_server'    => 'nullable|in:nginx,apache,none',
            'ip_local'      => 'nullable|ip',
        ]);

        $rawKey = Agent::generateApiKey();

        $agent = Agent::create([
            ...$data,
            'agent_id'      => Str::random(32),
            'api_key_hash'  => password_hash($rawKey, PASSWORD_BCRYPT),
            'status'        => Agent::STATUS_NEVER,
            'registered_at' => now(),
        ]);

        return response()->json([
            'success'  => true,
            'agent_id' => $agent->agent_id,
            'api_key'  => $rawKey, // only returned once — agent must store it
            'message'  => 'Agent registered. Store your api_key securely — it will not be shown again.',
        ], 201);
    }

    /**
     * POST /api/agent/incidents
     * Accepts a batch of security incidents from the agent.
     */
    public function incidents(Request $request): JsonResponse
    {
        $agent = $this->resolveAgent($request);
        if (! $agent) {
            return response()->json(['success' => false, 'message' => 'Unauthorized'], 401);
        }

        $data = $request->validate([
            'incidents'               => 'required|array|min:1|max:100',
            'incidents.*.incident_id' => 'required|string|max:32',
            'incidents.*.type'        => 'required|string|max:64',
            'incidents.*.severity'    => 'required|in:info,medium,high,critical',
            'incidents.*.source_ip'   => 'required|ip',
            'incidents.*.score'       => 'required|integer|min:0|max:100',
            'incidents.*.evidence'    => 'required|array',
            'incidents.*.detected_at' => 'required|date',
            'incidents.*.correlated'  => 'boolean',
            'incidents.*.metadata'    => 'nullable|array',
        ]);

        $created = 0;
        $skipped = 0;

        foreach ($data['incidents'] as $inc) {
            $exists = SecurityIncident::where('incident_id', $inc['incident_id'])->exists();
            if ($exists) {
                $skipped++;
                continue;
            }

            SecurityIncident::create([
                'incident_id'  => $inc['incident_id'],
                'agent_id'     => $agent->id,
                'type'         => $inc['type'],
                'severity'     => $inc['severity'],
                'source_ip'    => $inc['source_ip'],
                'score'        => $inc['score'],
                'correlated'   => $inc['correlated'] ?? false,
                'evidence'     => $inc['evidence'],
                'metadata'     => $inc['metadata'] ?? null,
                'detected_at'  => $inc['detected_at'],
            ]);
            $created++;
        }

        // Update agent status
        $agent->update(['status' => Agent::STATUS_ONLINE, 'last_seen_at' => now()]);

        return response()->json(['success' => true, 'created' => $created, 'skipped' => $skipped]);
    }

    /**
     * POST /api/agent/heartbeat
     * Periodic health ping + metric snapshot.
     */
    public function heartbeat(Request $request): JsonResponse
    {
        $agent = $this->resolveAgent($request);
        if (! $agent) {
            return response()->json(['success' => false, 'message' => 'Unauthorized'], 401);
        }

        $data = $request->validate([
            'agent_version'     => 'nullable|string|max:32',
            'health_score'      => 'numeric|min:0|max:100',
            'pending_incidents' => 'integer|min:0',
            'plugins_active'    => 'nullable|array',
            'metrics'           => 'nullable|array',
            'uptime_seconds'    => 'integer|min:0',
        ]);

        AgentHeartbeat::create([
            'agent_id'          => $agent->id,
            'agent_version'     => $data['agent_version'] ?? $agent->agent_version,
            'health_score'      => $data['health_score'] ?? 100,
            'pending_incidents' => $data['pending_incidents'] ?? 0,
            'plugins_active'    => $data['plugins_active'] ?? null,
            'metrics'           => $data['metrics'] ?? null,
            'uptime_seconds'    => $data['uptime_seconds'] ?? 0,
        ]);

        $agent->update([
            'status'         => Agent::STATUS_ONLINE,
            'health_score'   => $data['health_score'] ?? $agent->health_score,
            'agent_version'  => $data['agent_version'] ?? $agent->agent_version,
            'plugins_active' => $data['plugins_active'] ?? $agent->plugins_active,
            'last_seen_at'   => now(),
        ]);

        return response()->json(['success' => true]);
    }

    protected function resolveAgent(Request $request): ?Agent
    {
        $rawKey = $request->header('X-Agent-Key') ?? $request->input('api_key');
        if (! $rawKey) {
            return null;
        }

        // Agents table could be large — try find by agent_id hint first if sent
        $agentId = $request->header('X-Agent-Id') ?? $request->input('agent_id');

        if ($agentId) {
            $agent = Agent::where('agent_id', $agentId)->first();
            if ($agent && password_verify($rawKey, $agent->api_key_hash)) {
                return $agent;
            }
            return null;
        }

        return Agent::findByApiKey($rawKey);
    }
}
