<?php

namespace Nawasara\Secscan\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Str;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\AgentCommand;
use Nawasara\Secscan\Models\AgentHeartbeat;
use Nawasara\Secscan\Models\AgentScanFinding;
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
            'incidents.*.source_ip'   => 'nullable|string|max:45',
            'incidents.*.score'       => 'required|integer|min:0|max:100',
            'incidents.*.evidence'    => 'required|array',
            'incidents.*.detected_at' => 'required|date',
            'incidents.*.correlated'  => 'boolean',
            'incidents.*.metadata'    => 'nullable|array',
        ]);

        $windowHours = (int) config('nawasara-secscan.agent.incident_aggregation_hours', 24);
        $evidenceCap = (int) config('nawasara-secscan.agent.incident_evidence_cap', 20);

        $created    = 0;
        $aggregated = 0;

        foreach ($data['incidents'] as $inc) {
            $detectedAt = \Carbon\Carbon::parse($inc['detected_at']);
            $sourceIp   = $inc['source_ip'] ?: null;

            // Exact re-send: deterministic scanner IDs or retried buffered batches.
            $existing = SecurityIncident::where('incident_id', $inc['incident_id'])->first();

            // Logical duplicate: an ongoing attack (same agent + type + source IP)
            // keeps crossing the agent threshold and re-emits with a fresh random
            // ID. Fold it into the still-active incident instead of a new row.
            if (! $existing && $sourceIp) {
                $existing = SecurityIncident::where('agent_id', $agent->id)
                    ->where('type', $inc['type'])
                    ->where('source_ip', $sourceIp)
                    ->where('last_seen_at', '>=', now()->subHours($windowHours))
                    ->orderByDesc('last_seen_at')
                    ->first();
            }

            if ($existing) {
                $lastSeen = $existing->last_seen_at ?? $existing->detected_at;

                $existing->update([
                    'occurrences'  => $existing->occurrences + 1,
                    'last_seen_at' => $detectedAt->greaterThan($lastSeen) ? $detectedAt : $lastSeen,
                    'score'        => max($existing->score, $inc['score']),
                    'severity'     => SecurityIncident::maxSeverity($existing->severity, $inc['severity']),
                    'correlated'   => $existing->correlated || ($inc['correlated'] ?? false),
                    'evidence'     => array_slice(
                        array_merge($existing->evidence ?? [], $inc['evidence']),
                        -$evidenceCap
                    ),
                ]);
                $aggregated++;
                continue;
            }

            SecurityIncident::create([
                'incident_id'  => $inc['incident_id'],
                'agent_id'     => $agent->id,
                'type'         => $inc['type'],
                'severity'     => $inc['severity'],
                'source_ip'    => $sourceIp,
                'score'        => $inc['score'],
                'occurrences'  => 1,
                'correlated'   => $inc['correlated'] ?? false,
                'evidence'     => $inc['evidence'],
                'metadata'     => $inc['metadata'] ?? null,
                'detected_at'  => $inc['detected_at'],
                'last_seen_at' => $inc['detected_at'],
            ]);
            $created++;
        }

        // Update agent status
        $agent->update(['status' => Agent::STATUS_ONLINE, 'last_seen_at' => now()]);

        return response()->json(['success' => true, 'created' => $created, 'aggregated' => $aggregated]);
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

    /**
     * GET /api/agent/commands/pending
     *
     * Returns approved commands waiting to be executed by this agent.
     * Each command is marked as "sent" immediately so it's not returned twice.
     */
    public function commandsPending(Request $request): JsonResponse
    {
        $agent = $this->resolveAgent($request);
        if (! $agent) {
            return response()->json(['success' => false, 'message' => 'Unauthorized'], 401);
        }

        $commands = AgentCommand::where('agent_id', $agent->id)
            ->where('status', AgentCommand::STATUS_APPROVED)
            ->orderBy('approved_at')
            ->limit(10)
            ->get();

        // Mark as sent so they're not returned on next poll
        if ($commands->isNotEmpty()) {
            AgentCommand::whereIn('id', $commands->pluck('id'))
                ->update(['status' => AgentCommand::STATUS_SENT, 'sent_at' => now()]);
        }

        return response()->json([
            'commands' => $commands->map(fn ($cmd) => [
                'command_id' => $cmd->command_id,
                'action'     => $cmd->action,
                'params'     => $cmd->params ?? [],
                'issued_at'  => $cmd->approved_at->toIso8601String(),
            ]),
        ]);
    }

    /**
     * POST /api/agent/command-result
     *
     * Agent reports execution result for a previously received command.
     */
    public function commandResult(Request $request): JsonResponse
    {
        $agent = $this->resolveAgent($request);
        if (! $agent) {
            return response()->json(['success' => false, 'message' => 'Unauthorized'], 401);
        }

        $data = $request->validate([
            'command_id' => 'required|string|max:32',
            'success'    => 'required|boolean',
            'output'     => 'nullable|string|max:10000',
            'error'      => 'nullable|string|max:5000',
            'exec_at'    => 'nullable|date',
        ]);

        $cmd = AgentCommand::where('command_id', $data['command_id'])
            ->where('agent_id', $agent->id)
            ->first();

        if (! $cmd) {
            return response()->json(['success' => false, 'message' => 'Command not found'], 404);
        }

        $cmd->update([
            'status'  => $data['success'] ? AgentCommand::STATUS_COMPLETED : AgentCommand::STATUS_FAILED,
            'output'  => $data['output'] ?? null,
            'error'   => $data['error'] ?? null,
            'exec_at' => $data['exec_at'] ?? now(),
        ]);

        return response()->json(['success' => true]);
    }

    /**
     * POST /api/agent/scan-findings
     *
     * Accepts a single file scanner finding from the agent.
     * The agent pushes one JSON object per finding (not batched).
     */
    public function scanFinding(Request $request): JsonResponse
    {
        $agent = $this->resolveAgent($request);
        if (! $agent) {
            return response()->json(['success' => false, 'message' => 'Unauthorized'], 401);
        }

        $data = $request->validate([
            'finding_id'   => 'required|string|max:32',
            'path'         => 'required|string|max:1024',
            'signature_id' => 'required|string|max:64',
            'sig_name'     => 'required|string|max:128',
            'category'     => 'required|in:webshell,backdoor,exploit,integrity,suspicious',
            'severity'     => 'required|in:critical,high,medium',
            'score'        => 'required|integer|min:0|max:100',
            'description'  => 'nullable|string|max:1024',
            'matched_line' => 'nullable|string|max:512',
            'file_size'    => 'nullable|integer|min:0',
            'file_mtime'   => 'nullable|integer',  // unix timestamp
            'detected_at'  => 'nullable|integer',  // unix timestamp
        ]);

        $seenAt = isset($data['detected_at'])
            ? \Carbon\Carbon::createFromTimestamp($data['detected_at'])
            : now();

        // Deduplicate: exact finding_id (deterministic hash from agent ≥ 0.4),
        // then fall back to logical identity (same agent + path + signature) so
        // older agents that still send random IDs don't stack duplicate rows.
        $existing = AgentScanFinding::where('finding_id', $data['finding_id'])->first()
            ?? AgentScanFinding::where('agent_id', $agent->id)
                ->where('path', $data['path'])
                ->where('signature_id', $data['signature_id'])
                ->orderByDesc('detected_at')
                ->first();

        if ($existing) {
            $updates = [
                'last_seen_at' => $seenAt,
                'sig_name'     => $data['sig_name'],
                'severity'     => $data['severity'],
                'score'        => max($existing->score, $data['score']),
                'description'  => $data['description'] ?? $existing->description,
                'matched_line' => $data['matched_line'] ?? $existing->matched_line,
                'file_size'    => $data['file_size'] ?? $existing->file_size,
                'file_mtime'   => isset($data['file_mtime']) ? \Carbon\Carbon::createFromTimestamp($data['file_mtime']) : $existing->file_mtime,
            ];

            // The file was marked clean but the agent still detects it → reopen.
            // acknowledged / false_positive keep their status, only last_seen moves.
            if ($existing->status === AgentScanFinding::STATUS_RESOLVED) {
                $updates['status'] = AgentScanFinding::STATUS_OPEN;
            }

            $existing->update($updates);
            $agent->update(['status' => Agent::STATUS_ONLINE, 'last_seen_at' => now()]);

            return response()->json(['success' => true, 'updated' => true]);
        }

        AgentScanFinding::create([
            'finding_id'   => $data['finding_id'],
            'agent_id'     => $agent->id,
            'path'         => $data['path'],
            'signature_id' => $data['signature_id'],
            'sig_name'     => $data['sig_name'],
            'category'     => $data['category'],
            'severity'     => $data['severity'],
            'score'        => $data['score'],
            'description'  => $data['description'] ?? null,
            'matched_line' => $data['matched_line'] ?? null,
            'file_size'    => $data['file_size'] ?? null,
            'file_mtime'   => isset($data['file_mtime']) ? \Carbon\Carbon::createFromTimestamp($data['file_mtime']) : null,
            'status'       => AgentScanFinding::STATUS_OPEN,
            'detected_at'  => $seenAt,
            'last_seen_at' => $seenAt,
        ]);

        $agent->update(['status' => Agent::STATUS_ONLINE, 'last_seen_at' => now()]);

        return response()->json(['success' => true]);
    }

    /**
     * GET /agent/install.sh
     *
     * Serves a one-liner bash install script for nawasara-agent.
     * Returns text/plain so `curl | bash` works without CF bot challenge
     * (the route is excluded from CF managed challenge via WAF rule).
     */
    public function installScript(): \Illuminate\Http\Response
    {
        $dashboardUrl = rtrim(config('app.url'), '/');
        $repo         = config('nawasara-secscan.agent.github_repo', 'nawasara/agent');

        $script = <<<BASH
        #!/usr/bin/env bash
        # nawasara-agent installer
        # Usage: curl -sSL {$dashboardUrl}/agent/install.sh | bash
        set -euo pipefail

        DASHBOARD_URL="{$dashboardUrl}"
        GITHUB_REPO="{$repo}"
        INSTALL_DIR="/usr/local/bin"
        CONFIG_DIR="/etc/nawasara-agent"
        DATA_DIR="/var/lib/nawasara-agent"
        LOG_DIR="/var/log/nawasara-agent"
        SERVICE_FILE="/etc/systemd/system/nawasara-agent.service"

        # Detect arch
        ARCH=\$(uname -m)
        case "\$ARCH" in
            x86_64)  ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
            *) echo "Unsupported architecture: \$ARCH"; exit 1 ;;
        esac

        OS="linux"
        BINARY="nawasara-agent-\${OS}-\${ARCH}"
        DOWNLOAD_URL="\${DASHBOARD_URL}/agent/download/latest/\${OS}/\${ARCH}/nawasara-agent"

        echo "==> Nawasara Agent Installer"
        echo "    Dashboard : \${DASHBOARD_URL}"
        echo "    Arch      : \${ARCH}"
        echo ""

        # Create directories
        mkdir -p "\$CONFIG_DIR" "\$DATA_DIR" "\$LOG_DIR"

        # Download binary
        echo "==> Downloading nawasara-agent (\${ARCH})..."
        curl -sSL -o "\${INSTALL_DIR}/nawasara-agent" "\${DOWNLOAD_URL}"
        chmod +x "\${INSTALL_DIR}/nawasara-agent"
        echo "    Binary installed at \${INSTALL_DIR}/nawasara-agent"

        # Auto-register with the dashboard to obtain agent_id + api_key, unless
        # a config already exists (idempotent re-run keeps existing credentials).
        AGENT_ID=""
        API_KEY=""
        if [ ! -f "\${CONFIG_DIR}/config.yaml" ]; then
            echo "==> Registering agent with dashboard..."
            HOSTNAME_VAL="\$(hostname)"
            OS_VAL="\$(uname -s | tr A-Z a-z)"
            ARCH_VAL="\$(uname -m)"
            REG_PAYLOAD="{\"name\":\"\${HOSTNAME_VAL}\",\"hostname\":\"\${HOSTNAME_VAL}\",\"os\":\"\${OS_VAL}\",\"arch\":\"\${ARCH_VAL}\"}"

            REG_RESPONSE="\$(curl -sS -X POST "\${DASHBOARD_URL}/api/agent/register" \\
                -H 'Content-Type: application/json' \\
                -d "\${REG_PAYLOAD}")"

            # Extract agent_id + api_key from JSON without requiring jq.
            AGENT_ID="\$(echo "\${REG_RESPONSE}" | sed -n 's/.*"agent_id":"\\([^"]*\\)".*/\\1/p')"
            API_KEY="\$(echo "\${REG_RESPONSE}" | sed -n 's/.*"api_key":"\\([^"]*\\)".*/\\1/p')"

            if [ -z "\${AGENT_ID}" ] || [ -z "\${API_KEY}" ]; then
                echo "!! Registration failed. Dashboard response:"
                echo "   \${REG_RESPONSE}"
                echo "!! Check that \${DASHBOARD_URL}/api/agent/register is reachable (firewall / Cloudflare)."
                exit 1
            fi
            echo "    Registered — agent_id: \${AGENT_ID}"

            echo "==> Writing config to \${CONFIG_DIR}/config.yaml"
            cat > "\${CONFIG_DIR}/config.yaml" <<CONFIG
        # Nawasara Agent Configuration (auto-generated by install.sh)
        dashboard_url: \${DASHBOARD_URL}
        agent_name: \${HOSTNAME_VAL}
        agent_id: \${AGENT_ID}
        api_key: \${API_KEY}

        collector:
          web_server: auto
          ssh_log: auto
          metrics_interval: 30s

        reporter:
          heartbeat_interval: 60s

        plugins:
          enabled:
            - nginx
            - ssh
          # Server yang host aplikasi Laravel: tambahkan "- laravel" di enabled.
          laravel:
            log_paths:
              - /var/www/html/storage/logs/*.log

        scanner:
          enabled: false                           # Set true to enable the Phase 3 file scanner
          scan_interval: 6h
          web_dirs:
            - /var/www/html
            - /home/*/public_html
          watch_paths:                             # FILE saja — direktori diabaikan integrity checker
            - /etc/nginx/nginx.conf
            - /etc/ssh/sshd_config
          hash_db: /var/lib/nawasara-agent/hashes.db
        CONFIG
            chmod 600 "\${CONFIG_DIR}/config.yaml"
        else
            echo "    Config already exists — skipping registration."
        fi

        # Install systemd service
        if [ ! -f "\$SERVICE_FILE" ]; then
            echo "==> Installing systemd service..."
            cat > "\$SERVICE_FILE" <<'SERVICE'
        [Unit]
        Description=Nawasara Security Agent
        After=network.target

        [Service]
        Type=simple
        ExecStart=/usr/local/bin/nawasara-agent run --config /etc/nawasara-agent/config.yaml
        Restart=always
        RestartSec=10
        User=root
        StandardOutput=append:/var/log/nawasara-agent/agent.log
        StandardError=append:/var/log/nawasara-agent/agent.log

        [Install]
        WantedBy=multi-user.target
        SERVICE
            systemctl daemon-reload
            systemctl enable nawasara-agent
        fi

        # Start (or restart) the service now that config + service exist.
        echo "==> Starting nawasara-agent..."
        systemctl restart nawasara-agent

        echo ""
        echo "==> Installation complete! Agent registered + running."
        echo "    agent_id : \${AGENT_ID:-<existing>}"
        echo "    config   : \${CONFIG_DIR}/config.yaml"
        echo "    logs     : tail -f \${LOG_DIR}/agent.log"
        echo ""
        echo "    To enable the file scanner (Phase 3): set scanner.enabled: true"
        echo "    in the config and edit web_dirs/watch_paths, then:"
        echo "      systemctl restart nawasara-agent"
        BASH;

        // Strip leading spaces from heredoc indentation
        $lines  = explode("\n", $script);
        $script = implode("\n", array_map(fn ($l) => preg_replace('/^        /', '', $l), $lines));

        return response($script, 200, [
            'Content-Type'        => 'text/plain; charset=utf-8',
            'Content-Disposition' => 'inline; filename="install.sh"',
            'Cache-Control'       => 'no-store',
            'X-Robots-Tag'        => 'noindex',
        ]);
    }

    /**
     * GET /agent/download/{version}/{os}/{arch}/{binary}
     *
     * Redirects to the GitHub Releases asset for the requested binary.
     * version = "latest" resolves to the latest GitHub release tag.
     *
     * Examples:
     *   /agent/download/latest/linux/amd64/nawasara-agent
     *   /agent/download/v0.2.0/linux/arm64/nawasara-agent
     */
    public function download(string $version, string $os, string $arch, string $binary): RedirectResponse
    {
        $repo    = config('nawasara-secscan.agent.github_repo', 'nawasara/agent');
        $allowed = ['linux'];
        $archs   = ['amd64', 'arm64'];

        if (! in_array($os, $allowed, true) || ! in_array($arch, $archs, true)) {
            abort(404, 'Unsupported OS or architecture.');
        }

        // Sanitise binary name — only allow the expected filename
        if (! preg_match('/^nawasara-agent(\.exe)?$/', $binary)) {
            abort(404);
        }

        $assetName = "nawasara-agent-{$os}-{$arch}";

        if ($version === 'latest') {
            $url = "https://github.com/{$repo}/releases/latest/download/{$assetName}";
        } else {
            // Normalise — accept "v0.2.0" or "0.2.0"
            $tag = str_starts_with($version, 'v') ? $version : "v{$version}";
            $url = "https://github.com/{$repo}/releases/download/{$tag}/{$assetName}";
        }

        return redirect()->away($url);
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
