<?php

namespace Nawasara\Secscan\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Secscan\Services\DecisionEngine;

/**
 * Runs the Decision Engine for one incident off the request path, so incident
 * ingestion (POST /api/agent/incidents) stays fast and a Cloudflare call never
 * blocks the agent's HTTP request.
 */
class EvaluateIncidentJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 2;
    public int $timeout = 30;

    public function __construct(public int $incidentId)
    {
    }

    public function handle(DecisionEngine $engine): void
    {
        $incident = SecurityIncident::find($this->incidentId);
        if (! $incident) {
            return;
        }
        $engine->evaluate($incident);
    }
}
