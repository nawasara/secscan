<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Secscan\Http\Controllers\Api\AgentController;
use Nawasara\Secscan\Livewire\Agents\Index as AgentsIndex;
use Nawasara\Secscan\Livewire\Agents\Show as AgentShow;
use Nawasara\Secscan\Livewire\Dashboard\Index as DashboardIndex;
use Nawasara\Secscan\Livewire\Findings\Index as FindingsIndex;
use Nawasara\Secscan\Livewire\Incidents\Index as IncidentsIndex;
use Nawasara\Secscan\Livewire\IpTimeline\Show as IpTimelineShow;
use Spatie\Permission\Middleware\PermissionMiddleware;

Route::middleware(['web', 'auth'])->prefix('nawasara-secscan')->group(function () {
    Route::get('dashboard', DashboardIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.dashboard');

    Route::get('findings', FindingsIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.findings');

    Route::get('incidents', IncidentsIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.incidents');

    Route::get('agents', AgentsIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.agents');

    Route::get('agents/{agentId}', AgentShow::class)
        ->middleware(PermissionMiddleware::using('secscan.agent.view'))
        ->name('nawasara-secscan.agents.show');

    Route::get('ip/{ip}', IpTimelineShow::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->where('ip', '[0-9a-fA-F.:]+')
        ->name('nawasara-secscan.ip-timeline');
});

// Agent API — no auth session, uses X-Agent-Key + X-Agent-Id headers
Route::middleware(['api'])->prefix('api/agent')->group(function () {
    Route::post('register',          [AgentController::class, 'register']);
    Route::post('incidents',         [AgentController::class, 'incidents']);
    Route::post('heartbeat',         [AgentController::class, 'heartbeat']);
    Route::get('commands/pending',   [AgentController::class, 'commandsPending']);
    Route::post('command-result',    [AgentController::class, 'commandResult']);
});

// Agent binary download — redirects to GitHub Releases asset
// Example: GET /agent/download/latest/linux/amd64/nawasara-agent
Route::get('agent/download/{version}/{os}/{arch}/{binary}', [AgentController::class, 'download'])
    ->where('version', '[a-zA-Z0-9._-]+')
    ->where('os', '[a-z]+')
    ->where('arch', '[a-z0-9]+')
    ->where('binary', '[a-zA-Z0-9._-]+')
    ->name('nawasara-secscan.agent.download');
