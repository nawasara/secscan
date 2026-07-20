<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Secscan\Http\Controllers\Api\AgentController;
use Nawasara\Secscan\Livewire\Agents\Index as AgentsIndex;
use Nawasara\Secscan\Livewire\Agents\Show as AgentShow;
use Nawasara\Secscan\Livewire\Dashboard\Index as DashboardIndex;
use Nawasara\Secscan\Livewire\Findings\Index as FindingsIndex;
use Nawasara\Secscan\Livewire\Incidents\Index as IncidentsIndex;
use Nawasara\Secscan\Livewire\IpBlocks\Index as IpBlocksIndex;
use Nawasara\Secscan\Livewire\IpTimeline\Show as IpTimelineShow;
use Nawasara\Secscan\Livewire\Settings\Notification as SettingsNotification;
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

    Route::get('ip-blocks', IpBlocksIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.ip-block.manage'))
        ->name('nawasara-secscan.ip-blocks');

    Route::get('ip/{ip}', IpTimelineShow::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->where('ip', '[0-9a-fA-F.:]+')
        ->name('nawasara-secscan.ip-timeline');

    Route::get('settings/notification', SettingsNotification::class)
        ->middleware(PermissionMiddleware::using('secscan.settings.manage'))
        ->name('nawasara-secscan.settings.notification');
});

// Agent API routes are registered in routes/api.php (root app) to avoid
// web middleware CSRF redirect. See bootstrap/app.php apiPrefix: ''.

// Agent install script — served as text/plain, no auth required
// curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | bash
Route::get('agent/install.sh', [AgentController::class, 'installScript'])
    ->name('nawasara-secscan.agent.install');

// Agent binary download — redirects to GitHub Releases asset
// Example: GET /agent/download/latest/linux/amd64/nawasara-agent
Route::get('agent/download/{version}/{os}/{arch}/{binary}', [AgentController::class, 'download'])
    ->where('version', '[a-zA-Z0-9._-]+')
    ->where('os', '[a-z]+')
    ->where('arch', '[a-z0-9]+')
    ->where('binary', '[a-zA-Z0-9._-]+')
    ->name('nawasara-secscan.agent.download');
