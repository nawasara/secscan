<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Secscan\Http\Controllers\Api\AgentController;
use Nawasara\Secscan\Livewire\Agents\Index as AgentsIndex;
use Nawasara\Secscan\Livewire\Dashboard\Index as DashboardIndex;
use Nawasara\Secscan\Livewire\Findings\Index as FindingsIndex;
use Nawasara\Secscan\Livewire\Incidents\Index as IncidentsIndex;
use Spatie\Permission\Middleware\PermissionMiddleware;

Route::middleware(['web', 'auth'])->prefix('nawasara-secscan')->group(function () {
    Route::get('dashboard', DashboardIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.dashboard');

    Route::get('findings', FindingsIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.findings');

    Route::get('agents', AgentsIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.agents');

    Route::get('incidents', IncidentsIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.incidents');
});

// Agent API — no auth session, uses X-Agent-Key header
Route::middleware(['api'])->prefix('api/agent')->group(function () {
    Route::post('register',   [AgentController::class, 'register']);
    Route::post('incidents',  [AgentController::class, 'incidents']);
    Route::post('heartbeat',  [AgentController::class, 'heartbeat']);
});
