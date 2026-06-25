<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Secscan\Livewire\Dashboard\Index as DashboardIndex;
use Nawasara\Secscan\Livewire\Findings\Index as FindingsIndex;
use Spatie\Permission\Middleware\PermissionMiddleware;

Route::middleware(['web', 'auth'])->prefix('nawasara-secscan')->group(function () {
    Route::get('dashboard', DashboardIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.dashboard');

    Route::get('findings', FindingsIndex::class)
        ->middleware(PermissionMiddleware::using('secscan.view'))
        ->name('nawasara-secscan.findings');
});
